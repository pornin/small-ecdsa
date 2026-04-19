#include <stddef.h>
#include <stdint.h>

#include "ecdsa-p256-verify.h"

/*
 * One of TV_ARCH_GEN32 or TV_ARCH_GEN64 must be set; if neither is, then
 * we autodetect the "best" one: the 64-bit code is used if a
 * 64x64->128 multiplication is available, the 32-bit code otherwise.
 */
#if !defined TV_ARCH_GEN32 && !defined TV_ARCH_GEN64
#if defined __SIZEOF_INT128__ || defined _M_X64 || defined _M_ARM64
#define TV_ARCH_GEN64   1
#else
#define TV_ARCH_GEN32   1
#endif
#endif

/* ===== Finite field (integers modulo a 256-bit integer) ===== */
/*
 * The code works with integers represented over k limbs: limbs are
 * signed integers in base 2^h, and for limbs x_i (i = 0 to k-1),
 * the integer value is x = \sum_{i=0}^{k-1} x_i*2^(h*i).
 *
 * Limbs are stored in machine words of w bits, with w being greater
 * than h. The core idea is that the representation is redundant, i.e.
 * limb values are allowed to be outside of the nominal [0, 2^h-1]
 * range. Redundant representations allow for performing additions and
 * subtractions in a limb-wise way, without carry propagation or
 * cross-limb dependencies, making these operations especially
 * efficient. More generally, none of the primitives implemented here
 * really needs or even benefits from hardware support for carry/borrow
 * inputs and outputs for additions and subtractions; this should be
 * helpful, both for speed and code size, on architectures where carry
 * support is slow, or even completely absent (as in RISC-V systems).
 *
 * The flip side of redundant representations is that there are limits
 * to how many additions and subtractions can be performed in a row,
 * before performing an operation that shrinks back limbs to a 2^h-sized
 * range. Careful range analysis must be performed to ensure that all
 * operations always fit within these limits. This constraints the
 * choices for the number of limbs (k) and the base (h). The two
 * representations implemented below have been proven to allow for
 * correct outputs for the operations used in ECDSA signature
 * verification. Note that this is sensitive to the exact formulas used
 * for point addition (here, the Renes-Costello-Batina formulas) and if
 * these formulas are modified then the analysis must be performed
 * again.
 *
 * We define the following terms for an integer value, which is
 * represented as an integer x and considered modulo a given 256-bit
 * modulus m. The two considered moduli are p and n:
 *
 *  - p = 2^256 - 2^224 + 2^192 + 2^96 - 1
 *    is the modulus for the coordinate field, used to represent curve
 *    point coordinates (as used in the public key);
 *  - n = p + 1 - 89188191154553853111372247798585809583
 *    is the (prime) number of points on the curve, and the modulus for
 *    the scalar field (the (r,s) signature elements are scalars).
 *
 * We say that the value is _normalized_ if all limbs except the top one
 * are forced into a nominal range of size 2^h. The normalization is
 * _signed_ if that range is [-2^(h-1), 2^(h-1) - 1]; it is _unsigned_
 * if the range is [0, 2^h - 1]. Normalization allows to test the integer
 * for zero and negative values:
 *  - a normalized integer is zero if and only if all its limbs are zero;
 *  - an unsigned-normalized integer is negative if and only if its top
 *    limb is negative;
 *  - a signed-normalized integer is negative if and only if its highest
 *    non-zero limb is negative.
 *
 * A _reduced_ integer modulo m is such that its value is in a given range
 * of size m. _Signed-reduction_ uses the [-(m-1)/2, +(m-1)/2] range (note
 * that m is odd); _unsigned-reduction_ uses the [0, m-1] range.
 *
 * A _canonical_ integer modulo m is such that it has unsigned-normalization
 * and unsigned-reduction: its value is in the [0, m-1] range, all limbs
 * except the top one as in [0, 2^h - 1], and the top limb is non-negative.
 *
 * The gf_add() and gf_sub() functions implement limb-wise addition and
 * subtraction. gf_mul() implements Montgomery multiplication using a
 * constant R = 2*(k*h):
 *
 *  - The Montgomery representation of an integer x (modulo m) is an
 *    integer equal to x*R mod m. We denote that representation as Mont(x).
 *
 *  - Montgomery multiplication takes two inputs x and y, and returns
 *    mmul(x,y) = x*y/R mod m. Notably: mmul(Mont(x), Mont(y)) = Mont(x*y),
 *    which means that gf_mul() _is_ modular multiplication as long as
 *    inputs and outputs are considered to be in Montgomery representation.
 *
 *  - Montgomery reduction is Montgomery multiplication by 1. It converts
 *    a value from Montgomery to non-Montgomery representation:
 *       mmul(Mont(x), 1) = x*R*1/R = x mod m
 *    A byproduct if Montgomery reduction is that (with the implementations
 *    below) it returns a value with both signed-reduced and normalized
 *    (unsigned-normalized for the 64-bit implementation, signed-normalized
 *    for the 32-bit implementation).
 *
 * Conversion _to_ Montgomery representation is normally done by computing
 * a Montgomery multiplication with the constant R^2:
 *    mmul(x, R^2) = x*R^2/R = x*R = Mont(x) mod m
 * However, we do not need that operation for implementing ECDSA signature
 * verification. This is a byproduct of the use of projective coordinates
 * for curve points, and of inversion over scalars. Indeed, given an input
 * Mont(x), gf_invert() computes Mont(1/x) mod m (it does so using
 * Fermat's Little Theorem, i.e. raising to power m-2, which is done with
 * a lot of gf_mul() calls). Equivalently, given a plain integer x (which
 * is equal to Mont(x/R)), gf_invert() computes Mont(1/(x/R)) = Mont(R/x).
 * In the signature verification, the two scalars r and s are decoded,
 * then s is inverted and multiplied with r, so that we compute:
 *
 *   inversion:
 *     s' = Mont(R/s)
 *   multiplication with r:
 *     mmul(r, s') = mmul(Mont(r/R), Mont(R/s)) = Mont((r/R)*(R/s) = Mont(r/s)
 *
 * Montgomery reduction then yields r/s (non-Montgomery) in a reduced and
 * normalized format which is easy to canonicalize. At no point did we
 * need any explicit conversion to Montgomery representation; it just came
 * out as a byproduct of inversion. Correspondingly, the R^2 constant is
 * not included in the core code (it is present in the test code to support
 * some unit tests).
 *
 * A similar process happens with curve points. We use projective
 * coordinates (X:Y:Z) such that x = X/Z and y = Y/Z. We can consider
 * X, Y and Z to be either plain integers, or Montgomery representations
 * of X/R, Y/R and Z/R, respectively; both conventions work simultaneously
 * and designate the same point. When converting a point back to affine
 * coordinates, the same gf_invert()+gf_mul() yields Mont(x), and Montgomery
 * reduction leads to the (almost) canonicalized x coordinate, again without
 * needing any explicit conversion to Montgomery representation.
 *
 * ------------------------------------------------------------------------
 *
 * On 64-bit machines (that is, machines that support a 64x64->128
 * multiplication), we use k=5 limbs of h=54 bits each, represented over
 * 5 64-bit words (w=64). The output of gf_mul() is unsigned-normalized.
 * Montgomery constant is R = 2^270  (since 270 = 5*54). Values use
 * 40 bytes in RAM.
 *
 * On 32-bit machines (that is, machines that do not support a 64x64->128
 * multiplication), we use k=12 limbs of h=22 bits each, represented over
 * 12 32-bit words (w=32). The output of gf_mul() is signed-normalized
 * (signed-normalization is necessary to contain limb growth within an
 * acceptable range, even though it slightly complicates canonicalization).
 * Montgomery constant is R = 2^264  (since 264 = 12*22). Values use
 * 48 bytes in RAM.
 *
 * ------------------------------------------------------------------------
 *
 * NOTE ON SIDE CHANNELS:
 * ======================
 *
 * All this code is for a signature _verification_, where everything is
 * public and there is nothing to leak; thus, any notion of "constant-time
 * code" is irrelevant. Some of the functions below actually follow a
 * constant-time coding pattern, but this is mostly fortuitous and
 * MUST NOT be relied upon.
 */

#if defined TV_ARCH_GEN64
/* 64-bit code: 5 limbs of 54 bits. */
typedef int64_t limb;
typedef uint64_t ulimb;
#define NUM_LIMBS   5
#define LIMB_H      54
#define MMH         0x003FFFFFFFFFFFFF    /* 2^54 - 1 */
#elif defined TV_ARCH_GEN32
/* 32-bit code: 12 limbs of 22 bits. */
typedef int32_t limb;
typedef uint32_t ulimb;
#define NUM_LIMBS   12
#define LIMB_H      22
#define MMH         0x003FFFFF            /* 2^22 - 1 */
#endif

/* Type for a value. */
typedef struct {
	limb w[NUM_LIMBS];
} gf;

/* In order to represent the curve generator as a constant point, we
   need to define the 'point' structure here. */
typedef struct {
	gf x, y, z;
} point;

/* Each modulus is represented as an array of limbs, followed by a single
   word-sized element which is equal to (-1/m mod 2^h)*2^(w-h). This
   constant is used in gf_mul().

   The constants are:
      mod_P   modulus p
      mod_N   modulus n
      Bm      Mont(b) for curve parameter b
      G       conventional generator point
   Note that the generator point
   */

#if defined TV_ARCH_GEN64
/* p = modulus of the coordinate field. */
static const limb mod_P[] = {
	0x3FFFFFFFFFFFFF, 0x0003FFFFFFFFFF, 0x00000000000000,
	0x00000040000000, 0x0000FFFFFFFF00,
	0x0000000000000400   // (-1/p mod 2^54)*2^10
};
/* n = modulus of the scalar field (curve order). */
static const limb mod_N[] = {
	0x39CAC2FC632551, 0x2AB69C5E7A13CE, 0x3FFFFFFFFBCE6F,
	0x0000003FFFFFFF, 0x0000FFFFFFFF00,
	0x4722ABB802F13C00   // (-1/n mod 2^54)*2^10
};
/* Curve constant b (in Montgomery representation). */
static const gf gf_Bm = {
	{  0x188A712F77F70C,  0x1C543090D89CDF,  0x04BB5AB3C01732,
	   0x034097220ABF72,  0x00000187782DD2, }
};
/* Curve generator point. */
static const point G = {
	/* Gx */
	{ {  0x213945D898C296,  0x3604B7ACCE83D2,  0x163A440F277037,
	     0x0B1091FE2F39B9,  0x00006B17D1F2E1, } },
	/* Gy */
	{ {  0x36406837BF51F5,  0x0D5DACC57B3B2E,  0x27C0F9E162BCE3,
	     0x069FE6E3B9FAD2,  0x00004FE342E2FE, } },
	/* 1 */
	{ {  1, 0, 0, 0, 0, } },
};
#elif defined TV_ARCH_GEN32
/* p = modulus of the coordinate field. */
static const limb mod_P[] = {
	0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x3FFFFF, 0x0000FF, 0x000000,
	0x000000, 0x000000, 0x010000, 0x000000, 0x3FFFF0, 0x003FFF,
	0x00000400   /* (-1/p mod 2^22)*2^10 */
};
/* n = modulus of the scalar field (curve order). */
static const limb mod_N[] = {
	0x232551, 0x2B0BF1, 0x0F3B9C, 0x05E7A1, 0x3AADA7, 0x3EF39B,
	0x3FFFFF, 0x3FFFFF, 0x00FFFF, 0x000000, 0x3FFFF0, 0x003FFF,
	0x02F13C00   /* (-1/n mod 2^32)*2^10 */
};
/* Curve constant b (in Montgomery representation). */
static const gf gf_Bm = {
	{ -0x022024,  0x08A713,  0x09CDF6,  0x0C2436,  0x0C9C84, -0x0C3FE9,
	   0x12ED6B, -0x150238,  0x09A221,  0x1D20D0, -0x1E21F8,  0x000C02, }
};
/* Curve generator point. */
static const point G = {
	/* Gx (Montgomery representation). */
	{{  0x18C296, -0x1AE89E,  0x0F4A14, -0x053318, -0x027ED2,  0x09DC0E,
	   -0x05BBF1, -0x0646A7,  0x07F8BD,  0x04B109, -0x02E0D2,  0x001AC6, }},
	/* Gy (Montgomery representation). */
	{{ -0x00AE0B,  0x01A0DF, -0x13449C,  0x0C57B4, -0x0CA895,  0x18AF39,
	    0x00F9E1, -0x052D61,  0x1B8EE8, -0x079602, -0x0BD1D0,  0x0013F9, }},
	/* 1 */
	{{  1, 0, 0, 0, 0, }},
};
#endif

/* The Z coordinate of G is also the constant 1. */
#define gf_ONE   (G.z)

/* Decode a 32-byte input (unsigned big-endian encoding) into a
   256-bit integer (gf, canonical). */
static void
decode_int(gf *d, const uint8_t *src)
{
#if defined TV_ARCH_GEN64
	/* We accumulate bytes in high-to-low order, and output the
	   next limb when needed.
	    after i=4: total accumulated is 40 bits, limb 4 uses acc[0..39]
	    after i=11: total is 96 bits, limb 3 uses acc[2..55]
	    after i=18: total is 152 bits, limb 2 uses acc[4..57]
	    after i=25: total is 208 bits, limb 1 uses acc[6..59]
	   At the end (after i=31) we have 256 bits and limb 0 uses
	   bits acc[0..53]. */
	uint64_t acc = 0;
	int j = 5, s = 0;
	for (int i = 0, k = 2; i < 32; i ++) {
		acc = (acc << 8) | src[i];
		if (++ k == 7) {
			d->w[-- j] = (int64_t)((acc >> s) & MMH);
			k = 0;
			s += 2;
		}
	}
	d->w[0] = (int64_t)(acc & MMH);
#elif defined TV_ARCH_GEN32
	uint32_t acc = 0;
	int acc_len = 8;
	int j = 12;
	for (int i = 0; i < 32; i ++) {
		acc = (acc << 8) | src[i];
		acc_len += 8;
		if (acc_len >= 22) {
			acc_len -= 22;
			d->w[-- j] = (int32_t)((acc >> acc_len) & MMH);
		}
	}
#endif
}

/* Limb-wise addition. */
static inline void
zz_add(limb *d, const limb *a, const limb *b)
{
	for (int i = 0; i < NUM_LIMBS; i ++) {
		d[i] = a[i] + b[i];
	}
}

/* Limb-wise subtraction. */
static inline void
zz_sub(limb *d, const limb *a, const limb *b)
{
	for (int i = 0; i < NUM_LIMBS; i ++) {
		d[i] = a[i] - b[i];
	}
}

/* Wrapper macros that use gf pointers. */
#define gf_add(d, a, b)   zz_add((d)->w, (a)->w, (b)->w)
#define gf_sub(d, a, b)   zz_sub((d)->w, (a)->w, (b)->w)

/* Unsigned-normalize a value: all limbs except the top one are forced to
   [0, 2^h - 1] by propagating high bits. Once a value is unsigned-normalized:
    - It is equal to zero if and only if all limbs are zero.
    - It is negative (as an integer) if and only if its top limb is negative. */
static void
gf_unsigned_normalize(gf *d, const gf *a)
{
	limb cc = 0;
	for (int i = 0; i < (NUM_LIMBS - 1); i ++) {
		limb z = a->w[i] + cc;
		d->w[i] = z & MMH;
		cc = z >> LIMB_H;
	}
	d->w[NUM_LIMBS - 1] = a->w[NUM_LIMBS - 1] + cc;
}

#if defined TV_ARCH_GEN64

/* Montgomery multiplication. Output is unsigned-normalized. */
static void
gf_mul(gf *d, const gf *a, const gf *b, const int64_t *m)
{
	/* DEF_MULS(d, u, v) defines variables 'dlo' (uint64_t) and
	   'dhi' (int64_t), and fills them with the low and high halves
	   of the product of u by v (with u and v both being signed
	   64-bit values). */
	#ifdef __SIZEOF_INT128__
	#define DEF_MULS(d, u, v) \
		__int128 d ## 128 = (__int128)(u) * (__int128)(v); \
		uint64_t d ## lo = (uint64_t)d ## 128; \
		int64_t d ## hi = (int64_t)(d ## 128 >> 64);
	#else
	#define DEF_MULS(d, u, v) \
		uint64_t d ## lo = (uint64_t)(u) * (uint64_t)(v); \
		int64_t d ## hi = __mulh((u), (v));
	#endif

	int64_t aa[5];
	gf t = { { 0, 0, 0, 0, 0 } };

	/* m = modulus to use (N for scalars, P for coordinates)
	   m0i = (-1/m mod 2^54)*2^10 */
	uint64_t m0i = (uint64_t)m[5];

	/* Load first operand into aa, limbs preshifted by 5 bits */
	for (int i = 0; i < 5; i ++) {
		aa[i] = a->w[i] << 5;
	}

	for (int i = 0; i < 5; i ++) {
		/* Load multiplier, pre-shifted by 5 bits */
		int64_t bi = b->w[i] << 5;

		/* x <- (a_0*b_i)*2^10
		   The split of x0 into low and high halves (54-bit)
		   falls on the 64-bit boundary. */
		DEF_MULS(x, aa[0], bi)

		/* f <- (-(x + t_0)/m_0 mod 2^54) << 10
		   The left-shift by 10 bits is used to make the modular
		   reduction automatic (since uint64_t works modulo 2^64). */
		int64_t tt = t.w[0] + (int64_t)(xlo >> 10);
		uint64_t uf = (uint64_t)tt * m0i;
		/* We want the signed interpretation of f. */
		int64_t f = *(int64_t *)&uf;

		/* y <- (f*m_0)*2^10 */
		DEF_MULS(y, m[0], f)

		/* Choice of f ensures that x + y + (t_0 << 10) = 0 mod 2^64.
		   cc <- (x + y + (t_0 << 10)) >> 64
		   t_0 may have extra bits, and there could be carries from
		   the additions. */
		int64_t cclo = tt + (int64_t)(ylo >> 10);
		int64_t cc = xhi + yhi + (cclo >> 54);

		for (int j = 1; j < 5; j ++) {
			DEF_MULS(x, aa[j], bi)
			DEF_MULS(y, m[j], f)
			t.w[j - 1] = t.w[j] + cc
				+ (int64_t)((xlo >> 10) + (ylo >> 10));
			cc = xhi + yhi;
		}
		t.w[4] = cc;
	}

	/* Propagate upper bits to ensure that limbs 0 to 3 are in
	   the [0, 2^54 - 1] range. */
	gf_unsigned_normalize(d, &t);

	#undef DEF_MULS
}

#elif defined TV_ARCH_GEN32

/* Montgomery multiplication. Output is signed-normalized. */
static void
gf_mul(gf *d, const gf *a, const gf *b, const int32_t *m)
{
	/* DEF_MULS(d, u, v) defines variables 'dlo' (uint32_t) and
	   'dhi' (int32_t), and fills them with the low and high halves
	   of the product of u by v (with u and v both being signed
	   32-bit values). */
	#define DEF_MULS(d, u, v) \
		int64_t d ## 64 = (int64_t)(u) * (int64_t)(v); \
		uint32_t d ## lo = (uint32_t)d ## 64; \
		int32_t d ## hi = (int32_t)(d ## 64 >> 32);

	int32_t aa[12];
	int32_t t[12];
	uint32_t m0i = (uint32_t)m[12];   /* (-1/p mod 2^22)*2^10 */

	for (int i = 0; i < 12; i ++) {
		t[i] = 0;
	}
	for (int i = 0; i < 12; i ++) {
		aa[i] = a->w[i] << 5;
	}
	for (int i = 0; i < 12; i ++) {
		int32_t bi = b->w[i] << 5;
		DEF_MULS(x, aa[0], bi)
		int32_t tt = t[0] + (int32_t)(xlo >> 10);
		uint32_t uf = (uint32_t)tt * m0i;
		int32_t f = *(int32_t *)&uf;
		DEF_MULS(y, m[0], f)
		int32_t cclo = tt + (int32_t)(ylo >> 10);
		int32_t cc = xhi + yhi + (cclo >> 22);

		for (int j = 1; j < 12; j ++) {
			DEF_MULS(x, aa[j], bi)
			DEF_MULS(y, m[j], f)
			t[j - 1] = t[j] + cc
				+ (int32_t)((xlo >> 10) + (ylo >> 10));
			cc = xhi + yhi;
		}
		t[11] = cc;
	}

	/* For the 32-bit version, we need signed-normalization, otherwise
	   limbs grow too much within the curve formulas. */
	int32_t cc = 0;
	for (int j = 0; j < 11; j ++) {
		int32_t z = t[j] + cc;
		uint32_t uz = (uint32_t)z << 10;
		int32_t dj = *(int32_t *)&uz >> 10;
		d->w[j] = dj;
		cc = (z - dj) >> 22;
	}
	d->w[11] = t[11] + cc;

#undef DEF_MULS
}

#endif

/* Montgomery reduction is division by R; it is equivalent to Montgomery
   multiplication by 1. The output is normalized. For all the values used
   here, this also ensures that the output is in [-m/2, +m/2]. */
#define gf_mred(d, a, m)   gf_mul(d, a, &gf_ONE, m)

/* Check whether a value is zero or not. This works reliably only for
   normalized values, and uses equality over integers. */
static int
gf_iszero(const gf *a)
{
	limb x = 0;
	for (int i = 0; i < NUM_LIMBS; i ++) {
		x |= a->w[i];
	}
	return x == 0;
}

/* Check that a decoded value is in the expected range [0,m-1].
   This function assumes that the value is freshly decoded (limbs 0..3
   are in [0, 2^54-1], limb 4 is in [0, 2^40-1]). */
static int
gf_check_range(const gf *a, const limb *m)
{
	gf t;
	zz_sub(t.w, a->w, m);
	gf_unsigned_normalize(&t, &t);
	return t.w[NUM_LIMBS - 1] < 0;
}

/* Macros for bit enumeration. These macros define an iterator that can
   observe bits from a value in high to low order, from bit 255 down to
   bit 0.

   Enumeration usage must be encapsulated between ITER_BEGIN and ITER_END;
   this defines an inner C scope. The 'skip' parameter to ITER_BEGIN makes
   the iterator skip the first 'skip' bits of the value (this works only
   for small skip values, e.g. skip < 10).

   ITER_NEXT advances the iterator. ITER_DONE evaluates to 1 when the
   iterator has been advanced past its last element. It is up to the
   caller to organize a loop and use ITER_NEXT and ITER_DONE.

   ITER_TESTBIT(v) tests the bit of v at the index currently contained in
   the iterator (v should be a limb[] array). */

#define ITER_BEGIN(skip)   { \
	ulimb iter_mask = (ulimb)1 << (255 - (NUM_LIMBS - 1)*LIMB_H - (skip)); \
	int iter_index = NUM_LIMBS - 1;

#define ITER_TESTBIT(v)   (((v)[iter_index] & iter_mask) != 0)

#define ITER_NEXT   do { \
		iter_mask >>= 1; \
		if (iter_mask == 0) { \
			iter_index --; \
			iter_mask = (ulimb)1 << (LIMB_H - 1); \
		} \
	} while (0)

#define ITER_DONE   (iter_index < 0)

#define ITER_END   }

/* Modular inversion.
   This assumes that Montgomery representation is used, i.e. given x*R,
   it returns R/x mod m. If interpreted over plain integers, this function
   returns R^2/y mod m for input y. If input is zero, then zero is returned. */
static void
gf_invert(gf *x, const limb *m)
{
	gf t = *x;

	/* Exponent is m-2. For both p and n, the subtraction on the low
	   limb incurs no overflow, so the resulting exponent is still
	   canonical. */
	limb e[NUM_LIMBS];
	e[0] = m[0] - 2;
	for (int i = 1; i < NUM_LIMBS; i ++) {
		e[i] = m[i];
	}

	/* We iterate over bits of m-2 (skipping the top bit, which is
	   assumed to be 1, as is the case for both n and p), in high-to-low
	   order. */
	ITER_BEGIN(1)
	while (!ITER_DONE) {
		/* x <- x^2 */
		gf_mul(x, x, x, m);

		/* If next bit of m-2 is one: x <- x*t
		   (t contains a copy of the original value). */
		if (ITER_TESTBIT(e)) {
			gf_mul(x, x, &t, m);
		}
		ITER_NEXT;
	}
	ITER_END
}

/* Canonicalize a value by converting it out of Montgomery representation,
   then ensuring that all limbs are non-negative and the overall value is
   in [0,m-1]. */
static void
gf_canonicalize(gf *x, const limb *m)
{
	/* Montgomery reduction returns a value in [-m/2, +m/2]. */
	gf_mred(x, x, m);

#if defined TV_ARCH_GEN32
	/* gf_mred() output is signed-normalized, but this is inconvenient
	   for testing the sign, so we unsigned-normalize it. */
	gf_unsigned_normalize(x, x);
#endif

	/* On an unsigned-normalized value, we can look at its top limb to
	   get its sign, and add m only if it is negative. */
	if (x->w[NUM_LIMBS - 1] < 0) {
		zz_add(x->w, x->w, m);
		gf_unsigned_normalize(x, x);
	}
}

/* Set a value to zero. */
static inline void
gf_set_zero(gf *d)
{
	for (int i = 0; i < NUM_LIMBS; i ++) {
		d->w[i] = 0;
	}
}

/* Set a value to one. */
static inline void
gf_set_one(gf *d)
{
	d->w[0] = 1;
	for (int i = 1; i < NUM_LIMBS; i ++) {
		d->w[i] = 0;
	}
}

#ifdef TV_ECDSA_P256_TEST
/*
 * The test API implements some primitive functions for working in the
 * coordinate and scalar fields. For users of this API, values are
 * field elements, and Montgomery representation is invisible; thus,
 * the decoding function (tv_gf_decode()) converts the value to
 * Montgomery representation, and the encoding function (tv_gf_encode())
 * converts back to plain (canonical) representation.
 */

#if defined TV_ARCH_GEN64
/* 2^540 mod p */
static const gf gf_R2p = {
	{  0x00000030000000,  0x3FFFC000000000,  0x3EFFFFFFFBFFFF,
	   0x3FFFFFFFFFFFFF,  0x00004FFFFFFFDF, }
};
/* 2^540 mod n */
static const gf gf_R2n = {
	{  0x3644694887AC57,  0x28AB84C1E17805,  0x19619076A9EA8C,
	   0x059212A4ADAFB1,  0x000055ABA83AFC, }
};
#elif defined TV_ARCH_GEN32
/* 2^528 mod p */
static const gf gf_R2p = {
	{  0x030000,  0x000000,  0x000000, -0x004000,  0x000000, -0x000010,
	  -0x001000,  0x000000,  0x000000, -0x000800,  0x100000,  0x000001, }
};

/* 2^528 mod n */
static const gf gf_R2n = {
	{  0x1FEDCF, -0x1DD596, -0x1F07F2, -0x113234,  0x068A2B,  0x01AAE3,
	   0x059619,  0x0ADAFB, -0x1B4DC7,  0x187F06,  0x15ABA5,  0x000B65, }
};
#endif

/* Tell whether the internal format uses an unreduced format with limb
   limits. */
int
tv_gf_has_unreduced(void)
{
	return 1;
}

/* Check that the provided value is within the correct ranges. */
int
tv_gf_check(const gf *x, int scalar)
{
	(void)scalar;
	for (int i = 0; i < NUM_LIMBS; i ++) {
#if defined TV_ARCH_GEN64
		/* We allow limbs up to 5.5 times the nominal limb range
		   (in absolute value). */
		uint64_t m;
		if (i == NUM_LIMBS - 1) {
			m = (uint64_t)11 << 39;
		} else {
			m = (uint64_t)11 << 53;
		}
		int64_t z = (int64_t)x->w[i];
		uint64_t zs = (uint64_t)(z >> 63);
		uint64_t a = ((uint64_t)z ^ zs) - zs;
#elif defined TV_ARCH_GEN32
		uint32_t m;
		if (i == NUM_LIMBS - 1) {
			m = (uint32_t)11 << 13;
		} else {
			m = (uint32_t)11 << 21;
		}
		int32_t z = (int32_t)x->w[i];
		uint32_t zs = (uint32_t)(z >> 31);
		uint32_t a = ((uint32_t)z ^ zs) - zs;
#endif
		if (a >= m) {
			return 0;
		}
	}
	return 1;
}

/* Decode a value. This function is allowed to enforce the modulus range
   and/or reject zeros; it may also use implicit reduction. */
int
tv_gf_decode(gf *restrict d, const void *restrict src, int scalar)
{
	decode_int(d, src);
	gf_mul(d, d, scalar ? &gf_R2n : &gf_R2p, scalar ? mod_N : mod_P);
	return 1;
}

/* Test wrappers for addition, subtraction, multiplication and inversion.
   Modulus is n if scalar != 0, p otherwise. */

void
tv_gf_add(gf *d, const gf *a, const gf *b, int scalar)
{
	(void)scalar;
	gf_add(d, a, b);
}

void
tv_gf_sub(gf *d, const gf *a, const gf *b, int scalar)
{
	(void)scalar;
	gf_sub(d, a, b);
}

void
tv_gf_mul(gf *d, const gf *a, const gf *b, int scalar)
{
	gf_mul(d, a, b, scalar ? mod_N : mod_P);
}

void
tv_gf_invert(gf *x, int scalar)
{
	gf_invert(x, scalar ? mod_N : mod_P);
}

/* Encode a value over 32 bytes (unsigned big-endian). This function must
   enforce a canonical output. It may return 0 in case of detected
   internal error. */
int
tv_gf_encode(void *dst, const gf *x, int scalar)
{
	gf y = *x;
	gf_canonicalize(&y, scalar ? mod_N : mod_P);

	/* Internal verification: all limbs should be non-negative
	   and in the expected range. */
	for (int i = 0; i < NUM_LIMBS; i ++) {
		if (y.w[i] < 0 || y.w[i] > MMH) {
			return 0;
		}
	}

	uint8_t *buf = dst;
	int acc_len = 0;
	uint64_t acc = 0;
	int j = 0;
	for (int i = 31; i >= 0; i --) {
		if (acc_len < 8) {
			acc |= (uint64_t)y.w[j] << acc_len;
			acc_len += LIMB_H;
			j ++;
		}
		buf[i] = (uint8_t)acc;
		acc >>= 8;
		acc_len -= 8;
	}

	/* Internal verification: all bits should have been used. If
	   acc is not zero at this point, then the top limb was not in
	   the expected canonical range. */
	return acc == 0;
}

#endif

/* ===== P-256 curve ===== */

/* We use projective coordinates (X:Y:Z) with x = X/Z and y = Y/Z.
   Y != 0 for all points. The neutral is (0:Y:0) for any Y != 0. For
   non-neutral points, Z != 0. */

/* Check that the provided point designates a correct curve point.
   The x and y coordinate MUST be freshly decoded from the public key
   (i.e. still in purported canonical representation); the z coordinate
   is IGNORED and assumed to be equal to 1. This function verifies that
   both x and y are in [0,p-1], and that they fulfill the curve
   equation. */
static int
check_decoded_point(const point *p)
{
	/* Check that both coordinates are in [0,p-1]. */
	gf_check_range(&p->x, mod_P);
	gf_check_range(&p->y, mod_P);

	/* The curve equation is y^2 = x^3 - 3*x + b. However, since
	   our multiplication is Montgomery multiplication, we are
	   really working with Montgomery representations; in other
	   words, we really have projective coordinates (X:Y:Z) with
	   Z = 1/R. In projective coordinates, equation is:
	      (Y^2)*Z = X^3 - 3*X*Z^2 + b*Z^3
	   which we rewrite into:
	      ((3*X - b*Z)*Z + Y^2)*Z - X^3 = 0
	   Multipication by Z is really Montgomery reduction, which
	   we compute with gf_mred(). */
	gf t, u;

	/* t <- b*Z */
	gf_mred(&t, &gf_Bm, mod_P);

	/* t <- (b*Z - 3*X)*Z */
	gf_sub(&t, &t, &p->x);
	gf_sub(&t, &t, &p->x);
	gf_sub(&t, &t, &p->x);
	gf_mred(&t, &t, mod_P);

	/* t <- -(((3*X - b*Z)*Z) + Y^2)*Z */
	gf_mul(&u, &p->y, &p->y, mod_P);
	gf_sub(&t, &t, &u);
	gf_mred(&t, &t, mod_P);

	/* t <- X^3 - (((3*X - b*Z)*Z) + Y^2)*Z */
	gf_mul(&u, &p->x, &p->x, mod_P);
	gf_mul(&u, &u, &p->x, mod_P);
	gf_add(&t, &t, &u);

	/* Point is valid only if t = 0 mod p. We apply canonicalization
	   to ensure that the value is normalized and in [0, p-1]. */
	gf_canonicalize(&t, mod_P);
	return gf_iszero(&t);
}

/* For point addition, we use formulas from
   https://eprint.iacr.org/2015/1060 (Renes-Costello-Batina),
   specifically algorithm 4 (since P-256 has equation y^2 = x^3 - 3*x + b).

   The formulas listed in the paper assume that there are 5 temporary
   slots for field elements (t0 to t4) and that the destination point
   (X3:Y3:Z3) is distinct from the two source points (X1:Y1:Z1) and
   (X2:Y2:Z2); since this won't be the case in our API, we extend the
   number of temporaries to 8 (t0 to t7), so that we can write the output
   into the first operand. */

/* P1 <- P1 + P2 */
static void
point_addto(point *p1, const point *p2)
{
	/* For a more compact implementation, we use a custom interpreter:
	   each instruction is a 16-bit word, which encodes the operation
	   (add, sub, mul) and the source and destination operands. The
	   operands are indicated by offsets within the vp[] array, which
	   contains pointers to the temporaries (t0 to t7), P1 coordinates,
	   P2 coordinates, and the curve constant b. */
	gf *vp[15];
	gf tt[8];
	for (int i = 0; i < 8; i ++) {
		vp[i] = &tt[i];
	}
	vp[8] = &p1->x;
	vp[9] = &p1->y;
	vp[10] = &p1->z;
	vp[11] = (gf *)&p2->x;
	vp[12] = (gf *)&p2->y;
	vp[13] = (gf *)&p2->z;
	vp[14] = (gf *)&gf_Bm;

#define OP(op, d, a, b)   ((op) | ((d) << 4) | ((a) << 8) | ((b) << 12))
#define OP_ADD(d, a, b)   OP(0, d, a, b)
#define OP_SUB(d, a, b)   OP(1, d, a, b)
#define OP_MUL(d, a, b)   OP(2, d, a, b)
#define t0    0
#define t1    1
#define t2    2
#define t3    3
#define t4    4
#define t5    5
#define t6    6
#define t7    7
#define X1    8
#define Y1    9
#define Z1   10
#define X2   11
#define Y2   12
#define Z2   13
#define bb   14
	static const uint16_t INSTR[] = {
		OP_MUL(t0, X1, X2),   /* t0 <- X1 * X2 */
		OP_MUL(t1, Y1, Y2),   /* t1 <- Y1 * Y2 */
		OP_MUL(t2, Z1, Z2),   /* t2 <- Z1 * Z2 */
		OP_ADD(t3, X1, Y1),   /* t3 <- X1 + Y1 */
		OP_ADD(t4, X2, Y2),   /* t4 <- X2 + Y2 */
		OP_MUL(t3, t3, t4),   /* t3 <- t3 * t4 */
		OP_ADD(t4, t0, t1),   /* t4 <- t0 + t1 */
		OP_SUB(t3, t3, t4),   /* t3 <- t3 - t4 */
		OP_ADD(t4, Y1, Z1),   /* t4 <- Y1 + Z1 */
		OP_ADD(t5, Y2, Z2),   /* t5 <- Y2 + Z2 */
		OP_MUL(t4, t4, t5),   /* t4 <- t4 * t5 */
		OP_ADD(t5, t1, t2),   /* t5 <- t1 + t2 */
		OP_SUB(t4, t4, t5),   /* t4 <- t4 - t5 */
		OP_ADD(t5, X1, Z1),   /* t5 <- X1 + Z1 */
		OP_ADD(t6, X2, Z2),   /* t6 <- X2 + Z2 */
		OP_MUL(t5, t5, t6),   /* t5 <- t5 * t6 */
		OP_ADD(t6, t0, t2),   /* t6 <- t0 + t2 */
		OP_SUB(t6, t5, t6),   /* t6 <- t5 - t6 */
		OP_MUL(t7, bb, t2),   /* t7 <- bb * t2 */
		OP_SUB(t5, t6, t7),   /* t5 <- t6 - t7 */
		OP_ADD(t7, t5, t5),   /* t7 <- t5 + t5 */
		OP_ADD(t5, t5, t7),   /* t5 <- t5 + t7 */
		OP_SUB(t7, t1, t5),   /* t7 <- t1 - t5 */
		OP_ADD(t5, t1, t5),   /* t5 <- t1 + t5 */
		OP_MUL(t6, bb, t6),   /* t6 <- bb * t6 */
		OP_ADD(t1, t2, t2),   /* t1 <- t2 + t2 */
		OP_ADD(t2, t1, t2),   /* t2 <- t1 + t2 */
		OP_SUB(t6, t6, t2),   /* t6 <- t6 - t2 */
		OP_SUB(t6, t6, t0),   /* t6 <- t6 - t0 */
		OP_ADD(t1, t6, t6),   /* t1 <- t6 + t6 */
		OP_ADD(t6, t1, t6),   /* t6 <- t1 + t6 */
		OP_ADD(t1, t0, t0),   /* t1 <- t0 + t0 */
		OP_ADD(t0, t1, t0),   /* t0 <- t1 + t0 */
		OP_SUB(t0, t0, t2),   /* t0 <- t0 - t2 */
		OP_MUL(t1, t4, t6),   /* t1 <- t4 * t6 */
		OP_MUL(t2, t0, t6),   /* t2 <- t0 * t6 */
		OP_MUL(t6, t5, t7),   /* t6 <- t5 * t7 */
		OP_ADD(Y1, t6, t2),   /* Y1 <- t6 + t2 */
		OP_MUL(t5, t3, t5),   /* t5 <- t3 * t5 */
		OP_SUB(X1, t5, t1),   /* X1 <- t5 - t1 */
		OP_MUL(t7, t4, t7),   /* t7 <- t4 * t7 */
		OP_MUL(t1, t3, t0),   /* t1 <- t3 * t0 */
		OP_ADD(Z1, t7, t1),   /* Z1 <- t7 + t1 */
	};
#undef OP
#undef OP_ADD
#undef OP_SUB
#undef OP_MUL
#undef t0
#undef t1
#undef t2
#undef t3
#undef t4
#undef t5
#undef t6
#undef t7
#undef X1
#undef Y1
#undef Z1
#undef X2
#undef Y2
#undef Z2
#undef bb

	for (size_t i = 0; i < (sizeof INSTR) / (sizeof INSTR[0]); i ++) {
		unsigned op = INSTR[i];
		gf *d = vp[(op >> 4) & 0x0F];
		gf *a = vp[(op >> 8) & 0x0F];
		gf *b = vp[op >> 12];
		switch (op & 0x0F) {
		case 0:  gf_add(d, a, b);  break;
		case 1:  gf_sub(d, a, b);  break;
		case 2:  gf_mul(d, a, b, mod_P);  break;
		}
	}
}

#ifdef TV_ECDSA_P256_TEST

int
tv_point_decode(point *p, const void *src)
{
	const uint8_t *buf = src;
	decode_int(&p->x, buf + 1);
	decode_int(&p->y, buf + 33);
	gf_set_one(&p->z);
	return check_decoded_point(p);
}

void
tv_point_add(point *p3, const point *p1, const point *p2)
{
	point q = *p2;
	point_addto(&q, p1);
	*p3 = q;
}

void
tv_point_sub(point *p3, const point *p1, const point *p2)
{
	point q = *p2;
	gf z;
	gf_set_zero(&z);
	gf_sub(&q.y, &z, &q.y);
	point_addto(&q, p1);
	*p3 = q;
}

void
tv_point_set_neutral(point *p)
{
	/* We can use any Y != 0 for the neutral, here we use 1, even
	   though the coordinates are supposed to be in Montgomery
	   representation. */
	gf_set_zero(&p->x);
	gf_set_one(&p->y);
	gf_set_zero(&p->z);
}

size_t
tv_point_encode(void *dst, const point *p)
{
	uint8_t *buf = dst;
	gf t = p->z;
	gf_mred(&t, &t, mod_P);
	if (gf_iszero(&t)) {
		buf[0] = 0x00;
		return 1;
	}
	gf iz = p->z;
	gf_invert(&iz, mod_P);
	buf[0] = 0x04;
	gf_mul(&t, &iz, &p->x, mod_P);
	tv_gf_encode(buf + 1, &t, 0);
	gf_mul(&t, &iz, &p->y, mod_P);
	tv_gf_encode(buf + 33, &t, 0);
	return 65;
}
#endif

/* ===== ECDSA ===== */

/* see ecdsa-p256-verify.h */
int
tv_ecdsa_p256_verify(const void *sig, size_t sig_len,
	const void *pub, size_t pub_len,
	const void *hv, size_t hv_len)
{
	/* Check lengths. */
	if (sig_len != 64 || pub_len != 65 || hv_len < 32 || hv_len > 64) {
		return 0;
	}

	/* Decode the (r,s) values from the signature and ensure that
	   they are non-zero and in range. */
	const uint8_t *sbuf = sig;
	gf r, s, e;
	decode_int(&r, sbuf);
	if (gf_iszero(&r) || !gf_check_range(&r, mod_N)) {
		return 0;
	}
	decode_int(&s, sbuf + 32);
	if (gf_iszero(&s) || !gf_check_range(&s, mod_N)) {
		return 0;
	}

	/* Per FIPS 186-5, we should truncate the hash value to its
	   leftmost 256 bits (since the order of P-256 is a 256-bit
	   integer); this is equivalent to considering only its first
	   32 bytes. We use implicit reduction. */
	decode_int(&e, hv);

	/* Since we use Montgomery multiplication, we work with
	   Montgomery representations. At this point, we really have
	   the Montgomery representations of r/R, s/R and e/R.
	   We now compute u = e/s and v = r/s. Inversion of s/R
	   yields the Montgomery representation of R/s, which we
	   can multiply (with gf_mul()) with r/R and e/R, yielding
	   the Montgomery representations of u and v. */
	gf_invert(&s, mod_N);
	gf_mul(&e, &e, &s, mod_N);
	gf_mul(&s, &s, &r, mod_N);

	/* We canonicalize u and v (stored in e and s, respectively).
	   This converts out of Montgomery representation, thus yielding
	   the values we need for the curve computations. */
	gf_canonicalize(&e, mod_N);
	gf_canonicalize(&s, mod_N);

	/* Decode public key (Q). */
	point Q;
	const uint8_t *qbuf = pub;
	if (qbuf[0] != 0x04) {
		return 0;
	}
	decode_int(&Q.x, qbuf + 1);
	decode_int(&Q.y, qbuf + 33);
	gf_set_one(&Q.z);
	if (!check_decoded_point(&Q)) {
		return 0;
	}

	/* Compute point W = u*G + v*Q */
	point W;

	/* Set W to the neutral (point-at-infinity).
	   We can use whatever non-zero value we want for Y. */
	gf_set_zero(&W.x);
	gf_set_one(&W.y);
	gf_set_zero(&W.z);

	/* Process bits of u and v in high-to-low order, for a simple
	   double-and-add-and-add algorithm. */
	ITER_BEGIN(0)
	while (!ITER_DONE) {
		/* W <- 2*W */
		point_addto(&W, &W);
		/* If bit i of u is set, add G. u is currently in e. */
		if (ITER_TESTBIT(e.w)) {
			point_addto(&W, &G);
		}
		/* If bit i of v is set, add Q. u is currently in s. */
		if (ITER_TESTBIT(s.w)) {
			point_addto(&W, &Q);
		}
		ITER_NEXT;
	}
	ITER_END

	/* Signature is valid if the x coordinate of W, reinterpreted as
	   an integer (in [0,p-1]) then as a scalar (reduction modulo n),
	   is equal to r. */

	/* Get the affine coordinate x of W. */
	gf_invert(&W.z, mod_P);
	gf_mul(&W.x, &W.x, &W.z, mod_P);
	gf_canonicalize(&W.x, mod_P);

	/* If W is the point-at-infinity then the signature is invalid.
	   In that situation, the gf_invert() call above set W.z to zero,
	   which will lead to signature rejection below, since the r
	   value (from the signature) was verified not to be zero; thus,
	   we do not have to handle the point-at-infinity case in any
	   special way. */

	/* Reinterpret x(W) as a scalar with implicit reduction and compare
	   it to the value r. */
	gf_sub(&r, &r, &W.x);
	gf_mred(&r, &r, mod_N);
	return gf_iszero(&r);
}

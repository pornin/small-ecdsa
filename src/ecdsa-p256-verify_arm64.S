	.arch	armv8-a
	.file	"ecdsa-p256-verify_arm64.S"
	.text

// ========================================================================
// PLATFORM COMPATIBILITY
//
// This code uses only plain Armv8 instructions (no use of any optional
// feature). It respects the 16-byte stack alignment. It follows the
// Aarch64 call convention, but is also compatible with Windows' ARM64EC
// ABI (special Aarch64 for easy emulation of x86 code), which means that
// it does not use registers x13, x14, x23 or x24. No use is made of the
// 16-byte "red zone" below the stack pointer. Floating-point and SIMD
// (NEON) are not used.
// ========================================================================

// ========================================================================
// INTEGER FORMATS
//
// All values are nominally signed integers, kept over five limbs in base
// 2^54 (little-endian order). Limbs are signed and may exceed the 54-bit
// range. Exact allowed range depends on the involved value (an extensive
// range analysis, done externally, shows that all the operations here
// remain within the allowed ranges).
//
// A value is said to be _normalized_ if limbs 0 to 3 are in [0, 2^54 - 1].
// For a normalized value:
//  - The value is negative if and only if the top limb (limb 4) is negative.
//  - The value is zero if and only if all five limbs are zero.
//
// These integers nominally represent values modulo a 256-bit prime m which
// is either p (for the coordinate field) or n (for the scalar field).
// Addition and subtraction are done limb-wise, and thus do not depend on
// the involved modulus. Multiplication is done via the Montgomery
// multiplication:
//  - Let R = 2^270.
//  - Montgomery multiplication of x and y computes (x*y)/R modulo m.
//  - The Montgomery representation of x is x*R mod m. The Montgomery
//    multiplication of the x*R and y*R yields (x*y)*R, i.e. the
//    Montgomery multiplication does compute modular multiplication as
//    long as inputs and outputs are in Montgomery representation.
//
// A _fully reduced value_ is one which is normalized and also such that
// it is (as an integer) in the [-m/2,+m/2] range. Montgomery multiplication
// returns a normalized value, but not necessarily fully reduced modulo m.
// _Montgomery reduction_ is a Montgomery multiplication with the value 1;
// it is equivalent to dividing the value by R. Montgomery reduction outputs
// a value which is not only normalized but also fully reduced.
//
// A _canonical_ value is one that is normalized and also in the [0, m-1]
// range. A canonical value can be obtained from a fully reduced value by
// adding m if and only if the fully reduced value is negative.
//
// Since Montgomery reduction is also division by R, it can be viewed as
// a function that converts the Montgomery representation x*R into x.
// Normally, generic functions for modular arithmetics also provide a way
// to do the conversion in the other direction, which can be done by
// doing a Montgomery multiplication with the (precomputed) constant
// R^2 mod m. This is not provided here because this is not really needed
// in our case: the conversion to Montgomery representation can be subsumed
// into the use of projective coordinates for elliptic curve points. Indeed,
// a point (x,y) is represented as a triplet (X:Y:Z) such that x = X/Z and
// y = Y/Z. In particular, we can consider that (x:y:1) uses the Montgomery
// representations of X = x*(1/R), Y = y*(1/R) and Z = 1*(1/R), respectively,
// so that the affine, plain integer coordinates can be used as is as the
// Montgomery representation of a valid triplet for the same point.
// ========================================================================

// Curve constants, in that order:
//   Gx           curve generator point, X coordinate
//   Gy           curve generator point, Y coordinate
//   Bm           curve parameter b (Montgomery representation with R = 2^270)
//   mod_scalar   modulus n (scalar field)
//   n0i          (-1/n mod 2^54)*2^10 (one 64-bit word)
//   mod_coord    modulus p (coordinate field)
// All values (except n0i) use unsigned big-endian encoding (32 bytes per
// value).
// WARNING: values MUST NOT be separated or reordered.
// WARNING: the bytecode must follow immediately after the curve constants.
curve_constants:
// Gx*2^270 mod p
	.byte	0x17, 0xDD, 0xAF, 0x71, 0xD5, 0x71, 0x98, 0x5A
	.byte	0xDC, 0xCA, 0xDD, 0xD8, 0x89, 0x44, 0x1D, 0x6E
	.byte	0xA5, 0x7F, 0x11, 0xD7, 0x6D, 0x80, 0x5E, 0x79
	.byte	0xCC, 0x35, 0x06, 0x2A, 0x45, 0x0F, 0x06, 0x24
// Gy*2^270 mod p
	.byte	0x7F, 0xC6, 0x2A, 0xBE, 0x17, 0x61, 0x53, 0x5E
	.byte	0x21, 0xA2, 0x37, 0x48, 0x7C, 0xC9, 0x62, 0xD2
	.byte	0xAE, 0x39, 0x0D, 0x2A, 0x79, 0x17, 0x37, 0x7C
	.byte	0x94, 0xD5, 0xF3, 0xA5, 0x55, 0x82, 0xA1, 0x5C
// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
	.byte	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
	.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.byte	0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84
	.byte	0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
// n0i = (-1/n mod 2^54)*2^10
	.quad	0x4722ABB802F13C00
// p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
	.byte	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01
	.byte	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	.byte	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
	.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	// Value p0i = (-1/p mod 2^54)*2^10 is equal to 0x400, it is
	// hardcoded in the INTERPRETER_MAIN macro.

// -------------------------------------------------------------------------
// BEGIN BYTECODE
// -------------------------------------------------------------------------

// ========================================================================
// Custom virtual machine.
//
// We use an interpreter for a virtual machine with a few instructions.
// The instructions are specialized for the problem at hand. Each
// instruction fits on one byte (except CALL, which uses two bytes).
// The VM works with 32 values (numbered 0 to 31); each value holds an
// integer in 5-limb format:
//  - Value 0 is the accumulator; it is used as source and/or destination
//    operand by many of the instructions.
//  - Value 1 contains the current modulus (which can be set to either
//    mod_N or mod_P with the SMOD instruction); it can be read, but not
//    written to.
//  - Values 2 to 31 are other values. A few are preloaded with constants,
//    which in general should not be modified by code:
//       2    ONE (the integer value 1)
//       30   Gx (x coordinate of generator point, affine, Montgomery)
//       31   Gy (y coordinate of generator point, affine, Montgomery)
//    All other values are initialized at zero. Value 28 is conventionally
//    considered to be "the" constant ZERO.
// Symbolic names are defined for modifiable values; from the VM point of
// view, these values are nothing special, but the bytecode uses them to
// organize its ECDSA subroutines:
//        3       Kr         r (first signature half)
//        4       Ks         s (second signature half)
//        5       Ke         e (reduced hash value)
//        6       Qx         x coordinate of public key
//        7       Qy         y coordinate of public key
//        8       Wx         X coordinate of work point W (projective)
//        9       Wy         Y coordinate of work point W (projective)
//       10       Wz         Z coordinate of work point W (projective)
//       11       Hx         X coordinate of work point H (projective)
//       12       Hy         Y coordinate of work point H (projective)
//       13       Hz         Z coordinate of work point H (projective)
//       16..25   T0 to T9   temporaries
// The tv_ecdsa_p256_verify() function, when setting up the interpreter,
// loads Kr, Ks, Ke, Qx and Qy with the relevant values, freshly decoded
// from the paramters (signature, hash value and public key). The values
// are decoded into 5-limb format but not otherwise checked; the bytecode
// is responsible for verifying that:
//    0 < r < n
//    0 < s < n
//    0 <= Qx < p
//    0 <= Qy < p
//    (Qx,Qy) is a point on the curve
//
// Instructions are the following:
//
//    encoding   mnemonic     operation
//    --------   --------     ---------
//    xxxxx000   LD x         acc <- x
//    xxxxx001   ST x         x <- acc
//    xxxxx010   ADD x        acc <- acc + x
//    xxxxx011   SUB x        acc <- acc - x
//    xxxxx100   SMOD y       set modulus to mod_N (y = 26) or mod_P (y = 27)
//    xxxxx101   MUL x        acc <- (acc * x)/R (Montgomery multiplication)
//    xxxxx110   SKIPBITZ x   skip next if current bit in x is zero
//    00000111   CALL label   call subroutine (+immediate offset)
//    00001111   SKIPNZ       skip next is acc is non-zero
//    00010111   SKIPNEG      skip next is acc is negative
//    00011111   FNEXT        consume first iteration
//    00100111   RET          return from subroutine
//    00101111   FOR          initialize bit iterator
//    00110111   NEXT         loop back iterator
//    00111111   OK           exit with a success
//    01000111   FAIL         exit with a failure
//    01001111   NORM         normalize value in accumulator
//
// "LD x" copies value x (0 <= x <= 31) into the accumulator. "ST x" copies
// the accumulator into value x. "ADD x" (resp. "SUB x") adds x to (resp.
// subtracts x from) the accumulator. "MUL x" multiplies the accumulator with
// value x (Montgomery multiplication, i.e. it computes (acc*x)/R), using
// the currently set modulus. "SMOD y" switches the current modulus (parameter
// y must be 26 or 27, for n and p, respectively), as readable in value 1
// and used in Montgomery multiplications.
//
// "SKIPNZ" and "SKIPNEG" make the VM skip the next instruction if a
// condition on the accumulator is true; the condition is "accumulator is
// non-zero" and "accumulator is negative", respectively. Thus,
// "SKIPNEG ; SUB 1" will subtract the modulus from the accumulator only
// in case the accumulator is currently non-negative. These tests work
// reliably only if the value in the accumulator is normalized (i.e. four
// lower limbs are in [0, 2^54]); the "NORM" instruction normalizes the
// accumulator value.
//
// A single loop facility is provided; it cannot nest (the code cannot run
// an internal loop within an outer loop). "FOR" starts the loop, and
// "NEXT" triggers the next iteration. The loop runs for exactly 256
// iterations. There can be several "NEXT" opcodes matching a single "FOR".
// The "FNEXT" instruction is a "NEXT" that is triggered only on the first
// iteration, i.e. it can be used to skip that iteration. While the iteration
// runs, the "SKIPBITZ x" opcode uses the current iteration counter (255 to 0)
// as a bit index within value x, and tests whether the corresponding bit
// is set or cleared; if cleared, then the next instruction is skipped. This
// facility is meant to support square-and-multiply exponentiation as well
// as double-and-add point multiplication. For bit values to be meaningfull,
// tested value x should be canonicalized (i.e. normalized, non-negative,
// and less than the relevant modulus).
//
// Subroutines are supported: "CALL label" jumps to the subroutine located
// at the provided assembly label; "RET" returns from the current subroutine
// to the caller. Nested calls are supported. In the encoding, the subroutine
// offset is encoded as an 8-bit unsigned value that immediately follows the
// "CALL": this implies that the target of the CALL can only be located
// _after_ the call site in the bytecode (and it must not be farther than
// 255 bytes away). The "skip" instructions correctly skip the two bytes of
// a "CALL" function.
//
// The "OK" and "FAIL" instructions terminate the interpreter with an exit
// status of 1 or 0, respectively. They can be used within called subroutines,
// not just at the toplevel.
// ========================================================================

// VALUE ALLOCATION
// WARNING: code relies on Kr, Ks, Ke, Qx and Qy to be consecutive.

	// Symbolic identifiers for various slots.
	.equ	_M,     1    // current modulus
	.equ	_ONE,   2    // constant one
	.equ	_ZERO, 28    // constant zero
	.equ	_Bm,   29    // constant Bm (curve param b, Montgomery repr.)
	.equ	_Gx,   30    // constant Gx (x coordinate of generator)
	.equ	_Gy,   31    // constant Gy (y coordinate of generator)
	.equ	_T0,   16    // temporary 0
	.equ	_T1,   17    // temporary 1
	.equ	_T2,   18    // temporary 2
	.equ	_T3,   19    // temporary 3
	.equ	_T4,   20    // temporary 4
	.equ	_T5,   21    // temporary 5
	.equ	_T6,   22    // temporary 6
	.equ	_T7,   23    // temporary 7
	.equ	_T8,   24    // temporary 8
	.equ	_T9,   25    // temporary 9

	.equ	_Kr,    3    // r (first signature half)
	.equ	_Ks,    4    // s (second signature half)
	.equ	_Ke,    5    // e (reduced hash value)
	.equ	_Qx,    6    // Qx (x coordinate of public key)
	.equ	_Qy,    7    // Qy (y coordinate of public key)
	.equ	_Wx,    8    // Wx (X coordinate of work point W)
	.equ	_Wy,    9    // Wy (Y coordinate of work point W)
	.equ	_Wz,   10    // Wz (Z coordinate of work point W)
	.equ	_Hx,   11    // Hx (X coordinate of second point operand)
	.equ	_Hy,   12    // Hy (Y coordinate of second point operand)
	.equ	_Hz,   13    // Hz (Z coordinate of second point operand)

	# Opcode base values.
	.equ	OP_LD,        0x00
	.equ	OP_ST,        0x01
	.equ	OP_ADD,       0x02
	.equ	OP_SUB,       0x03
	.equ	OP_SMOD,      0x04
	.equ	OP_MUL,       0x05
	.equ	OP_SKIPBITZ,  0x06
	.equ	OP_CALL,      0x07
	.equ	OP_SKIPNZ,    0x0F
	.equ	OP_SKIPNEG,   0x17
	.equ	OP_FNEXT,     0x1F
	.equ	OP_RET,       0x27
	.equ	OP_FOR,       0x2F
	.equ	OP_NEXT,      0x37
	.equ	OP_OK,        0x3F
	.equ	OP_FAIL,      0x47    // REQUIRED: OP_FAIL = OP_OK + 8
	.equ	OP_NORM,      0x4F

// Macros to help write bytecode.
.macro	_LD x
	.byte	(\x) * 8 + OP_LD
.endm
.macro	_ST x
	.byte	(\x) * 8 + OP_ST
.endm
.macro	_ADD x
	.byte	(\x) * 8 + OP_ADD
.endm
.macro	_SUB x
	.byte	(\x) * 8 + OP_SUB
.endm
.macro	_SMOD y
	.byte	(\y) * 8 + OP_SMOD
.endm
.macro	_MUL x
	.byte	(\x) * 8 + OP_MUL
.endm
.macro	_SKIPBITZ x
	.byte	(\x) * 8 + OP_SKIPBITZ
.endm
.macro	_SKIPNZ
	.byte	OP_SKIPNZ
.endm
.macro	_SKIPNEG
	.byte	OP_SKIPNEG
.endm
.macro	_FNEXT
	.byte	OP_FNEXT
.endm
.macro	_RET
	.byte	OP_RET
.endm
.macro	_FOR
	.byte	OP_FOR
.endm
.macro	_NEXT
	.byte	OP_NEXT
.endm
.macro	_OK
	.byte	OP_OK
.endm
.macro	_FAIL
	.byte	OP_FAIL
.endm
.macro	_NORM
	.byte	OP_NORM
.endm
.macro	_CALL  label
	.byte	OP_CALL
	.byte	\label - 1f
1:
.endm

// _MRED is a pseudo-instruction that maps to _MUL _ONE, i.e. Montgomery
// reduction.
.macro	_MRED
	_MUL _ONE
.endm

// _MODN is an alias for _SMOD 26, i.e. switching modulus to mod_N.
.macro	_MODN
	_SMOD 26
.endm

// _MODP is an alias for _SMOD 27, i.e. switching modulus to mod_P.
.macro	_MODP
	_SMOD 27
.endm

// BYTECODE ENTRY POINT
// WARNING: the code locates the entry point relatively to the
// constants: it must immediately follow the modulus p in the curve constants
// block.

	// Check that r and s are both non-zero and below n
	_LD _Kr ; _CALL check_scalar
	_LD _Ks ; _CALL check_scalar
	// Invert s. Ks currently contains Mont(s/R) (Montgomery
	// representation of s/R); inversion returns Mont(R/s).
	// Accumulator currently contains s - n = s mod n, which is fine for us.
	_CALL invert_mod ; _ST _Ks
	// Compute u = e/s (canonicalized, into Ke).
	// Since Ke contains Mont(e/R) and we have computed Mont(R/s),
	// a Montgomery multiplication yields Mont((e/R)*(R/s)) = Mont(u),
	// which we can canonicalize.
	_MUL _Ke ; _CALL canonicalize ; _ST _Ke
	// Compute v = r/s (canonicalized, into Ks).
	_LD _Ks ; _MUL _Kr ; _CALL canonicalize ; _ST _Ks

	// We have u and v; we now switch to modulus p for curve computations.
	_MODP
	// Compute Bm = b*2^270 mod p from the generator coordinates. At
	// this point, (Gx,Gy) are still in Montgomery representation.
	//    b = Gy^2 - Gx^3 + 3*Gx
	_LD _Gx ; _MUL _Gx ; _MUL _Gx ; _ST _T0
	_LD _Gy ; _MUL _Gy ; _SUB _T0 ; _ADD _Gx ; _ADD _Gx ; _ADD _Gx
	_ST _Bm

	// Convert (Gx,Gy) out of Montgomery representation (so that
	// (Gx:Gy:1) is a valid triplet).
	_LD _Gx ; _MRED ; _ST _Gx
	_LD _Gy ; _MRED ; _ST _Gy

	// Check that the point in (Qx,Qy) is a valid curve point.
	_CALL check_point

	// Compute W = u*G + v*Q
	// Set work point W to the neutral (0:1:0). Values Wx and Wz were
	// initialized at zero by the interpreter initialization, so we only
	// need to set Wy to 1.
	_LD _ONE ; _ST _Wy
	// We loop over bits in u and v (high to low).
	_FOR
	// Double W.
	_LD _Wx ; _ST _Hx ; _LD _Wy ; _ST _Hy ; _LD _Wz ; _ST _Hz
	_CALL point_add_to_W
	// Add G if bit i of u is set; u is in Ke
	_LD _Gx ; _ST _Hx ; _LD _Gy ; _ST _Hy ; _LD _ONE ; _ST _Hz
	_SKIPBITZ _Ke ; _CALL point_add_to_W
	// Add Q if bit i of v is set; v is in Ks; Hz still contains 1
	_LD _Qx ; _ST _Hx ; _LD _Qy ; _ST _Hy
	_SKIPBITZ _Ks ; _CALL point_add_to_W
	// Loop until all bits have been processed.
	_NEXT

	// Get x coordinate of point W, canonicalized. For now we suppose
	// the W is not the point-at-infinity.
	_LD _Wz ; _CALL invert_mod ; _MUL _Wx ; _CALL canonicalize

	// Signature is valid if and only if we get back the same value
	// as r, when reduced modulo n. We switch back to computations
	// modulo n, then compute r - x(W) mod n.
	_MODN ; _SUB _Kr
	// To compare with zero, we reduce the value; this entails an
	// extra division by R, but this does not matter since we are
	// only interested in knowing if the value is zero.
	_MRED ; _SKIPNZ ; _OK ; _FAIL

	// If W was the point-at-infinity, then inversion of Wz yielded zero,
	// and the rebuilt x(W) was zero. Since r != 0 (we checked it
	// explicitly), this case implies a signature rejection, which is
	// the correct result.

// BYTECODE: Check that a value (just decoded) is non-zero and less than
// the modulus. This is meant for scalars; it uses the current modulus.
// Input:
//    acc   value to check
// Output:
//    acc   x - m if source value is x and modulus is m
check_scalar:
	_SKIPNZ ; _FAIL ; _SUB _M ; _NORM ; _SKIPNEG ; _FAIL ; _RET

// BYTECODE: Modular inversion. The current modulus is used.
// Input:
//    acc   value to invert
// Output:
//    acc   computed inverse (zero if input is zero)
// Clobbers: T0, T1
invert_mod:
	// Copy source value into T0.
	_ST _T0
	// Set T1 to exponent, which is m-2 (canonical) for modulus m.
	// Subtraction is limb-wise but for the two involved moduli (p and n)
	// this does not overflow any limb, so m-2 is still canonical.
	_LD _M ; _SUB _ONE ; _SUB _ONE ; _ST _T1
	// Set accumulator to source.
	_LD _T0
	// Start iterator and consume first iteration
	_FOR ; _FNEXT
	// Square current value (except on first iteration)
	_MUL 0
	// If current bit is 1, multiply accumulator by operand
	_SKIPBITZ _T1 ; _MUL _T0
	// Loop until finished, then exit
	_NEXT ; _RET

// BYTECODE: Fully reduce a value and return the canonical representation.
// Input is expected in Montgomery representation.
// Input:
//    acc
// Output:
//    acc
// Clobbers: none
canonicalize:
	// Get out of Montgomery representation; this also returns a
	// normalized value whose absolute value is less than m.
	_MRED
	// If the value is non-negative then it's canonical.
	_SKIPNEG ; _RET
	// Add the modulus to get a canonical value.
	_ADD _M ; _NORM ; _RET

// BYTECODE: Check decoded point. This function verifies that the two
// coordinates are in [0,p-1] and that they fulfill the curve equation.
// Input:
//    current modulus MUST be mod_P
//    Qx   candidate x coordinate (affine, non-Montgomery)
//    Qy   candidate y coordinate (affine, non-Montgomery)
// No output. A failure is triggered if the point is incorrect.
// Clobbers: T0, T1, T2
check_point:
	// Check that Qx is lower than p. It was just decoded, and thus
	// we can simply subtract the modulus and check for sign.
	_LD _Qx ; _SUB _M ; _NORM ; _SKIPNEG ; _FAIL
	// While it's loaded in the accumulator, compute X^3 and store
	// it into _T1.
	_MUL _Qx ; _MUL _Qx ; _ST _T1
	// Check that Qy is lower than p (same treatment as Qx).
	_LD _Qy ; _SUB _M ; _NORM ; _SKIPNEG ; _FAIL
	// Compute Y^2 and store it into T2.
	_MUL _Qy ; _ST _T2
	// We use (X:Y:Z) = (x:y:1) as coordinates, but the projective
	// coordinates are supposed to be Montgomery representations, so
	// we really set X = x/R, Y = y/R and Z = 1/R.
	// We must check the curve equation:
	//    Y^2*Z = X^3 - 3*X*Z^2 + b*Z^3
	// which we rewrite as:
	//    ((3*X - b*Z)*Z + Y^2)*Z - X^3 = 0
	// We have b (in Montgomery representation) in constant Bm; each
	// multiplication by Z is a Montgomery reduction.
	_LD _Bm ; _MRED                // acc <- b*Z
	_SUB _Qx ; _SUB _Qx ; _SUB _Qx // acc <- b*Z - 3*X
	_MRED                          // acc <- (b*Z - 3*X)*Z
	_SUB _T2                       // acc <- -(((3*X - b*Z)*Z) + Y^2)
	_MRED                          // acc <- -(((3*X - b*Z)*Z) + Y^2)*Z
	_ADD _T1                       // acc <- X^3 - (((3*X - b*Z)*Z) + Y^2)*Z
	_MRED ; _SKIPNZ ; _RET         // success if acc == 0
	_FAIL

// Add a curve point to point W. Point W is in projective coordinates
// in (Wx:Wy:Wz); the other operand is read from (Hx:Hy:Hz).
// Inputs:
//    Wx   first operand X coordinate
//    Wy   first operand Y coordinate
//    Wz   first operand Z coordinate
//    Hx   second operand X coordinate
//    Hy   second operand Y coordinate
//    Hz   second operand Z coordinate
// Output is written back into (Wx:Wy:Wz).
// Clobbers: T0 to T8
point_add_to_W:
	// t0 <- X1 * X2
	_LD _Wx ; _MUL _Hx ; _ST _T0
	// t1 <- Y1 * Y2
	_LD _Wy ; _MUL _Hy ; _ST _T1
	// t2 <- Z1 * Z2
	// t7 <- bb * t2
	_LD _Wz ; _MUL _Hz ; _ST _T2 ; _MUL _Bm ; _ST _T7

	// t3 <- (X1 + Y1)*(X2 + Y2) - t0 - t1
	_LD _Wx ; _ADD _Wy ; _ST _T3
	_LD _Hx ; _ADD _Hy ; _MUL _T3 ; _SUB _T0 ; _SUB _T1 ; _ST _T3

	// t6 <- (X1 + Z1)*(X2 + Z2) - t0 - t2
	_LD _Wx ; _ADD _Wz ; _ST _T6
	_LD _Hx ; _ADD _Hz ; _MUL _T6 ; _SUB _T0 ; _SUB _T2 ; _ST _T6
	// t6 is still in acc
	// t5 <- t1 + 3*(t6 - t7)
	// t7 <- t1 - 3*(t6 - t7)
	_SUB _T7 ; _ST _T5 ; _ADD 0 ; _ADD _T5   // acc <- 3*(t6 - t7)
	_ST _T7 ; _ADD _T1 ; _ST _T5
	_LD _T1 ; _SUB _T7 ; _ST _T7

	// t8 <- 3*t2
	_LD _T2 ; _ADD 0 ; _ADD _T2 ; _ST _T8

	// t6 <- 3*(b*t6 - t0 - t8)
	_LD _T6 ; _MUL _Bm ; _SUB _T0 ; _SUB _T8 ; _ST _T6
	_ADD 0 ; _ADD _T6 ; _ST _T6

	// t4 <- (Y1 + Z1)*(Y2 + Z2) - t1 - t2
	_LD _Wy ; _ADD _Wz ; _ST _T4
	_LD _Hy ; _ADD _Hz ; _MUL _T4 ; _SUB _T1 ; _SUB _T2 ; _ST _T4
	// t4 is still in acc
	// X1 <- t3*t5 - t4*t6
	_MUL _T6 ; _ST _Wx
	_LD _T3 ; _MUL _T5 ; _SUB _Wx ; _ST _Wx

	// t0 <- 3*t0 - t8
	_LD _T0 ; _ADD 0 ; _ADD _T0 ; _SUB _T8 ; _ST _T0
	// t0 is still in acc
	// Y1 <- t0*t6 + t5*t7
	_MUL _T6 ; _ST _Wy ; _LD _T5 ; _MUL _T7 ; _ADD _Wy ; _ST _Wy

	// Z1 <- t4*t7 + t3*t0
	_LD _T4 ; _MUL _T7 ; _ST _Wz
	_LD _T3 ; _MUL _T0 ; _ADD _Wz ; _ST _Wz

	_RET

// -------------------------------------------------------------------------
// END BYTECODE
// -------------------------------------------------------------------------

	.balign	4

// ========================================================================
// void decode_int(gf *d, const uint8_t *src)
// Decode value from the source (32 bytes, unsigned, big-endian) into
// the destination (five 54-bit limbs, little-endian). Output is
// normalized and non-negative.
// SPECIAL ABI: on output:
//    x0 = (uint8_t *)d + 40
//    x1 = src + 32
// Clobbers: x2, x3, x4, x5, x6
// ========================================================================

	.type	decode_int, %function
decode_int:
	mov	x3, #32                // offset within source
	mov	x4, xzr                // accumulated bytes
	mov	x5, #1                 // multiplier
Ldeccode_int__loop:
	sub	x3, x3, #1
	ldrb	w2, [x1, x3]           // read next source byte (low to high)
	madd	x4, x2, x5, x4         // plug byte into x4
	lsl	x5, x5, #8
	lsr	x6, x5, #54
	cbz	x6, Ldecode_int__cont
	// We have accumulated at least 54 bits, we can emit a limb.
	ubfx	x2, x4, #0, #54
	str	x2, [x0], #8
	mov	x5, x6
	lsr	x4, x4, #54
Ldecode_int__cont:
	cbnz	x3, Ldeccode_int__loop
	str	x4, [x0], #8           // Emit last limb (40 bits)
	add	x1, x1, #32
	ret

// ========================================================================
// add_mul_wide()
//    d <- d + a*f
// Values are in 54-bit limbs; no bit propagation.
// SPECIAL API:
// Input:
//   x0   d (6 words)
//   x1   a (5 words)
//   x3   f (1 word, pre-shifted by 5 bits)
// Output:
//   d[] is updated (6 words)
//   x0   +40
//   x1   +40
// Clobbers: x4, x5, x6, x7, x19
// ========================================================================

	.type	add_mul_wide, %function
add_mul_wide:
	mov	x19, #5
Ladd_mul_wide__loop:
	ldp	x6, x7, [x0]    // x6, x7 <- d_i, d_{i+1}
	ldr	x4, [x1], #8    // x4 <- a_i
	lsl	x4, x4, #5      // pre-shift a_i (5 bits)
	smulh	x5, x4, x3      // x6 <- delayed word for next round
	mul	x4, x4, x3      // x4 <- (f*a_i mod 2^54)*2^10
	add	x6, x6, x4, lsr #10
	add	x7, x7, x5
	stp	x6, x7, [x0], #8
	subs	x19, x19, #1
	b.ne	Ladd_mul_wide__loop
	ret
	.size	add_mul_wide, . - add_mul_wide

// ========================================================================
// VM INTERPRETER
//
// The interpreter maintains a context structure on the stack, of size
// 1328 bytes. The x15 register points to that context.
// Value x (for 0 <= x <= 31) is at address x15+40*x; moduli n and p are
// located at x15+1280 and x15+1328, respectively (each modulus uses 48 bytes:
// the 5 limbs, followed by the value (-1/m mod 2^54)*2^10, which is used
// for Montgomery multiplication). Value 1 is special, in that instructions
// that read that value obtain the current modulus limbs; the storage space
// of value 1 is currently used to store some saved register values.
//
// The iteration counter is maintained in the physical bit offset format,
// which accounts for the fact that limbs contain 54 logical bits but use
// 64 bits in RAM. Thus, the start value is 295 (for the logical bit index
// 255).
//
// Instruction decoding uses first the translation_table (below), which
// points to the offset of the native routine for the instruction. The
// index consists of the three low bits of the instruction, and the
// offset is over one byte. This handles instructions LD, ST, ADD, SUB,
// SMOD, MUL, and SKIPBITZ (all instructions with a 5-bit parameter);
// other instructions are handled with op_extended, which does a secondary
// decoding with another table.
// Armv8 instructions are always 32-bit aligned; we store offsets divided
// by 4 so that values all fit in a single byte each.
translation_table:
	.byte	(op_ld - translation_table) >> 2
	.byte	(op_st - translation_table) >> 2
	.byte	(op_add - translation_table) >> 2
	.byte	(op_sub - translation_table) >> 2
	.byte	(op_smod - translation_table) >> 2
	.byte	(op_mul - translation_table) >> 2
	.byte	(op_skipbitz - translation_table) >> 2
	.byte	(op_extended - translation_table) >> 2

	.balign	4

// Instruction routine conventions:
//  - each routine is invoked with 'blr' and ends with a ret opcode
//  - x1 contains the routine's own address
//  - x0 contains 8*x (for x = hi5(opcode))
//  - x2 points to the explicit operand value (i.e. x15+40*x)
//  - x15 points to the context structure
//  - x12 points to the current modulus
//  - x8 contains the instruction pointer (pointing to the byte that
//    follows the instruction); the interpreter will restart from there,
//    so it must be preserved (or possibly altered)
//  - x9 contains the exit flag, currently 0; if it becomes non-zero then
//    the interpreter will exit
//  - x10 is the current loop counter, and x11 the loop start address
//  - the CPU carry flag (C) is cleared
// x15, x12, x8, x9, x10 and x11 are non-transient and must be preserved (or
// altered only along their ongoing semantics). x0..x7, x16 and x17 are
// available as scratch registers.
// The stack is used for subroutine calls; every such call involves pushing
// the current instruction pointer on the stack (to preserve 16-byte stack
// alignment, stack pointer is decreased by 16 in that case).

// ST x    copy accumulator into value x
op_st:
	// Set the carry flag (C) (in Armv8, borrow = not(carry))
	subs	xzr, xzr, xzr
	// FALL THROUGH
// LD x    copy value x into accumulator
op_ld:
	// We copy words from x3 to x4.
	// Carry C is set for TD, cleared for LD.
	csel	x3, x15, x2, cs
	csel	x4, x2, x15, cs
	mov	x5, #5
Lop_ld__loop:
	ldr	x1, [x3], #8
	str	x1, [x4], #8
	subs	x5, x5, #1
	b.ne	Lop_ld__loop
	ret

// SUB x   subtract value x from accumulator
op_sub:
	// Set the carry flag (C) (in Armv8, borrow = not(carry))
	subs	xzr, xzr, xzr
	// FALL THROUGH
// ADD x   add value x to accumulator
op_add:
	// Carry C is set for SUB, cleared for ADD.
	// None of the operations in the loop changes the flags.
	mov	x3, #40
Lop_add__loop:
	sub	x3, x3, #8
	ldr	x4, [x2, x3]
	ldr	x0, [x15, x3]
	cneg	x4, x4, cs
	add	x0, x0, x4
	str	x0, [x15, x3]
	cbnz	x3, Lop_add__loop
	ret

// SMOD y    switch current modulus (y = 26 for mod_N, y = 27 for mod_P)
op_smod:
	// &mod_N == x15+1280
	// &mod_P == x15+1328 == &mod_N + 48
	// we have 8*y in x0, and x15+40*y in x2, and:
	//    32 + (40*y) + 8*y = 1280 if y = 26, or 1328 if y = 27
	add	x0, x0, x2
	add	x12, x0, #32
	ret

// MUL x   multiply accumulator with x
// This uses Montgomery multiplication, so that it really computes (x*acc)/R.
// The current modulus is used.
op_mul:
	// Save x19 and the return address.
	// x19 is used as temporary in add_mul_wide()
	stp	x19, lr, [sp, #-16]!

	// Allocate and initialize stack buffer (10 words).
	mov	x4, #5
Lop_mul__loop:
	stp	xzr, xzr, [sp, #-16]!
	subs	x4, x4, #1
	b.ne	Lop_mul__loop

	// x16 <- (-1/m mod 2^54)*2^10
	ldr	x16, [x12, #40]

	// Process second operand word by word.
	mov	x0, sp
	mov	x17, #5          // loop counter
Lop_mul__loop2:
	// t <- t + a*b_i
	mov	x1, x15
	ldr	x3, [x2], #8     // x3 <- b_i
	lsl	x3, x3, #5       // pre-shift b_i
	bl	add_mul_wide
	// x3 <- f = (-t/m mod 2^54)*2^5  (signed)
	ldr	x3, [x0, #-40]!  // also restore x0
	mul	x3, x3, x16
	asr	x3, x3, #5
	// t <- t + m*f
	mov	x1, x12
	bl	add_mul_wide
	// Propagate upper bits of dropped word
	ldp	x3, x4, [x0, #-40]
	add	x4, x4, x3, asr #54
	str	x4, [x0, #-32]!
	// x0 has been adjusted to drop the low word
	subs	x17, x17, #1
	b.ne	Lop_mul__loop2

	// Recover return address.
	ldp	x19, lr, [sp, #80]

	// Size of t is now 5 words. We copy it to the destination,
	// with high bit propagation.
	// op_norm() also tail-calls here. API:
	//  - source address is x0 (consumed)
	//  - destination address is x15 (preserved)
	//  - after the move, sp is incremented by 96
normalize_limbs:
	mov	x4, #5         // loop counter
	mov	x3, xzr        // previous word with upper bits
Lnormalize_limbs__loop:
	ldr	x1, [x0], #8
	add	x3, x1, x3, asr #54
	subs	x4, x4, #1
	b.eq	Lnormalize_limbs__cont
	ubfx	x1, x3, #0, #54
	str	x1, [x15], #8
	b	Lnormalize_limbs__loop
Lnormalize_limbs__cont:
	str	x3, [x15], #-32
	add	sp, sp, #96
	ret

// SKIPBITZ x   skip next instruction if current bit is set in x
// The "current bit" relates to the iterator; this instruction makes sense
// only when an iteration is ongoing.
op_skipbitz:
	// Bit offset is a combined value: low 3 bits are the limb index
	// (0 to 4), bits 3+ are the bit offset within the limb.
	ubfx	x0, x10, #0, #3         // x0 <- limb index j
	lsr	x1, x10, #3             // x1 <- bit offset
	ldr	x0, [x2, x0, lsl #3]    // x0 <- limb j
	lsr	x0, x0, x1
	tbnz	x0, #0, Lret1
	// FALL THROUGH
// Common sequence for skipping the next instruction.
doskip:
	// Increment the instruction pointer to skip the next instruction;
	// take care that the CALL instruction has size 2 bytes.
	ldrb	w0, [x8], #1
	cmp	w0, #OP_CALL
	cinc	x8, x8, eq
Lret1:
	ret

// The extended translation table is used for opcodes that do not have
// a value operand. This table contains routine offsets relative to
// op_extended.
extended_translation_table:
	// WARNING: if table size is changed, the ldrb instruction
	// in op_extended MUST be altered accordingly.
	.byte	op_call - op_extended
	.byte	op_skipnz - op_extended
	.byte	op_skipneg - op_extended
	.byte	op_fnext - op_extended
	.byte	op_ret - op_extended
	.byte	op_for - op_extended
	.byte	op_next - op_extended
	.byte	op_ok - op_extended
	.byte	op_fail - op_extended
	.byte	op_norm - op_extended

	// ARMv8 requires 32-bit alignment for opcodes
	.balign	4

// Pseudo-instruction invoked for extended opcodes.
op_extended:
	// a0 contains 8*x, where x designates the opcode. We use
	// the secondary translation table, which we locate from a1,
	// which contains the address of op_extended. The table size
	// is 10 bytes.
	// WARNING: if the table size is modified, the offset in the
	// ldrb instruction below MUST be modified. Beware that instruction
	// alignment may enlarge the table.
	add	x3, x1, x0, lsr #3      // x2 <- op_extended + x
	ldrb	w3, [x3, #-12]          // x3 <- offset of routine
	add	x1, x1, x3              // x1 <- opcode routine address
	br	x1

// In extended opcodes, x0 contains the top 5 bits of the opcode value.

// NORM   normalize the accumulator
// Normalization does not change the value as an integer, but it
// ensures that the four low limbs are in [0, 2^54-1]. After normalization,
// the sign of the top limb matches the sign of the whole integer.
op_norm:
	// normalize_limbs has a special API
	sub	sp, sp, #96
	mov	x0, x15      // source to normalize
	b	normalize_limbs

// SKIPNZ   skip next instruction if accumulator is non-zero
// This works correctly only if the accumulator has been normalized. This
// is a comparison over the plain integers; for a comparison over _modular_
// integers, the value must be fully reduced first.
op_skipnz:
	add	x2, x15, #40
Lop_skipnz:
	ldr	x0, [x2, #-8]!
	cbnz	x0, doskip
	cmp	x2, x15
	b.ne	Lop_skipnz
	ret

// SKIPNEG   skip next instruction if accumulator is negative
// This works correctly only if the accumulator has been normalized. This
// is a comparison over the plain integers.
op_skipneg:
	ldr	x0, [x15, #32]
	asr	x0, x0, #63
	cbnz	x0, doskip
	ret

// RET     return from subroutine
op_ret:
	ldp	x0, x8, [sp], #16
	ret

// FOR    start the iterator
// This sets the iterator counter to 255. Each NEXT instruction will
// decrement the iterator and loop back to immediately after the FOR,
// unless the counter reaches -1 (which terminates the loop).
op_for:
	// Save address of next instruction; this is where execution
	// will loop back upon NEXT.
	mov	x11, x8
	// Loop counter is stored as:
	//    floor(i/54) + 8*(i mod 54)
	// for i = 255 to 0. Start value is then 316.
	mov	x10, #316
Lret2:
	ret

// FNEXT   consume first iteration
// This is like a NEXT which is performed only on first iteration.
op_fnext:
	cmp	x10, #316
	b.ne	Lret2
	// FALL THROUGH
// NEXT   decrement iterator counter and loop
// If the counter is at zero, then the loop exits. Otherwise, the counter
// is decremented, and execution jumps to right after the FOR instruction
// that started the iterator.
op_next:
	// Decrement bit offset.
	cbz	x10, Lret2
	subs	x10, x10, #8
	b.pl	Lop_next__cont
	// Value became negative, which means that we crossed a limb boundary.
	// Value was j (limb index) and is now j-8; we want (j-1) + 53*8,
	// so we add 53*8 + 7 = 431.
	add	x10, x10, #431
Lop_next__cont:
	// Store new counter value and loop. Iteration start address
	// was stored x11 by FOR.
	mov	x8, x11
	ret

// OK     exit the interpreter with a success status
// FAIL   exit the interpreter with a failed status
op_ok:
op_fail:
	// x0 is equal to either OK_OK - 7, or OP_FAIL - 7
	// OP_FAIL == OP_OK + 8
	// We set x9 to either -7 (OK) or +1 (FAIL)
	sub	x9, x0, #OP_OK
	// POSSIBLE OPTIMIZATION: the exit routine of tv_ecdsa_p256_verify()
	// (INTERPRETER_END and ret) could be hardcoded here; this would
	// allow removing the exit flag (x9) altogether, and would save
	// a couple of instructions. However, it would make the code more
	// obscure, and it would make it more difficult for unit test
	// functions to setup interpreters of their own.
	ret

// CALL   call subroutine
// The target subroutine address is provided as one inline byte
// immediately following the instruction; the byte is the offset
// (unsigned) to add to the current instruction pointer to obtain the
// address of the called subroutine. Since the offset is unsigned,
// this can only call subroutines located after the call site.
op_call:
	// Fetch target offset.
	ldrb	w0, [x8], #1
	// Save instruction pointer.
	stp	xzr, x8, [sp, #-16]!
	// Jump to the designated subroutine.
	add	x8, x8, x0
	ret

// Interpreter is built as three macros, so that the test code may use
// some interpreters to exercise subroutines.

// Interpreter initialization: allocate and setup the stack context.
// Outputs:
//    x12   points to mod_N
//    x8    points to the bytecode entry point
//    context is on top-of-stack
// Clobbers: x0..x6
// ra is saved, and will be restored by INTERPRETER_END.
// 1376 bytes are stored on the stack.
.macro	INTERPRETER_BEGIN
	// Allocate the context structure (1376 bytes = 172 words), filled
	// with zeros.
	mov	x0, #86    // 172 = 2*86 (we write two words at a time)
1:
	stp	xzr, xzr, [sp, #-16]!
	subs	x0, x0, #1
	b.ne	1b
	// Value 2 is ONE. Also save lr in sp+72.
	mov	x0, #1
	stp	lr, x0, [sp, #72]

	// Decode curve constants Gx, Gy, and mod_N.
	add	x0, sp, #(_Gx*40)
	adr	x1, curve_constants
	bl	decode_int    // Gx
	bl	decode_int    // Gy
	mov	x12, x0       // initial modulus is mod_N
	bl	decode_int    // mod_N
	ldr	x2, [x1], #8
	str	x2, [x0], #8  // n0i
	bl	decode_int    // mod_P
	mov	x2, #0x400
	str	x2, [x0]      // p0i

	mov	x8, x1        // bytecode entry point
.endm

// Main interpreter loop.
// Inputs:
//    x15   context pointer
//    x12   current modulus
//    x8    instruction pointer
// Outputs:
//    x15   context pointer
//    x9    negative on success, 1 on failure
//    stack MAY have grown (use x15 to access stack elements)
// Clobbers:
//    x0..x9, x10..x12, x16, x17
.macro	INTERPRETER_MAIN
	mov	x9, xzr       // exit flag
1:
	// Load next instruction.
	ldrb	w0, [x8], #1
	// Split instruction into the opcode index (low 3 bits) and
	// the parameter (high 5 bits = 8*x).
	ubfx	x1, x0, 0, #3       // x1 <- opcode index
	sub	x0, x0, x1          // x0 <- 8*x
	adr	x3, translation_table
	add	x2, x0, x0, lsl #2  // x2 <- 40*x
	ldrb	w1, [x3, x1]        // opcode routine offset
	add	x2, x2, x15         // address of value x
	// If x == 1 then the operand is the special modulus value
	cmp	x0, #8
	csel	x2, x12, x2, eq
	adds	x1, x3, x1, lsl #2    // opcode routine address (also clears C)
	blr	x1
	// Loop as long as the exit flag is not set
	cbz	x9, 1b
.endm

// Wind down the interpreter. The stack and lr are restored to their
// state when INTERPRETER_BEGIN was invoked. x0 is set to the code exit
// status.
// Input:
//    x15   points to context
//    x9    exit status (negative = success, non-negative = failure)
// Output:
//    x0   exit status (1 = success, 0 = failure)
// lr is restored to the value it had upon entry into INTERPRETER_BEGIN.
.macro	INTERPRETER_END
	// Set exit status
	lsr	x0, x9, #63
	// Restore stack and saved registers
	ldr	lr, [x15, #72]
	add	sp, x15, #1376
.endm

// ========================================================================
// int tv_ecdsa_p256_verify(const void *sig, size_t sig_len,
//         const void *pub, size_t pub_len,
//         const void *hv, size_t hv_len)
// ========================================================================

// Small helper chunk to report early errors.
Ltv_ecdsa_p256_verify__err:
	mov	x0, xzr
	ret

	.global	tv_ecdsa_p256_verify
	.type	tv_ecdsa_p256_verify, %function
tv_ecdsa_p256_verify:
	// Check public key length (65 bytes)
	cmp	x3, #65
	b.ne	Ltv_ecdsa_p256_verify__err
	// Check public key first byte (0x04) and signature length (64 bytes)
	ldrb	w6, [x2], #1
	cmp	x1, #64
	ccmp	w6, #0x04, #0, eq
	b.ne	Ltv_ecdsa_p256_verify__err
	// Check hash value length (32 to 64 bytes)
	sub	x5, x5, #32
	cmp	x5, #32
	b.hi	Ltv_ecdsa_p256_verify__err

	// We need to allocate the interpreter context; this will not
	// clobber x9, x10 or x11
	// It will also save ra, hence we can call sub-functions now.
	mov	x9, x0    // sig
	mov	x10, x2   // pub+1
	mov	x11, x4   // hv
	INTERPRETER_BEGIN

	// Decode r, s, e, Qx and Qy into the appropriate slots.
	// This uses the fact that the slots are consecutive.
	add	x0, sp, #(40*_Kr)
	mov	x1, x9
	bl	decode_int   // r
	bl	decode_int   // s
	mov	x1, x11
	bl	decode_int   // e
	mov	x1, x10
	bl	decode_int   // Qx
	bl	decode_int   // Qy

	// x8 still contains the pointer to the bytecode.
	mov	x15, sp
	INTERPRETER_MAIN

	INTERPRETER_END
	// x0 was set according to the bytecode exit status
	ret
	.size	tv_ecdsa_p256_verify, . - tv_ecdsa_p256_verify

#ifdef TV_ECDSA_P256_TEST

// ========================================================================
// ========================================================================
// ========================================================================
// ###########################<<< TEST CODE >>>############################
//
// Everything below this line is test code which is used by external unit
// tests; this is not meant to be compiled in released builds. When the
// TV_ECDSA_P256_TEST macro is not defined, this code is omitted.
// ========================================================================
// ========================================================================
// ========================================================================

// This code uses an unreduced format, we return 1.
	.global	tv_gf_has_unreduced
	.type	tv_gf_has_unreduced, %function
tv_gf_has_unreduced:
	mov	x0, #1
	ret
	.size	tv_gf_has_unreduced, . - tv_gf_has_unreduced

// We accept the value if its limbs are at most 5.5*2^t in absolute value,
// where t = 54 for limbs 0..3, and t = 40 for limb 4. We ignore the 'scalar'
// parameter (check is the same for both fields).
	.global	tv_gf_check
	.type	tv_gf_check, %function
tv_gf_check:
	// x4 <- 5.5*2^54
	mov	x4, #11
	lsl	x4, x4, #53
	mov	x5, #5     // loop counter
Ltv_gf_check__loop:
	// Read next limb.
	ldr	x1, [x0], #8
	// x1 <- abs(x1)
	eor	x2, x1, x1, asr #63
	sub	x1, x2, x1, asr #63
	// Loop control: exit for last limb.
	subs	x5, x5, #1
	b.eq	Ltv_gf_check__cont
	cmp	x1, x4
	b.lo	Ltv_gf_check__loop
	mov	x0, xzr
	ret
Ltv_gf_check__cont:
	// Max value for limb 4 is 5.5*2^40, not 5.5*2^54.
	lsr	x4, x4, #14
	cmp	x1, x4
	cset	x0, lo
	ret
	.size	tv_gf_check, . - tv_gf_check

// For additions, subtractions, multiplications and inversion, we fire up
// an interpreter and use the relevant bytecode.

bytecode_add:
	_ADD _T0 ; _RET
bytecode_sub:
	_SUB _T0 ; _RET
bytecode_mul:
	_MUL _T0 ; _RET
bytecode_ok:
	_OK
	.balign	4

// gf_copy(gf *dst, const gf *src)
// Output:
//   x0 is updated (+40)
//   x1 is updated (+40)
// Clobbers: x2, x3
gf_copy:
	ldp	x2, x3, [x1], #16
	stp	x2, x3, [x0], #16
	ldp	x2, x3, [x1], #16
	stp	x2, x3, [x0], #16
	ldr	x2, [x1], #8
	str	x2, [x0], #8
	ret

// gf_op(gf *d, const gf *a, const gf *b, int scalar, const uint8_t *code)
	.type	gf_op, %function
gf_op:
	// Save parameters.
	stp	x4, x20, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!
	stp	x0, x1, [sp, #-16]!
	mov	x20, sp    // We use x20 as a custom frame pointer

	INTERPRETER_BEGIN

	// Copy operands:
	//  - If a != NULL then this is an add, sub or mul; the two source
	//    operands go to the accumulator and value T0, respectively.
	//  - If a == NULL then this is an inversion or an encoding, *d is
	//    copied into the accumulator.
	mov	x0, sp
	ldr	x1, [x20, #8]
	cbz	x1, Lgf_op__cont1
	// acc <- a
	bl	gf_copy
	// T0 <- b
	add	x0, sp, #(40*_T0)
	ldr	x1, [x20, #16]
	bl	gf_copy
	b	Lgf_op__cont2
Lgf_op__cont1:
	// acc <- d
	ldr	x1, [x20]
	bl	gf_copy
Lgf_op__cont2:
	// Set modulus according to the 'scalar' argument: it was set to
	// mod_N by INTERPRETER_BEGIN, but we change that to mod_P if
	// scalar = 0.
	add	x2, x12, #48      // &mod_P == &mod_N + 48
	ldr	w3, [x20, #24]
	cmp	w3, #0
	csel	x12, x2, x12, eq
	// Simulate a call, with a return pointer leading to bytecode_ok,
	// then use the provided code pointer.
	mov	x15, sp
	adr	x0, bytecode_ok
	stp	x0, x0, [sp, #-16]!
	ldr	x8, [x20, #32]    // 'code' parameter
	INTERPRETER_MAIN

	// Copy result into destination.
	ldr	x0, [x20]
	mov	x1, x15
	bl	gf_copy

	INTERPRETER_END

	ldr	x20, [sp, #40]
	add	sp, sp, #48
	ret
	.size	gf_op, . - gf_op

// tv_gf_add() uses gf_op()
	.global	tv_gf_add
	.type	tv_gf_add, %function
tv_gf_add:
	adr	x4, bytecode_add
	b	gf_op
	.size	tv_gf_add, . - tv_gf_add

// tv_gf_sub() uses gf_op()
	.global	tv_gf_sub
	.type	tv_gf_sub, %function
tv_gf_sub:
	adr	x4, bytecode_sub
	b	gf_op
	.size	tv_gf_sub, . - tv_gf_sub

// tv_gf_mul() uses gf_op()
	.global	tv_gf_mul
	.type	tv_gf_mul, %function
tv_gf_mul:
	adr	x4, bytecode_mul
	b	gf_op
	.size	tv_gf_mul, . - tv_gf_mul

// tv_gf_invert() uses gf_op()
	.global	tv_gf_invert
	.type	tv_gf_invert, %function
tv_gf_invert:
	mov	x3, x1
	mov	x1, xzr
	mov	x2, xzr
	adr	x4, invert_mod
	b	gf_op
	.size	tv_gf_invert, . - tv_gf_invert

// This function applies conversion to Montgomery representation.
	.global	tv_gf_decode
	.type	tv_gf_decode, %function
tv_gf_decode:
	stp	x2, lr, [sp, #-16]!
	stp	x0, x1, [sp, #-16]!

	// Raw decode.
	bl	decode_int

	// Multiply by the appropriate constant R^2 (conversion to
	// Montgomery representation).
	adr	x2, gf_R2n
	adr	x5, gf_R2p
	ldr	x3, [sp, #16]
	cmp	x3, #0
	csel	x2, x5, x2, eq
	ldr	x0, [sp]
	mov	x1, x0
	bl	tv_gf_mul

	ldr	lr, [sp, #24]
	add	sp, sp, #32
	ret
	.size	tv_gf_decode, . - tv_gf_decode

// tv_gf_encode() uses gf_op() to perform a canonical reduction.
	.global	tv_gf_encode
	.type	tv_gf_encode, %function
tv_gf_encode:
	stp	x2, lr, [sp, #-16]!
	stp	x0, x1, [sp, #-16]!
	sub	sp, sp, #48

	// Copy source into stack buffer.
	mov	x0, sp
	bl	gf_copy
	// Use gf_op() to perform canonicalization.
	mov	x0, sp
	mov	x1, xzr
	mov	x2, xzr
	ldr	x3, [sp, #64]
	adr	x4, canonicalize
	bl	gf_op
	// Load the five output words and check that they are all
	// non-negative and in range.
	ldp	x0, x1, [sp]
	ldp	x2, x3, [sp, #16]
	ldr	x4, [sp, #32]
	mov	x7, #0x0040000000000000
	cmp	x0, x7
	b.hs	Ltv_gf_encode__err
	cmp	x1, x7
	b.hs	Ltv_gf_encode__err
	cmp	x2, x7
	b.hs	Ltv_gf_encode__err
	cmp	x3, x7
	b.hs	Ltv_gf_encode__err
	lsr	x7, x7, #14
	cmp	x4, x7
	b.hs	Ltv_gf_encode__err

	// Reassemble the data into four 64-bit words.
	orr	x0, x0, x1, lsl #54
	lsr	x1, x1, #10
	orr	x1, x1, x2, lsl #44
	lsr	x2, x2, #20
	orr	x2, x2, x3, lsl #34
	lsr	x3, x3, #30
	orr	x3, x3, x4, lsl #24

	// Write words in big-endian order.
	// We first write them back to the stack, then copy from the stack
	// to the output, so that we perform no unaligned access if the
	// output is not aligned (unaligned accesses are normally well
	// tolerated by Armv8 hardware, but the rest of the code is
	// alignment-clean).
	rev	x0, x0
	rev	x1, x1
	rev	x2, x2
	rev	x3, x3
	stp	x3, x2, [sp]
	stp	x1, x0, [sp, #16]
	ldr	x0, [sp, #48]
	mov	x1, sp
	mov	x3, #32
Ltv_gf_encode__loop:
	ldrb	w2, [x1], #1
	strb	w2, [x0], #1
	subs	x3, x3, #1
	b.ne	Ltv_gf_encode__loop

	// Decoding success.
	mov	x0, #1

Ltv_gf_encode__exit:
	ldr	lr, [sp, #72]
	add	sp, sp, #80
	ret
Ltv_gf_encode__err:
	mov	x0, xzr
	b	Ltv_gf_encode__exit
	.size	tv_gf_encode, . - tv_gf_encode

// tv_point_decode()
	.global	tv_point_decode
	.type	tv_point_decode, %function
tv_point_decode:
	stp	x20, lr, [sp, #-16]!
	mov	x20, x0     // output pointer

	// Skip leading byte.
	add	x10, x1, #1

	INTERPRETER_BEGIN

	// Decode coordinates as integers into slots Qx and Qy
	add	x0, sp, #(40*_Qx)
	mov	x1, x10
	bl	decode_int
	bl	decode_int

	// Set modulus to mod_P  (&mod_P == &mod_N + 48)
	add	x12, x12, #48

	// Set Bm.
	add	x0, sp, #(40*_Bm)
	adr	x1, gf_Bm
	bl	decode_int

	// Simulate a call, with a return pointer leading to bytecode_ok.
	mov	x15, sp
	adr	x0, bytecode_ok
	stp	x0, x0, [sp, #-16]!
	adr	x8, check_point
	INTERPRETER_MAIN

	// Copy decoded x and y to destination P.X and P.Y; set P.Z to 1.
	mov	x0, x20
	add	x1, x15, (40*_Qx)
	bl	gf_copy
	bl	gf_copy
	mov	x1, #1
	stp	x1, xzr, [x0]
	stp	xzr, xzr, [x0, #16]
	str	xzr, [x0, #32]

	INTERPRETER_END

	ldp	x20, lr, [sp], #16
	ret
	.size	tv_point_decode, . - tv_point_decode

// tv_point_encode()
	.global	tv_point_encode
	.type	tv_point_encode, %function
tv_point_encode:
	stp	x1, lr, [sp, #-16]!
	stp	xzr, x0, [sp, #-16]!
	sub	sp, sp, #80

	// Copy Z coordinate to sp+0
	mov	x0, sp
	add	x1, x1, #80
	bl	gf_copy
	// Invert Z
	mov	x0, sp
	mov	x1, xzr
	bl	tv_gf_invert
	// Multiply 1/Z with Y, into sp+40
	// (We use Montgomery multiplication but that still works: we
	// are multiplying the Montgomery representations of X/R and R/Z,
	// thus we get the Montgomery representation of X/Z.)
	add	x0, sp, #40
	mov	x1, sp
	ldr	x2, [sp, #96]
	add	x2, x2, #40
	mov	x3, xzr
	bl	tv_gf_mul
	// Multiply 1/Z with X, into sp
	mov	x0, sp
	mov	x1, sp
	ldr	x2, [sp, #96]
	mov	x3, xzr
	bl	tv_gf_mul
	// Encode x and y into sp+0 and sp+32, respectively.
	mov	x0, sp
	mov	x1, sp
	mov	x2, xzr
	bl	tv_gf_encode
	add	x0, sp, #32
	add	x1, sp, #40
	mov	x2, xzr
	bl	tv_gf_encode
	// If Z was zero then tv_gf_invert() returned zero, and both x and y
	// are zero. For non-neutral points, y is always non-zero since the
	// curve has odd order.
	ldp	x0, x1, [sp, #32]
	ldp	x2, x3, [sp, #48]
	orr	x0, x0, x1
	orr	x2, x2, x3
	orr	x0, x0, x2
	cbnz	x0, Ltv_point_encode__cont
	// Point-at-infinity encodes into a single byte of value 0x00.
	ldr	x0, [sp, #88]
	strb	wzr, [x0]
	mov	x0, #1
	b	Ltv_point_encode__exit
Ltv_point_encode__cont:
	// Non-infinity point encodes into 65 bytes.
	ldr	x0, [sp, #88]
	mov	x2, #0x04
	strb	w2, [x0], #1
	mov	x1, sp
	mov	x3, #64
Ltv_point_encode__loop:
	sub	x3, x3, #1
	ldrb	w2, [x1], #1
	strb	w2, [x0], #1
	cbnz	x3, Ltv_point_encode__loop
	mov	x0, #65

Ltv_point_encode__exit:
	ldr	lr, [sp, #104]
	add	sp, sp, #112
	ret
	.size	tv_point_encode, . - tv_point_encode

//# tv_point_set_neutral()
	.global	tv_point_set_neutral
	.type	tv_point_set_neutral, %function
tv_point_set_neutral:
	// Clear all 120 useful bytes of the structure, then set Y to a
	// non-zero value.
	mov	x1, #1
	stp	xzr, xzr, [x0]
	stp	xzr, xzr, [x0, #16]
	stp	xzr, x1,  [x0, #32]
	stp	xzr, xzr, [x0, #48]
	stp	xzr, xzr, [x0, #64]
	stp	xzr, xzr, [x0, #80]
	stp	xzr, xzr, [x0, #96]
	str	xzr, [x0, #112]
	ret
	.size	tv_point_set_neutral, . - tv_point_set_neutral

// point_addsub(point *p3, point *p1, point *p2, int sub)
// when sub == 0: p3 <- p1 + p2
// when sub != 0: p3 <- p1 - p2
	.type	point_addsub, %function
point_addsub:
	stp	x20, lr, [sp, #-16]!
	stp	x2, x3, [sp, #-16]!
	stp	x0, x1, [sp, #-16]!
	mov	x20, sp

	INTERPRETER_BEGIN

	// Copy source coordinates to _W* and _H*
	add	x0, sp, #(40*_Wx)
	ldr	x1, [x20, #8]
	bl	gf_copy
	bl	gf_copy
	bl	gf_copy
	add	x0, sp, #(40*_Hx)
	ldr	x1, [x20, #16]
	bl	gf_copy
	bl	gf_copy
	bl	gf_copy

	// If subtracting: negate _Hy (limb-wise)
	ldr	w3, [x20, #24]
	cbz	w3, Lpoint_addsub__cont
	add	x0, sp, #(40*_Hy)
	ldp	x1, x2, [x0]
	ldp	x3, x4, [x0, #16]
	ldr	x5, [x0, #32]
	neg	x1, x1
	neg	x2, x2
	neg	x3, x3
	neg	x4, x4
	neg	x5, x5
	stp	x1, x2, [x0]
	stp	x3, x4, [x0, #16]
	str	x5, [x0, #32]
Lpoint_addsub__cont:

	// Set modulus to mod_P  (&mod_P == &mod_N + 48)
	add	x12, x12, #48

	// Set Bm.
	add	x0, sp, #(40*_Bm)
	adr	x1, gf_Bm
	bl	decode_int

	// Simulate a call, with a return pointer leading to bytecode_ok.
	mov	x15, sp
	adr	x0, bytecode_ok
	stp	x0, x0, [sp, #-16]!
	adr	x8, point_add_to_W
	INTERPRETER_MAIN

	ldr	x0, [x20]
	add	x1, x15, #(40*_Wx)
	bl	gf_copy
	bl	gf_copy
	bl	gf_copy

	INTERPRETER_END

	add	sp, sp, #32
	ldp	x20, lr, [sp], #16
	ret
	.size	point_addsub, . - point_addsub

# tv_point_add()
	.global	tv_point_add
	.type	tv_point_add, %function
tv_point_add:
	mov	x3, xzr
	b	point_addsub
	.size	tv_point_add, . - tv_point_add

# tv_point_sub()
	.global	tv_point_sub
	.type	tv_point_sub, %function
tv_point_sub:
	mov	x3, #1
	b	point_addsub
	.size	tv_point_sub, . - tv_point_sub

	.balign	8
gf_R2p:
	.quad	0x00000030000000, 0x3FFFC000000000, 0x3EFFFFFFFBFFFF
	.quad	0x3FFFFFFFFFFFFF, 0x00004FFFFFFFDF
gf_R2n:
	.quad	0x3644694887AC57, 0x28AB84C1E17805, 0x19619076A9EA8C
	.quad	0x059212A4ADAFB1, 0x000055ABA83AFC
// b*2^270 mod p
gf_Bm:
	.byte	0x01, 0x87, 0x78, 0x2D, 0xD2, 0x0D, 0x02, 0x5C
	.byte	0x88, 0x2A, 0xFD, 0xC8, 0x4B, 0xB5, 0xAB, 0x3C
	.byte	0x01, 0x73, 0x27, 0x15, 0x0C, 0x24, 0x36, 0x27
	.byte	0x37, 0xD8, 0x8A, 0x71, 0x2F, 0x77, 0xF7, 0x0C

// ========================================================================
#endif

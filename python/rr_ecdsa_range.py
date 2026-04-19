# ==========================================================================

# This script defines functions that perform a range analysis on an ECDSA
# verifier implementation (for curve P-256) with redundant representation
# of big integers, and Montgomery multiplication with variants. To use
# it, import it in a Python prompt, then call some functions:
#
#    $ python3
#    Python 3.12.3 (main, Mar  3 2026, 12:15:18) [GCC 13.3.0] on linux
#    Type "help", "copyright", "credits" or "license" for more information.
#    >>> from rr_ecdsa_range import *
#    >>> test_core()
#    Test basic arithmetics: ...........
#    (etc.)
#
# It should work on any recently up-to-date Python installation (it was
# tested with Python 3.12.3 as provided with Ubuntu 24.04); it does
# not require extra packages, using only the 'copy' and 'hashlib' imports
# that should be part of the Python standard library.
#
#
# The test_core() function runs basic unit tests on exact values for
# modular arithmetics (add, sub, mul), modular inversion, and curve
# point addition. For inversions and point additions, the relevant bytecode
# subroutines are used. test_core() takes no parameter.
#
# test_ecdsa() and range_analysis() both use the following parameters:
#   k      number of limbs
#   s      limb nominal size (radix is 2^s)
#   w      word size (normally 32 or 64)
#   slf    True for signed Montgomery factors f_i (default: False)
#   slv    True for signed normalization after multiplication (default: False)
#   slm    True for signed-normalized moduli (default: False)
#   spec   bitwise combination of 1, 2 and/or 4 (default: 0)
# The spec flags, when set, add _NORM instructions in the bytecode at
# various places:
#   1   extra _NORM in invert_mod; needed for correctness if slm=True
#   2   extra _NORM in canonicalize; needed for correctness if slv=True
#   4   extra _NORM in point_add_to_W; needed for some (k,s,w) combinations
#
# If range_analysis() passes with no error (it prints "OK" without throwing
# and exception), then that combination of parameters supports the entire
# ECDSA verification with no overflows. Otherwise, the exception will point
# out at which instruction the failure was obtained. The folllowing calls
# succeed:
#
#    range_analysis(5, 54, 64, slf=True)
#    range_analysis(12, 22, 32, slf=True, spec=4)
#    range_analysis(12, 22, 32, slf=True, slv=True, spec=2)
#
# For any parameter combination that passes range analysis, the ECDSA test
# vectors can be used; these are 492 test vectors extracted from the
# project Wycheproof vectors (both p1363 and ASN.1 vectors, the latter
# having been converted to p1363 format):
#
#    test_ecdsa(5, 54, 64, slf=True)
#    test_ecdsa(12, 22, 32, slf=True, spec=4)
#    test_ecdsa(12, 22, 32, slf=True, slv=True, spec=2)
#
# A dot ('.') is printed for each passed vector. Note that passing all
# vectors takes a lot of time (it can exceed an hour, depending on the
# parameters).

# ==========================================================================

from copy import copy

# We handle the following value types, each represented by immutable
# instances:
#  - Exact integer: a Python 'int'
#    This is a value which is known; it is typically used for constants.
#  - Range: a ZRange instance
#    This is a value which is not known exactly, but is assumed to always be
#    within a given [low, high] range (the low and high bounds are included).
#  - Container: a ZContainer instance
#    This is a ZRange value wrapped within what is, conceptually, a machine
#    word; it verifies for each operation that the resulting ZRange never
#    overflows the container range. Container ranges correspond to a word
#    with a fixed size in bits, with either signed or unsigned interpretation.

# A ZRange instance represents a range of possible values.
class ZRange:
    def __init__(self, low, high):
        assert low <= high
        self.low = low
        self.high = high

    # Get the range of values representable over s bits in signed
    # interpretation ([-2^(s-1), 2^(s-1) - 1]).
    def signed(s):
        assert s > 0
        return ZRange(-(1 << (s - 1)), (1 << (s - 1)) - 1)

    # Get the range of values representable over s bits in unsigned
    # interpretation ([0, 2^s - 1]).
    def unsigned(s):
        assert s > 0
        return ZRange(0, (1 << s) - 1)

    # Get a range reduced to a unique integer.
    def exact(x):
        return ZRange(x, x)

    # Convert this range to a signed s-bit range. This function assumes
    # that this range is either [0, 2^s - 1], or [-2^(s-1), 2^(s-1) - 1].
    def to_signed_range(self):
        if self.low < 0:
            return self
        cH = self.high >> 1
        return ZRange(-(cH + 1), cH)

    # Convert this range to an unsigned s-bit range. This function assumes
    # that this range is either [0, 2^s - 1], or [-2^(s-1), 2^(s-1) - 1].
    def to_unsigned_range(self):
        if self.low >= 0:
            return self
        cH = self.high - self.low
        return ZRange(0, cH)

    # Tell whether this range pinpoints a single value.
    def is_exact(self):
        return self.low == self.high

    # Tell whether this range pinpoints a single value.
    def is_exact(self):
        return self.low == self.high

    def __add__(self, other):
        if type(other) is ZRange:
            return ZRange(self.low + other.low, self.high + other.high)
        return NotImplemented

    def __radd__(self, other):
        if type(other) is ZRange:
            return ZRange(other.low + self.low, other.high + self.high)
        return NotImplemented

    def __sub__(self, other):
        if type(other) is ZRange:
            return ZRange(self.low - other.high, self.high - other.low)
        return NotImplemented

    def __rsub__(self, other):
        if type(other) is ZRange:
            return ZRange(other.low - self.high, other.high - self.low)
        return NotImplemented

    def __neg__(self):
        return ZRange(-self.high, -self.low)

    def __mul__(self, other):
        if type(other) is ZRange:
            xLL = self.low  * other.low
            xLH = self.low  * other.high
            xHL = self.high * other.low
            xHH = self.high * other.high
            return ZRange(min(xLL, xLH, xHL, xHH), max(xLL, xLH, xHL, xHH))
        return NotImplemented

    def __rmul__(self, other):
        if type(other) is ZRange:
            xLL = self.low  * other.low
            xLH = self.low  * other.high
            xHL = self.high * other.low
            xHH = self.high * other.high
            return ZRange(min(xLL, xLH, xHL, xHH), max(xLL, xLH, xHL, xHH))
        return NotImplemented

    def __lshift__(self, other):
        assert other >= 0
        return ZRange(self.low << other, self.high << other)

    def __rshift__(self, other):
        assert other >= 0
        return ZRange(self.low >> other, self.high >> other)

    def __eq__(self, other):
        if type(other) is ZRange:
            return (self.low == other.low) and (self.high == other.high)
        return NotImplemented

    def __str__(self):
        return '[%d, %d]' % (self.low, self.high)

    # Get the intersection of two ranges. Returned value is None if the
    # intersection is empty.
    def inter(self, other):
        xL = max(self.low, other.low)
        xH = min(self.high, other.high)
        if xL > xH:
            return None
        else:
            return ZRange(xL, xH)

    # Get the union of two ranges.
    def union(self, other):
        return ZRange(min(self.low, other.low), max(self.high, other.high))

    # Check whether the provide range is a sub-range of this range.
    def contains_range(self, other):
        return (self.low <= other.low) and (other.high <= self.high)

    # Truncate this value to an s-bit range, which is provided as
    # a container, i.e. another range which is either [0, 2^s - 1]
    # (unsigned container) or [-2^(s-1), 2^(s-1) - 1] (signed container).
    def mask_container(self, container):
        # Convert the container range to unsigned, applying a corresponding
        # offset on the source value if necessary.
        cL = container.low
        cH = container.high
        vL = self.low
        vH = self.high
        if cL < 0:
            off = -cL
            cH += off
            vL += off
            vH += off
        else:
            off = 0

        # Truncate the value to the unsigned range.
        if (vH - vL + 1) > cH:
            # The value range spans an interval which is at least as large
            # as the container range, so we can get all values.
            vL = 0
            vH = cH
        else:
            # The value range spans an interval which is smaller than the
            # container range; what we get depends on whether that interval
            # spans over the "wrap-around" threshold.
            vL &= cH
            vH &= cH
            if vL > vH:
                vL = 0
                vH = cH

        # Re-apply the offset on output.
        return ZRange(vL - off, vH - off)

    # Truncate this value to s bits, with signed interpretation (the
    # s-bit value is sign-extended).
    def mask_signed(self, s):
        assert s >= 1
        off = 1 << (s - 1)
        zr = ZRange(self.low + off, self.high + off).mask_unsigned(s)
        return ZRange(zr.low - off, zr.high - off)

    # Truncate this value to s bits, with unsigned interpretation (the
    # s-bit value is zero-extended).
    def mask_unsigned(self, s):
        assert s >= 1
        sm = (1 << s) - 1
        if (self.high - self.low + 1) > sm:
            return ZRange.unsigned(s)
        mL = self.low & sm
        mH = self.high & sm
        if mL > mH:
            return ZRange.unsigned(s)
        else:
            return ZRange(mL, mH)

ZRange.ZERO = ZRange.exact(0)
ZRange.ONE = ZRange.exact(1)

# A ZWord instance wraps around a ZRange but furthermore checks for
# overflows, assuming a storage mechanism over w bits with either signed
# or unsigned interpretation. ZWord also offers some "wrapping"
# operations, and a "long multiplication" with an output over two words.
class ZWord:
    def __init__(self, value, container):
        if not(container.contains_range(value)):
            raise Exception('value range %s exceeds container range %s' % (value, container))
        self.value = value
        self.container = container

    # Make a new instance of value 0, within a signed container of w bits.
    def new_signed(w):
        assert w > 0
        return ZWord(ZRange(0, 0), ZRange.signed(w))

    # Make a new instance of value 0, within an unsigned container of w bits.
    def new_unsigned(w):
        assert w > 0
        return ZWord(ZRange(0, 0), ZRange.unsigned(w))

    # Make a new instance with the provided value, truncated to a given
    # container.
    def truncate(value, container):
        return ZWord(value.mask_container(container), container)

    def __add__(self, other):
        if type(other) is ZWord:
            assert(self.container == other.container)
            return ZWord(self.value + other.value, self.container)
        return NotImplemented

    def __radd__(self, other):
        if type(other) is ZWord:
            assert(self.container == other.container)
            return ZWord(other.value + self.value, self.container)
        return NotImplemented

    def __sub__(self, other):
        if type(other) is ZWord:
            assert(self.container == other.container)
            return ZWord(self.value - other.value, self.container)
        return NotImplemented

    def __rsub__(self, other):
        if type(other) is ZWord:
            assert(self.container == other.container)
            return ZWord(other.value - self.value, self.container)
        return NotImplemented

    def __neg__(self):
        return ZWord(-self.value, self.container)

    def __lshift__(self, other):
        return ZWord(self.value << other, self.container)

    def __rshift__(self, other):
        return ZWord(self.value >> other, self.container)

    def mask_signed(self, s):
        return ZWord(self.value.mask_signed(s), self.container)

    def mask_unsigned(self, s):
        return ZWord(self.value.mask_unsigned(s), self.container)

    # Convert word to signed interpretation. The value is implicitly
    # truncated/recast.
    def to_signed(self):
        if self.container.low < 0:
            # Already signed.
            return self
        cH = self.container.high >> 1   # cH = 2^(w-1) - 1
        cL = -(cH + 1)                  # cL = -2^(w-1)
        nc = ZRange(cL, cH)             # signed container
        return ZWord.truncate(self.value, nc)

    # Convert word to unsigned interpretation. The value is implicitly
    # truncated/recast.
    def to_unsigned(self):
        if self.container.low == 0:
            # Already unsigned.
            return self
        cH = (self.container.high << 1) + 1   # cH = 2^w - 1
        nc = ZRange(0, cH)                    # unsigned container
        return ZWord.truncate(self.value, nc)

    # Merge this word with another one (value range union). Both containers
    # must be identical.
    def union(self, other):
        assert self.container == other.container
        return ZWord(self.value.union(other.value), self.container)

    # Wrapping addition.
    def wrapping_add(self, other):
        assert self.container == other.container
        return ZWord.truncate(self.value + other.value, self.container)

    # Wrapping subtraction.
    def wrapping_sub(self, other):
        assert self.container == other.container
        return ZWord.truncate(self.value - other.value, self.container)

    # Wrapping negation.
    def wrapping_neg(self):
        return ZWord.truncate(-self.value, self.container)

    # Wrapping multiplication.
    def wrapping_mul(self, other):
        return ZWord.truncate(self.value * other.value, self.container)

    # Wrapping left shift.
    def wrapping_lshift(self, other):
        assert other >= 0
        return ZWord.truncate(self.value << other, self.container)

    # Long multiplication: output is two words. The low word is in an
    # unsigned container. The high word is in a signed container, unless
    # both source operands were unsigned, in which case the high word of
    # the output is also unsigned.
    def longmul(self, other):
        c1 = self.container
        c2 = other.container
        assert (c1.high - c1.low) == (c2.high - c2.low)
        if c1.low < 0:
            if c2.low < 0:
                # operand 1 and operand 2 are both signed
                cLo = c1.to_unsigned_range()
                cHi = c1
            else:
                # operand 1 is signed, operand 2 is unsigned
                cLo = c2
                cHi = c1
        else:
            if c2.low < 0:
                # operand 1 is unsigned, operand 2 is signed
                cLo = c1
                cHi = c2
            else:
                # operand 1 and operand 2 are both unsigned
                cLo = c1
                cHi = c2
        w = cLo.high.bit_length()

        # cLo is the container for the low output word
        # cHi is the container for the high output word
        # w is the size of cLo
        v = self.value * other.value
        xLo = ZWord.truncate(v, cLo)
        xHi = ZWord(v >> w, cHi)
        return (xLo, xHi)

# A computation context for multi-limb integers.
#  k      number of limbs
#  s      size of each limb (in bits)
#  w      size of container words (in bits)
#  sh1    pre-shift of first operand in multiplications (default: -1)
#  slf    True to make limbs of Montgomery factor f signed (default: False)
#  slv    True to make limbs of output value signed (default: False)
#
# Rules:
#  k > 0
#  s > 1
#  s < w
#  0 <= sh1 <= w-s
#
# sh1: left-shift amount of limbs of the first operand in multiplications;
# second operand is left-shifted by w-s-sh1 bits. If the provided sh1 is
# negative (this is the default), then a value of floor((w-s)/2) is used.
#
# slf: in Montgomery reduction of integer z as (z + f*m)/R, factor f is
# computed limb by limb; if slf is True then these limbs are signed s-bit
# integers (in [-2^(s-1), 2^(s-1) - 1]); otherwise, the limbs of f are
# unsigned (in [0, 2^s - 1]).
#
# slv: if True, then in Motgomery multiplication, output limbs 0 to k-2 are
# forced into a signed s-bit range ([-2^(s-1), 2^(s-1) - 1]); otherwise,
# they are forced to an unsigned s-bit range ([0, 2^s - 1]).
class MLIntContext:
    def __init__(self, k, s, w, sh1=-1, slf=False, slv=False):
        assert k > 0
        assert s > 1
        assert s < w
        if sh1 < 0:
            sh1 = (w - s) >> 1
        else:
            assert sh1 <= w - s
        sh2 = w - s - sh1
        self.k = k
        self.s = s
        self.w = w
        self.wr = ZRange.signed(w)
        self.limb_zero = ZWord(ZRange.ZERO, self.wr)
        self.limb_one = ZWord(ZRange.ONE, self.wr)
        self.sh1 = sh1
        self.sh2 = sh2
        self.slf = slf
        self.slv = slv
        self.ZERO = MLInt(self, [self.limb_zero]*k, ZRange.ZERO)
        self.ONE = MLInt(self, [self.limb_one] + [self.limb_zero]*(k - 1), ZRange.ONE)
        self.m = None

    # Decode a source value (range) into a multi-limb integer.
    # If slx=False then limb values are normalized to the unsigned range
    # (in [0, 2^s - 1]); otherwise, normalization targets a signed
    # range ([-2^(s-1), 2^(s-1) - 1]).
    def decode_int(self, x, slx=False):
        orig = x
        k = self.k
        s = self.s
        wr = self.wr
        d = []
        for i in range(0, k - 1):
            t = ZWord.truncate(x, wr)
            if slx:
                t = t.mask_signed(s)
                x = x - t.value
            else:
                t = t.mask_unsigned(s)
            d.append(t)
            x = x >> s
        d.append(ZWord(x, wr))   # This checks for overflows
        return MLInt(self, d, orig)

# Modulus for Montgomery multiplication.
# If slm is False, then limbs are normalized to unsigned ([0, 2^s - 1]),
# otherwise they are normalized to signed ([-2^(2-1), 2^(s-1) - 1]).
# Rules:
#   m > 1
#   m is odd
class MLIntModulus:
    def __init__(self, ctx, m, slm=False):
        self.m = ctx.decode_int(m, slm)
        # m0i = (-1/m mod 2^s)*2^(w-s)
        s = ctx.s
        w = ctx.w
        mask_s = (1 << s) - 1
        if m.is_exact():
            xm = m.low
            assert xm > 1
            assert (xm & 1) == 1
            # We compute the exact value with a Hensel's lifting lemma
            # (specialized):
            #    Let x = m mod 2^s
            #    Let y = 4 - x mod 4  (we have x*y = -1 mod 2^2)
            #    If y is such that x*y = -1 mod 2^t, then:
            #       x*y = u*2^t - 1   (for some integer u)
            #    Therefore:
            #       x*y*(x*y + 2) = (u*2^t - 1)*(u*2^t + 1)
            #                     = (u^2)*2^(2*t) - 1
            #    So we can replace y with y*(x*y + 2), which is a solution
            #    modulo 2^(2*t). We only need log(s) iterations to obtain
            #    the wanted value. We can do all computations modulo 2^s.
            x = xm & mask_s
            y = 4 - (x & 3)
            ncb = 2
            while ncb < s:
                y = (y*(x*y + 2)) & mask_s
                ncb <<= 1
            assert ((xm*y) & mask_s) == mask_s
            y <<= w - s
            self.m0i = ZWord(ZRange(y, y), ZRange.unsigned(w))
        else:
            # We do not have the exact value of the modulus, so we assume
            # that -1/m mod 2^s can be any odd value in [0, 2^s - 1].
            yL = 1 << (w - s)
            yH = mask_s << (w - s)
            self.m0i = ZWord(ZRange(yL, yH), ZRange.unsigned(w))

# A multi-limb integer.
# Such an integer exists within a given computation context. Its value
# is split into k signed limbs in base 2^s, with limbs contained in w-bit
# words. The MLInt instance contains the limb values (as contained ranges)
# as well as a range for the full value.
class MLInt:
    def __init__(self, ctx, limbs, value):
        self.ctx = ctx
        self.limbs = limbs
        self.value = value

    def __add__(self, other):
        assert self.ctx == other.ctx
        a = self.limbs
        b = other.limbs
        d = []
        for i in range(0, len(a)):
            d.append(a[i] + b[i])
        return MLInt(self.ctx, d, self.value + other.value)

    def __sub__(self, other):
        assert self.ctx == other.ctx
        a = self.limbs
        b = other.limbs
        d = []
        for i in range(0, len(a)):
            d.append(a[i] - b[i])
        return MLInt(self.ctx, d, self.value - other.value)

    def __neg__(self):
        a = self.limbs
        d = []
        for i in range(0, len(a)):
            d.append(-a[i])
        return MLInt(self.ctx, d, -self.value)

    def montymul(self, other, mod):
        assert self.ctx == other.ctx
        assert self.ctx == mod.m.ctx
        a = self.limbs       # operand 1 limbs
        b = other.limbs      # operand 2 limbs
        ctx = self.ctx
        k = ctx.k            # k = number of limbs
        s = ctx.s            # s = base (log)
        w = ctx.w            # w = container word size
        sh1 = ctx.sh1        # sh1 = pre-shift for operand 1
        sh2 = ctx.sh2        # sh2 = pre-shift for operand 2
        slf = ctx.slf        # slf = True if Montgomery factor f is signed
        slv = ctx.slv        # slv = True if final normalization is signed
        m = mod.m.limbs      # modulus limbs
        m0i = mod.m0i        # m0i = (-1/m mod 2^s)*2^(w-s) (unsigned)
        t = [ctx.limb_zero]*k
        f = [ctx.limb_zero]*k   # we record f for the range analysis
        for i in range(0, k):
            # Multiplier for this round.
            b_i = b[i] << sh2

            # x <- a[0]*b[i]
            (xlo, xhi) = (a[0] << sh1).longmul(b_i)

            # Split x into low part (s bits, unsigned) and high part; then
            # add t[0] to the low part.
            xlo = (xlo >> (w - s)).to_signed() + t[0]

            # Updated xlo is used to compute the factor f[i]. Since m0i is
            # pre-shifted, this naturally truncates f[i] to s bits and
            # pre-shifts it by w-s bits.
            f_i = xlo.to_unsigned().wrapping_mul(m0i)
            if slf:
                # Make f_i signed if requested.
                f_i = f_i.to_signed()
            # f[i] is nominally used only for this iteration but we want
            # to keep it around for the whole-value range analysis.
            f[i] = (f_i >> (w - s)).to_signed()

            # y <- m[0]*f[i]
            # y also splits into low and high parts.
            # Note: f_i is signed or unsigned, depending on slf; however,
            # m[0] is always signed.
            (ylo, yhi) = m[0].longmul(f_i)
            ylo = (ylo >> (w - s)).to_signed()

            # x + y should be a multiple of 2^s.
            # We can check that if the range is exact.
            zlo = xlo + ylo
            if zlo.value.low == zlo.value.high:
                assert (zlo.value.low & ((1 << s) - 1)) == 0

            # Compute initial carry word.
            cc = xhi + yhi + (zlo >> s)

            # Limbs 1 to k-1
            for j in range(1, k):
                (xlo, xhi) = (a[j] << sh1).longmul(b_i)
                (ylo, yhi) = m[j].longmul(f_i)
                xlo = (xlo >> (w - s)).to_signed()
                ylo = (ylo >> (w - s)).to_signed()
                t[j - 1] = xlo + ylo + t[j] + cc
                cc = xhi + yhi
            # Carry provides new top limb.
            t[k - 1] = cc

        # Finalization: this is either signed or unsigned normalization.
        cc = ctx.limb_zero
        for i in range(0, k - 1):
            z = t[i] + cc
            if slv:
                d_i = z.mask_signed(s)
                z -= d_i
            else:
                d_i = z.mask_unsigned(s)
            cc = z >> s
            t[i] = d_i
        t[k - 1] = t[k - 1] + cc

        # Range analysis: we recompute the full factor f from the recorded
        # f_i limbs.
        ff = ZRange.ZERO
        for i in range(k - 1, -1, -1):
            ff = (ff << s) + f[i].value
        u = self.value*other.value + ff*mod.m.value
        d = u >> (k*s)

        # Correct computation check:
        #  - u is a multiple of 2^(k*s)
        #  - contents of t[] match the value d
        # We can perform these checks only when ranges are exact.
        if self.value.is_exact() and other.value.is_exact() and mod.m.value.is_exact():
            assert ff.is_exact()
            xa = self.value.low
            xb = other.value.low
            xf = ff.low
            xm = mod.m.value.low
            xu = xa*xb + xf*xm
            assert (xu & ((1 << (k*s)) - 1)) == 0
            xd = xu >> (k*s)
            xv = 0
            for i in range(k - 1, -1, -1):
                assert t[i].value.is_exact()
                xv = (xv << s) + t[i].value.low
            assert xv == xd

        return MLInt(ctx, t, d)

    # Unsigned normalization: limbs 0 to k-2 are forced into the
    # unsigned s-bit range [0, 2^s - 1].
    # The overall value of the integer is unchanged.
    def normalize_unsigned(self):
        ctx = self.ctx
        s = ctx.s
        v = self.limbs
        d = []
        cc = ctx.limb_zero
        for i in range(0, len(v) - 1):
            z = v[i] + cc
            d.append(z.mask_unsigned(s))
            cc = z >> s
        d.append(v[-1] + cc)
        return MLInt(ctx, d, self.value)

    # Signed normalization: limbs 0 to k-2 are forced into the
    # signed s-bit range [-2^(s-1), 2^(s-1) - 1].
    # The overall value of the integer is unchanged.
    def normalize_signed(self):
        ctx = self.ctx
        s = self.s
        v = self.limbs
        d = []
        cc = ctx.limb_zero
        for i in range(0, len(v) - 1):
            z = v[i] + cc
            d_i = z.mask_signed(s)
            d.append(d_i)
            cc = (z - d_i) >> s
        d.append(v[-1] + cc)
        return MLInt(ctx, d, self.value)

    # Merge this integer with another one (value range union).
    def union(self, other):
        assert self.ctx == other.ctx
        d = []
        for i in range(0, len(self.limbs)):
            d.append(self.limbs[i].union(other.limbs[i]))
        return MLInt(self.ctx, d, self.value.union(other.value))

    # Tell whether this integer has an exact value.
    def is_exact(self):
        el = True
        for v in self.limbs:
            if not(v.value.is_exact()):
                el = False
                break
        ev = self.value.is_exact()
        assert el == ev
        return el

    # Get the exact value of this integer. This checks that the value is
    # indeed exact, both for the overall value and for all limbs, and that
    # limb values match the overall value.
    def to_int(self):
        assert self.value.is_exact()
        x = self.value.low
        y = 0
        ctx = self.ctx
        k = ctx.k
        s = ctx.s
        d = self.limbs
        for i in range(k - 1, -1, -1):
            assert d[i].value.is_exact()
            y = (y << s) + d[i].value.low
        assert y == x
        return x

    # Check whether the top limb sign is known.
    def is_top_sign_known(self):
        tl = self.limbs[-1].value
        return tl.is_exact() or tl.low >= 0 or tl.high < 0

    # Check whether the top limb is negative. This can work only if the
    # value is exact.
    def is_top_negative(self):
        assert self.is_top_sign_known()
        return self.limbs[-1].value.low < 0

    # Check whether all limbs are zero. This can work only if the value
    # is exact.
    def is_all_zeros(self):
        for t in self.limbs:
            assert t.value.is_exact()
            if t.value.low != 0:
                return False
        return True

    # Get the value of bit j. This can work only if the value is exact.
    # The returned bit value (0 or 1) correspond to bit j%s of limb j/s;
    # the caller should make sure that the value is properly canonicalized.
    def get_bit(self, j):
        s = self.ctx.s
        v = self.limbs[j // s]
        assert v.value.is_exact()
        return (v.value.low >> (j % s)) & 1

    # Get a copy of this value with the additional hypothesis that the
    # top limb is negative; other limbs are unchanged.
    def assume_top_negative(self):
        # Get top limb; if already known to be negative, then this value
        # is fine.
        tl = self.limbs[-1]
        if tl.value.high < 0:
            return self

        # Assuming that the top limb is negative can work only if that limb
        # _can_ be negative.
        assert tl.value.low < 0

        # Set top limb maximum to -1, and recomputed maximum overall value.
        ctx = self.ctx
        s = ctx.s
        k = ctx.k
        d = copy(self.limbs)
        d[-1] = ZWord(ZRange(tl.value.low, -1), tl.container)
        hi = -1
        for i in range(k - 2, -1, -1):
            hi = (hi << s) + d[i].value.high
        v = self.value
        if v.high > hi:
            v = ZRange(v.low, hi)
        return MLInt(ctx, d, v)

    # Get a copy of this value with the additional hypothesis that the
    # top limb is non-negative; other limbs are unchanged.
    def assume_top_nonnegative(self):
        # Get top limb; if already known to be non-negative, then this value
        # is fine.
        tl = self.limbs[-1]
        if tl.value.low >= 0:
            return self

        # Assuming that the top limb is non-negative can work only if that limb
        # _can_ be non-negative.
        assert tl.value.high >= 0

        # Set top limb minimum to 0, and recomputed maximum overall value.
        ctx = self.ctx
        s = ctx.s
        k = ctx.k
        d = copy(self.limbs)
        d[-1] = ZWord(ZRange(0, tl.value.high), tl.container)
        lo = 0
        for i in range(k - 2, -1, -1):
            lo = (lo << s) + d[i].value.low
        v = self.value
        if v.low < lo:
            v = ZRange(lo, v.high)
        return MLInt(ctx, d, v)

# ========================================================================

# Gx*2^270 mod p
curve_Gx = 0x17DDAF71D571985ADCCADDD889441D6EA57F11D76D805E79CC35062A450F0624
# Gy*2^270 mod p
curve_Gy = 0x7FC62ABE1761535E21A237487CC962D2AE390D2A7917377C94D5F3A55582A15C
# n (scalar field modulus)
mod_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
# p (coordinate field modulus)
mod_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

bytecode_str = """
entry:
	# Check that r and s are both non-zero and below n
	_LD _Kr ; _CALL check_scalar
	_LD _Ks ; _CALL check_scalar
	# Invert s. Ks currently contains Mont(s/R) (Montgomery
	# representation of s/R); inversion returns Mont(R/s).
	# Accumulator currently contains s - n = s mod n, which is fine for us.
	_CALL invert_mod ; _ST _Ks
	# Compute u = e/s (canonicalized, into Ke).
	# Since Ke contains Mont(e/R) and we have computed Mont(R/s),
	# a Montgomery multiplication yields Mont((e/R)*(R/s)) = Mont(u),
	# which we can canonicalize.
	_MUL _Ke ; _CALL canonicalize ; inspect_canon_modn_1: _ST _Ke
	# Compute v = r/s (canonicalized, into Ks).
	_LD _Ks ; _MUL _Kr ; _CALL canonicalize ; inspect_canon_modn_2: _ST _Ks

	# We have u and v; we now switch to modulus p for curve computations.
	_MODP
	# Compute Bm = b*2^270 mod p from the generator coordinates. At
	# this point, (Gx,Gy) are still in Montgomery representation.
	#    b = Gy^2 - Gx^3 + 3*Gx
	_LD _Gx ; _MUL _Gx ; _MUL _Gx ; _ST _T0
	_LD _Gy ; _MUL _Gy ; _SUB _T0 ; _ADD _Gx ; _ADD _Gx ; _ADD _Gx
	_ST _Bm

	# Convert (Gx,Gy) out of Montgomery representation (so that
	# (Gx:Gy:1) is a valid triplet).
	_LD _Gx ; _MRED ; _ST _Gx
	_LD _Gy ; _MRED ; _ST _Gy

	# Check that the point in (Qx,Qy) is a valid curve point.
	_CALL check_point

	# Compute W = u*G + v*Q
	# Set work point W to the neutral (0:1:0). Values Wx and Wz were
	# initialized at zero by the interpreter initializatio, so we only
	# need to set Wy to 1.
	_LD _ONE ; _ST _Wy
	# We loop over bits in u and v (high to low).
	_FOR
	# Double W.
	_LD _Wx ; _ST _Hx ; _LD _Wy ; _ST _Hy ; _LD _Wz ; _ST _Hz
	_CALL point_add_to_W
	# Add G if bit i of u is set; u is in Ke
	_LD _Gx ; _ST _Hx ; _LD _Gy ; _ST _Hy ; _LD _ONE ; _ST _Hz
	_SKIPBITZ _Ke ; _CALL point_add_to_W
	# Add Q if bit i of v is set; v is in Ks; Hz still contains 1
	_LD _Qx ; _ST _Hx ; _LD _Qy ; _ST _Hy
	_SKIPBITZ _Ks ; _CALL point_add_to_W
	# Loop until all bits have been processed.
	_NEXT

	# Get x coordinate of point W, canonicalized. For now we suppose
	# the W point is not the point-at-infinity.
	_LD _Wz ; _CALL invert_mod ; _MUL _Wx ; _CALL canonicalize
inspect_canon_modp:

	# Signature is valid if and only if we get back the same value
	# as r, when reduced modulo n. We switch back to computations
	# modulo n, then compute r - x(W) mod n.
	_MODN ; _SUB _Kr
	# To compare with zero, we reduce the value; this entails an
	# extra division by R, but this does not matter since we are
	# only interested in knowing if the value is zero.
	_MRED ; _SKIPNZ ; _OK ; _FAIL

	# If W was the point-at-infinity, then inversion of Wz yielded zero,
	# and the rebuilt x(W) was zero. Since r != 0 (we checked it
	# explicitly), this case implies a signature rejection, which is
	# the correct result.

# BYTECODE: Check that a value (just decoded) is non-zero and less than
# the modulus. This is meant for scalars; it uses the current modulus.
# Input:
#    acc   value to check
# Output:
#    acc   x - m if source value is x and modulus is m
check_scalar:
	_SKIPNZ ; _FAIL ; _SUB _M ; _NORM ; _SKIPNEG ; _FAIL ; _RET

# BYTECODE: Modular inversion. The current modulus is used.
# Input:
#    acc   value to invert
# Output:
#    acc   computed inverse (zero if input is zero)
# Clobbers: T0, T1
invert_mod:
	# Copy source value into T0.
	_ST _T0
	# Set T1 to exponent, which is m-2 (canonical) for modulus m.
	# Subtraction is limb-wise but for the two involved moduli (p and n)
	# this does not overflow any limb, so m-2 is still canonical.
	_LD _M ; _SUB _ONE ; _SUB _ONE
    _SPECIAL_NORM 0     # NORM or no-op, depending on flag spec0
    _ST _T1
	# Set accumulator to source.
	_LD _T0
	# Start iterator and consume first iteration
	_FOR ; _FNEXT
	# Square current value (except on first iteration)
	_MUL 0
	# If current bit is 1, multiply accumulator by operand
	_SKIPBITZ _T1 ; _MUL _T0
	# Loop until finished, then exit
	_NEXT ; _RET

# BYTECODE: Fully reduce a value and return the canonical representation.
# Input is expected in Montgomery representation.
# Input:
#    acc
# Output:
#    acc
# Clobbers: none
canonicalize:
	# Get out of Montgomery representation; this also returns a
	# normalized value whose absolute value is less than m.
	_MRED
    _SPECIAL_NORM 1     # NORM or no-op, depending on flag spec1
	# If the value is non-negative then it's canonical.
	_SKIPNEG ; _RET
	# Add the modulus to get a canonical value.
	_ADD _M ; _NORM ; _RET

# BYTECODE: Check decoded point. This function verifies that the two
# coordinates are in [0,p-1] and that they fulfill the curve equation.
# Input:
#    current modulus MUST be mod_P
#    Qx   candidate x coordinate (affine, non-Montgomery)
#    Qy   candidate y coordinate (affine, non-Montgomery)
# No output. A failure is triggered if the point is incorrect.
# Clobbers: T0, T1, T2
check_point:
	# Check that Qx is lower than p. It was just decoded, and thus
	# we can simply subtract the modulus and check for sign.
	_LD _Qx ; _SUB _M ; _NORM ; _SKIPNEG ; _FAIL
	# While it's loaded in the accumulator, compute X^3 and store
	# it into _T1.
	_MUL _Qx ; _MUL _Qx ; _ST _T1
	# Check that Qy is lower than p (same treatment as Qx).
	_LD _Qy ; _SUB _M ; _NORM ; _SKIPNEG ; _FAIL
	# Compute Y^2 and store it into T2.
	_MUL _Qy ; _ST _T2
	# We use (X:Y:Z) = (x:y:1) as coordinates, but the projective
	# coordinates are supposed to be Montgomery representations, so
	# we really set X = x/R, Y = y/R and Z = 1/R.
	# We must check the curve equation:
	#    Y^2*Z = X^3 - 3*X*Z^2 + b*Z^3
	# which we rewrite as:
	#    ((3*X - b*Z)*Z + Y^2)*Z - X^3 = 0
	# We have b (in Montgomery representation) in constant Bm; each
	# multiplication by Z is a Montgomery reduction.
	_LD _Bm ; _MRED                 # acc <- b*Z
	_SUB _Qx ; _SUB _Qx ; _SUB _Qx  # acc <- b*Z - 3*X
	_MRED                           # acc <- (b*Z - 3*X)*Z
	_SUB _T2                        # acc <- -(((3*X - b*Z)*Z) + Y^2)
	_MRED                           # acc <- -(((3*X - b*Z)*Z) + Y^2)*Z
	_ADD _T1                        # acc <- X^3 - (((3*X - b*Z)*Z) + Y^2)*Z
	_MRED ; _SKIPNZ ; _RET          # success if acc == 0
	_FAIL

# Add a curve point to point W. Point W is in projective coordinates
# in (Wx:Wy:Wz); the other operand is read from (Hx:Hy:Hz).
# Inputs:
#    Wx   first operand X coordinate
#    Wy   first operand Y coordinate
#    Wz   first operand Z coordinate
#    Hx   second operand X coordinate
#    Hy   second operand Y coordinate
#    Hz   second operand Z coordinate
# Output is written back into (Wx:Wy:Wz).
# Clobbers: T0 to T8
point_add_to_W:
	# t0 <- X1 * X2
	_LD _Wx ; _MUL _Hx ; _ST _T0
	# t1 <- Y1 * Y2
	_LD _Wy ; _MUL _Hy ; _ST _T1
	# t2 <- Z1 * Z2
	# t7 <- bb * t2
	_LD _Wz ; _MUL _Hz ; _ST _T2 ; _MUL _Bm ; _ST _T7

	# t3 <- (X1 + Y1)*(X2 + Y2) - t0 - t1
	_LD _Wx ; _ADD _Wy ; _ST _T3
	_LD _Hx ; _ADD _Hy ; _MUL _T3 ; _SUB _T0 ; _SUB _T1 ; _ST _T3

	# t6 <- (X1 + Z1)*(X2 + Z2) - t0 - t2
	_LD _Wx ; _ADD _Wz ; _ST _T6
	_LD _Hx ; _ADD _Hz ; _MUL _T6 ; _SUB _T0 ; _SUB _T2 ; _ST _T6
	# t6 is still in acc
	# t5 <- t1 + 3*(t6 - t7)
	# t7 <- t1 - 3*(t6 - t7)
	_SUB _T7 ; _ST _T5 ; _ADD 0 ; _ADD _T5   # acc <- 3*(t6 - t7)
	_ST _T7 ; _ADD _T1 ; _ST _T5
	_LD _T1 ; _SUB _T7 ; _ST _T7

	# t8 <- 3*t2
	_LD _T2 ; _ADD 0 ; _ADD _T2 ; _ST _T8

	# t6 <- 3*(b*t6 - t0 - t8)
	_LD _T6 ; _MUL _Bm ; _SUB _T0 ; _SUB _T8 ; _ST _T6
	_ADD 0 ; _ADD _T6 ; _ST _T6

	# t4 <- (Y1 + Z1)*(Y2 + Z2) - t1 - t2
	_LD _Wy ; _ADD _Wz ; _ST _T4
	_LD _Hy ; _ADD _Hz ; _MUL _T4 ; _SUB _T1 ; _SUB _T2 ; _ST _T4
	# t4 is still in acc
	# X1 <- t3*t5 - t4*t6
	_MUL _T6 ; _ST _Wx
	_LD _T3 ; _MUL _T5 ; _SUB _Wx ; _ST _Wx

	# t0 <- 3*t0 - t8
	_LD _T0 ; _ADD 0 ; _ADD _T0 ; _SUB _T8 ; _ST _T0
	# t0 is still in acc
	# Y1 <- t0*t6 + t5*t7
	_MUL _T6 ; _ST _Wy ; _LD _T5
    _SPECIAL_NORM 2     # NORM or no-op, depending on flag spec2
    _MUL _T7 ; _ADD _Wy ; _ST _Wy

	# Z1 <- t4*t7 + t3*t0
	_LD _T4 ; _MUL _T7 ; _ST _Wz
	_LD _T3 ; _MUL _T0 ; _ADD _Wz ; _ST _Wz

inspect_point_add_to_W:
	_RET
"""

# Parse next token from source string s, starting at index j. Returned values
# are the parsed token (a string) and the new value of j. If no token is
# found then this function returns (None, len(s)).
def next_token(s, j):
    n = len(s)
    while j < n:
        x = ord(s[j])
        if x >= 0x21:
            break
        j += 1
    if j >= n:
        return (None, n)
    if s[j] == ';':
        return (';', j + 1)
    if s[j] == ':':
        return (':', j + 1)
    i = j
    while j < n:
        x = ord(s[j])
        if not((x >= 0x30 and x <= 0x39) or (x >= 0x41 and x <= 0x5A) or (x == 0x5F) or (x >= 0x61 and x <= 0x7A)):
            break
        j += 1
    if i == j:
        raise Exception('unexpected character: "%s"' % s[i])
    return (s[i:j], j)

bytecode_constants = {
    '_M':     1,   # current modulus
    '_ONE':   2,   # constant one
    '_ZERO': 28,   # constant zero
    '_Bm':   29,   # constant Bm (curve param b, Montgomery repr.)
    '_Gx':   30,   # constant Gx (x coordinate of generator)
    '_Gy':   31,   # constant Gy (y coordinate of generator)
    '_T0':   16,   # temporary 0
    '_T1':   17,   # temporary 1
    '_T2':   18,   # temporary 2
    '_T3':   19,   # temporary 3
    '_T4':   20,   # temporary 4
    '_T5':   21,   # temporary 5
    '_T6':   22,   # temporary 6
    '_T7':   23,   # temporary 7
    '_T8':   24,   # temporary 8
    '_T9':   25,   # temporary 9
    '_Kr':    3,   # r (first signature half)
    '_Ks':    4,   # s (second signature half)
    '_Ke':    5,   # e (reduced hash value)
    '_Qx':    6,   # Qx (x coordinate of public key)
    '_Qy':    7,   # Qy (y coordinate of public key)
    '_Wx':    8,   # Wx (X coordinate of work point W)
    '_Wy':    9,   # Wy (Y coordinate of work point W)
    '_Wz':   10,   # Wz (Z coordinate of work point W)
    '_Hx':   11,   # Hx (X coordinate of second point operand)
    '_Hy':   12,   # Hy (Y coordinate of second point operand)
    '_Hz':   13,   # Hz (Z coordinate of second point operand)
}

# Parse a numerical argument, which is either an integer in the 0..31 range,
# or a symbolic value. Parsing starts at index j. Returned value is (x, j)
# with x the parsed integer value, and j the updated scan index.
def parse_argument(s, j):
    (t, j) = next_token(s, j)
    if t is None:
        raise Exception('missing instruction argument')
    x = bytecode_constants.get(t)
    if x is None:
        x = int(t)
        if x < 0 or x > 31:
            raise Exception('integer argument is out of range: %d' % x)
    return (x, j)

# Parse the bytecode into the appropriate internal representation.
# Returned value is (code, labels):
#   code     list of individual opcodes
#   labels   map of label name to offset within code[]
def parse_bytecode(src):
    code = []
    labels = {}
    linenum = 0
    for line in src.splitlines():
        linenum += 1
        # Remove comments
        s = line
        j = s.find('#')
        if j >= 0:
            s = s[0:j]
        j = 0
        while True:
            (t, j) = next_token(s, j)
            if t is None:
                # Line is finished
                break
            if t == ';':
                # ';' is an accepted instruction separator
                continue
            match t:
                case '_LD':
                    (x, j) = parse_argument(s, j)
                    op = OpLD(x)
                case '_ST':
                    (x, j) = parse_argument(s, j)
                    op = OpST(x)
                case '_ADD':
                    (x, j) = parse_argument(s, j)
                    op = OpADD(x)
                case '_SUB':
                    (x, j) = parse_argument(s, j)
                    op = OpSUB(x)
                case '_SMOD':
                    (x, j) = parse_argument(s, j)
                    op = OpSMOD(x)
                case '_MUL':
                    (x, j) = parse_argument(s, j)
                    op = OpMUL(x)
                case '_SKIPBITZ':
                    (x, j) = parse_argument(s, j)
                    op = OpSKIPBITZ(x)
                case '_SKIPNZ':
                    op = OpSKIPNZ()
                case '_SKIPNEG':
                    op = OpSKIPNEG()
                case '_FNEXT':
                    op = OpFNEXT()
                case '_RET':
                    op = OpRET()
                case '_FOR':
                    op = OpFOR()
                case '_NEXT':
                    op = OpNEXT()
                case '_OK':
                    op = OpOK()
                case '_FAIL':
                    op = OpFAIL()
                case '_NORM':
                    op = OpNORM()
                case '_SPECIAL_NORM':
                    (x, j) = parse_argument(s, j)
                    op = OpSPECIAL_NORM(x)
                case '_CALL':
                    (t, j) = next_token(s, j)
                    if t is None:
                        raise Exception('missing _CALL argument')
                    op = OpCALL_UNRESOLVED(t)
                case '_MRED':
                    op = OpMUL(bytecode_constants['_ONE'])
                case '_MODN':
                    op = OpSMOD(26)
                case '_MODP':
                    op = OpSMOD(27)
                case _:
                    # This may be a label definition.
                    (u, j) = next_token(s, j)
                    if u is None:
                        raise Exception('unexpected end of line')
                    if u != ':':
                        raise Exception('missing colon after label "%s"' % t)
                    if t in labels:
                        raise Exception('duplicate label "%s"' % t)
                    labels[t] = len(code)
                    continue
            op.linenum = linenum
            code.append(op)
    # Resolve calls.
    for i in range(0, len(code)):
        if type(code[i]) is OpCALL_UNRESOLVED:
            t = labels.get(code[i].target)
            if t is None:
                raise Exception('call to inexistent label "%s"' % t)
            code[i] = OpCALL(t)

    return (code, labels)

# RunState is a structure that contains the VM state at a specific point
# of the execution.
# Instances are meant to be immutable; each instruction creates its output
# state as a modified clone of its input state.
#
# The state contains the following values:
#    ctx      context for MLInt computations
#    modn     modulus n (scalar field modulus)
#    modp     modulus p (coordinate field modulus)
#    acc      accumulator (MLInt)
#    val[]    values 1..31 (value i is in val[i-1], val[0] is modulus)
#    exit     exit status (-1 = ok, 1 = error, 0 = no exit)
#    addr     current loop address
#    count    current loop counter (255 to 0)
#    code     currently executed bytecode (array of opcodes)
#    ip       instruction pointer (int)
#    calls    saved instruction pointers (int[])
#    fstate   merged function output state (for conditional RETs), or None
#    spec     special flags (bit j is set for flag j)
class RunState:
    def __init__(self, code, k, s, w, sh1=-1, slf=False, slv=False, slm=False):
        ctx = MLIntContext(k, s, w, sh1, slf, slv)
        self.ctx = ctx
        self.modn = MLIntModulus(ctx, ZRange.exact(mod_N), slm)
        self.modp = MLIntModulus(ctx, ZRange.exact(mod_P), slm)
        # Value 0 (accumulator) is kept as a separate variable so that most
        # operations do not have to clone the array of values.
        self.acc = ctx.ZERO
        # Value 1 is the current modulus (default is n).
        self.mod = self.modn
        # Value i = 2..31 is in val[i - 2].
        # Value 2 is ONE.
        # Values 30 and 31 receive Gx and Gy (in Montgomery representation
        # at this point).
        gx = ctx.decode_int(ZRange.exact(curve_Gx), slv)
        gy = ctx.decode_int(ZRange.exact(curve_Gy), slv)
        self.val = [ctx.ONE] + [ctx.ZERO]*27 + [gx, gy]
        self.exit = 0
        self.addr = 0
        self.count = 0
        self.code = code
        self.ip = 0
        self.calls = []
        self.spec = 0

    # Clone this state into an independent instance; the clone's 'calls'
    # stack is emptied.
    def clone(self):
        state = copy(self)
        state.val = copy(state.val)
        state.calls = []
        return state

    # Merge the ranges from the provided state into this object. This
    # instance is modified.
    def merge(self, state):
        if self.addr != state.addr or self.count != state.count:
            raise Exception('invalid state merging: different loop states')
        if self.mod != state.mod:
            raise Exception('invalid state merging: different moduli')
        self.acc = self.acc.union(state.acc)
        for i in range(0, 30):
            self.val[i] = self.val[i].union(state.val[i])

    # Replace the ranges in this object by copying the ranges from the
    # provided state. This instance is modified.
    def replace(self, state):
        if self.addr != state.addr or self.count != state.count:
            raise Exception('invalid state merging: different loop states')
        if self.mod != state.mod:
            raise Exception('invalid state merging: different moduli')
        self.acc = state.acc
        for i in range(0, 30):
            self.val[i] = state.val[i]

    # Get the contents of a given value i (0 to 31).
    def get_value(self, i):
        if i == 0:
            return self.acc
        if i == 1:
            return self.mod.m
        assert i >= 2 and i <= 31
        return self.val[i - 2]

    # Set the value i (0, or 2 to 31) to the value v.
    def set_value(self, i, v):
        if i == 0:
            self.acc = v
        elif i >= 2 and i <= 31:
            self.val[i - 2] = v
        else:
            raise Exception('invalid store targt value: %d' % i)

    # Like set_value(), except that the value is provided as a plain integer,
    # which is internally decoded.
    def set_zint(self, i, x, slx=False):
        v = self.ctx.decode_int(x, slx)
        self.set_value(i, v)

# Each instruction has a run() method which receives the current state,
# and should return the new state resulting from the execution of the
# instruction.

class OpLD:
    def __init__(self, arg):
        self.arg = arg

    def __str__(self):
        return 'LD %d' % self.arg

    def run(self, state):
        state.acc = state.get_value(self.arg)

class OpST:
    def __init__(self, arg):
        if arg == 0:
            raise Exception('invalid store to self (value 0)')
        if arg == 1:
            raise Exception('invalid store to modulus (value 1)')
        self.arg = arg

    def __str__(self):
        return 'ST %d' % self.arg

    def run(self, state):
        state.set_value(self.arg, state.acc)

class OpADD:
    def __init__(self, arg):
        self.arg = arg

    def __str__(self):
        return 'ADD %d' % self.arg

    def run(self, state):
        state.acc += state.get_value(self.arg)

class OpSUB:
    def __init__(self, arg):
        self.arg = arg

    def __str__(self):
        return 'SUB %d' % self.arg

    def run(self, state):
        state.acc -= state.get_value(self.arg)

class OpSMOD:
    def __init__(self, arg):
        if arg != 26 and arg != 27:
            raise Exception('invalid SMOD argument: %d' % arg)
        self.arg = arg

    def __str__(self):
        if self.arg == 26:
            return 'MODN'
        else:
            return 'MODP'

    def run(self, state):
        # Current modulus is in value 1, which is located in val[0].
        if self.arg == 26:
            state.mod = state.modn
        else:
            state.mod = state.modp

class OpMUL:
    def __init__(self, arg):
        self.arg = arg

    def __str__(self):
        return 'MUL %d' % self.arg

    def run(self, state):
        state.acc = state.acc.montymul(state.get_value(self.arg), state.mod)

# Shared routine: run the code in the next instruction, then merge the
# resulting state (if not exiting) into the current state, to account for
# the conditional skip.
def do_skipcond(state, skipneg=False):
    # Get next instruction.
    op = state.code[state.ip]
    state.ip += 1

    # Treatment depends on the conditionally skipped opcode.
    # Skipping a FOR, NEXT, FNEXT, or another skip is not supported.
    if (type(op) is OpFNEXT) or (type(op) is OpNEXT):
        raise Exception('unsupported: skip of (F)NEXT')
    if (type(op) is OpSKIPBITZ) or (type(op) is OpSKIPNZ) or (type(op) is OpSKIPNEG):
        raise Exception('unsupported: skip of skip')

    # Skipping a CALL is done by calling the function in a separate loop,
    # and merging the output.
    if type(op) is OpCALL:
        nstate = state.clone()
        # TODO: apply inspector on sub-call?
        if run_code(nstate, op.off, True) == 0:
            # Called function may return: merge its output into the state.
            state.merge(nstate)
        return

    # OK or FAIL are ignored (since we are working on inexact values, we
    # cannot decide whether the instruction is executed or not, but either
    # way they do not change the current state).
    if (type(op) is OpOK) or (type(op) is OpFAIL):
        return

    # State clone for the "no skip" branch (conditional instruction is
    # executed).
    state_noskip = state.clone()

    # For a SKIPNEG, we can reduce the ranges for the accumulator into
    # both branches (this treatment is needed to prove that canonicalization
    # works).
    if skipneg:
        state.acc = state.acc.assume_top_negative()
        state_noskip.acc = state_noskip.acc.assume_top_nonnegative()

    # Conditionally skipping a RET is done with merging into fstate.
    if type(op) is OpRET:
        if len(state.calls) == 0:
            raise Exception('unmatched RET')
        (ip, fstate) = state.calls[-1]
        if fstate is None:
            state.calls.pop()
            state.calls.append((ip, state_noskip))
        else:
            fstate.merge(state_noskip)
        return

    # Next instruction is not a RET or an unsupported instruction. We
    # run it provisionally.
    op.run(state_noskip)
    state.merge(state_noskip)

class OpSKIPBITZ:
    def __init__(self, arg):
        self.arg = arg

    def __str__(self):
        return 'SKIPBITZ %d' % self.arg

    def run(self, state):
        u = state.get_value(self.arg)
        if u.is_exact():
            # Value is exact, so we can skip or not skip the next value
            # depending on the bit value.
            if u.get_bit(state.count) == 0:
                state.ip += 1
        else:
            # Value is not exact, so we execute _both_ branches and merge
            # the output ranges.
            do_skipcond(state)

class OpSKIPNZ:
    def __init__(self):
        pass

    def __str__(self):
        return 'SKIPNZ'

    def run(self, state):
        if state.acc.is_exact():
            if not(state.acc.is_all_zeros()):
                state.ip += 1
        else:
            do_skipcond(state)

class OpSKIPNEG:
    def __init__(self):
        pass

    def __str__(self):
        return 'SKIPNEG'

    def run(self, state):
        # If the top limb sign is known then we can exectue the skip.
        if state.acc.is_top_sign_known():
            if state.acc.is_top_negative():
                state.ip += 1
            return
        # The skip is really conditional. However, we can still propagate
        # the knowledge of the sign into both branches.
        do_skipcond(state, skipneg=True)

class OpFNEXT:
    def __init__(self):
        pass

    def __str__(self):
        return 'FNEXT'

    def run(self, state):
        if state.count == 255:
            state.count -= 1
            state.ip = state.addr

class OpRET:
    def __init__(self):
        pass

    def __str__(self):
        return 'RET'

    def run(self, state):
        if len(state.calls) == 0:
            raise Exception('unmatched RET')
        (ip, fstate) = state.calls.pop()
        if not(fstate is None):
            state.merge(fstate)
        state.ip = ip

class OpFOR:
    def __init__(self):
        pass

    def __str__(self):
        return 'FOR'

    def run(self, state):
        if state.count != 0:
            raise Exception('nested loops')
        state.count = 255
        state.addr = state.ip

class OpNEXT:
    def __init__(self):
        pass

    def __str__(self):
        return 'NEXT'

    def run(self, state):
        if state.count != 0:
            state.count -= 1
            state.ip = state.addr

def do_exit(state, ok):
    if len(state.calls) > 0:
        (ip, fstate) = state.calls[-1]
        if not(fstate is None):
            # We have some dangling conditional RET, so this exit instruction
            # is not necessarily reached; instead, we assume that the previous
            # RET was in fact executed.
            state.calls.pop()
            state.replace(fstate)
            state.ip = ip
            return
    if ok:
        state.exit = -1
    else:
        state.exit = 1

class OpOK:
    def __init__(self):
        pass

    def __str__(self):
        return 'OK'

    def run(self, state):
        do_exit(state, True)

class OpFAIL:
    def __init__(self):
        pass

    def __str__(self):
        return 'FAIL'

    def run(self, state):
        do_exit(state, False)

class OpNORM:
    def __init__(self):
        pass

    def __str__(self):
        return 'NORM'

    def run(self, state):
        state.acc = state.acc.normalize_unsigned()

class OpSPECIAL_NORM:
    def __init__(self, arg):
        self.arg = arg
        self.mask = 1 << arg

    def __str__(self):
        return 'SPECIAL_NORM %d' % self.arg

    def run(self, state):
        # "SPECIAL_NORM" is a "NORM" if the implementation uses signed
        # normalization (slv=True); otherwise, it's a no-op.
        if (self.mask & state.spec) != 0:
            state.acc = state.acc.normalize_unsigned()

class OpCALL_UNRESOLVED:
    def __init__(self, target):
        self.target = target

    def __str__(self):
        return 'CALL (UNRESOLVED, target=%s)' % self.target

    def run(self, state):
        raise Exception("CALL to unresolved target '%s'" % self.target)

class OpCALL:
    def __init__(self, off):
        self.off = off

    def __str__(self):
        return 'CALL [%d]' % self.off

    def run(self, state):
        state.calls.append((state.ip, None))
        state.ip = self.off

# Run the provided function until the matching RET is reached, or an
# exit instruction is executed. If is_function is False, then the call is
# for the entire bytecode, and reaching a RET triggers an error.
# Returned value is 0 if the RET was reached, or a non-zero value if
# an exit instruction was reached.
def run_code(state, ip, is_function, inspector=None):
    state.ip = ip
    if is_function:
        state.calls.append((-1, None))
    this_ip = ip
    try:
        while state.ip >= 0:
            this_ip = state.ip
            if not(inspector is None):
                f = inspector.get(this_ip)
                if not(f is None):
                    f(state)
            op = state.code[this_ip]
            state.ip += 1
            op.run(state)
            if state.exit != 0:
                return state.exit
    except:
        op = state.code[this_ip]
        if hasattr(op, 'linenum'):
            linenum = op.linenum
            print('<current IP = %d [line %d]: %s>' % (this_ip, linenum, op))
        else:
            print('<current IP = %d: %s>' % (this_ip, op))
        raise
    return 0

(bytecode, labels) = parse_bytecode(bytecode_str)

# ========================================================================

import hashlib

# Each group of five values is:
#   test identifer (symbolic string)
#   public key (up to 65 bytes) (correct size is 65)
#   message (up to 20 bytes)
#   signature (up to 82 bytes) (correct size is 64)
#   validity (G for "good", F for "failed")
# All tests use SHA-256 as hash function.
# There are 492 test vectors in total.
KAT_ECDSA_P256_SHA256_VERIFY = [
	# From Wycheproof: https://github.com/C2SP/wycheproof/
	# Vectors are:
	#  - testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json, as of
	#    commit e0df04e0c033f2d25c5051dd06230336c7822358 (2025-10-07).
	#  - testvectors_v1/ecdsa_secp256r1_sha256_test.json, as of
	#    commit 0fd0ec1cf2114f456f5c3e7c61ba807fb1311b45 (2026-01-19).
	# In the latter file, about half of the tests are about ASN.1/DER
	# encoding of the signature. Since this implementation uses the
	# "p1363" encoding (r and s in unsigned big-endian, 32 bytes each,
	# concatenated), all signatures have been reencoded in the p1363
	# format, and tests that exercise specific DER misencodings have
	# been removed.

	# ecdsa_secp256r1_sha256_p1363_test.json - 1
	"ecdsa_secp256r1_sha256_p1363_test.json - 1",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 2
	"ecdsa_secp256r1_sha256_p1363_test.json - 2",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"012ba3a8bd6b94d5ed80a6d9d1190a436ebccc0833490686deac8635bcb9bf536900b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 3
	"ecdsa_secp256r1_sha256_p1363_test.json - 3",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"01002ba3a7be6b94d6ec80a6d9d1190a432be6dfbb2cb98d6d4d72972df620817f180000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 4
	"ecdsa_secp256r1_sha256_p1363_test.json - 4",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 5
	"ecdsa_secp256r1_sha256_p1363_test.json - 5",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"012ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e1800b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 6
	"ecdsa_secp256r1_sha256_p1363_test.json - 6",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0100000000000000002ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18000000000000000000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 7
	"ecdsa_secp256r1_sha256_p1363_test.json - 7",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"01b329f478a2bbd0a6c384ee1493b1f518276e0e4a5375928d6fcd160c11cb6d2c00b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 8
	"ecdsa_secp256r1_sha256_p1363_test.json - 8",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0100b329f379a2bbd1a5c384ee1493b1f4d55181c143c3fc78fc35de0e45788d98db0000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 9
	"ecdsa_secp256r1_sha256_p1363_test.json - 9",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"01b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db00b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 10
	"ecdsa_secp256r1_sha256_p1363_test.json - 10",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"010000000000000000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db000000000000000000b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 11
	"ecdsa_secp256r1_sha256_p1363_test.json - 11",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 12
	"ecdsa_secp256r1_sha256_p1363_test.json - 12",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 13
	"ecdsa_secp256r1_sha256_p1363_test.json - 13",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 14
	"ecdsa_secp256r1_sha256_p1363_test.json - 14",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 15
	"ecdsa_secp256r1_sha256_p1363_test.json - 15",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 16
	"ecdsa_secp256r1_sha256_p1363_test.json - 16",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 17
	"ecdsa_secp256r1_sha256_p1363_test.json - 17",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 18
	"ecdsa_secp256r1_sha256_p1363_test.json - 18",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 19
	"ecdsa_secp256r1_sha256_p1363_test.json - 19",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 20
	"ecdsa_secp256r1_sha256_p1363_test.json - 20",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 21
	"ecdsa_secp256r1_sha256_p1363_test.json - 21",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 22
	"ecdsa_secp256r1_sha256_p1363_test.json - 22",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 23
	"ecdsa_secp256r1_sha256_p1363_test.json - 23",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 24
	"ecdsa_secp256r1_sha256_p1363_test.json - 24",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 25
	"ecdsa_secp256r1_sha256_p1363_test.json - 25",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 26
	"ecdsa_secp256r1_sha256_p1363_test.json - 26",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 27
	"ecdsa_secp256r1_sha256_p1363_test.json - 27",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 28
	"ecdsa_secp256r1_sha256_p1363_test.json - 28",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 29
	"ecdsa_secp256r1_sha256_p1363_test.json - 29",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 30
	"ecdsa_secp256r1_sha256_p1363_test.json - 30",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 31
	"ecdsa_secp256r1_sha256_p1363_test.json - 31",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 32
	"ecdsa_secp256r1_sha256_p1363_test.json - 32",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325500000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 33
	"ecdsa_secp256r1_sha256_p1363_test.json - 33",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325500000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 34
	"ecdsa_secp256r1_sha256_p1363_test.json - 34",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 35
	"ecdsa_secp256r1_sha256_p1363_test.json - 35",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 36
	"ecdsa_secp256r1_sha256_p1363_test.json - 36",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 37
	"ecdsa_secp256r1_sha256_p1363_test.json - 37",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 38
	"ecdsa_secp256r1_sha256_p1363_test.json - 38",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 39
	"ecdsa_secp256r1_sha256_p1363_test.json - 39",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325520000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 40
	"ecdsa_secp256r1_sha256_p1363_test.json - 40",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325520000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 41
	"ecdsa_secp256r1_sha256_p1363_test.json - 41",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 42
	"ecdsa_secp256r1_sha256_p1363_test.json - 42",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 43
	"ecdsa_secp256r1_sha256_p1363_test.json - 43",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 44
	"ecdsa_secp256r1_sha256_p1363_test.json - 44",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 45
	"ecdsa_secp256r1_sha256_p1363_test.json - 45",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 46
	"ecdsa_secp256r1_sha256_p1363_test.json - 46",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 47
	"ecdsa_secp256r1_sha256_p1363_test.json - 47",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 48
	"ecdsa_secp256r1_sha256_p1363_test.json - 48",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 49
	"ecdsa_secp256r1_sha256_p1363_test.json - 49",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 50
	"ecdsa_secp256r1_sha256_p1363_test.json - 50",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 51
	"ecdsa_secp256r1_sha256_p1363_test.json - 51",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 52
	"ecdsa_secp256r1_sha256_p1363_test.json - 52",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 53
	"ecdsa_secp256r1_sha256_p1363_test.json - 53",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff000000010000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 54
	"ecdsa_secp256r1_sha256_p1363_test.json - 54",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff000000010000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 55
	"ecdsa_secp256r1_sha256_p1363_test.json - 55",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 56
	"ecdsa_secp256r1_sha256_p1363_test.json - 56",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 57
	"ecdsa_secp256r1_sha256_p1363_test.json - 57",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 58
	"ecdsa_secp256r1_sha256_p1363_test.json - 58",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 59
	"ecdsa_secp256r1_sha256_p1363_test.json - 59",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 60
	"ecdsa_secp256r1_sha256_p1363_test.json - 60",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3639383139",
	"64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e6af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 61
	"ecdsa_secp256r1_sha256_p1363_test.json - 61",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"343236343739373234",
	"16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 62
	"ecdsa_secp256r1_sha256_p1363_test.json - 62",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"37313338363834383931",
	"9cc98be2347d469bf476dfc26b9b733df2d26d6ef524af917c665baccb23c882093496459effe2d8d70727b82462f61d0ec1b7847929d10ea631dacb16b56c32",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 63
	"ecdsa_secp256r1_sha256_p1363_test.json - 63",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130333539333331363638",
	"73b3c90ecd390028058164524dde892703dce3dea0d53fa8093999f07ab8aa432f67b0b8e20636695bb7d8bf0a651c802ed25a395387b5f4188c0c4075c88634",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 64
	"ecdsa_secp256r1_sha256_p1363_test.json - 64",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33393439343031323135",
	"bfab3098252847b328fadf2f89b95c851a7f0eb390763378f37e90119d5ba3ddbdd64e234e832b1067c2d058ccb44d978195ccebb65c2aaf1e2da9b8b4987e3b",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 65
	"ecdsa_secp256r1_sha256_p1363_test.json - 65",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31333434323933303739",
	"204a9784074b246d8bf8bf04a4ceb1c1f1c9aaab168b1596d17093c5cd21d2cd51cce41670636783dc06a759c8847868a406c2506fe17975582fe648d1d88b52",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 66
	"ecdsa_secp256r1_sha256_p1363_test.json - 66",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33373036323131373132",
	"ed66dc34f551ac82f63d4aa4f81fe2cb0031a91d1314f835027bca0f1ceeaa0399ca123aa09b13cd194a422e18d5fda167623c3f6e5d4d6abb8953d67c0c48c7",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 67
	"ecdsa_secp256r1_sha256_p1363_test.json - 67",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"333433363838373132",
	"060b700bef665c68899d44f2356a578d126b062023ccc3c056bf0f60a237012b8d186c027832965f4fcc78a3366ca95dedbb410cbef3f26d6be5d581c11d3610",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 68
	"ecdsa_secp256r1_sha256_p1363_test.json - 68",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31333531353330333730",
	"9f6adfe8d5eb5b2c24d7aa7934b6cf29c93ea76cd313c9132bb0c8e38c96831db26a9c9e40e55ee0890c944cf271756c906a33e66b5bd15e051593883b5e9902",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 69
	"ecdsa_secp256r1_sha256_p1363_test.json - 69",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"36353533323033313236",
	"a1af03ca91677b673ad2f33615e56174a1abf6da168cebfa8868f4ba273f16b720aa73ffe48afa6435cd258b173d0c2377d69022e7d098d75caf24c8c5e06b1c",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 70
	"ecdsa_secp256r1_sha256_p1363_test.json - 70",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31353634333436363033",
	"fdc70602766f8eed11a6c99a71c973d5659355507b843da6e327a28c11893db93df5349688a085b137b1eacf456a9e9e0f6d15ec0078ca60a7f83f2b10d21350",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 71
	"ecdsa_secp256r1_sha256_p1363_test.json - 71",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"34343239353339313137",
	"b516a314f2fce530d6537f6a6c49966c23456f63c643cf8e0dc738f7b876e675d39ffd033c92b6d717dd536fbc5efdf1967c4bd80954479ba66b0120cd16fff2",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 72
	"ecdsa_secp256r1_sha256_p1363_test.json - 72",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130393533323631333531",
	"3b2cbf046eac45842ecb7984d475831582717bebb6492fd0a485c101e29ff0a84c9b7b47a98b0f82de512bc9313aaf51701099cac5f76e68c8595fc1c1d99258",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 73
	"ecdsa_secp256r1_sha256_p1363_test.json - 73",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"35393837333530303431",
	"30c87d35e636f540841f14af54e2f9edd79d0312cfa1ab656c3fb15bfde48dcf47c15a5a82d24b75c85a692bd6ecafeb71409ede23efd08e0db9abf6340677ed",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 74
	"ecdsa_secp256r1_sha256_p1363_test.json - 74",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33343633303036383738",
	"38686ff0fda2cef6bc43b58cfe6647b9e2e8176d168dec3c68ff262113760f52067ec3b651f422669601662167fa8717e976e2db5e6a4cf7c2ddabb3fde9d67d",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 75
	"ecdsa_secp256r1_sha256_p1363_test.json - 75",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"39383137333230323837",
	"44a3e23bf314f2b344fc25c7f2de8b6af3e17d27f5ee844b225985ab6e2775cf2d48e223205e98041ddc87be532abed584f0411f5729500493c9cc3f4dd15e86",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 76
	"ecdsa_secp256r1_sha256_p1363_test.json - 76",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33323232303431303436",
	"2ded5b7ec8e90e7bf11f967a3d95110c41b99db3b5aa8d330eb9d638781688e97d5792c53628155e1bfc46fb1a67e3088de049c328ae1f44ec69238a009808f9",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 77
	"ecdsa_secp256r1_sha256_p1363_test.json - 77",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"36363636333037313034",
	"bdae7bcb580bf335efd3bc3d31870f923eaccafcd40ec2f605976f15137d8b8ff6dfa12f19e525270b0106eecfe257499f373a4fb318994f24838122ce7ec3c7",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 78
	"ecdsa_secp256r1_sha256_p1363_test.json - 78",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31303335393531383938",
	"50f9c4f0cd6940e162720957ffff513799209b78596956d21ece251c2401f1c6d7033a0a787d338e889defaaabb106b95a4355e411a59c32aa5167dfab244726",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 79
	"ecdsa_secp256r1_sha256_p1363_test.json - 79",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31383436353937313935",
	"f612820687604fa01906066a378d67540982e29575d019aabe90924ead5c860d3f9367702dd7dd4f75ea98afd20e328a1a99f4857b316525328230ce294b0fef",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 80
	"ecdsa_secp256r1_sha256_p1363_test.json - 80",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33313336303436313839",
	"9505e407657d6e8bc93db5da7aa6f5081f61980c1949f56b0f2f507da5782a7ac60d31904e3669738ffbeccab6c3656c08e0ed5cb92b3cfa5e7f71784f9c5021",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 81
	"ecdsa_secp256r1_sha256_p1363_test.json - 81",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"32363633373834323534",
	"bbd16fbbb656b6d0d83e6a7787cd691b08735aed371732723e1c68a40404517d9d8e35dba96028b7787d91315be675877d2d097be5e8ee34560e3e7fd25c0f00",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 82
	"ecdsa_secp256r1_sha256_p1363_test.json - 82",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31363532313030353234",
	"2ec9760122db98fd06ea76848d35a6da442d2ceef7559a30cf57c61e92df327e7ab271da90859479701fccf86e462ee3393fb6814c27b760c4963625c0a19878",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 83
	"ecdsa_secp256r1_sha256_p1363_test.json - 83",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"35373438303831363936",
	"54e76b7683b6650baa6a7fc49b1c51eed9ba9dd463221f7a4f1005a89fe00c592ea076886c773eb937ec1cc8374b7915cfd11b1c1ae1166152f2f7806a31c8fd",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 84
	"ecdsa_secp256r1_sha256_p1363_test.json - 84",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"36333433393133343638",
	"5291deaf24659ffbbce6e3c26f6021097a74abdbb69be4fb10419c0c496c946665d6fcf336d27cc7cdb982bb4e4ecef5827f84742f29f10abf83469270a03dc3",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 85
	"ecdsa_secp256r1_sha256_p1363_test.json - 85",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31353431313033353938",
	"207a3241812d75d947419dc58efb05e8003b33fc17eb50f9d15166a88479f107cdee749f2e492b213ce80b32d0574f62f1c5d70793cf55e382d5caadf7592767",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 86
	"ecdsa_secp256r1_sha256_p1363_test.json - 86",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130343738353830313238",
	"6554e49f82a855204328ac94913bf01bbe84437a355a0a37c0dee3cf81aa7728aea00de2507ddaf5c94e1e126980d3df16250a2eaebc8be486effe7f22b4f929",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 87
	"ecdsa_secp256r1_sha256_p1363_test.json - 87",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130353336323835353638",
	"a54c5062648339d2bff06f71c88216c26c6e19b4d80a8c602990ac82707efdfce99bbe7fcfafae3e69fd016777517aa01056317f467ad09aff09be73c9731b0d",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 88
	"ecdsa_secp256r1_sha256_p1363_test.json - 88",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"393533393034313035",
	"975bd7157a8d363b309f1f444012b1a1d23096593133e71b4ca8b059cff37eaf7faa7a28b1c822baa241793f2abc930bd4c69840fe090f2aacc46786bf919622",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 89
	"ecdsa_secp256r1_sha256_p1363_test.json - 89",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"393738383438303339",
	"5694a6f84b8f875c276afd2ebcfe4d61de9ec90305afb1357b95b3e0da43885e0dffad9ffd0b757d8051dec02ebdf70d8ee2dc5c7870c0823b6ccc7c679cbaa4",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 90
	"ecdsa_secp256r1_sha256_p1363_test.json - 90",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33363130363732343432",
	"a0c30e8026fdb2b4b4968a27d16a6d08f7098f1a98d21620d7454ba9790f1ba65e470453a8a399f15baf463f9deceb53acc5ca64459149688bd2760c65424339",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 91
	"ecdsa_secp256r1_sha256_p1363_test.json - 91",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31303534323430373035",
	"614ea84acf736527dd73602cd4bb4eea1dfebebd5ad8aca52aa0228cf7b99a88737cc85f5f2d2f60d1b8183f3ed490e4de14368e96a9482c2a4dd193195c902f",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 92
	"ecdsa_secp256r1_sha256_p1363_test.json - 92",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"35313734343438313937",
	"bead6734ebe44b810d3fb2ea00b1732945377338febfd439a8d74dfbd0f942fa6bb18eae36616a7d3cad35919fd21a8af4bbe7a10f73b3e036a46b103ef56e2a",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 93
	"ecdsa_secp256r1_sha256_p1363_test.json - 93",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31393637353631323531",
	"499625479e161dacd4db9d9ce64854c98d922cbf212703e9654fae182df9bad242c177cf37b8193a0131108d97819edd9439936028864ac195b64fca76d9d693",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 94
	"ecdsa_secp256r1_sha256_p1363_test.json - 94",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33343437323533333433",
	"08f16b8093a8fb4d66a2c8065b541b3d31e3bfe694f6b89c50fb1aaa6ff6c9b29d6455e2d5d1779748573b611cb95d4a21f967410399b39b535ba3e5af81ca2e",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 95
	"ecdsa_secp256r1_sha256_p1363_test.json - 95",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"333638323634333138",
	"be26231b6191658a19dd72ddb99ed8f8c579b6938d19bce8eed8dc2b338cb5f8e1d9a32ee56cffed37f0f22b2dcb57d5c943c14f79694a03b9c5e96952575c89",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 96
	"ecdsa_secp256r1_sha256_p1363_test.json - 96",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33323631313938363038",
	"15e76880898316b16204ac920a02d58045f36a229d4aa4f812638c455abe0443e74d357d3fcb5c8c5337bd6aba4178b455ca10e226e13f9638196506a1939123",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 97
	"ecdsa_secp256r1_sha256_p1363_test.json - 97",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"39363738373831303934",
	"352ecb53f8df2c503a45f9846fc28d1d31e6307d3ddbffc1132315cc07f16dad1348dfa9c482c558e1d05c5242ca1c39436726ecd28258b1899792887dd0a3c6",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 98
	"ecdsa_secp256r1_sha256_p1363_test.json - 98",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"34393538383233383233",
	"4a40801a7e606ba78a0da9882ab23c7677b8642349ed3d652c5bfa5f2a9558fb3a49b64848d682ef7f605f2832f7384bdc24ed2925825bf8ea77dc5981725782",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 99
	"ecdsa_secp256r1_sha256_p1363_test.json - 99",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"383234363337383337",
	"eacc5e1a8304a74d2be412b078924b3bb3511bac855c05c9e5e9e44df3d61e967451cd8e18d6ed1885dd827714847f96ec4bb0ed4c36ce9808db8f714204f6d1",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 100
	"ecdsa_secp256r1_sha256_p1363_test.json - 100",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3131303230383333373736",
	"2f7a5e9e5771d424f30f67fdab61e8ce4f8cd1214882adb65f7de94c31577052ac4e69808345809b44acb0b2bd889175fb75dd050c5a449ab9528f8f78daa10c",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 101
	"ecdsa_secp256r1_sha256_p1363_test.json - 101",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313333383731363438",
	"ffcda40f792ce4d93e7e0f0e95e1a2147dddd7f6487621c30a03d710b330021979938b55f8a17f7ed7ba9ade8f2065a1fa77618f0b67add8d58c422c2453a49a",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 102
	"ecdsa_secp256r1_sha256_p1363_test.json - 102",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"333232313434313632",
	"81f2359c4faba6b53d3e8c8c3fcc16a948350f7ab3a588b28c17603a431e39a8cd6f6a5cc3b55ead0ff695d06c6860b509e46d99fccefb9f7f9e101857f74300",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 103
	"ecdsa_secp256r1_sha256_p1363_test.json - 103",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130363836363535353436",
	"dfc8bf520445cbb8ee1596fb073ea283ea130251a6fdffa5c3f5f2aaf75ca808048e33efce147c9dd92823640e338e68bfd7d0dc7a4905b3a7ac711e577e90e7",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 104
	"ecdsa_secp256r1_sha256_p1363_test.json - 104",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3632313535323436",
	"ad019f74c6941d20efda70b46c53db166503a0e393e932f688227688ba6a576293320eb7ca0710255346bdbb3102cdcf7964ef2e0988e712bc05efe16c199345",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 105
	"ecdsa_secp256r1_sha256_p1363_test.json - 105",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"37303330383138373734",
	"ac8096842e8add68c34e78ce11dd71e4b54316bd3ebf7fffdeb7bd5a3ebc1883f5ca2f4f23d674502d4caf85d187215d36e3ce9f0ce219709f21a3aac003b7a8",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 106
	"ecdsa_secp256r1_sha256_p1363_test.json - 106",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"35393234353233373434",
	"677b2d3a59b18a5ff939b70ea002250889ddcd7b7b9d776854b4943693fb92f76b4ba856ade7677bf30307b21f3ccda35d2f63aee81efd0bab6972cc0795db55",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 107
	"ecdsa_secp256r1_sha256_p1363_test.json - 107",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31343935353836363231",
	"479e1ded14bcaed0379ba8e1b73d3115d84d31d4b7c30e1f05e1fc0d5957cfb0918f79e35b3d89487cf634a4f05b2e0c30857ca879f97c771e877027355b2443",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 108
	"ecdsa_secp256r1_sha256_p1363_test.json - 108",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"34303035333134343036",
	"43dfccd0edb9e280d9a58f01164d55c3d711e14b12ac5cf3b64840ead512a0a31dbe33fa8ba84533cd5c4934365b3442ca1174899b78ef9a3199f49584389772",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 109
	"ecdsa_secp256r1_sha256_p1363_test.json - 109",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33303936343537353132",
	"5b09ab637bd4caf0f4c7c7e4bca592fea20e9087c259d26a38bb4085f0bbff1145b7eb467b6748af618e9d80d6fdcd6aa24964e5a13f885bca8101de08eb0d75",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 110
	"ecdsa_secp256r1_sha256_p1363_test.json - 110",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"32373834303235363230",
	"5e9b1c5a028070df5728c5c8af9b74e0667afa570a6cfa0114a5039ed15ee06fb1360907e2d9785ead362bb8d7bd661b6c29eeffd3c5037744edaeb9ad990c20",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 111
	"ecdsa_secp256r1_sha256_p1363_test.json - 111",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"32363138373837343138",
	"0671a0a85c2b72d54a2fb0990e34538b4890050f5a5712f6d1a7a5fb8578f32edb1846bab6b7361479ab9c3285ca41291808f27fd5bd4fdac720e5854713694c",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 112
	"ecdsa_secp256r1_sha256_p1363_test.json - 112",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31363432363235323632",
	"7673f8526748446477dbbb0590a45492c5d7d69859d301abbaedb35b2095103a3dc70ddf9c6b524d886bed9e6af02e0e4dec0d417a414fed3807ef4422913d7c",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 113
	"ecdsa_secp256r1_sha256_p1363_test.json - 113",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"36383234313839343336",
	"7f085441070ecd2bb21285089ebb1aa6450d1a06c36d3ff39dfd657a796d12b5249712012029870a2459d18d47da9aa492a5e6cb4b2d8dafa9e4c5c54a2b9a8b",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 114
	"ecdsa_secp256r1_sha256_p1363_test.json - 114",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"343834323435343235",
	"914c67fb61dd1e27c867398ea7322d5ab76df04bc5aa6683a8e0f30a5d287348fa07474031481dda4953e3ac1959ee8cea7e66ec412b38d6c96d28f6d37304ea",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 115
	"ecdsa_secp256r1_sha256_p1363_test.json - 115",
	"040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e",
	"313233343030",
	"000000000000000000000000000000004319055358e8617b0c46353d039cdaabffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 116
	"ecdsa_secp256r1_sha256_p1363_test.json - 116",
	"040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e",
	"313233343030",
	"ffffffff00000001000000000000000000000000fffffffffffffffffffffffcffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 117
	"ecdsa_secp256r1_sha256_p1363_test.json - 117",
	"04ab05fd9d0de26b9ce6f4819652d9fc69193d0aa398f0fba8013e09c58220455419235271228c786759095d12b75af0692dd4103f19f6a8c32f49435a1e9b8d45",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 118
	"ecdsa_secp256r1_sha256_p1363_test.json - 118",
	"0480984f39a1ff38a86a68aa4201b6be5dfbfecf876219710b07badf6fdd4c6c5611feb97390d9826e7a06dfb41871c940d74415ed3cac2089f1445019bb55ed95",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd909135bdb6799286170f5ead2de4f6511453fe50914f3df2de54a36383df8dd4",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 119
	"ecdsa_secp256r1_sha256_p1363_test.json - 119",
	"044201b4272944201c3294f5baa9a3232b6dd687495fcc19a70a95bc602b4f7c0595c37eba9ee8171c1bb5ac6feaf753bc36f463e3aef16629572c0c0a8fb0800e",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd27b4577ca009376f71303fd5dd227dcef5deb773ad5f5a84360644669ca249a5",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 120
	"ecdsa_secp256r1_sha256_p1363_test.json - 120",
	"04a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000001",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 121
	"ecdsa_secp256r1_sha256_p1363_test.json - 121",
	"04a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
	"313233343030",
	"0501",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 122
	"ecdsa_secp256r1_sha256_p1363_test.json - 122",
	"046627cec4f0731ea23fc2931f90ebe5b7572f597d20df08fc2b31ee8ef16b15726170ed77d8d0a14fc5c9c3c4c9be7f0d3ee18f709bb275eaf2073e258fe694a5",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000003",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 123
	"ecdsa_secp256r1_sha256_p1363_test.json - 123",
	"046627cec4f0731ea23fc2931f90ebe5b7572f597d20df08fc2b31ee8ef16b15726170ed77d8d0a14fc5c9c3c4c9be7f0d3ee18f709bb275eaf2073e258fe694a5",
	"313233343030",
	"0503",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 124
	"ecdsa_secp256r1_sha256_p1363_test.json - 124",
	"045a7c8825e85691cce1f5e7544c54e73f14afc010cb731343262ca7ec5a77f5bfef6edf62a4497c1bd7b147fb6c3d22af3c39bfce95f30e13a16d3d7b2812f813",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000005",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 125
	"ecdsa_secp256r1_sha256_p1363_test.json - 125",
	"045a7c8825e85691cce1f5e7544c54e73f14afc010cb731343262ca7ec5a77f5bfef6edf62a4497c1bd7b147fb6c3d22af3c39bfce95f30e13a16d3d7b2812f813",
	"313233343030",
	"0505",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 126
	"ecdsa_secp256r1_sha256_p1363_test.json - 126",
	"04cbe0c29132cd738364fedd603152990c048e5e2fff996d883fa6caca7978c73770af6a8ce44cb41224b2603606f4c04d188e80bff7cc31ad5189d4ab0d70e8c1",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 127
	"ecdsa_secp256r1_sha256_p1363_test.json - 127",
	"04cbe0c29132cd738364fedd603152990c048e5e2fff996d883fa6caca7978c73770af6a8ce44cb41224b2603606f4c04d188e80bff7cc31ad5189d4ab0d70e8c1",
	"313233343030",
	"0506",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 128
	"ecdsa_secp256r1_sha256_p1363_test.json - 128",
	"042ef747671c97d9c7f9cb2f6a30d678c3d84757ba241ef7183d51a29f52d87c2ea8fb2ea635b761baefc1c4ded2099281b844e13e044c328553bbbafa337d8a76",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000001",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 129
	"ecdsa_secp256r1_sha256_p1363_test.json - 129",
	"042ef747671c97d9c7f9cb2f6a30d678c3d84757ba241ef7183d51a29f52d87c2ea8fb2ea635b761baefc1c4ded2099281b844e13e044c328553bbbafa337d8a76",
	"313233343030",
	"0601",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 130
	"ecdsa_secp256r1_sha256_p1363_test.json - 130",
	"04931cc49cda4d87d25b1601c56c3b83b4f45e44971998f2d3e7d3c55152214edf058dc140abbba42fc1ddbf30dab8eb9b46ee7338b3f7ee96242bf45e1df5e995",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000003",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 131
	"ecdsa_secp256r1_sha256_p1363_test.json - 131",
	"04931cc49cda4d87d25b1601c56c3b83b4f45e44971998f2d3e7d3c55152214edf058dc140abbba42fc1ddbf30dab8eb9b46ee7338b3f7ee96242bf45e1df5e995",
	"313233343030",
	"0603",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 132
	"ecdsa_secp256r1_sha256_p1363_test.json - 132",
	"04899a4af61867e3f3c190dbb48f8bc9fc74b70a467a4a1f06477b3af2f39ab8ed47ac000f9ea8a3034939bf48ad5d061a69fc8495ae4df2dbec7effa03a0062b3",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000006",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 133
	"ecdsa_secp256r1_sha256_p1363_test.json - 133",
	"04899a4af61867e3f3c190dbb48f8bc9fc74b70a467a4a1f06477b3af2f39ab8ed47ac000f9ea8a3034939bf48ad5d061a69fc8495ae4df2dbec7effa03a0062b3",
	"313233343030",
	"0606",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 134
	"ecdsa_secp256r1_sha256_p1363_test.json - 134",
	"04d03eb09913cc20c6a8d0070f0d8d2a7f63527fafa44117fce6bd1ef2aa4ae3c46d5df3f45ac58fa334c6d102381b3120b7a2455600dcaff3d1a845514f12bf46",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000007",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 135
	"ecdsa_secp256r1_sha256_p1363_test.json - 135",
	"04d03eb09913cc20c6a8d0070f0d8d2a7f63527fafa44117fce6bd1ef2aa4ae3c46d5df3f45ac58fa334c6d102381b3120b7a2455600dcaff3d1a845514f12bf46",
	"313233343030",
	"0607",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 136
	"ecdsa_secp256r1_sha256_p1363_test.json - 136",
	"04d03eb09913cc20c6a8d0070f0d8d2a7f63527fafa44117fce6bd1ef2aa4ae3c46d5df3f45ac58fa334c6d102381b3120b7a2455600dcaff3d1a845514f12bf46",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325570000000000000000000000000000000000000000000000000000000000000007",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 137
	"ecdsa_secp256r1_sha256_p1363_test.json - 137",
	"043a72476291571193b4d109b2c37b59f2807e8fe9cffd804eacded903e77ca0da592dbc74fee0ca7508cc7bc282b0c51a143286ff53c60131668e7a0929e4ed04",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000006ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc75fbd8",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 138
	"ecdsa_secp256r1_sha256_p1363_test.json - 138",
	"04d0f73792203716afd4be4329faa48d269f15313ebbba379d7783c97bf3e890d9971f4a3206605bec21782bf5e275c714417e8f566549e6bc68690d2363c89cc1",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000001008f1e3c7862c58b16bb76eddbb76eddbb516af4f63f2d74d76e0d28c9bb75ea88",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 139
	"ecdsa_secp256r1_sha256_p1363_test.json - 139",
	"044838b2be35a6276a80ef9e228140f9d9b96ce83b7a254f71ccdebbb8054ce05ffa9cbc123c919b19e00238198d04069043bd660a828814051fcb8aac738a6c6b",
	"313233343030",
	"000000000000000000000000000000000000000000000000002d9b4d347952d6ef3043e7329581dbb3974497710ab11505ee1c87ff907beebadd195a0ffe6d7a",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 140
	"ecdsa_secp256r1_sha256_p1363_test.json - 140",
	"047393983ca30a520bbc4783dc9960746aab444ef520c0a8e771119aa4e74b0f64e9d7be1ab01a0bf626e709863e6a486dbaf32793afccf774e2c6cd27b1857526",
	"313233343030",
	"000000000000000000000000000000000000001033e67e37b32b445580bf4eff8b748b74000000008b748b748b748b7466e769ad4a16d3dcd87129b8e91d1b4d",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 141
	"ecdsa_secp256r1_sha256_p1363_test.json - 141",
	"045ac331a1103fe966697379f356a937f350588a05477e308851b8a502d5dfcdc5fe9993df4b57939b2b8da095bf6d794265204cfe03be995a02e65d408c871c0b",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000100ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 142
	"ecdsa_secp256r1_sha256_p1363_test.json - 142",
	"041d209be8de2de877095a399d3904c74cc458d926e27bb8e58e5eae5767c41509dd59e04c214f7b18dce351fc2a549893a6860e80163f38cc60a4f2c9d040d8c9",
	"313233343030",
	"00000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c25ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 143
	"ecdsa_secp256r1_sha256_p1363_test.json - 143",
	"04083539fbee44625e3acaafa2fcb41349392cef0633a1b8fabecee0c133b10e99915c1ebe7bf00df8535196770a58047ae2a402f26326bb7d41d4d7616337911e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6324d5555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 144
	"ecdsa_secp256r1_sha256_p1363_test.json - 144",
	"04e075effd9607d08d5f34e3652f64cfa3bd6d20c58d0a232f058491260ab212a4cc61760ac8b0680c1b644c03cc628ba9dc4a3c0561368489c692bd40f43aa3ca",
	"313233343030",
	"0000000000000000000000000000000000000000000000009c44febf31c3594f000000000000000000000000000000000000000000000000839ed28247c2b06b",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 145
	"ecdsa_secp256r1_sha256_p1363_test.json - 145",
	"04e075effd9607d08d5f34e3652f64cfa3bd6d20c58d0a232f058491260ab212a4cc61760ac8b0680c1b644c03cc628ba9dc4a3c0561368489c692bd40f43aa3ca",
	"313233343030",
	"9c44febf31c3594f839ed28247c2b06b",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 146
	"ecdsa_secp256r1_sha256_p1363_test.json - 146",
	"04cffb758c3073ea3c08efd9f7f17a85b6ae385c5a140c146ad5f1f5a826718bc8dfdc6bebc894144c6d418ac5d97339726ad2ae925df868426e5628e9f4e62342",
	"313233343030",
	"0000000000000000000000000000000000000009df8b682430beef6f5fd7c7cd000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 147
	"ecdsa_secp256r1_sha256_p1363_test.json - 147",
	"04cffb758c3073ea3c08efd9f7f17a85b6ae385c5a140c146ad5f1f5a826718bc8dfdc6bebc894144c6d418ac5d97339726ad2ae925df868426e5628e9f4e62342",
	"313233343030",
	"09df8b682430beef6f5fd7c7cd0fd0a62e13778f4222a0d61c8a",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 148
	"ecdsa_secp256r1_sha256_p1363_test.json - 148",
	"04b98740e69e61a325d5f772e3b5c4f67fb7150b16a9afeca9ddc4afcbb6fa0549c446e814138e4ebc82dbf86a390056d4595dcf45e381fef217a4597d7bd51498",
	"313233343030",
	"000000000000000000000000000000008a598e563a89f526c32ebec8de26367c0000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 149
	"ecdsa_secp256r1_sha256_p1363_test.json - 149",
	"04b98740e69e61a325d5f772e3b5c4f67fb7150b16a9afeca9ddc4afcbb6fa0549c446e814138e4ebc82dbf86a390056d4595dcf45e381fef217a4597d7bd51498",
	"313233343030",
	"8a598e563a89f526c32ebec8de26367c84f633e2042630e99dd0f1e16f7a04bf",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 150
	"ecdsa_secp256r1_sha256_p1363_test.json - 150",
	"0484536a270c3932bb2084732adf2c768efc6d3977e5220229ea9a44888b8f9d7b1766398cdac2fc8000017b29a7ba15a58f196037f35f7008ed4286ddff00fd46",
	"313233343030",
	"000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0bdf000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 151
	"ecdsa_secp256r1_sha256_p1363_test.json - 151",
	"0484536a270c3932bb2084732adf2c768efc6d3977e5220229ea9a44888b8f9d7b1766398cdac2fc8000017b29a7ba15a58f196037f35f7008ed4286ddff00fd46",
	"313233343030",
	"aa6eeb5823f7fa31b466bb473797f0d0314c0bdfe2977c479e6d25703cebbc6bd561938cc9d1bfb9",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 152
	"ecdsa_secp256r1_sha256_p1363_test.json - 152",
	"048aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e1937387405bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c700000000000000000000000000000000000000000000000000000000000000001",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 153
	"ecdsa_secp256r1_sha256_p1363_test.json - 153",
	"048aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e1937387405bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c700000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 154
	"ecdsa_secp256r1_sha256_p1363_test.json - 154",
	"0461722eaba731c697c7a9ba4d0afdbb5713d8aa12b0eab601bb33dbaf792c5adc272cd993b2b663aba5b3a26c101182ff178684945e83879e71598b95fe647dfc",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7002f676969f451a8ccafa4c4f09791810e6d632dbd60b1d5540f3284fbe1889b0",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 155
	"ecdsa_secp256r1_sha256_p1363_test.json - 155",
	"04c4c91981e720e20d7e478ff19d09b95a98f58c0f469b72801a8ce844a347316594afcd4188182e7779889b3258d0368ece1e66797fe7c648c6f0b9e26bd71871",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c704e260962e33362ef0046126d2d5a4edc6947ab20e19b8ec19cf79e5908b6e628",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 156
	"ecdsa_secp256r1_sha256_p1363_test.json - 156",
	"04d58d47bf49bc8f416641f6f760fcbca80aa52a814e56a5fa40bab44fd6f6317216deaa84d45d8e0e29cc9ecf5653f8ee6444750813becae8deb42b04ba07a634",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70077ed0d8f20f697d8fc591ac64dd5219c7932122b4f9b9ec6441e44a0092cf21",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 157
	"ecdsa_secp256r1_sha256_p1363_test.json - 157",
	"0491e305822e5e44f3fdb616e2ef42cd98f241b86e9f68815bc4dba6a945e4eefb3c5937e2ac1d9466f6d65e49b35fc8d75ffc22e1fe2f32af42f5fa3c26f9b4b0",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c703e0292a67e181c6c0105ee35e956e78e9bdd033c6e71ae57884039a245e4175f",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 158
	"ecdsa_secp256r1_sha256_p1363_test.json - 158",
	"0424a0bc4d16dbbd40d2fd81a7c3f8d8ec741607d5bb406a0611cc60d0e683bd46b575cad039c15f7f3dffcfc007b4b0f743c871ecc76a504a32672fd84526d861",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7013d22b06d6b8f5d97e0c64962b4a3bae30f668ca6217ef5b35d799f159e23ebe",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 159
	"ecdsa_secp256r1_sha256_p1363_test.json - 159",
	"04d24dd06745cafb39186d22a92aa0e58169a79ab69488628a9da5ed3ef747269b7e9209d98faeb95355948adae61d5291c6015d3ee9513486d886fb05cbd25c6a",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c704523ce342e4994bb8968bf6613f60c06c86111f15a3a389309e72cd447d5dd99",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 160
	"ecdsa_secp256r1_sha256_p1363_test.json - 160",
	"048200f148e7eab1581bcd1e23946f8a9b8191d9641f9560341721f9d3fec3d63ece795669e0481e035de8623d716a6984d0a4809d6c65519443ee55260f7f3dcb",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7037d765be3c9c78189ad30edb5097a4db670de11686d01420e37039d4677f4809",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 161
	"ecdsa_secp256r1_sha256_p1363_test.json - 161",
	"04a8a69c5ed33b150ce8d37ac197070ed894c05d47258a80c9041d92486622024de85997c9666b60a393568efede8f4ca0167c1e10f626e62fc1b8c8e9c6ba6ed7",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7044237823b54e0c74c2bf5f759d9ac5f8cb897d537ffa92effd4f0bb6c9acd860",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 162
	"ecdsa_secp256r1_sha256_p1363_test.json - 162",
	"04ed0587e75b3b9a1dd0794f41d1729fcd432b2436cbf51c230d8bc7273273181735a57f09c7873d3964aa8102c9e25fa53070cd924cb7e3a459174740b8b71c34",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70266d30a485385906054ca86d46f5f2b17e7f4646a3092092ad92877126538111",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 163
	"ecdsa_secp256r1_sha256_p1363_test.json - 163",
	"04077091d99004a99ee08224e59a46a70495e6fba4eff681c3ce42127e588681ef4f1c16c77dfa440dde18245c9de76243d8f2fd9dea3f2782d6c04974d02f25dc",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70538c7b3798e84d0ce90340165806348971ed44db8f0c674f5f215968390f92ee",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 164
	"ecdsa_secp256r1_sha256_p1363_test.json - 164",
	"04616a8b8e57d82c11678f5827911024cd23a16cb52a65f230fb554a7b110c35a5bb466660be5cab3e4b587c12b45bd998bd56c7d66c2f94d03a1a6d2028d8a154",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c706fef0ef15d1688e15e704c4e6bb8bb7f40d52d3af5c661bb78c4ed9b408699b3",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 165
	"ecdsa_secp256r1_sha256_p1363_test.json - 165",
	"0471dc92b2b1baa7612c4a53427a0d2dfe548fa9cf829bb6b248f736a5eb30b513f91c7dff1144cb36057c2b859f35bd666a7961833b06de0f45159fbae208e326",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c706f44275e9aeb1331efcb8d58f35c0252791427e403ad84daad51d247cc2a64c6",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 166
	"ecdsa_secp256r1_sha256_p1363_test.json - 166",
	"04662f43ae614bd9c90ff3fcded25cf0ef186b6967a47aa6aa7ae7f396594df931f5f94a525edd50d3738f7a28d03d7a2a70095c8f89de9bb2c645fea8d8bac9e0",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7021323755b103d2f9da6ab83eccab9ad8598bcf625652f10e7a3eeee3c3945fb3",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 167
	"ecdsa_secp256r1_sha256_p1363_test.json - 167",
	"04dff107959bd2f7386497a5624430a0ab35e552c1a4e4dc9c298caeb96353170dcb5065d7947a676c76287ca8e430324f8a534b0ba6f21200e033c4b88852a3cc",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c706c50acfe76de1289e7a5edb240f1c2a7879db6873d5d931f3c6ac467a6eac171",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 168
	"ecdsa_secp256r1_sha256_p1363_test.json - 168",
	"04bd0862b0bfba85036922e06f5458754aafc3075b603a814b3ac75659bf24d7528258a607ffca2cfe05a300cb4c3c4e1963bbb1bc54d320e16969f85aad243385",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70755b7fffb0b17ad57dca50fcefb7fe297b029df25e5ccb5069e8e70c2742c2a6",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 169
	"ecdsa_secp256r1_sha256_p1363_test.json - 169",
	"04b533d4695dd5b8c5e07757e55e6e516f7e2c88fa0239e23f60e8ec07dd70f2871b134ee58cc583278456863f33c3a85d881f7d4a39850143e29d4eaf009afe47",
	"313233343030",
	"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 170
	"ecdsa_secp256r1_sha256_p1363_test.json - 170",
	"04f50d371b91bfb1d7d14e1323523bc3aa8cbf2c57f9e284de628c8b4536787b86f94ad887ac94d527247cd2e7d0c8b1291c553c9730405380b14cbb209f5fa2dd",
	"313233343030",
	"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a97fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 171
	"ecdsa_secp256r1_sha256_p1363_test.json - 171",
	"0468ec6e298eafe16539156ce57a14b04a7047c221bafc3a582eaeb0d857c4d94697bed1af17850117fdb39b2324f220a5698ed16c426a27335bb385ac8ca6fb30",
	"313233343030",
	"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a97fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 172
	"ecdsa_secp256r1_sha256_p1363_test.json - 172",
	"0469da0364734d2e530fece94019265fefb781a0f1b08f6c8897bdf6557927c8b866d2d3c7dcd518b23d726960f069ad71a933d86ef8abbcce8b20f71e2a847002",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 173
	"ecdsa_secp256r1_sha256_p1363_test.json - 173",
	"04d8adc00023a8edc02576e2b63e3e30621a471e2b2320620187bf067a1ac1ff3233e2b50ec09807accb36131fff95ed12a09a86b4ea9690aa32861576ba2362e1",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7044a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 174
	"ecdsa_secp256r1_sha256_p1363_test.json - 174",
	"043623ac973ced0a56fa6d882f03a7d5c7edca02cfc7b2401fab3690dbe75ab7858db06908e64b28613da7257e737f39793da8e713ba0643b92e9bb3252be7f8fe",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 175
	"ecdsa_secp256r1_sha256_p1363_test.json - 175",
	"04cf04ea77e9622523d894b93ff52dc3027b31959503b6fa3890e5e04263f922f1e8528fb7c006b3983c8b8400e57b4ed71740c2f3975438821199bedeaecab2e9",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 176
	"ecdsa_secp256r1_sha256_p1363_test.json - 176",
	"04db7a2c8a1ab573e5929dc24077b508d7e683d49227996bda3e9f78dbeff773504f417f3bc9a88075c2e0aadd5a13311730cf7cc76a82f11a36eaf08a6c99a206",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffde91e1ba60fdedb76a46bcb51dc0b8b4b7e019f0a28721885fa5d3a8196623397",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 177
	"ecdsa_secp256r1_sha256_p1363_test.json - 177",
	"04dead11c7a5b396862f21974dc4752fadeff994efe9bbd05ab413765ea80b6e1f1de3f0640e8ac6edcf89cff53c40e265bb94078a343736df07aa0318fc7fe1ff",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdfdea5843ffeb73af94313ba4831b53fe24f799e525b1e8e8c87b59b95b430ad9",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 178
	"ecdsa_secp256r1_sha256_p1363_test.json - 178",
	"04d0bc472e0d7c81ebaed3a6ef96c18613bb1fea6f994326fbe80e00dfde67c7e9986c723ea4843d48389b946f64ad56c83ad70ff17ba85335667d1bb9fa619efd",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd03ffcabf2f1b4d2a65190db1680d62bb994e41c5251cd73b3c3dfc5e5bafc035",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 179
	"ecdsa_secp256r1_sha256_p1363_test.json - 179",
	"04a0a44ca947d66a2acb736008b9c08d1ab2ad03776e02640f78495d458dd51c326337fe5cf8c4604b1f1c409dc2d872d4294a4762420df43a30a2392e40426add",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd4dfbc401f971cd304b33dfdb17d0fed0fe4c1a88ae648e0d2847f74977534989",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 180
	"ecdsa_secp256r1_sha256_p1363_test.json - 180",
	"04c9c2115290d008b45fb65fad0f602389298c25420b775019d42b62c3ce8a96b73877d25a8080dc02d987ca730f0405c2c9dbefac46f9e601cc3f06e9713973fd",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbc4024761cd2ffd43dfdb17d0fed112b988977055cd3a8e54971eba9cda5ca71",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 181
	"ecdsa_secp256r1_sha256_p1363_test.json - 181",
	"045eca1ef4c287dddc66b8bccf1b88e8a24c0018962f3c5e7efa83bc1a5ff6033e5e79c4cb2c245b8c45abdce8a8e4da758d92a607c32cd407ecaef22f1c934a71",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd788048ed39a5ffa77bfb62fa1fda2257742bf35d128fb3459f2a0c909ee86f91",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 182
	"ecdsa_secp256r1_sha256_p1363_test.json - 182",
	"045caaa030e7fdf0e4936bc7ab5a96353e0a01e4130c3f8bf22d473e317029a47adeb6adc462f7058f2a20d371e9702254e9b201642005b3ceda926b42b178bef9",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd476d9131fd381bd917d0fed112bc9e0a5924b5ed5b11167edd8b23582b3cb15e",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 183
	"ecdsa_secp256r1_sha256_p1363_test.json - 183",
	"04c2fd20bac06e555bb8ac0ce69eb1ea20f83a1fc3501c8a66469b1a31f619b0986237050779f52b615bd7b8d76a25fc95ca2ed32525c75f27ffc87ac397e6cbaf",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd8374253e3e21bd154448d0a8f640fe46fafa8b19ce78d538f6cc0a19662d3601",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 184
	"ecdsa_secp256r1_sha256_p1363_test.json - 184",
	"043fd6a1ca7f77fb3b0bbe726c372010068426e11ea6ae78ce17bedae4bba86ced03ce5516406bf8cfaab8745eac1cd69018ad6f50b5461872ddfc56e0db3c8ff4",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd357cfd3be4d01d413c5b9ede36cba5452c11ee7fe14879e749ae6a2d897a52d6",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 185
	"ecdsa_secp256r1_sha256_p1363_test.json - 185",
	"049cb8e51e27a5ae3b624a60d6dc32734e4989db20e9bca3ede1edf7b086911114b4c104ab3c677e4b36d6556e8ad5f523410a19f2e277aa895fc57322b4427544",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd29798c5c0ee287d4a5e8e6b799fd86b8df5225298e6ffc807cd2f2bc27a0a6d8",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 186
	"ecdsa_secp256r1_sha256_p1363_test.json - 186",
	"04a3e52c156dcaf10502620b7955bc2b40bc78ef3d569e1223c262512d8f49602a4a2039f31c1097024ad3cc86e57321de032355463486164cf192944977df147f",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0b70f22c781092452dca1a5711fa3a5a1f72add1bf52c2ff7cae4820b30078dd",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 187
	"ecdsa_secp256r1_sha256_p1363_test.json - 187",
	"04f19b78928720d5bee8e670fb90010fb15c37bf91b58a5157c3f3c059b2655e88cf701ec962fb4a11dcf273f5dc357e58468560c7cfeb942d074abd4329260509",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd16e1e458f021248a5b9434ae23f474b43ee55ba37ea585fef95c90416600f1ba",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 188
	"ecdsa_secp256r1_sha256_p1363_test.json - 188",
	"0483a744459ecdfb01a5cf52b27a05bb7337482d242f235d7b4cb89345545c90a8c05d49337b9649813287de9ffe90355fd905df5f3c32945828121f37cc50de6e",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd2252d6856831b6cf895e4f0535eeaf0e5e5809753df848fe760ad86219016a97",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 189
	"ecdsa_secp256r1_sha256_p1363_test.json - 189",
	"04dd13c6b34c56982ddae124f039dfd23f4b19bbe88cee8e528ae51e5d6f3a21d7bfad4c2e6f263fe5eb59ca974d039fc0e4c3345692fb5320bdae4bd3b42a45ff",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd81ffe55f178da695b28c86d8b406b15dab1a9e39661a3ae017fbe390ac0972c3",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 190
	"ecdsa_secp256r1_sha256_p1363_test.json - 190",
	"0467e6f659cdde869a2f65f094e94e5b4dfad636bbf95192feeed01b0f3deb7460a37e0a51f258b7aeb51dfe592f5cfd5685bbe58712c8d9233c62886437c38ba0",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd7fffffffaaaaaaaaffffffffffffffffe9a2538f37b28a2c513dee40fecbb71a",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 191
	"ecdsa_secp256r1_sha256_p1363_test.json - 191",
	"042eb6412505aec05c6545f029932087e490d05511e8ec1f599617bb367f9ecaaf805f51efcc4803403f9b1ae0124890f06a43fedcddb31830f6669af292895cb0",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdb62f26b5f2a2b26f6de86d42ad8a13da3ab3cccd0459b201de009e526adf21f2",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 192
	"ecdsa_secp256r1_sha256_p1363_test.json - 192",
	"0484db645868eab35e3a9fd80e056e2e855435e3a6b68d75a50a854625fe0d7f356d2589ac655edc9a11ef3e075eddda9abf92e72171570ef7bf43a2ee39338cfe",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbb1d9ac949dd748cd02bbbe749bd351cd57b38bb61403d700686aa7b4c90851e",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 193
	"ecdsa_secp256r1_sha256_p1363_test.json - 193",
	"0491b9e47c56278662d75c0983b22ca8ea6aa5059b7a2ff7637eb2975e386ad66349aa8ff283d0f77c18d6d11dc062165fd13c3c0310679c1408302a16854ecfbd",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd66755a00638cdaec1c732513ca0234ece52545dac11f816e818f725b4f60aaf2",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 194
	"ecdsa_secp256r1_sha256_p1363_test.json - 194",
	"04f3ec2f13caf04d0192b47fb4c5311fb6d4dc6b0a9e802e5327f7ec5ee8e4834df97e3e468b7d0db867d6ecfe81e2b0f9531df87efdb47c1338ac321fefe5a432",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd55a00c9fcdaebb6032513ca0234ecfffe98ebe492fdf02e48ca48e982beb3669",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 195
	"ecdsa_secp256r1_sha256_p1363_test.json - 195",
	"04d92b200aefcab6ac7dafd9acaf2fa10b3180235b8f46b4503e4693c670fccc885ef2f3aebf5b317475336256768f7c19efb7352d27e4cccadc85b6b8ab922c72",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdab40193f9b5d76c064a27940469d9fffd31d7c925fbe05c919491d3057d66cd2",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 196
	"ecdsa_secp256r1_sha256_p1363_test.json - 196",
	"040a88361eb92ecca2625b38e5f98bbabb96bf179b3d76fc48140a3bcd881523cde6bdf56033f84a5054035597375d90866aa2c96b86a41ccf6edebf47298ad489",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdca0234ebb5fdcb13ca0234ecffffffffcb0dadbbc7f549f8a26b4408d0dc8600",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 197
	"ecdsa_secp256r1_sha256_p1363_test.json - 197",
	"04d0fb17ccd8fafe827e0c1afc5d8d80366e2b20e7f14a563a2ba50469d84375e868612569d39e2bb9f554355564646de99ac602cc6349cf8c1e236a7de7637d93",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbfffffff3ea3677e082b9310572620ae19933a9e65b285598711c77298815ad3",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 198
	"ecdsa_secp256r1_sha256_p1363_test.json - 198",
	"04836f33bbc1dc0d3d3abbcef0d91f11e2ac4181076c9af0a22b1e4309d3edb2769ab443ff6f901e30c773867582997c2bec2b0cb8120d760236f3a95bbe881f75",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd266666663bbbbbbbe6666666666666665b37902e023fab7c8f055d86e5cc41f4",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 199
	"ecdsa_secp256r1_sha256_p1363_test.json - 199",
	"0492f99fbe973ed4a299719baee4b432741237034dec8d72ba5103cb33e55feeb8033dd0e91134c734174889f3ebcf1b7a1ac05767289280ee7a794cebd6e69697",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbfffffff36db6db7a492492492492492146c573f4c6dfc8d08a443e258970b09",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 200
	"ecdsa_secp256r1_sha256_p1363_test.json - 200",
	"04d35ba58da30197d378e618ec0fa7e2e2d12cffd73ebbb2049d130bba434af09eff83986e6875e41ea432b7585a49b3a6c77cbb3c47919f8e82874c794635c1d2",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbfffffff2aaaaaab7fffffffffffffffc815d0e60b3e596ecb1ad3a27cfd49c4",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 201
	"ecdsa_secp256r1_sha256_p1363_test.json - 201",
	"048651ce490f1b46d73f3ff475149be29136697334a519d7ddab0725c8d0793224e11c65bd8ca92dc8bc9ae82911f0b52751ce21dd9003ae60900bd825f590cc28",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd7fffffff55555555ffffffffffffffffd344a71e6f651458a27bdc81fd976e37",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 202
	"ecdsa_secp256r1_sha256_p1363_test.json - 202",
	"046d8e1b12c831a0da8795650ff95f101ed921d9e2f72b15b1cdaca9826b9cfc6def6d63e2bc5c089570394a4bc9f892d5e6c7a6a637b20469a58c106ad486bf37",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd3fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192aa",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 203
	"ecdsa_secp256r1_sha256_p1363_test.json - 203",
	"040ae580bae933b4ef2997cbdbb0922328ca9a410f627a0f7dff24cb4d920e15428911e7f8cc365a8a88eb81421a361ccc2b99e309d8dcd9a98ba83c3949d893e3",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd5d8ecd64a4eeba466815ddf3a4de9a8e6abd9c5db0a01eb80343553da648428f",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 204
	"ecdsa_secp256r1_sha256_p1363_test.json - 204",
	"045b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc46963838a40f2a36092e9004e92d8d940cf5638550ce672ce8b8d4e15eba5499249e9",
	"313233343030",
	"6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 205
	"ecdsa_secp256r1_sha256_p1363_test.json - 205",
	"045b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc469637c75bf0c5c9f6d17ffb16d2726bf30a9c7aaf31a8d317472b1ea145ab66db616",
	"313233343030",
	"6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 206
	"ecdsa_secp256r1_sha256_p1363_test.json - 206",
	"046adda82b90261b0f319faa0d878665a6b6da497f09c903176222c34acfef72a647e6f50dcc40ad5d9b59f7602bb222fad71a41bf5e1f9df4959a364c62e488d9",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 207
	"ecdsa_secp256r1_sha256_p1363_test.json - 207",
	"042fca0d0a47914de77ed56e7eccc3276a601120c6df0069c825c8f6a01c9f382065f3450a1d17c6b24989a39beb1c7decfca8384fbdc294418e5d807b3c6ed7de",
	"313233343030",
	"010000000000000000000000000000000000000000000000000000000000000000003333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 208
	"ecdsa_secp256r1_sha256_p1363_test.json - 208",
	"04dd86d3b5f4a13e8511083b78002081c53ff467f11ebd98a51a633db76665d25045d5c8200c89f2fa10d849349226d21d8dfaed6ff8d5cb3e1b7e17474ebc18f7",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c703333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 209
	"ecdsa_secp256r1_sha256_p1363_test.json - 209",
	"044fea55b32cb32aca0c12c4cd0abfb4e64b0f5a516e578c016591a93f5a0fbcc5d7d3fd10b2be668c547b212f6bb14c88f0fecd38a8a4b2c785ed3be62ce4b280",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 210
	"ecdsa_secp256r1_sha256_p1363_test.json - 210",
	"04c6a771527024227792170a6f8eee735bf32b7f98af669ead299802e32d7c3107bc3b4b5e65ab887bbd343572b3e5619261fe3a073e2ffd78412f726867db589e",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 211
	"ecdsa_secp256r1_sha256_p1363_test.json - 211",
	"04851c2bbad08e54ec7a9af99f49f03644d6ec6d59b207fec98de85a7d15b956efcee9960283045075684b410be8d0f7494b91aa2379f60727319f10ddeb0fe9d6",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 212
	"ecdsa_secp256r1_sha256_p1363_test.json - 212",
	"04f6417c8a670584e388676949e53da7fc55911ff68318d1bf3061205acb19c48f8f2b743df34ad0f72674acb7505929784779cd9ac916c3669ead43026ab6d43f",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc476699783333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 213
	"ecdsa_secp256r1_sha256_p1363_test.json - 213",
	"04501421277be45a5eefec6c639930d636032565af420cf3373f557faa7f8a06438673d6cb6076e1cfcdc7dfe7384c8e5cac08d74501f2ae6e89cad195d0aa1371",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997849249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 214
	"ecdsa_secp256r1_sha256_p1363_test.json - 214",
	"040d935bf9ffc115a527735f729ca8a4ca23ee01a4894adf0e3415ac84e808bb343195a3762fea29ed38912bd9ea6c4fde70c3050893a4375850ce61d82eba33c5",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997816a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 215
	"ecdsa_secp256r1_sha256_p1363_test.json - 215",
	"045e59f50708646be8a589355014308e60b668fb670196206c41e748e64e4dca215de37fee5c97bcaf7144d5b459982f52eeeafbdf03aacbafef38e213624a01de",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 216
	"ecdsa_secp256r1_sha256_p1363_test.json - 216",
	"04169fb797325843faff2f7a5b5445da9e2fd6226f7ef90ef0bfe924104b02db8e7bbb8de662c7b9b1cf9b22f7a2e582bd46d581d68878efb2b861b131d8a1d667",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 217
	"ecdsa_secp256r1_sha256_p1363_test.json - 217",
	"04271cd89c000143096b62d4e9e4ca885aef2f7023d18affdaf8b7b548981487540a1c6e954e32108435b55fa385b0f76481a609b9149ccb4b02b2ca47fe8e4da5",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 218
	"ecdsa_secp256r1_sha256_p1363_test.json - 218",
	"043d0bc7ed8f09d2cb7ddb46ebc1ed799ab1563a9ab84bf524587a220afe499c12e22dc3b3c103824a4f378d96adb0a408abf19ce7d68aa6244f78cb216fa3f8df",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2963333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 219
	"ecdsa_secp256r1_sha256_p1363_test.json - 219",
	"04a6c885ade1a4c566f9bb010d066974abb281797fa701288c721bcbd23663a9b72e424b690957168d193a6096fc77a2b004a9c7d467e007e1f2058458f98af316",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29649249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 220
	"ecdsa_secp256r1_sha256_p1363_test.json - 220",
	"048d3c2c2c3b765ba8289e6ac3812572a25bf75df62d87ab7330c3bdbad9ebfa5c4c6845442d66935b238578d43aec54f7caa1621d1af241d4632e0b780c423f5d",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29616a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 221
	"ecdsa_secp256r1_sha256_p1363_test.json - 221",
	"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	"313233343030",
	"bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 222
	"ecdsa_secp256r1_sha256_p1363_test.json - 222",
	"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	"313233343030",
	"44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 223
	"ecdsa_secp256r1_sha256_p1363_test.json - 223",
	"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
	"313233343030",
	"bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 224
	"ecdsa_secp256r1_sha256_p1363_test.json - 224",
	"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
	"313233343030",
	"44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
	"F",

	# ecdsa_secp256r1_sha256_p1363_test.json - 225
	"ecdsa_secp256r1_sha256_p1363_test.json - 225",
	"0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
	"",
	"b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 226
	"ecdsa_secp256r1_sha256_p1363_test.json - 226",
	"0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
	"4d7367",
	"530bd6b0c9af2d69ba897f6b5fb59695cfbf33afe66dbadcf5b8d2a2a6538e23d85e489cb7a161fd55ededcedbf4cc0c0987e3e3f0f242cae934c72caa3f43e9",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 227
	"ecdsa_secp256r1_sha256_p1363_test.json - 227",
	"0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
	"313233343030",
	"a8ea150cb80125d7381c4c1f1da8e9de2711f9917060406a73d7904519e51388f3ab9fa68bd47973a73b2d40480c2ba50c22c9d76ec217257288293285449b86",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 228
	"ecdsa_secp256r1_sha256_p1363_test.json - 228",
	"0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
	"0000000000000000000000000000000000000000",
	"986e65933ef2ed4ee5aada139f52b70539aaf63f00a91f29c69178490d57fb713dafedfb8da6189d372308cbf1489bbbdabf0c0217d1c0ff0f701aaa7a694b9c",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 229
	"ecdsa_secp256r1_sha256_p1363_test.json - 229",
	"044f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
	"4d657373616765",
	"d434e262a49eab7781e353a3565e482550dd0fd5defa013c7f29745eff3569f19b0c0a93f267fb6052fd8077be769c2b98953195d7bc10de844218305c6ba17a",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 230
	"ecdsa_secp256r1_sha256_p1363_test.json - 230",
	"044f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
	"4d657373616765",
	"0fe774355c04d060f76d79fd7a772e421463489221bf0a33add0be9b1979110b500dcba1c69a8fbd43fa4f57f743ce124ca8b91a1f325f3fac6181175df55737",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 231
	"ecdsa_secp256r1_sha256_p1363_test.json - 231",
	"044f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
	"4d657373616765",
	"bb40bf217bed3fb3950c7d39f03d36dc8e3b2cd79693f125bfd06595ee1135e3541bf3532351ebb032710bdb6a1bf1bfc89a1e291ac692b3fa4780745bb55677",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 232
	"ecdsa_secp256r1_sha256_p1363_test.json - 232",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f49726500493584fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
	"4d657373616765",
	"664eb7ee6db84a34df3c86ea31389a5405badd5ca99231ff556d3e75a233e73a59f3c752e52eca46137642490a51560ce0badc678754b8f72e51a2901426a1bd",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 233
	"ecdsa_secp256r1_sha256_p1363_test.json - 233",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f49726500493584fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
	"4d657373616765",
	"4cd0429bbabd2827009d6fcd843d4ce39c3e42e2d1631fd001985a79d1fd8b439638bf12dd682f60be7ef1d0e0d98f08b7bca77a1a2b869ae466189d2acdabe3",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 234
	"ecdsa_secp256r1_sha256_p1363_test.json - 234",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f49726500493584fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
	"4d657373616765",
	"e56c6ea2d1b017091c44d8b6cb62b9f460e3ce9aed5e5fd41e8added97c56c04a308ec31f281e955be20b457e463440b4fcf2b80258078207fc1378180f89b55",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 235
	"ecdsa_secp256r1_sha256_p1363_test.json - 235",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f4972650049357b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
	"4d657373616765",
	"1158a08d291500b4cabed3346d891eee57c176356a2624fb011f8fbbf3466830228a8c486a736006e082325b85290c5bc91f378b75d487dda46798c18f285519",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 236
	"ecdsa_secp256r1_sha256_p1363_test.json - 236",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f4972650049357b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
	"4d657373616765",
	"b1db9289649f59410ea36b0c0fc8d6aa2687b29176939dd23e0dde56d309fa9d3e1535e4280559015b0dbd987366dcf43a6d1af5c23c7d584e1c3f48a1251336",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 237
	"ecdsa_secp256r1_sha256_p1363_test.json - 237",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f4972650049357b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
	"4d657373616765",
	"b7b16e762286cb96446aa8d4e6e7578b0a341a79f2dd1a220ac6f0ca4e24ed86ddc60a700a139b04661c547d07bbb0721780146df799ccf55e55234ecb8f12bc",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 238
	"ecdsa_secp256r1_sha256_p1363_test.json - 238",
	"042829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffffa01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
	"4d657373616765",
	"d82a7c2717261187c8e00d8df963ff35d796edad36bc6e6bd1c91c670d9105b43dcabddaf8fcaa61f4603e7cbac0f3c0351ecd5988efb23f680d07debd139929",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 239
	"ecdsa_secp256r1_sha256_p1363_test.json - 239",
	"042829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffffa01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
	"4d657373616765",
	"5eb9c8845de68eb13d5befe719f462d77787802baff30ce96a5cba063254af782c026ae9be2e2a5e7ca0ff9bbd92fb6e44972186228ee9a62b87ddbe2ef66fb5",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 240
	"ecdsa_secp256r1_sha256_p1363_test.json - 240",
	"042829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffffa01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
	"4d657373616765",
	"96843dd03c22abd2f3b782b170239f90f277921becc117d0404a8e4e36230c28f2be378f526f74a543f67165976de9ed9a31214eb4d7e6db19e1ede123dd991d",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 241
	"ecdsa_secp256r1_sha256_p1363_test.json - 241",
	"04fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f55a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
	"4d657373616765",
	"766456dce1857c906f9996af729339464d27e9d98edc2d0e3b760297067421f6402385ecadae0d8081dccaf5d19037ec4e55376eced699e93646bfbbf19d0b41",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 242
	"ecdsa_secp256r1_sha256_p1363_test.json - 242",
	"04fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f55a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
	"4d657373616765",
	"c605c4b2edeab20419e6518a11b2dbc2b97ed8b07cced0b19c34f777de7b9fd9edf0f612c5f46e03c719647bc8af1b29b2cde2eda700fb1cff5e159d47326dba",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 243
	"ecdsa_secp256r1_sha256_p1363_test.json - 243",
	"04fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f55a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
	"4d657373616765",
	"d48b68e6cabfe03cf6141c9ac54141f210e64485d9929ad7b732bfe3b7eb8a84feedae50c61bd00e19dc26f9b7e2265e4508c389109ad2f208f0772315b6c941",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 244
	"ecdsa_secp256r1_sha256_p1363_test.json - 244",
	"0400000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
	"4d657373616765",
	"b7c81457d4aeb6aa65957098569f0479710ad7f6595d5874c35a93d12a5dd4c7b7961a0b652878c2d568069a432ca18a1a9199f2ca574dad4b9e3a05c0a1cdb3",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 245
	"ecdsa_secp256r1_sha256_p1363_test.json - 245",
	"0400000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
	"4d657373616765",
	"6b01332ddb6edfa9a30a1321d5858e1ee3cf97e263e669f8de5e9652e76ff3f75939545fced457309a6a04ace2bd0f70139c8f7d86b02cb1cc58f9e69e96cd5a",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 246
	"ecdsa_secp256r1_sha256_p1363_test.json - 246",
	"0400000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
	"4d657373616765",
	"efdb884720eaeadc349f9fc356b6c0344101cd2fd8436b7d0e6a4fb93f106361f24bee6ad5dc05f7613975473aadf3aacba9e77de7d69b6ce48cb60d8113385d",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 247
	"ecdsa_secp256r1_sha256_p1363_test.json - 247",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
	"4d657373616765",
	"31230428405560dcb88fb5a646836aea9b23a23dd973dcbe8014c87b8b20eb070f9344d6e812ce166646747694a41b0aaf97374e19f3c5fb8bd7ae3d9bd0beff",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 248
	"ecdsa_secp256r1_sha256_p1363_test.json - 248",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
	"4d657373616765",
	"caa797da65b320ab0d5c470cda0b36b294359c7db9841d679174db34c4855743cf543a62f23e212745391aaf7505f345123d2685ee3b941d3de6d9b36242e5a0",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 249
	"ecdsa_secp256r1_sha256_p1363_test.json - 249",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
	"4d657373616765",
	"7e5f0ab5d900d3d3d7867657e5d6d36519bc54084536e7d21c336ed8001859459450c07f201faec94b82dfb322e5ac676688294aad35aa72e727ff0b19b646aa",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 250
	"ecdsa_secp256r1_sha256_p1363_test.json - 250",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
	"4d657373616765",
	"d7d70c581ae9e3f66dc6a480bf037ae23f8a1e4a2136fe4b03aa69f0ca25b35689c460f8a5a5c2bbba962c8a3ee833a413e85658e62a59e2af41d9127cc47224",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 251
	"ecdsa_secp256r1_sha256_p1363_test.json - 251",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
	"4d657373616765",
	"341c1b9ff3c83dd5e0dfa0bf68bcdf4bb7aa20c625975e5eeee34bb396266b3472b69f061b750fd5121b22b11366fad549c634e77765a017902a67099e0a4469",
	"G",

	# ecdsa_secp256r1_sha256_p1363_test.json - 252
	"ecdsa_secp256r1_sha256_p1363_test.json - 252",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
	"4d657373616765",
	"70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 1
	"ecdsa_secp256r1_sha256_test.json - 1",
	"0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
	"",
	"b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 2
	"ecdsa_secp256r1_sha256_test.json - 2",
	"0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
	"4d7367",
	"530bd6b0c9af2d69ba897f6b5fb59695cfbf33afe66dbadcf5b8d2a2a6538e23d85e489cb7a161fd55ededcedbf4cc0c0987e3e3f0f242cae934c72caa3f43e9",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 3
	"ecdsa_secp256r1_sha256_test.json - 3",
	"0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
	"313233343030",
	"a8ea150cb80125d7381c4c1f1da8e9de2711f9917060406a73d7904519e51388f3ab9fa68bd47973a73b2d40480c2ba50c22c9d76ec217257288293285449b86",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 4
	"ecdsa_secp256r1_sha256_test.json - 4",
	"0404aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad587d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d",
	"0000000000000000000000000000000000000000",
	"986e65933ef2ed4ee5aada139f52b70539aaf63f00a91f29c69178490d57fb713dafedfb8da6189d372308cbf1489bbbdabf0c0217d1c0ff0f701aaa7a694b9c",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 5
	"ecdsa_secp256r1_sha256_test.json - 5",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e184cd60b855d442f5b3c7b11eb6c4e0ae7525fe710fab9aa7c77a67f79e6fadd76",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 7
	"ecdsa_secp256r1_sha256_test.json - 7",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"2ba3a8be6b94d5ec80a6d9d1190a436effe50d85a1eee859b8cc6af9bd5c2e18b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 156
	"ecdsa_secp256r1_sha256_test.json - 156",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"d45c5740946b2a147f59262ee6f5bc90bd01ed280528b62b3aed5fc93f06f739b329f479a2bbd0a5c384ee1493b1f5186a87139cac5df4087c134b49156847db",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 168
	"ecdsa_secp256r1_sha256_test.json - 168",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 169
	"ecdsa_secp256r1_sha256_test.json - 169",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 171
	"ecdsa_secp256r1_sha256_test.json - 171",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 172
	"ecdsa_secp256r1_sha256_test.json - 172",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 173
	"ecdsa_secp256r1_sha256_test.json - 173",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 174
	"ecdsa_secp256r1_sha256_test.json - 174",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 175
	"ecdsa_secp256r1_sha256_test.json - 175",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000000ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 176
	"ecdsa_secp256r1_sha256_test.json - 176",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 177
	"ecdsa_secp256r1_sha256_test.json - 177",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 179
	"ecdsa_secp256r1_sha256_test.json - 179",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 180
	"ecdsa_secp256r1_sha256_test.json - 180",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 181
	"ecdsa_secp256r1_sha256_test.json - 181",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 182
	"ecdsa_secp256r1_sha256_test.json - 182",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 183
	"ecdsa_secp256r1_sha256_test.json - 183",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 192
	"ecdsa_secp256r1_sha256_test.json - 192",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 193
	"ecdsa_secp256r1_sha256_test.json - 193",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325510000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 195
	"ecdsa_secp256r1_sha256_test.json - 195",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 196
	"ecdsa_secp256r1_sha256_test.json - 196",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 197
	"ecdsa_secp256r1_sha256_test.json - 197",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 198
	"ecdsa_secp256r1_sha256_test.json - 198",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 199
	"ecdsa_secp256r1_sha256_test.json - 199",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 200
	"ecdsa_secp256r1_sha256_test.json - 200",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325500000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 201
	"ecdsa_secp256r1_sha256_test.json - 201",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325500000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 203
	"ecdsa_secp256r1_sha256_test.json - 203",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 204
	"ecdsa_secp256r1_sha256_test.json - 204",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 205
	"ecdsa_secp256r1_sha256_test.json - 205",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 206
	"ecdsa_secp256r1_sha256_test.json - 206",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 207
	"ecdsa_secp256r1_sha256_test.json - 207",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 208
	"ecdsa_secp256r1_sha256_test.json - 208",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325520000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 209
	"ecdsa_secp256r1_sha256_test.json - 209",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325520000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 211
	"ecdsa_secp256r1_sha256_test.json - 211",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 212
	"ecdsa_secp256r1_sha256_test.json - 212",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 213
	"ecdsa_secp256r1_sha256_test.json - 213",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 214
	"ecdsa_secp256r1_sha256_test.json - 214",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 215
	"ecdsa_secp256r1_sha256_test.json - 215",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 216
	"ecdsa_secp256r1_sha256_test.json - 216",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 217
	"ecdsa_secp256r1_sha256_test.json - 217",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 219
	"ecdsa_secp256r1_sha256_test.json - 219",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 220
	"ecdsa_secp256r1_sha256_test.json - 220",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 221
	"ecdsa_secp256r1_sha256_test.json - 221",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 222
	"ecdsa_secp256r1_sha256_test.json - 222",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 223
	"ecdsa_secp256r1_sha256_test.json - 223",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000000ffffffffffffffffffffffffffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 224
	"ecdsa_secp256r1_sha256_test.json - 224",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff000000010000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 225
	"ecdsa_secp256r1_sha256_test.json - 225",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff000000010000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 227
	"ecdsa_secp256r1_sha256_test.json - 227",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 228
	"ecdsa_secp256r1_sha256_test.json - 228",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 229
	"ecdsa_secp256r1_sha256_test.json - 229",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632552",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 230
	"ecdsa_secp256r1_sha256_test.json - 230",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 231
	"ecdsa_secp256r1_sha256_test.json - 231",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313233343030",
	"ffffffff00000001000000000000000000000001000000000000000000000000ffffffff00000001000000000000000000000001000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 295
	"ecdsa_secp256r1_sha256_test.json - 295",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3639383139",
	"64a1aab5000d0e804f3e2fc02bdee9be8ff312334e2ba16d11547c97711c898e6af015971cc30be6d1a206d4e013e0997772a2f91d73286ffd683b9bb2cf4f1b",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 296
	"ecdsa_secp256r1_sha256_test.json - 296",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"343236343739373234",
	"16aea964a2f6506d6f78c81c91fc7e8bded7d397738448de1e19a0ec580bf266252cd762130c6667cfe8b7bc47d27d78391e8e80c578d1cd38c3ff033be928e9",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 297
	"ecdsa_secp256r1_sha256_test.json - 297",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"37313338363834383931",
	"9cc98be2347d469bf476dfc26b9b733df2d26d6ef524af917c665baccb23c882093496459effe2d8d70727b82462f61d0ec1b7847929d10ea631dacb16b56c32",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 298
	"ecdsa_secp256r1_sha256_test.json - 298",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130333539333331363638",
	"73b3c90ecd390028058164524dde892703dce3dea0d53fa8093999f07ab8aa432f67b0b8e20636695bb7d8bf0a651c802ed25a395387b5f4188c0c4075c88634",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 299
	"ecdsa_secp256r1_sha256_test.json - 299",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33393439343031323135",
	"bfab3098252847b328fadf2f89b95c851a7f0eb390763378f37e90119d5ba3ddbdd64e234e832b1067c2d058ccb44d978195ccebb65c2aaf1e2da9b8b4987e3b",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 300
	"ecdsa_secp256r1_sha256_test.json - 300",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31333434323933303739",
	"204a9784074b246d8bf8bf04a4ceb1c1f1c9aaab168b1596d17093c5cd21d2cd51cce41670636783dc06a759c8847868a406c2506fe17975582fe648d1d88b52",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 301
	"ecdsa_secp256r1_sha256_test.json - 301",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33373036323131373132",
	"ed66dc34f551ac82f63d4aa4f81fe2cb0031a91d1314f835027bca0f1ceeaa0399ca123aa09b13cd194a422e18d5fda167623c3f6e5d4d6abb8953d67c0c48c7",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 302
	"ecdsa_secp256r1_sha256_test.json - 302",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"333433363838373132",
	"060b700bef665c68899d44f2356a578d126b062023ccc3c056bf0f60a237012b8d186c027832965f4fcc78a3366ca95dedbb410cbef3f26d6be5d581c11d3610",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 303
	"ecdsa_secp256r1_sha256_test.json - 303",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31333531353330333730",
	"9f6adfe8d5eb5b2c24d7aa7934b6cf29c93ea76cd313c9132bb0c8e38c96831db26a9c9e40e55ee0890c944cf271756c906a33e66b5bd15e051593883b5e9902",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 304
	"ecdsa_secp256r1_sha256_test.json - 304",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"36353533323033313236",
	"a1af03ca91677b673ad2f33615e56174a1abf6da168cebfa8868f4ba273f16b720aa73ffe48afa6435cd258b173d0c2377d69022e7d098d75caf24c8c5e06b1c",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 305
	"ecdsa_secp256r1_sha256_test.json - 305",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31353634333436363033",
	"fdc70602766f8eed11a6c99a71c973d5659355507b843da6e327a28c11893db93df5349688a085b137b1eacf456a9e9e0f6d15ec0078ca60a7f83f2b10d21350",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 306
	"ecdsa_secp256r1_sha256_test.json - 306",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"34343239353339313137",
	"b516a314f2fce530d6537f6a6c49966c23456f63c643cf8e0dc738f7b876e675d39ffd033c92b6d717dd536fbc5efdf1967c4bd80954479ba66b0120cd16fff2",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 307
	"ecdsa_secp256r1_sha256_test.json - 307",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130393533323631333531",
	"3b2cbf046eac45842ecb7984d475831582717bebb6492fd0a485c101e29ff0a84c9b7b47a98b0f82de512bc9313aaf51701099cac5f76e68c8595fc1c1d99258",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 308
	"ecdsa_secp256r1_sha256_test.json - 308",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"35393837333530303431",
	"30c87d35e636f540841f14af54e2f9edd79d0312cfa1ab656c3fb15bfde48dcf47c15a5a82d24b75c85a692bd6ecafeb71409ede23efd08e0db9abf6340677ed",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 309
	"ecdsa_secp256r1_sha256_test.json - 309",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33343633303036383738",
	"38686ff0fda2cef6bc43b58cfe6647b9e2e8176d168dec3c68ff262113760f52067ec3b651f422669601662167fa8717e976e2db5e6a4cf7c2ddabb3fde9d67d",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 310
	"ecdsa_secp256r1_sha256_test.json - 310",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"39383137333230323837",
	"44a3e23bf314f2b344fc25c7f2de8b6af3e17d27f5ee844b225985ab6e2775cf2d48e223205e98041ddc87be532abed584f0411f5729500493c9cc3f4dd15e86",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 311
	"ecdsa_secp256r1_sha256_test.json - 311",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33323232303431303436",
	"2ded5b7ec8e90e7bf11f967a3d95110c41b99db3b5aa8d330eb9d638781688e97d5792c53628155e1bfc46fb1a67e3088de049c328ae1f44ec69238a009808f9",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 312
	"ecdsa_secp256r1_sha256_test.json - 312",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"36363636333037313034",
	"bdae7bcb580bf335efd3bc3d31870f923eaccafcd40ec2f605976f15137d8b8ff6dfa12f19e525270b0106eecfe257499f373a4fb318994f24838122ce7ec3c7",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 313
	"ecdsa_secp256r1_sha256_test.json - 313",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31303335393531383938",
	"50f9c4f0cd6940e162720957ffff513799209b78596956d21ece251c2401f1c6d7033a0a787d338e889defaaabb106b95a4355e411a59c32aa5167dfab244726",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 314
	"ecdsa_secp256r1_sha256_test.json - 314",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31383436353937313935",
	"f612820687604fa01906066a378d67540982e29575d019aabe90924ead5c860d3f9367702dd7dd4f75ea98afd20e328a1a99f4857b316525328230ce294b0fef",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 315
	"ecdsa_secp256r1_sha256_test.json - 315",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33313336303436313839",
	"9505e407657d6e8bc93db5da7aa6f5081f61980c1949f56b0f2f507da5782a7ac60d31904e3669738ffbeccab6c3656c08e0ed5cb92b3cfa5e7f71784f9c5021",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 316
	"ecdsa_secp256r1_sha256_test.json - 316",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"32363633373834323534",
	"bbd16fbbb656b6d0d83e6a7787cd691b08735aed371732723e1c68a40404517d9d8e35dba96028b7787d91315be675877d2d097be5e8ee34560e3e7fd25c0f00",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 317
	"ecdsa_secp256r1_sha256_test.json - 317",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31363532313030353234",
	"2ec9760122db98fd06ea76848d35a6da442d2ceef7559a30cf57c61e92df327e7ab271da90859479701fccf86e462ee3393fb6814c27b760c4963625c0a19878",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 318
	"ecdsa_secp256r1_sha256_test.json - 318",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"35373438303831363936",
	"54e76b7683b6650baa6a7fc49b1c51eed9ba9dd463221f7a4f1005a89fe00c592ea076886c773eb937ec1cc8374b7915cfd11b1c1ae1166152f2f7806a31c8fd",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 319
	"ecdsa_secp256r1_sha256_test.json - 319",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"36333433393133343638",
	"5291deaf24659ffbbce6e3c26f6021097a74abdbb69be4fb10419c0c496c946665d6fcf336d27cc7cdb982bb4e4ecef5827f84742f29f10abf83469270a03dc3",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 320
	"ecdsa_secp256r1_sha256_test.json - 320",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31353431313033353938",
	"207a3241812d75d947419dc58efb05e8003b33fc17eb50f9d15166a88479f107cdee749f2e492b213ce80b32d0574f62f1c5d70793cf55e382d5caadf7592767",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 321
	"ecdsa_secp256r1_sha256_test.json - 321",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130343738353830313238",
	"6554e49f82a855204328ac94913bf01bbe84437a355a0a37c0dee3cf81aa7728aea00de2507ddaf5c94e1e126980d3df16250a2eaebc8be486effe7f22b4f929",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 322
	"ecdsa_secp256r1_sha256_test.json - 322",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130353336323835353638",
	"a54c5062648339d2bff06f71c88216c26c6e19b4d80a8c602990ac82707efdfce99bbe7fcfafae3e69fd016777517aa01056317f467ad09aff09be73c9731b0d",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 323
	"ecdsa_secp256r1_sha256_test.json - 323",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"393533393034313035",
	"975bd7157a8d363b309f1f444012b1a1d23096593133e71b4ca8b059cff37eaf7faa7a28b1c822baa241793f2abc930bd4c69840fe090f2aacc46786bf919622",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 324
	"ecdsa_secp256r1_sha256_test.json - 324",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"393738383438303339",
	"5694a6f84b8f875c276afd2ebcfe4d61de9ec90305afb1357b95b3e0da43885e0dffad9ffd0b757d8051dec02ebdf70d8ee2dc5c7870c0823b6ccc7c679cbaa4",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 325
	"ecdsa_secp256r1_sha256_test.json - 325",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33363130363732343432",
	"a0c30e8026fdb2b4b4968a27d16a6d08f7098f1a98d21620d7454ba9790f1ba65e470453a8a399f15baf463f9deceb53acc5ca64459149688bd2760c65424339",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 326
	"ecdsa_secp256r1_sha256_test.json - 326",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31303534323430373035",
	"614ea84acf736527dd73602cd4bb4eea1dfebebd5ad8aca52aa0228cf7b99a88737cc85f5f2d2f60d1b8183f3ed490e4de14368e96a9482c2a4dd193195c902f",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 327
	"ecdsa_secp256r1_sha256_test.json - 327",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"35313734343438313937",
	"bead6734ebe44b810d3fb2ea00b1732945377338febfd439a8d74dfbd0f942fa6bb18eae36616a7d3cad35919fd21a8af4bbe7a10f73b3e036a46b103ef56e2a",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 328
	"ecdsa_secp256r1_sha256_test.json - 328",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31393637353631323531",
	"499625479e161dacd4db9d9ce64854c98d922cbf212703e9654fae182df9bad242c177cf37b8193a0131108d97819edd9439936028864ac195b64fca76d9d693",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 329
	"ecdsa_secp256r1_sha256_test.json - 329",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33343437323533333433",
	"08f16b8093a8fb4d66a2c8065b541b3d31e3bfe694f6b89c50fb1aaa6ff6c9b29d6455e2d5d1779748573b611cb95d4a21f967410399b39b535ba3e5af81ca2e",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 330
	"ecdsa_secp256r1_sha256_test.json - 330",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"333638323634333138",
	"be26231b6191658a19dd72ddb99ed8f8c579b6938d19bce8eed8dc2b338cb5f8e1d9a32ee56cffed37f0f22b2dcb57d5c943c14f79694a03b9c5e96952575c89",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 331
	"ecdsa_secp256r1_sha256_test.json - 331",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33323631313938363038",
	"15e76880898316b16204ac920a02d58045f36a229d4aa4f812638c455abe0443e74d357d3fcb5c8c5337bd6aba4178b455ca10e226e13f9638196506a1939123",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 332
	"ecdsa_secp256r1_sha256_test.json - 332",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"39363738373831303934",
	"352ecb53f8df2c503a45f9846fc28d1d31e6307d3ddbffc1132315cc07f16dad1348dfa9c482c558e1d05c5242ca1c39436726ecd28258b1899792887dd0a3c6",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 333
	"ecdsa_secp256r1_sha256_test.json - 333",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"34393538383233383233",
	"4a40801a7e606ba78a0da9882ab23c7677b8642349ed3d652c5bfa5f2a9558fb3a49b64848d682ef7f605f2832f7384bdc24ed2925825bf8ea77dc5981725782",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 334
	"ecdsa_secp256r1_sha256_test.json - 334",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"383234363337383337",
	"eacc5e1a8304a74d2be412b078924b3bb3511bac855c05c9e5e9e44df3d61e967451cd8e18d6ed1885dd827714847f96ec4bb0ed4c36ce9808db8f714204f6d1",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 335
	"ecdsa_secp256r1_sha256_test.json - 335",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3131303230383333373736",
	"2f7a5e9e5771d424f30f67fdab61e8ce4f8cd1214882adb65f7de94c31577052ac4e69808345809b44acb0b2bd889175fb75dd050c5a449ab9528f8f78daa10c",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 336
	"ecdsa_secp256r1_sha256_test.json - 336",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"313333383731363438",
	"ffcda40f792ce4d93e7e0f0e95e1a2147dddd7f6487621c30a03d710b330021979938b55f8a17f7ed7ba9ade8f2065a1fa77618f0b67add8d58c422c2453a49a",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 337
	"ecdsa_secp256r1_sha256_test.json - 337",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"333232313434313632",
	"81f2359c4faba6b53d3e8c8c3fcc16a948350f7ab3a588b28c17603a431e39a8cd6f6a5cc3b55ead0ff695d06c6860b509e46d99fccefb9f7f9e101857f74300",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 338
	"ecdsa_secp256r1_sha256_test.json - 338",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3130363836363535353436",
	"dfc8bf520445cbb8ee1596fb073ea283ea130251a6fdffa5c3f5f2aaf75ca808048e33efce147c9dd92823640e338e68bfd7d0dc7a4905b3a7ac711e577e90e7",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 339
	"ecdsa_secp256r1_sha256_test.json - 339",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"3632313535323436",
	"ad019f74c6941d20efda70b46c53db166503a0e393e932f688227688ba6a576293320eb7ca0710255346bdbb3102cdcf7964ef2e0988e712bc05efe16c199345",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 340
	"ecdsa_secp256r1_sha256_test.json - 340",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"37303330383138373734",
	"ac8096842e8add68c34e78ce11dd71e4b54316bd3ebf7fffdeb7bd5a3ebc1883f5ca2f4f23d674502d4caf85d187215d36e3ce9f0ce219709f21a3aac003b7a8",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 341
	"ecdsa_secp256r1_sha256_test.json - 341",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"35393234353233373434",
	"677b2d3a59b18a5ff939b70ea002250889ddcd7b7b9d776854b4943693fb92f76b4ba856ade7677bf30307b21f3ccda35d2f63aee81efd0bab6972cc0795db55",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 342
	"ecdsa_secp256r1_sha256_test.json - 342",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31343935353836363231",
	"479e1ded14bcaed0379ba8e1b73d3115d84d31d4b7c30e1f05e1fc0d5957cfb0918f79e35b3d89487cf634a4f05b2e0c30857ca879f97c771e877027355b2443",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 343
	"ecdsa_secp256r1_sha256_test.json - 343",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"34303035333134343036",
	"43dfccd0edb9e280d9a58f01164d55c3d711e14b12ac5cf3b64840ead512a0a31dbe33fa8ba84533cd5c4934365b3442ca1174899b78ef9a3199f49584389772",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 344
	"ecdsa_secp256r1_sha256_test.json - 344",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"33303936343537353132",
	"5b09ab637bd4caf0f4c7c7e4bca592fea20e9087c259d26a38bb4085f0bbff1145b7eb467b6748af618e9d80d6fdcd6aa24964e5a13f885bca8101de08eb0d75",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 345
	"ecdsa_secp256r1_sha256_test.json - 345",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"32373834303235363230",
	"5e9b1c5a028070df5728c5c8af9b74e0667afa570a6cfa0114a5039ed15ee06fb1360907e2d9785ead362bb8d7bd661b6c29eeffd3c5037744edaeb9ad990c20",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 346
	"ecdsa_secp256r1_sha256_test.json - 346",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"32363138373837343138",
	"0671a0a85c2b72d54a2fb0990e34538b4890050f5a5712f6d1a7a5fb8578f32edb1846bab6b7361479ab9c3285ca41291808f27fd5bd4fdac720e5854713694c",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 347
	"ecdsa_secp256r1_sha256_test.json - 347",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"31363432363235323632",
	"7673f8526748446477dbbb0590a45492c5d7d69859d301abbaedb35b2095103a3dc70ddf9c6b524d886bed9e6af02e0e4dec0d417a414fed3807ef4422913d7c",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 348
	"ecdsa_secp256r1_sha256_test.json - 348",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"36383234313839343336",
	"7f085441070ecd2bb21285089ebb1aa6450d1a06c36d3ff39dfd657a796d12b5249712012029870a2459d18d47da9aa492a5e6cb4b2d8dafa9e4c5c54a2b9a8b",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 349
	"ecdsa_secp256r1_sha256_test.json - 349",
	"042927b10512bae3eddcfe467828128bad2903269919f7086069c8c4df6c732838c7787964eaac00e5921fb1498a60f4606766b3d9685001558d1a974e7341513e",
	"343834323435343235",
	"914c67fb61dd1e27c867398ea7322d5ab76df04bc5aa6683a8e0f30a5d287348fa07474031481dda4953e3ac1959ee8cea7e66ec412b38d6c96d28f6d37304ea",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 350
	"ecdsa_secp256r1_sha256_test.json - 350",
	"040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e",
	"313233343030",
	"000000000000000000000000000000004319055358e8617b0c46353d039cdaabffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 351
	"ecdsa_secp256r1_sha256_test.json - 351",
	"040ad99500288d466940031d72a9f5445a4d43784640855bf0a69874d2de5fe103c5011e6ef2c42dcd50d5d3d29f99ae6eba2c80c9244f4c5422f0979ff0c3ba5e",
	"313233343030",
	"ffffffff00000001000000000000000000000000fffffffffffffffffffffffcffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 352
	"ecdsa_secp256r1_sha256_test.json - 352",
	"04ab05fd9d0de26b9ce6f4819652d9fc69193d0aa398f0fba8013e09c58220455419235271228c786759095d12b75af0692dd4103f19f6a8c32f49435a1e9b8d45",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254fffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 353
	"ecdsa_secp256r1_sha256_test.json - 353",
	"0480984f39a1ff38a86a68aa4201b6be5dfbfecf876219710b07badf6fdd4c6c5611feb97390d9826e7a06dfb41871c940d74415ed3cac2089f1445019bb55ed95",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd909135bdb6799286170f5ead2de4f6511453fe50914f3df2de54a36383df8dd4",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 354
	"ecdsa_secp256r1_sha256_test.json - 354",
	"044201b4272944201c3294f5baa9a3232b6dd687495fcc19a70a95bc602b4f7c0595c37eba9ee8171c1bb5ac6feaf753bc36f463e3aef16629572c0c0a8fb0800e",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd27b4577ca009376f71303fd5dd227dcef5deb773ad5f5a84360644669ca249a5",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 355
	"ecdsa_secp256r1_sha256_test.json - 355",
	"04a71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac9575d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000001",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 356
	"ecdsa_secp256r1_sha256_test.json - 356",
	"046627cec4f0731ea23fc2931f90ebe5b7572f597d20df08fc2b31ee8ef16b15726170ed77d8d0a14fc5c9c3c4c9be7f0d3ee18f709bb275eaf2073e258fe694a5",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000003",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 357
	"ecdsa_secp256r1_sha256_test.json - 357",
	"045a7c8825e85691cce1f5e7544c54e73f14afc010cb731343262ca7ec5a77f5bfef6edf62a4497c1bd7b147fb6c3d22af3c39bfce95f30e13a16d3d7b2812f813",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000005",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 358
	"ecdsa_secp256r1_sha256_test.json - 358",
	"04cbe0c29132cd738364fedd603152990c048e5e2fff996d883fa6caca7978c73770af6a8ce44cb41224b2603606f4c04d188e80bff7cc31ad5189d4ab0d70e8c1",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000006",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 359
	"ecdsa_secp256r1_sha256_test.json - 359",
	"042ef747671c97d9c7f9cb2f6a30d678c3d84757ba241ef7183d51a29f52d87c2ea8fb2ea635b761baefc1c4ded2099281b844e13e044c328553bbbafa337d8a76",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000001",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 360
	"ecdsa_secp256r1_sha256_test.json - 360",
	"04931cc49cda4d87d25b1601c56c3b83b4f45e44971998f2d3e7d3c55152214edf058dc140abbba42fc1ddbf30dab8eb9b46ee7338b3f7ee96242bf45e1df5e995",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000003",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 361
	"ecdsa_secp256r1_sha256_test.json - 361",
	"04899a4af61867e3f3c190dbb48f8bc9fc74b70a467a4a1f06477b3af2f39ab8ed47ac000f9ea8a3034939bf48ad5d061a69fc8495ae4df2dbec7effa03a0062b3",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000006",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 362
	"ecdsa_secp256r1_sha256_test.json - 362",
	"04d03eb09913cc20c6a8d0070f0d8d2a7f63527fafa44117fce6bd1ef2aa4ae3c46d5df3f45ac58fa334c6d102381b3120b7a2455600dcaff3d1a845514f12bf46",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000007",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 363
	"ecdsa_secp256r1_sha256_test.json - 363",
	"04d03eb09913cc20c6a8d0070f0d8d2a7f63527fafa44117fce6bd1ef2aa4ae3c46d5df3f45ac58fa334c6d102381b3120b7a2455600dcaff3d1a845514f12bf46",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6325570000000000000000000000000000000000000000000000000000000000000007",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 364
	"ecdsa_secp256r1_sha256_test.json - 364",
	"043a72476291571193b4d109b2c37b59f2807e8fe9cffd804eacded903e77ca0da592dbc74fee0ca7508cc7bc282b0c51a143286ff53c60131668e7a0929e4ed04",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000006ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc75fbd8",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 365
	"ecdsa_secp256r1_sha256_test.json - 365",
	"04d0f73792203716afd4be4329faa48d269f15313ebbba379d7783c97bf3e890d9971f4a3206605bec21782bf5e275c714417e8f566549e6bc68690d2363c89cc1",
	"313233343030",
	"00000000000000000000000000000000000000000000000000000000000001008f1e3c7862c58b16bb76eddbb76eddbb516af4f63f2d74d76e0d28c9bb75ea88",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 366
	"ecdsa_secp256r1_sha256_test.json - 366",
	"044838b2be35a6276a80ef9e228140f9d9b96ce83b7a254f71ccdebbb8054ce05ffa9cbc123c919b19e00238198d04069043bd660a828814051fcb8aac738a6c6b",
	"313233343030",
	"000000000000000000000000000000000000000000000000002d9b4d347952d6ef3043e7329581dbb3974497710ab11505ee1c87ff907beebadd195a0ffe6d7a",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 367
	"ecdsa_secp256r1_sha256_test.json - 367",
	"047393983ca30a520bbc4783dc9960746aab444ef520c0a8e771119aa4e74b0f64e9d7be1ab01a0bf626e709863e6a486dbaf32793afccf774e2c6cd27b1857526",
	"313233343030",
	"000000000000000000000000000000000000001033e67e37b32b445580bf4eff8b748b74000000008b748b748b748b7466e769ad4a16d3dcd87129b8e91d1b4d",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 368
	"ecdsa_secp256r1_sha256_test.json - 368",
	"045ac331a1103fe966697379f356a937f350588a05477e308851b8a502d5dfcdc5fe9993df4b57939b2b8da095bf6d794265204cfe03be995a02e65d408c871c0b",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000100ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 369
	"ecdsa_secp256r1_sha256_test.json - 369",
	"041d209be8de2de877095a399d3904c74cc458d926e27bb8e58e5eae5767c41509dd59e04c214f7b18dce351fc2a549893a6860e80163f38cc60a4f2c9d040d8c9",
	"313233343030",
	"00000000000000000000000000000000000000062522bbd3ecbe7c39e93e7c25ef9f6ba4d97c09d03178fa20b4aaad83be3cf9cb824a879fec3270fc4b81ef5b",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 370
	"ecdsa_secp256r1_sha256_test.json - 370",
	"04083539fbee44625e3acaafa2fcb41349392cef0633a1b8fabecee0c133b10e99915c1ebe7bf00df8535196770a58047ae2a402f26326bb7d41d4d7616337911e",
	"313233343030",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc6324d5555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 371
	"ecdsa_secp256r1_sha256_test.json - 371",
	"04e075effd9607d08d5f34e3652f64cfa3bd6d20c58d0a232f058491260ab212a4cc61760ac8b0680c1b644c03cc628ba9dc4a3c0561368489c692bd40f43aa3ca",
	"313233343030",
	"0000000000000000000000000000000000000000000000009c44febf31c3594f000000000000000000000000000000000000000000000000839ed28247c2b06b",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 372
	"ecdsa_secp256r1_sha256_test.json - 372",
	"04cffb758c3073ea3c08efd9f7f17a85b6ae385c5a140c146ad5f1f5a826718bc8dfdc6bebc894144c6d418ac5d97339726ad2ae925df868426e5628e9f4e62342",
	"313233343030",
	"0000000000000000000000000000000000000009df8b682430beef6f5fd7c7cd000000000000000000000000000000000000000fd0a62e13778f4222a0d61c8a",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 373
	"ecdsa_secp256r1_sha256_test.json - 373",
	"04b98740e69e61a325d5f772e3b5c4f67fb7150b16a9afeca9ddc4afcbb6fa0549c446e814138e4ebc82dbf86a390056d4595dcf45e381fef217a4597d7bd51498",
	"313233343030",
	"000000000000000000000000000000008a598e563a89f526c32ebec8de26367c0000000000000000000000000000000084f633e2042630e99dd0f1e16f7a04bf",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 374
	"ecdsa_secp256r1_sha256_test.json - 374",
	"0484536a270c3932bb2084732adf2c768efc6d3977e5220229ea9a44888b8f9d7b1766398cdac2fc8000017b29a7ba15a58f196037f35f7008ed4286ddff00fd46",
	"313233343030",
	"000000000000000000000000aa6eeb5823f7fa31b466bb473797f0d0314c0bdf000000000000000000000000e2977c479e6d25703cebbc6bd561938cc9d1bfb9",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 375
	"ecdsa_secp256r1_sha256_test.json - 375",
	"048aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e1937387405bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c700000000000000000000000000000000000000000000000000000000000000001",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 376
	"ecdsa_secp256r1_sha256_test.json - 376",
	"048aeb368a7027a4d64abdea37390c0c1d6a26f399e2d9734de1eb3d0e1937387405bd13834715e1dbae9b875cf07bd55e1b6691c7f7536aef3b19bf7a4adf576d",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c700000000000000000000000000000000000000000000000000000000000000000",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 377
	"ecdsa_secp256r1_sha256_test.json - 377",
	"0461722eaba731c697c7a9ba4d0afdbb5713d8aa12b0eab601bb33dbaf792c5adc272cd993b2b663aba5b3a26c101182ff178684945e83879e71598b95fe647dfc",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7002f676969f451a8ccafa4c4f09791810e6d632dbd60b1d5540f3284fbe1889b0",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 378
	"ecdsa_secp256r1_sha256_test.json - 378",
	"04c4c91981e720e20d7e478ff19d09b95a98f58c0f469b72801a8ce844a347316594afcd4188182e7779889b3258d0368ece1e66797fe7c648c6f0b9e26bd71871",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c704e260962e33362ef0046126d2d5a4edc6947ab20e19b8ec19cf79e5908b6e628",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 379
	"ecdsa_secp256r1_sha256_test.json - 379",
	"04d58d47bf49bc8f416641f6f760fcbca80aa52a814e56a5fa40bab44fd6f6317216deaa84d45d8e0e29cc9ecf5653f8ee6444750813becae8deb42b04ba07a634",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70077ed0d8f20f697d8fc591ac64dd5219c7932122b4f9b9ec6441e44a0092cf21",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 380
	"ecdsa_secp256r1_sha256_test.json - 380",
	"0491e305822e5e44f3fdb616e2ef42cd98f241b86e9f68815bc4dba6a945e4eefb3c5937e2ac1d9466f6d65e49b35fc8d75ffc22e1fe2f32af42f5fa3c26f9b4b0",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c703e0292a67e181c6c0105ee35e956e78e9bdd033c6e71ae57884039a245e4175f",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 381
	"ecdsa_secp256r1_sha256_test.json - 381",
	"0424a0bc4d16dbbd40d2fd81a7c3f8d8ec741607d5bb406a0611cc60d0e683bd46b575cad039c15f7f3dffcfc007b4b0f743c871ecc76a504a32672fd84526d861",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7013d22b06d6b8f5d97e0c64962b4a3bae30f668ca6217ef5b35d799f159e23ebe",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 382
	"ecdsa_secp256r1_sha256_test.json - 382",
	"04d24dd06745cafb39186d22a92aa0e58169a79ab69488628a9da5ed3ef747269b7e9209d98faeb95355948adae61d5291c6015d3ee9513486d886fb05cbd25c6a",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c704523ce342e4994bb8968bf6613f60c06c86111f15a3a389309e72cd447d5dd99",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 383
	"ecdsa_secp256r1_sha256_test.json - 383",
	"048200f148e7eab1581bcd1e23946f8a9b8191d9641f9560341721f9d3fec3d63ece795669e0481e035de8623d716a6984d0a4809d6c65519443ee55260f7f3dcb",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7037d765be3c9c78189ad30edb5097a4db670de11686d01420e37039d4677f4809",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 384
	"ecdsa_secp256r1_sha256_test.json - 384",
	"04a8a69c5ed33b150ce8d37ac197070ed894c05d47258a80c9041d92486622024de85997c9666b60a393568efede8f4ca0167c1e10f626e62fc1b8c8e9c6ba6ed7",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7044237823b54e0c74c2bf5f759d9ac5f8cb897d537ffa92effd4f0bb6c9acd860",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 385
	"ecdsa_secp256r1_sha256_test.json - 385",
	"04ed0587e75b3b9a1dd0794f41d1729fcd432b2436cbf51c230d8bc7273273181735a57f09c7873d3964aa8102c9e25fa53070cd924cb7e3a459174740b8b71c34",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70266d30a485385906054ca86d46f5f2b17e7f4646a3092092ad92877126538111",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 386
	"ecdsa_secp256r1_sha256_test.json - 386",
	"04077091d99004a99ee08224e59a46a70495e6fba4eff681c3ce42127e588681ef4f1c16c77dfa440dde18245c9de76243d8f2fd9dea3f2782d6c04974d02f25dc",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70538c7b3798e84d0ce90340165806348971ed44db8f0c674f5f215968390f92ee",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 387
	"ecdsa_secp256r1_sha256_test.json - 387",
	"04616a8b8e57d82c11678f5827911024cd23a16cb52a65f230fb554a7b110c35a5bb466660be5cab3e4b587c12b45bd998bd56c7d66c2f94d03a1a6d2028d8a154",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c706fef0ef15d1688e15e704c4e6bb8bb7f40d52d3af5c661bb78c4ed9b408699b3",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 388
	"ecdsa_secp256r1_sha256_test.json - 388",
	"0471dc92b2b1baa7612c4a53427a0d2dfe548fa9cf829bb6b248f736a5eb30b513f91c7dff1144cb36057c2b859f35bd666a7961833b06de0f45159fbae208e326",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c706f44275e9aeb1331efcb8d58f35c0252791427e403ad84daad51d247cc2a64c6",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 389
	"ecdsa_secp256r1_sha256_test.json - 389",
	"04662f43ae614bd9c90ff3fcded25cf0ef186b6967a47aa6aa7ae7f396594df931f5f94a525edd50d3738f7a28d03d7a2a70095c8f89de9bb2c645fea8d8bac9e0",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7021323755b103d2f9da6ab83eccab9ad8598bcf625652f10e7a3eeee3c3945fb3",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 390
	"ecdsa_secp256r1_sha256_test.json - 390",
	"04dff107959bd2f7386497a5624430a0ab35e552c1a4e4dc9c298caeb96353170dcb5065d7947a676c76287ca8e430324f8a534b0ba6f21200e033c4b88852a3cc",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c706c50acfe76de1289e7a5edb240f1c2a7879db6873d5d931f3c6ac467a6eac171",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 391
	"ecdsa_secp256r1_sha256_test.json - 391",
	"04bd0862b0bfba85036922e06f5458754aafc3075b603a814b3ac75659bf24d7528258a607ffca2cfe05a300cb4c3c4e1963bbb1bc54d320e16969f85aad243385",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70755b7fffb0b17ad57dca50fcefb7fe297b029df25e5ccb5069e8e70c2742c2a6",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 392
	"ecdsa_secp256r1_sha256_test.json - 392",
	"04b533d4695dd5b8c5e07757e55e6e516f7e2c88fa0239e23f60e8ec07dd70f2871b134ee58cc583278456863f33c3a85d881f7d4a39850143e29d4eaf009afe47",
	"313233343030",
	"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 393
	"ecdsa_secp256r1_sha256_test.json - 393",
	"04f50d371b91bfb1d7d14e1323523bc3aa8cbf2c57f9e284de628c8b4536787b86f94ad887ac94d527247cd2e7d0c8b1291c553c9730405380b14cbb209f5fa2dd",
	"313233343030",
	"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a97fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 394
	"ecdsa_secp256r1_sha256_test.json - 394",
	"0468ec6e298eafe16539156ce57a14b04a7047c221bafc3a582eaeb0d857c4d94697bed1af17850117fdb39b2324f220a5698ed16c426a27335bb385ac8ca6fb30",
	"313233343030",
	"7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a97fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a9",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 395
	"ecdsa_secp256r1_sha256_test.json - 395",
	"0469da0364734d2e530fece94019265fefb781a0f1b08f6c8897bdf6557927c8b866d2d3c7dcd518b23d726960f069ad71a933d86ef8abbcce8b20f71e2a847002",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 396
	"ecdsa_secp256r1_sha256_test.json - 396",
	"04d8adc00023a8edc02576e2b63e3e30621a471e2b2320620187bf067a1ac1ff3233e2b50ec09807accb36131fff95ed12a09a86b4ea9690aa32861576ba2362e1",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c7044a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 397
	"ecdsa_secp256r1_sha256_test.json - 397",
	"043623ac973ced0a56fa6d882f03a7d5c7edca02cfc7b2401fab3690dbe75ab7858db06908e64b28613da7257e737f39793da8e713ba0643b92e9bb3252be7f8fe",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 398
	"ecdsa_secp256r1_sha256_test.json - 398",
	"04cf04ea77e9622523d894b93ff52dc3027b31959503b6fa3890e5e04263f922f1e8528fb7c006b3983c8b8400e57b4ed71740c2f3975438821199bedeaecab2e9",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c70aaaaaaaa00000000aaaaaaaaaaaaaaaa7def51c91a0fbf034d26872ca84218e1",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 399
	"ecdsa_secp256r1_sha256_test.json - 399",
	"04db7a2c8a1ab573e5929dc24077b508d7e683d49227996bda3e9f78dbeff773504f417f3bc9a88075c2e0aadd5a13311730cf7cc76a82f11a36eaf08a6c99a206",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffde91e1ba60fdedb76a46bcb51dc0b8b4b7e019f0a28721885fa5d3a8196623397",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 400
	"ecdsa_secp256r1_sha256_test.json - 400",
	"04dead11c7a5b396862f21974dc4752fadeff994efe9bbd05ab413765ea80b6e1f1de3f0640e8ac6edcf89cff53c40e265bb94078a343736df07aa0318fc7fe1ff",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdfdea5843ffeb73af94313ba4831b53fe24f799e525b1e8e8c87b59b95b430ad9",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 401
	"ecdsa_secp256r1_sha256_test.json - 401",
	"04d0bc472e0d7c81ebaed3a6ef96c18613bb1fea6f994326fbe80e00dfde67c7e9986c723ea4843d48389b946f64ad56c83ad70ff17ba85335667d1bb9fa619efd",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd03ffcabf2f1b4d2a65190db1680d62bb994e41c5251cd73b3c3dfc5e5bafc035",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 402
	"ecdsa_secp256r1_sha256_test.json - 402",
	"04a0a44ca947d66a2acb736008b9c08d1ab2ad03776e02640f78495d458dd51c326337fe5cf8c4604b1f1c409dc2d872d4294a4762420df43a30a2392e40426add",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd4dfbc401f971cd304b33dfdb17d0fed0fe4c1a88ae648e0d2847f74977534989",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 403
	"ecdsa_secp256r1_sha256_test.json - 403",
	"04c9c2115290d008b45fb65fad0f602389298c25420b775019d42b62c3ce8a96b73877d25a8080dc02d987ca730f0405c2c9dbefac46f9e601cc3f06e9713973fd",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbc4024761cd2ffd43dfdb17d0fed112b988977055cd3a8e54971eba9cda5ca71",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 404
	"ecdsa_secp256r1_sha256_test.json - 404",
	"045eca1ef4c287dddc66b8bccf1b88e8a24c0018962f3c5e7efa83bc1a5ff6033e5e79c4cb2c245b8c45abdce8a8e4da758d92a607c32cd407ecaef22f1c934a71",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd788048ed39a5ffa77bfb62fa1fda2257742bf35d128fb3459f2a0c909ee86f91",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 405
	"ecdsa_secp256r1_sha256_test.json - 405",
	"045caaa030e7fdf0e4936bc7ab5a96353e0a01e4130c3f8bf22d473e317029a47adeb6adc462f7058f2a20d371e9702254e9b201642005b3ceda926b42b178bef9",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd476d9131fd381bd917d0fed112bc9e0a5924b5ed5b11167edd8b23582b3cb15e",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 406
	"ecdsa_secp256r1_sha256_test.json - 406",
	"04c2fd20bac06e555bb8ac0ce69eb1ea20f83a1fc3501c8a66469b1a31f619b0986237050779f52b615bd7b8d76a25fc95ca2ed32525c75f27ffc87ac397e6cbaf",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd8374253e3e21bd154448d0a8f640fe46fafa8b19ce78d538f6cc0a19662d3601",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 407
	"ecdsa_secp256r1_sha256_test.json - 407",
	"043fd6a1ca7f77fb3b0bbe726c372010068426e11ea6ae78ce17bedae4bba86ced03ce5516406bf8cfaab8745eac1cd69018ad6f50b5461872ddfc56e0db3c8ff4",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd357cfd3be4d01d413c5b9ede36cba5452c11ee7fe14879e749ae6a2d897a52d6",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 408
	"ecdsa_secp256r1_sha256_test.json - 408",
	"049cb8e51e27a5ae3b624a60d6dc32734e4989db20e9bca3ede1edf7b086911114b4c104ab3c677e4b36d6556e8ad5f523410a19f2e277aa895fc57322b4427544",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd29798c5c0ee287d4a5e8e6b799fd86b8df5225298e6ffc807cd2f2bc27a0a6d8",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 409
	"ecdsa_secp256r1_sha256_test.json - 409",
	"04a3e52c156dcaf10502620b7955bc2b40bc78ef3d569e1223c262512d8f49602a4a2039f31c1097024ad3cc86e57321de032355463486164cf192944977df147f",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd0b70f22c781092452dca1a5711fa3a5a1f72add1bf52c2ff7cae4820b30078dd",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 410
	"ecdsa_secp256r1_sha256_test.json - 410",
	"04f19b78928720d5bee8e670fb90010fb15c37bf91b58a5157c3f3c059b2655e88cf701ec962fb4a11dcf273f5dc357e58468560c7cfeb942d074abd4329260509",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd16e1e458f021248a5b9434ae23f474b43ee55ba37ea585fef95c90416600f1ba",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 411
	"ecdsa_secp256r1_sha256_test.json - 411",
	"0483a744459ecdfb01a5cf52b27a05bb7337482d242f235d7b4cb89345545c90a8c05d49337b9649813287de9ffe90355fd905df5f3c32945828121f37cc50de6e",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd2252d6856831b6cf895e4f0535eeaf0e5e5809753df848fe760ad86219016a97",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 412
	"ecdsa_secp256r1_sha256_test.json - 412",
	"04dd13c6b34c56982ddae124f039dfd23f4b19bbe88cee8e528ae51e5d6f3a21d7bfad4c2e6f263fe5eb59ca974d039fc0e4c3345692fb5320bdae4bd3b42a45ff",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd81ffe55f178da695b28c86d8b406b15dab1a9e39661a3ae017fbe390ac0972c3",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 413
	"ecdsa_secp256r1_sha256_test.json - 413",
	"0467e6f659cdde869a2f65f094e94e5b4dfad636bbf95192feeed01b0f3deb7460a37e0a51f258b7aeb51dfe592f5cfd5685bbe58712c8d9233c62886437c38ba0",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd7fffffffaaaaaaaaffffffffffffffffe9a2538f37b28a2c513dee40fecbb71a",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 414
	"ecdsa_secp256r1_sha256_test.json - 414",
	"042eb6412505aec05c6545f029932087e490d05511e8ec1f599617bb367f9ecaaf805f51efcc4803403f9b1ae0124890f06a43fedcddb31830f6669af292895cb0",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdb62f26b5f2a2b26f6de86d42ad8a13da3ab3cccd0459b201de009e526adf21f2",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 415
	"ecdsa_secp256r1_sha256_test.json - 415",
	"0484db645868eab35e3a9fd80e056e2e855435e3a6b68d75a50a854625fe0d7f356d2589ac655edc9a11ef3e075eddda9abf92e72171570ef7bf43a2ee39338cfe",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbb1d9ac949dd748cd02bbbe749bd351cd57b38bb61403d700686aa7b4c90851e",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 416
	"ecdsa_secp256r1_sha256_test.json - 416",
	"0491b9e47c56278662d75c0983b22ca8ea6aa5059b7a2ff7637eb2975e386ad66349aa8ff283d0f77c18d6d11dc062165fd13c3c0310679c1408302a16854ecfbd",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd66755a00638cdaec1c732513ca0234ece52545dac11f816e818f725b4f60aaf2",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 417
	"ecdsa_secp256r1_sha256_test.json - 417",
	"04f3ec2f13caf04d0192b47fb4c5311fb6d4dc6b0a9e802e5327f7ec5ee8e4834df97e3e468b7d0db867d6ecfe81e2b0f9531df87efdb47c1338ac321fefe5a432",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd55a00c9fcdaebb6032513ca0234ecfffe98ebe492fdf02e48ca48e982beb3669",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 418
	"ecdsa_secp256r1_sha256_test.json - 418",
	"04d92b200aefcab6ac7dafd9acaf2fa10b3180235b8f46b4503e4693c670fccc885ef2f3aebf5b317475336256768f7c19efb7352d27e4cccadc85b6b8ab922c72",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdab40193f9b5d76c064a27940469d9fffd31d7c925fbe05c919491d3057d66cd2",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 419
	"ecdsa_secp256r1_sha256_test.json - 419",
	"040a88361eb92ecca2625b38e5f98bbabb96bf179b3d76fc48140a3bcd881523cde6bdf56033f84a5054035597375d90866aa2c96b86a41ccf6edebf47298ad489",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdca0234ebb5fdcb13ca0234ecffffffffcb0dadbbc7f549f8a26b4408d0dc8600",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 420
	"ecdsa_secp256r1_sha256_test.json - 420",
	"04d0fb17ccd8fafe827e0c1afc5d8d80366e2b20e7f14a563a2ba50469d84375e868612569d39e2bb9f554355564646de99ac602cc6349cf8c1e236a7de7637d93",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbfffffff3ea3677e082b9310572620ae19933a9e65b285598711c77298815ad3",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 421
	"ecdsa_secp256r1_sha256_test.json - 421",
	"04836f33bbc1dc0d3d3abbcef0d91f11e2ac4181076c9af0a22b1e4309d3edb2769ab443ff6f901e30c773867582997c2bec2b0cb8120d760236f3a95bbe881f75",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd266666663bbbbbbbe6666666666666665b37902e023fab7c8f055d86e5cc41f4",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 422
	"ecdsa_secp256r1_sha256_test.json - 422",
	"0492f99fbe973ed4a299719baee4b432741237034dec8d72ba5103cb33e55feeb8033dd0e91134c734174889f3ebcf1b7a1ac05767289280ee7a794cebd6e69697",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbfffffff36db6db7a492492492492492146c573f4c6dfc8d08a443e258970b09",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 423
	"ecdsa_secp256r1_sha256_test.json - 423",
	"04d35ba58da30197d378e618ec0fa7e2e2d12cffd73ebbb2049d130bba434af09eff83986e6875e41ea432b7585a49b3a6c77cbb3c47919f8e82874c794635c1d2",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdbfffffff2aaaaaab7fffffffffffffffc815d0e60b3e596ecb1ad3a27cfd49c4",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 424
	"ecdsa_secp256r1_sha256_test.json - 424",
	"048651ce490f1b46d73f3ff475149be29136697334a519d7ddab0725c8d0793224e11c65bd8ca92dc8bc9ae82911f0b52751ce21dd9003ae60900bd825f590cc28",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd7fffffff55555555ffffffffffffffffd344a71e6f651458a27bdc81fd976e37",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 425
	"ecdsa_secp256r1_sha256_test.json - 425",
	"046d8e1b12c831a0da8795650ff95f101ed921d9e2f72b15b1cdaca9826b9cfc6def6d63e2bc5c089570394a4bc9f892d5e6c7a6a637b20469a58c106ad486bf37",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd3fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192aa",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 426
	"ecdsa_secp256r1_sha256_test.json - 426",
	"040ae580bae933b4ef2997cbdbb0922328ca9a410f627a0f7dff24cb4d920e15428911e7f8cc365a8a88eb81421a361ccc2b99e309d8dcd9a98ba83c3949d893e3",
	"313233343030",
	"7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd5d8ecd64a4eeba466815ddf3a4de9a8e6abd9c5db0a01eb80343553da648428f",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 427
	"ecdsa_secp256r1_sha256_test.json - 427",
	"045b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc46963838a40f2a36092e9004e92d8d940cf5638550ce672ce8b8d4e15eba5499249e9",
	"313233343030",
	"6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 428
	"ecdsa_secp256r1_sha256_test.json - 428",
	"045b812fd521aafa69835a849cce6fbdeb6983b442d2444fe70e134c027fc469637c75bf0c5c9f6d17ffb16d2726bf30a9c7aaf31a8d317472b1ea145ab66db616",
	"313233343030",
	"6f2347cab7dd76858fe0555ac3bc99048c4aacafdfb6bcbe05ea6c42c4934569bb726660235793aa9957a61e76e00c2c435109cf9a15dd624d53f4301047856b",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 429
	"ecdsa_secp256r1_sha256_test.json - 429",
	"046adda82b90261b0f319faa0d878665a6b6da497f09c903176222c34acfef72a647e6f50dcc40ad5d9b59f7602bb222fad71a41bf5e1f9df4959a364c62e488d9",
	"313233343030",
	"0000000000000000000000000000000000000000000000000000000000000001555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 431
	"ecdsa_secp256r1_sha256_test.json - 431",
	"04dd86d3b5f4a13e8511083b78002081c53ff467f11ebd98a51a633db76665d25045d5c8200c89f2fa10d849349226d21d8dfaed6ff8d5cb3e1b7e17474ebc18f7",
	"313233343030",
	"555555550000000055555555555555553ef7a8e48d07df81a693439654210c703333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aa9",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 432
	"ecdsa_secp256r1_sha256_test.json - 432",
	"044fea55b32cb32aca0c12c4cd0abfb4e64b0f5a516e578c016591a93f5a0fbcc5d7d3fd10b2be668c547b212f6bb14c88f0fecd38a8a4b2c785ed3be62ce4b280",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 433
	"ecdsa_secp256r1_sha256_test.json - 433",
	"04c6a771527024227792170a6f8eee735bf32b7f98af669ead299802e32d7c3107bc3b4b5e65ab887bbd343572b3e5619261fe3a073e2ffd78412f726867db589e",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 434
	"ecdsa_secp256r1_sha256_test.json - 434",
	"04851c2bbad08e54ec7a9af99f49f03644d6ec6d59b207fec98de85a7d15b956efcee9960283045075684b410be8d0f7494b91aa2379f60727319f10ddeb0fe9d6",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 435
	"ecdsa_secp256r1_sha256_test.json - 435",
	"04f6417c8a670584e388676949e53da7fc55911ff68318d1bf3061205acb19c48f8f2b743df34ad0f72674acb7505929784779cd9ac916c3669ead43026ab6d43f",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc476699783333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 436
	"ecdsa_secp256r1_sha256_test.json - 436",
	"04501421277be45a5eefec6c639930d636032565af420cf3373f557faa7f8a06438673d6cb6076e1cfcdc7dfe7384c8e5cac08d74501f2ae6e89cad195d0aa1371",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997849249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 437
	"ecdsa_secp256r1_sha256_test.json - 437",
	"040d935bf9ffc115a527735f729ca8a4ca23ee01a4894adf0e3415ac84e808bb343195a3762fea29ed38912bd9ea6c4fde70c3050893a4375850ce61d82eba33c5",
	"313233343030",
	"7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997816a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 438
	"ecdsa_secp256r1_sha256_test.json - 438",
	"045e59f50708646be8a589355014308e60b668fb670196206c41e748e64e4dca215de37fee5c97bcaf7144d5b459982f52eeeafbdf03aacbafef38e213624a01de",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296555555550000000055555555555555553ef7a8e48d07df81a693439654210c70",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 439
	"ecdsa_secp256r1_sha256_test.json - 439",
	"04169fb797325843faff2f7a5b5445da9e2fd6226f7ef90ef0bfe924104b02db8e7bbb8de662c7b9b1cf9b22f7a2e582bd46d581d68878efb2b861b131d8a1d667",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b6db6db6249249254924924924924924625bd7a09bec4ca81bcdd9f8fd6b63cc",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 440
	"ecdsa_secp256r1_sha256_test.json - 440",
	"04271cd89c000143096b62d4e9e4ca885aef2f7023d18affdaf8b7b548981487540a1c6e954e32108435b55fa385b0f76481a609b9149ccb4b02b2ca47fe8e4da5",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296cccccccc00000000cccccccccccccccc971f2ef152794b9d8fc7d568c9e8eaa7",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 441
	"ecdsa_secp256r1_sha256_test.json - 441",
	"043d0bc7ed8f09d2cb7ddb46ebc1ed799ab1563a9ab84bf524587a220afe499c12e22dc3b3c103824a4f378d96adb0a408abf19ce7d68aa6244f78cb216fa3f8df",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2963333333300000000333333333333333325c7cbbc549e52e763f1f55a327a3aaa",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 442
	"ecdsa_secp256r1_sha256_test.json - 442",
	"04a6c885ade1a4c566f9bb010d066974abb281797fa701288c721bcbd23663a9b72e424b690957168d193a6096fc77a2b004a9c7d467e007e1f2058458f98af316",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29649249248db6db6dbb6db6db6db6db6db5a8b230d0b2b51dcd7ebf0c9fef7c185",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 443
	"ecdsa_secp256r1_sha256_test.json - 443",
	"048d3c2c2c3b765ba8289e6ac3812572a25bf75df62d87ab7330c3bdbad9ebfa5c4c6845442d66935b238578d43aec54f7caa1621d1af241d4632e0b780c423f5d",
	"313233343030",
	"6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29616a4502e2781e11ac82cbc9d1edd8c981584d13e18411e2f6e0478c34416e3bb",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 444
	"ecdsa_secp256r1_sha256_test.json - 444",
	"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	"313233343030",
	"bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 445
	"ecdsa_secp256r1_sha256_test.json - 445",
	"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
	"313233343030",
	"44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 446
	"ecdsa_secp256r1_sha256_test.json - 446",
	"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
	"313233343030",
	"bb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 447
	"ecdsa_secp256r1_sha256_test.json - 447",
	"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a",
	"313233343030",
	"44a5ad0ad0636d9f12bc9e0a6bdd5e1cbcb012ea7bf091fcec15b0c43202d52e249249246db6db6ddb6db6db6db6db6dad4591868595a8ee6bf5f864ff7be0c2",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 448
	"ecdsa_secp256r1_sha256_test.json - 448",
	"044f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
	"4d657373616765",
	"d434e262a49eab7781e353a3565e482550dd0fd5defa013c7f29745eff3569f19b0c0a93f267fb6052fd8077be769c2b98953195d7bc10de844218305c6ba17a",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 449
	"ecdsa_secp256r1_sha256_test.json - 449",
	"044f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
	"4d657373616765",
	"0fe774355c04d060f76d79fd7a772e421463489221bf0a33add0be9b1979110b500dcba1c69a8fbd43fa4f57f743ce124ca8b91a1f325f3fac6181175df55737",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 450
	"ecdsa_secp256r1_sha256_test.json - 450",
	"044f337ccfd67726a805e4f1600ae2849df3807eca117380239fbd816900000000ed9dea124cc8c396416411e988c30f427eb504af43a3146cd5df7ea60666d685",
	"4d657373616765",
	"bb40bf217bed3fb3950c7d39f03d36dc8e3b2cd79693f125bfd06595ee1135e3541bf3532351ebb032710bdb6a1bf1bfc89a1e291ac692b3fa4780745bb55677",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 451
	"ecdsa_secp256r1_sha256_test.json - 451",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f49726500493584fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
	"4d657373616765",
	"664eb7ee6db84a34df3c86ea31389a5405badd5ca99231ff556d3e75a233e73a59f3c752e52eca46137642490a51560ce0badc678754b8f72e51a2901426a1bd",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 452
	"ecdsa_secp256r1_sha256_test.json - 452",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f49726500493584fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
	"4d657373616765",
	"4cd0429bbabd2827009d6fcd843d4ce39c3e42e2d1631fd001985a79d1fd8b439638bf12dd682f60be7ef1d0e0d98f08b7bca77a1a2b869ae466189d2acdabe3",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 453
	"ecdsa_secp256r1_sha256_test.json - 453",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f49726500493584fa174d791c72bf2ce3880a8960dd2a7c7a1338a82f85a9e59cdbde80000000",
	"4d657373616765",
	"e56c6ea2d1b017091c44d8b6cb62b9f460e3ce9aed5e5fd41e8added97c56c04a308ec31f281e955be20b457e463440b4fcf2b80258078207fc1378180f89b55",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 454
	"ecdsa_secp256r1_sha256_test.json - 454",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f4972650049357b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
	"4d657373616765",
	"1158a08d291500b4cabed3346d891eee57c176356a2624fb011f8fbbf3466830228a8c486a736006e082325b85290c5bc91f378b75d487dda46798c18f285519",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 455
	"ecdsa_secp256r1_sha256_test.json - 455",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f4972650049357b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
	"4d657373616765",
	"b1db9289649f59410ea36b0c0fc8d6aa2687b29176939dd23e0dde56d309fa9d3e1535e4280559015b0dbd987366dcf43a6d1af5c23c7d584e1c3f48a1251336",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 456
	"ecdsa_secp256r1_sha256_test.json - 456",
	"043cf03d614d8939cfd499a07873fac281618f06b8ff87e8015c3f4972650049357b05e8b186e38d41d31c77f5769f22d58385ecc857d07a561a6324217fffffff",
	"4d657373616765",
	"b7b16e762286cb96446aa8d4e6e7578b0a341a79f2dd1a220ac6f0ca4e24ed86ddc60a700a139b04661c547d07bbb0721780146df799ccf55e55234ecb8f12bc",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 457
	"ecdsa_secp256r1_sha256_test.json - 457",
	"042829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffffa01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
	"4d657373616765",
	"d82a7c2717261187c8e00d8df963ff35d796edad36bc6e6bd1c91c670d9105b43dcabddaf8fcaa61f4603e7cbac0f3c0351ecd5988efb23f680d07debd139929",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 458
	"ecdsa_secp256r1_sha256_test.json - 458",
	"042829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffffa01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
	"4d657373616765",
	"5eb9c8845de68eb13d5befe719f462d77787802baff30ce96a5cba063254af782c026ae9be2e2a5e7ca0ff9bbd92fb6e44972186228ee9a62b87ddbe2ef66fb5",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 459
	"ecdsa_secp256r1_sha256_test.json - 459",
	"042829c31faa2e400e344ed94bca3fcd0545956ebcfe8ad0f6dfa5ff8effffffffa01aafaf000e52585855afa7676ade284113099052df57e7eb3bd37ebeb9222e",
	"4d657373616765",
	"96843dd03c22abd2f3b782b170239f90f277921becc117d0404a8e4e36230c28f2be378f526f74a543f67165976de9ed9a31214eb4d7e6db19e1ede123dd991d",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 460
	"ecdsa_secp256r1_sha256_test.json - 460",
	"04fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f55a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
	"4d657373616765",
	"766456dce1857c906f9996af729339464d27e9d98edc2d0e3b760297067421f6402385ecadae0d8081dccaf5d19037ec4e55376eced699e93646bfbbf19d0b41",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 461
	"ecdsa_secp256r1_sha256_test.json - 461",
	"04fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f55a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
	"4d657373616765",
	"c605c4b2edeab20419e6518a11b2dbc2b97ed8b07cced0b19c34f777de7b9fd9edf0f612c5f46e03c719647bc8af1b29b2cde2eda700fb1cff5e159d47326dba",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 462
	"ecdsa_secp256r1_sha256_test.json - 462",
	"04fffffff948081e6a0458dd8f9e738f2665ff9059ad6aac0708318c4ca9a7a4f55a8abcba2dda8474311ee54149b973cae0c0fb89557ad0bf78e6529a1663bd73",
	"4d657373616765",
	"d48b68e6cabfe03cf6141c9ac54141f210e64485d9929ad7b732bfe3b7eb8a84feedae50c61bd00e19dc26f9b7e2265e4508c389109ad2f208f0772315b6c941",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 463
	"ecdsa_secp256r1_sha256_test.json - 463",
	"0400000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
	"4d657373616765",
	"b7c81457d4aeb6aa65957098569f0479710ad7f6595d5874c35a93d12a5dd4c7b7961a0b652878c2d568069a432ca18a1a9199f2ca574dad4b9e3a05c0a1cdb3",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 464
	"ecdsa_secp256r1_sha256_test.json - 464",
	"0400000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
	"4d657373616765",
	"6b01332ddb6edfa9a30a1321d5858e1ee3cf97e263e669f8de5e9652e76ff3f75939545fced457309a6a04ace2bd0f70139c8f7d86b02cb1cc58f9e69e96cd5a",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 465
	"ecdsa_secp256r1_sha256_test.json - 465",
	"0400000003fa15f963949d5f03a6f5c7f86f9e0015eeb23aebbff1173937ba748e1099872070e8e87c555fa13659cca5d7fadcfcb0023ea889548ca48af2ba7e71",
	"4d657373616765",
	"efdb884720eaeadc349f9fc356b6c0344101cd2fd8436b7d0e6a4fb93f106361f24bee6ad5dc05f7613975473aadf3aacba9e77de7d69b6ce48cb60d8113385d",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 466
	"ecdsa_secp256r1_sha256_test.json - 466",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
	"4d657373616765",
	"31230428405560dcb88fb5a646836aea9b23a23dd973dcbe8014c87b8b20eb070f9344d6e812ce166646747694a41b0aaf97374e19f3c5fb8bd7ae3d9bd0beff",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 467
	"ecdsa_secp256r1_sha256_test.json - 467",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
	"4d657373616765",
	"caa797da65b320ab0d5c470cda0b36b294359c7db9841d679174db34c4855743cf543a62f23e212745391aaf7505f345123d2685ee3b941d3de6d9b36242e5a0",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 468
	"ecdsa_secp256r1_sha256_test.json - 468",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015000000001352bb4a0fa2ea4cceb9ab63dd684ade5a1127bcf300a698a7193bc2",
	"4d657373616765",
	"7e5f0ab5d900d3d3d7867657e5d6d36519bc54084536e7d21c336ed8001859459450c07f201faec94b82dfb322e5ac676688294aad35aa72e727ff0b19b646aa",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 469
	"ecdsa_secp256r1_sha256_test.json - 469",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
	"4d657373616765",
	"d7d70c581ae9e3f66dc6a480bf037ae23f8a1e4a2136fe4b03aa69f0ca25b35689c460f8a5a5c2bbba962c8a3ee833a413e85658e62a59e2af41d9127cc47224",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 470
	"ecdsa_secp256r1_sha256_test.json - 470",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
	"4d657373616765",
	"341c1b9ff3c83dd5e0dfa0bf68bcdf4bb7aa20c625975e5eeee34bb396266b3472b69f061b750fd5121b22b11366fad549c634e77765a017902a67099e0a4469",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 471
	"ecdsa_secp256r1_sha256_test.json - 471",
	"04bcbb2914c79f045eaa6ecbbc612816b3be5d2d6796707d8125e9f851c18af015fffffffeecad44b6f05d15b33146549c2297b522a5eed8430cff596758e6c43d",
	"4d657373616765",
	"70bebe684cdcb5ca72a42f0d873879359bd1781a591809947628d313a3814f67aec03aca8f5587a4d535fa31027bbe9cc0e464b1c3577f4c2dcde6b2094798a9",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 475
	"ecdsa_secp256r1_sha256_test.json - 475",
	"04264d796a0dab9b376d34eea6fe297dde1c7b73e53944bc96c8f1e8a6850bb6c9cf5308020eed460c649ddae61d4ef8bb79958113f106befaf4f18876d12a5e64",
	"68656c6c6f2c20776f726c64",
	"0000000000000000000000000000000000000000000000000000000000000005ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 476
	"ecdsa_secp256r1_sha256_test.json - 476",
	"04add76677e54a92e79bbee36a70e1754838273ec4b39295e4018a587290a7fc73f240d625642c943e610d80d953c5c6b8a12760a624ba3b90a0b7902755e1ae79",
	"68656c6c6f2c20776f726c64",
	"0000000000000000000000000000000000000000000000000000000000000006ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 477
	"ecdsa_secp256r1_sha256_test.json - 477",
	"04264d796a0dab9b376d34eea6fe297dde1c7b73e53944bc96c8f1e8a6850bb6c9cf5308020eed460c649ddae61d4ef8bb79958113f106befaf4f18876d12a5e64",
	"68656c6c6f2c20776f726c64",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632556ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 478
	"ecdsa_secp256r1_sha256_test.json - 478",
	"04e7e49dd82812432744fefe723f7f69663214ad1b85c02b2650b4ca0354743a325223c51c415f457aec69cb019bbe3d27585b38f8b79c39dfea6c27c2f0d8146a",
	"68656c6c6f2c20776f726c64",
	"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254effffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 479
	"ecdsa_secp256r1_sha256_test.json - 479",
	"04ce24c99032d52ac6ead23c0ae3ec68ef41e51a281fd457808c83136d7dcce90e8f7a154b551e9f39c59279357aa491b2a62bdebc2bb78613883fc72936c057e0",
	"68656c6c6f2c20776f726c64",
	"0000000000000000000000000000000000000000000000000000000000000003ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"G",

	# ecdsa_secp256r1_sha256_test.json - 480
	"ecdsa_secp256r1_sha256_test.json - 480",
	"04c981c75ddfd3910387eb147098fe5658c43aaaa34c681cd6d514b6ad5b6baa6d14fbddb53a6e6db18e90602bc60f2e736d625765f7f2cca4be76f4eeccf12c18",
	"68656c6c6f2c20776f726c64",
	"0000000000000000000000000000000000000000000000000000000000000004ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 481
	"ecdsa_secp256r1_sha256_test.json - 481",
	"040ec505bc19b14a43e05678cccf07a443d3e871a2e19b68a4da91859a0650f32477300e4f64e9982d94dff5d294428bb37cc9be66117cae9c389d2d495f68b987",
	"68656c6c6f2c20776f726c64",
	"000000000000000000000000000000004319055358e8617b0c46353d039cdab3ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"F",

	# ecdsa_secp256r1_sha256_test.json - 482
	"ecdsa_secp256r1_sha256_test.json - 482",
	"04d42ce21e730f3d2a84e949828574b4dceeb77d4f89556735f34fba03028ee3ed32daf8bfd3f0a7a0821170840f4e032056722386b35d9bdd4f4f450696f4fb52",
	"68656c6c6f2c20776f726c64",
	"00000000ffffffff00000000000000004319055258e8617b0c46353d039cdab4ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc63254e",
	"F",
]

# Inner function for arithmetic tests.
def test_arith_inner(ctx, mod):
    xm = mod.m.value.low
    xmlen = xm.bit_length()
    rsize = (xmlen + 7) >> 3
    mask_m = (1 << xmlen) - 1
    sR = ctx.k * ctx.s
    for i in range(0, 70):
        sh = hashlib.shake_256(b'a' + i.to_bytes(4, byteorder='little'))
        xa = int.from_bytes(sh.digest(rsize), byteorder='little') & mask_m
        xb = int.from_bytes(sh.digest(rsize), byteorder='little') & mask_m
        a = ctx.decode_int(ZRange.exact(xa))
        b = ctx.decode_int(ZRange.exact(xb))

        c = a.montymul(b, mod)
        assert (xa*xb - (c.to_int() << sR)) % xm == 0
        a = -a
        c = a.montymul(b, mod)
        assert (xa*xb + (c.to_int() << sR)) % xm == 0
        b = -b
        c = a.montymul(b, mod)
        assert (xa*xb - (c.to_int() << sR)) % xm == 0

        print('.', end='', flush=True)

# Test basic arithmetic modulo a 256-bit prime (randomize).
def test_arith():
    print('Test basic arithmetics:', end='', flush=True)
    xm = 0xB2E384AEAE51ABA17C3496A1824A69B6AD86AC0BD94E154E96379EC18EF16615
    for i in range(0, 8):
        # We try all 8 combinations of slf, slv and slm.
        print(' ', end='', flush=True)
        ctx = MLIntContext(5, 54, 64, slf=((i & 1) != 0), slv=((i & 2) != 0))
        mod = MLIntModulus(ctx, ZRange.exact(xm), ((i & 4) != 0))
        test_arith_inner(ctx, mod)
    print('')

# Test inversion modulo N (invert_mod).
def test_invert():
    print('Test modular inversion: ', end='', flush=True)
    for i in range(0, 30):
        sh = hashlib.shake_256(b'a' + i.to_bytes(4, byteorder='little'))
        x = int.from_bytes(sh.digest(48), byteorder='little') % mod_N
        state = RunState(bytecode, 5, 54, 64, slf=True)
        state.set_zint(0, ZRange.exact(x))
        run_code(state, labels['invert_mod'], True)
        y = state.get_value(0).to_int()
        assert (x*y - 2**540) % mod_N == 0
        print('.', end='', flush=True)
    print()

# Each sequence of 9 values is three points T1, T2 and T3, with T3 = T1 + T2.
# Each point uses randomized projective coordinates (X:Y:Z).
# Points have been randomly chosen, except that a few tests exercise adding
# a point to itself or to its opposite, or adding the point-at-infinity.
KAT_P256_ARITH = [
    0xDF27945AD6F4C1C188D31DA234A80232784FC95DD72062FAE2804B339F08B844,
    0xAF6F822E9E6F5B4DE07C707E42A9EAA007CE05D7CC95C7D3FC4E7E49A38D7F31,
    0x285898D8FA670E2093A4284540786FE965D2AF20B57671CD44AA64E506E42588,
    0xDE9D5E3B72AE96BF8CC08982AAA92CEA79F16C9B7DA9E3A8A1152DCBFF7F0C95,
    0x7B0CD8288A586A466FD30C8F9D15594A65645A0E45A0A6FAD7598856B09D8ED9,
    0x9ADFFB041EACC0A59B1F028BB777DD77733152F0D55457FD59DCBA5001A26598,
    0xD8E96828EAE92F7A32AC9D861A78BDAE0E35BB3ADF4527D27000CAFE43CCF257,
    0xEF06EE151858F0B7AF9AC86F153E4D39A31D3EF20BCAA455ED43D85E9C032462,
    0xCA13534A068356E9D32401C49AFBDBCB58382757CA716D3E4823949F342E4F23,

    0x296A660BC61D88CCC20FC140E06E87A533CB87FC8DF35044993D8C6842446116,
    0xD59353E241D0724E9FFEC25E7DCE80E23A2CE5B1EF5C42DB6749054513149F60,
    0xE2D1B75F9D74F87B9E5E9EC7C8A638C06FACC06CA102904BAAF0FBF0A7E4A0D1,
    0xCE6A4E394DC19EB23BD21269908F2CB770CBD73BC51040E04BF09F8463A24748,
    0x530919A3712C86C00B6C7498888E0D5B6BD8E019DF2674777B234D9A0BDD1D2A,
    0xC6E3F159984956913889ACDC5375FB4502E3577C460EBA546A34D5EC5E330D2E,
    0x4E94F7034F7CF57584D5B67808326D06338C432CB85AD51C66139B4E5903291B,
    0x7002B026A2B445776C8D142131F4EECF2BA6B132D846F0D60C76E15877FEF473,
    0x6745B08E5977777E9467821040F023FE93410CE8159EBDA81C6D8943A9FDF275,

    0x926DD4D9033DCE06471051DA2CA5B1021673B921430AD1E6D4C3D96D4C531466,
    0x6F44BEE7F1B333210FECE8C9EE99FD903609301D14B033AF030A71927EE24DCA,
    0x23287568AE7A7435C5A165D99816670C23721EF6CFF529AF3AF4704DDA14C13C,
    0xA169E3DAC4DBB295938B1D692E4BA69974419E10189838B9A1AF3D78D032BE5B,
    0xDB9C1967059C1A6565D400CBB2D791B1E354D1CACDD3172A5AECBE2D014D6B23,
    0xDF28F1FE6FD6D209D412ABAB810EC7556CFDBD394A1FCDDE65AFCE395784A33D,
    0xEA29368093F8067F0DE9AF8027A35360E755E9ED51E22AA1BCEE2FB6CAB6873D,
    0x3E6F99E9014EE90E607750EFD020FDDBCF09CD8AC3724186B2E29D3F418AC1CB,
    0x0162DA1C4500BBEA2BE53921F10925F46E15C2F82F3C447B7D8160E95127EDC6,

    0x0833232DB3EDEDB3D4017D0983CB5B23DD5A8CBE9CDFE29D795CBB3AFB3E72EE,
    0x2D38627D59CCD01A2C453A9319D4E06ADB1F21E3B1E22D41E51CC37F98A430A0,
    0x68CB98300C486D7E981847EDB9AA86C4968F2A8BC9E2F1E01EDADBEA38F8947E,
    0x3EA4568CED94EA87366FB5D774C10B6BF475302DB5814A03099EA79B4BFE2D61,
    0x4477FDF5ADDB63930311D368BBC390D385DDB211AD127ABE99BB95B234BABEA9,
    0x452D3BE6179C33F1B4FA6C179C379E92F8FF36DEDAFC272087F8E9A63824D332,
    0xDE14D40ADA956425C3EAA47581110FB9684D01CA7525438F265A1CF01336E8B0,
    0x59BC423D6A25330F9DE4A0738ABC99A8FB6B8F343DEF7A244C88B8D5BB216D96,
    0x15570760F0490583961B32679A8C0D8ACA1CF533947DCB2C56E6476CDDF5E082,

    0x3CA969BC4C315CA11D58F5946ECC913FA567D7CB3783835D5C884A11234A6743,
    0xC6DBD0AFE513D96BBDC25B7E3868A10B7C771AAFF5B8A86C230C73947E3878DA,
    0x30194310F74FEED50F965333D15F63884F9F840552CCADED58CE84EA8B4316F5,
    0x1CCE4FA3CEBF76590221EE6F6D736C0B3B6F2658A83BCF5E144849590A05C8E9,
    0xF73E2040C80DC5FDC2E7FCF978D4C290050EAB2CBD52502174FEC30D382878C4,
    0x401D7230E07F839F7B74D3ED273DF39ADFCF08F0E74177C0905303E6BBB5CD55,
    0x68E561D23AF2F9D8D11046355DC12F59AD7F14B0E10C7459B1315CDFFB3BFE0C,
    0xE02C702BE2EEC409DAA4ED3B2FC361EC457021EDE5D42547047F58EFF6459944,
    0x7CEFAC9F25F7193FD539B093269ADAC0A7B982181179F756615F75B286C857DB,

    0x31608B3996EC28C4B4FD115B3911AA00871A65E28469C77584839BCEC27C44AE,
    0x79EC33CDE96830E1DA33D657DFF31EBE0A366F011C69C89A6EEA090D69182C51,
    0x80340A564C6FD3CFEA2B82B985802E7A53904BDD52D543FD33D352600AD1F142,
    0xE6A346BC91A9DD588542E959FE6E4102D115DC839415FB8F056B082707EF1828,
    0x5C8338CF5B4912AE1A552A1247EEF4D3C46D9DD848DC6707E8F17EEF338C8B73,
    0x0AA31A5DA373107698CD1EA4479A6F1681569BB0593189FCDD971FCBC5C5CF97,
    0xD9A35E77F7A4252D1286750AA7A687A2416B2B99737F4015D43D0EF34AFFC1E8,
    0x83E00D20F90B8AA2B5165BBC2A4DABD2C472DAE661DB16B0E420264F628C931E,
    0xFA338CCD9A074C9F9619431897EAA6E75D977BFCA244476898787FD0A3243DC1,

    0xA986AB7142E45B3266FF079F40B7B7DC0B5E5BC548D5A47DF1A849271A351BE9,
    0x75E081979724330E546753B0C2F79088CF7DE380B759D619A8DCDA505DCADA01,
    0xA2E3C8D06AAA708587961A8DDFCEF997754BFBE565351DCEDAEBD5022EEEEB97,
    0x8E26AAE2987AEFE8086A905D6481AC3D8AFA5BB4338EC33058675D2315908697,
    0xAF81E1ED99928B63A645F2E474CD976832C8E762F76EE2CACF7E7EF9C176775B,
    0x5081C549A0D8A19A2E30E3F087D5ED5A016216A696A4230F01113BD85A1BBC89,
    0xC7C148F270A8D042186DBF985D8AEF6D2DF55DE03F552D8839897BDC07B59C12,
    0x2151AA0ACFDD25423A6F12B39D4FFFCF145DE99FC639CC7272C4D1A475356354,
    0x01AE4637D9124371A8916DBEBAD36EB731D724FF3F84CCBE7F58C42F6B532ABA,

    0x25D51B4DFCD78BC04ACC3B5D8414C5D850053DD5A84E821B20CED32E93499030,
    0xE3FF64404142403772E79A4CB5F5C009B531E25D1F44D4653570276D883C3793,
    0x21AACEA371A51B37F054404313C8FDFAC920B76A67851B20BFC8D1CE4225CB31,
    0xC1087525F90E3B52BA3174194A22ECAF385CAC7570A8076A44871A89DB8592D0,
    0xAF494F43A371BAD83CF813490B52C2A5FCB732F83F1B317F7B7BA42F3E2E588E,
    0xCDC959937447B643BE617BD4AF21115D36B117B15CC893E2B0DD7E0C61F1C0FD,
    0x2C8DC8E13AD1D88B6D09AA6B2607286CF7D2CD57BF9B66F6643954531AA6D04E,
    0xFD22D4F3F7C2CE12D3360BFA398CF953D4388DB04C69BDE2680F23A23A0C3151,
    0x16A512A303B516A4A4EC9E31541E37C715428B91706C75B440997A799743D669,

    0x8D6A5465CF6AA5548D94CDF328B50A85B0F9E93B3EBF8D65752535288BE89CC6,
    0xF7A9183C92F2ECF799DF53A78A2AD6F610E6803042B74FD6F8FA7D71CF925A2A,
    0xE69FC095B9A9B906608EB5870350F68D5B098686919B23D981A0F22E112D9730,
    0x5CCF1C728E45D01E6BFAE02177D48B2DA7A58A723AA935F2D00FEAE5F10B47D8,
    0x36EAD5DB70D1DD51ED50648189A8BBDF6EDFFB236A1369093C3DAE343E63E6DF,
    0x17793918C771A49B5ED271AF17EA3CC73C804A3C2591A18437CC33758F431BFE,
    0x3B3F4BA39A239B5A6850CA05667558832BE466CF61EDF289B5F5D7B1A97E8066,
    0xC7C3898ED8BCE26649A6340C6FBE09378C7B5EB217F33A39AED8C46EC8075BF9,
    0x133026F99120A2EA95EC9C4DDA6288255C78EE60D59D20BBF8EBF4B37B1823C4,

    0x0532CBD704E931964D78B5B2BDBF37D1252E6610ED881BA5C74BB2A18C80AAED,
    0x36B96E1E5A47868B8B79941D3E338961288F53A18CD07890ABE9969D6F8C0581,
    0xF1E3EE761C6437F7DA975436100CB952B777B1C62D537791B2DC78138D3030CF,
    0xA4354029EC954A5C178AFDE6F992E19DD0D39353F87485121D04032BA392A2FE,
    0x1ACF90E1FA25177CAFEC7B46F03496E4DE0C1CB75CC0F66D8DB1C726E2416D23,
    0x8ACC2ECF904613835FAE889F7F314DD4927F121FFE0416090712F75220557D02,
    0x4996BB72FCA06C9AE13BE521306C49474A42C10AAF3B4E8668F29FE247524CA3,
    0x3F181F509D952AF288538823253A153D9E0518EA549AA710ED8346A0E423E3FB,
    0x6A38A3204635A4DA1BF6CDA8CCCE7A57DC131B1BD75234442AA82D8D621DB300,

    # T1 = T2
    0x543CE14010551182077AB63CF1D1373DE773E40E50E9613A54F71A4F4FADA269,
    0x14BA8A7834B0F30E2FFED7C7706E3D7B5FBA610D80722F2C087169127E9F9600,
    0xCB662FBB541FD8A22FA5E122FDBD89D8CE8AA024F2890E558781E3DFB8FA8208,
    0x606BA274568DACF7C2992DCA5C45248FF184E59CAC348CCC9DC9A3DAD4ED283D,
    0x8DEC58250CC7D99B763923FBD837D50AD7425E36BB12624017136D9E5A7F0E9A,
    0x79A72C3B078DE7F1A96ABCEE833CE624BB33C874C7C8E4B0A5F7A2783DB5C8E4,
    0xF7C61DF0CDFF9818F4479AA0B11DFF716B9F4063ED0E7E6202A82B65AF93B45E,
    0x9F097A2AD0D554408BF54C1A361138E26AD154B46934B16AFC5DC8520E8261DE,
    0x9FB2C33EFCB105898FCAF2CB33847D232985C1F8165C844228B6D296F0B5D641,

    # T1 = -T2
    0xE63B45ADA81C67278187D775C325334F120B0C4B2E3EF8B80F3591623DA72EC9,
    0xC6D93C64E15EC519A2744AD13FD77EFE16A02151D963DB322983CA2547F08E5E,
    0x96D4D27A74E78F335A02B6075D2A5BD3DC03612289C5692974968994B072EE38,
    0x9D65607C3C99D3896A632BB619827E7315C0B5C9D9A1D45659ECEA0BE8477192,
    0x2C2B668283211624A3BBE6B37A3281FAC23ACDCF2575DD64DD0C887760A69F24,
    0xCB53B2EFB953631351B0D101437FD5CB3A6D3D5604AD1F3A7363838C7BD1129B,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0xB386133C4145535F64A4F3D2D05475F96AAE3183A23C0142D3272861181B0120,
    0x0000000000000000000000000000000000000000000000000000000000000000,

    # T1 = infinity
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x620FC45F9614AFA47420ABFED7D21ADF8F04F7751AC000B02113813C1022BB22,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x184BB15CED50911FE2BA3164D7117C94FD2CE87DD38CAE596D1A9E6DDDEF4E09,
    0x4E07E85EA96A41F6FC82F0D9AA5A4660ECED9AF93BBDBAE3282A4700FCF02EC1,
    0x87C20AD5433CBEBC1370ECB59BC9AD820639738F276AC12A77F24A68E82CCA00,
    0x643529C10020E97B36E11C68AEF60EF83939ED1995550A5A30C274C3E52581CC,
    0x73C145A16966A932895A729BCDA377697278A4D1E2A0EA665707D5C0C67D353B,
    0x80DD95076EE7DC83B0DC0E4F440B2B52966B7B7FC41730FE54786464351DC8D8,

    # T2 = infinity
    0xF0FB04C1D4965C669E6012F1A9BC41D774760A26AAFD8389DBA5D6E9CDF64B5C,
    0xC4DE12BF980DB5A440529AAAEA741DA05FF71E1F495D08FFC9428003FA454E75,
    0xF547399C79465258FF93DB95331395C84CDBE095CB0FA7C40140EF5011FB6323,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x8EF49ACCCC37C52BBD6407A3DA7073958200B102D512C4C684C555623DCD3018,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x1441A5B3BBD97E7D5235940A309EBE2B99784EA6E987CBB2B69698409C876B33,
    0x4ACC3056BBA6D9D8DD9AC7EDB5F2F971FC891D534516B55E8450121F2493A39F,
    0x0E229B22069B5603F0E51E19E0384A2A4A8A8E2941B57830333F03D26AEE072B,

    # T1 = T2 = infinity
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x6B8A374C38FE902E07911CD3D26CB03C6FD2B5747725B5F902B3E4133D1DE0C5,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x5A21A9FEC40EF2D16CFB52EA89324B252EA76CD93688A7BEDFFAEF27019CF5DF,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0x0000000000000000000000000000000000000000000000000000000000000000,
    0xB868B7CE74CEE19CCBD96B8EDD0AE68BD1815B4EEA0C9888316F81C1471515BD,
    0x0000000000000000000000000000000000000000000000000000000000000000,
]

# Test elliptic curve point addition (in P-256) (point_add_to_W).
def test_point_add():
    print('Test curve point addition: ', end='', flush=True)
    p = mod_P
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    bm = (b << 270) % mod_P
    i = 0
    while i < len(KAT_P256_ARITH):
        X1 = KAT_P256_ARITH[i + 0]
        Y1 = KAT_P256_ARITH[i + 1]
        Z1 = KAT_P256_ARITH[i + 2]
        X2 = KAT_P256_ARITH[i + 3]
        Y2 = KAT_P256_ARITH[i + 4]
        Z2 = KAT_P256_ARITH[i + 5]
        X3 = KAT_P256_ARITH[i + 6]
        Y3 = KAT_P256_ARITH[i + 7]
        Z3 = KAT_P256_ARITH[i + 8]
        i += 9
        state = RunState(bytecode, 5, 54, 64, slf=True)
        state.mod = state.modp
        state.set_zint(bytecode_constants['_Bm'], ZRange.exact(bm))
        state.set_zint(bytecode_constants['_Wx'], ZRange.exact(X1))
        state.set_zint(bytecode_constants['_Wy'], ZRange.exact(Y1))
        state.set_zint(bytecode_constants['_Wz'], ZRange.exact(Z1))
        state.set_zint(bytecode_constants['_Hx'], ZRange.exact(X2))
        state.set_zint(bytecode_constants['_Hy'], ZRange.exact(Y2))
        state.set_zint(bytecode_constants['_Hz'], ZRange.exact(Z2))
        run_code(state, labels['point_add_to_W'], True)
        X4 = state.get_value(bytecode_constants['_Wx']).to_int() % p
        Y4 = state.get_value(bytecode_constants['_Wy']).to_int() % p
        Z4 = state.get_value(bytecode_constants['_Wz']).to_int() % p
        if Z3 == 0:
            assert X4 == 0
            assert Y4 != 0
            assert Z4 == 0
        else:
            assert Z3 != 0
            assert (X3*Z4 - X4*Z3) % p == 0
            assert (Y3*Z4 - Y4*Z3) % p == 0
        print('.', end='', flush=True)
    print()

# Aggregate function which runs the core tests (basic arithmetic operations;
# modular inversions, curve point addition).
def test_core():
    test_arith()
    test_invert()
    test_point_add()

# Run all ECDSA test vectors from Wycheproof. For each test vector, exact
# ranges are used, so all conditionals (skip opcodes) can be evaluated, and
# the execution yields the proper signature verification status.
# For parameters, see explanations at the top of this file.
def test_ecdsa(k, s, w, slf=False, slv=False, slm=False, spec=0):
    i = 0
    while (i + 5) <= len(KAT_ECDSA_P256_SHA256_VERIFY):
        ident = KAT_ECDSA_P256_SHA256_VERIFY[i + 0]
        s_pub = KAT_ECDSA_P256_SHA256_VERIFY[i + 1]
        s_msg = KAT_ECDSA_P256_SHA256_VERIFY[i + 2]
        s_sig = KAT_ECDSA_P256_SHA256_VERIFY[i + 3]
        status = KAT_ECDSA_P256_SHA256_VERIFY[i + 4]
        i += 5
        pub = bytes.fromhex(s_pub)
        msg = bytes.fromhex(s_msg)
        sig = bytes.fromhex(s_sig)
        sh = hashlib.sha256()
        sh.update(msg)
        hv = sh.digest()
        if len(pub) != 65 or pub[0] != 0x04 or len(sig) != 64:
            assert status == 'F'
            print('.', end='', flush=True)
            continue
        qx = int.from_bytes(pub[1:33], byteorder='big')
        qy = int.from_bytes(pub[33:65], byteorder='big')
        r = int.from_bytes(sig[0:32], byteorder='big')
        s = int.from_bytes(sig[32:64], byteorder='big')
        e = int.from_bytes(hv[0:32], byteorder='big')
        state = RunState(bytecode, 5, 54, 64, slf=slf, slv=slv, slm=slm)
        state.spec |= spec
        state.set_zint(bytecode_constants['_Qx'], ZRange.exact(qx))
        state.set_zint(bytecode_constants['_Qy'], ZRange.exact(qy))
        state.set_zint(bytecode_constants['_Kr'], ZRange.exact(r))
        state.set_zint(bytecode_constants['_Ks'], ZRange.exact(s))
        state.set_zint(bytecode_constants['_Ke'], ZRange.exact(e))
        run_code(state, labels['entry'], False)
        assert state.exit != 0
        if state.exit < 0:
            assert status == 'G'
        else:
            assert status == 'F'
        print('.', end='', flush=True)
    print('')

#def print_state(state):
#    for i in range(0, 32):
#        print('%2d: %s' % (i, state.get_value(i).value))

#def print_W_range(state):
#    print('count = %d' % state.count)
#    print('Wx = %s' % state.get_value(bytecode_constants['_Wx']).value)
#    print('Wy = %s' % state.get_value(bytecode_constants['_Wy']).value)
#    print('Wz = %s' % state.get_value(bytecode_constants['_Wz']).value)

#def get_max_W(state):
#    state.max_Wx = state.max_Wx.union(state.get_value(bytecode_constants['_Wx']).value)
#    state.max_Wy = state.max_Wx.union(state.get_value(bytecode_constants['_Wy']).value)
#    state.max_Wz = state.max_Wx.union(state.get_value(bytecode_constants['_Wz']).value)

def check_canon_modn(state):
    x = state.get_value(0).value
    #print('mod(n): %s' % x)
    assert x.low >= 0 and x.high <= mod_N - 1

def check_canon_modp(state):
    x = state.get_value(0).value
    #print('mod(p): %s' % x)
    assert x.low >= 0 and x.high <= mod_P - 1

# Run the complete range analysis. It verifies that none of the internal
# computations overflows, and that integer canonicalizations necessarily
# work (i.e. yield a value in [0, m-1] for modulus m).
# For parameters, see explanations at the top of this file.
def range_analysis(k, s, w, slf=False, slv=False, slm=False, spec=0):
    state = RunState(bytecode, k, s, w, slf=slf, slv=slv, slm=slm)
    state.spec |= spec
    range256 = ZRange(0, (1 << 256) - 1)
    state.set_zint(bytecode_constants['_Qx'], range256)
    state.set_zint(bytecode_constants['_Qy'], range256)
    state.set_zint(bytecode_constants['_Kr'], range256)
    state.set_zint(bytecode_constants['_Ks'], range256)
    state.set_zint(bytecode_constants['_Ke'], range256)
    state.max_Wx = ZRange.ZERO
    state.max_Wy = ZRange.ZERO
    state.max_Wz = ZRange.ZERO
    mm = {}
    #mm[labels['inspect_point_add_to_W']] = get_max_W
    mm[labels['inspect_canon_modn_1']] = check_canon_modn
    mm[labels['inspect_canon_modn_2']] = check_canon_modn
    mm[labels['inspect_canon_modp']] = check_canon_modp
    run_code(state, labels['entry'], False, mm)
    #print('Wx -> %s' % state.max_Wx)
    #print('Wy -> %s' % state.max_Wy)
    #print('Wz -> %s' % state.max_Wz)
    print('OK')

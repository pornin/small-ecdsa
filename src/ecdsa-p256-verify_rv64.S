	.file	"ecdsa-p256-verify_rv64.S"
	.attribute	4, 16  # stack alignment
	.attribute	5, "rv64i2p1_m2p0_c2p0"
	.text

# ========================================================================
# PLATFORM COMPATIBILITY
#
# This code assumes a which supports the RV64I (base integer) instructions,
# as well as the M (multiplication) and C (compressed) instructions. It
# does not use divisions, so that M could really be the Zmmul subset.
# The implementation follows the standard ABI amd does not make unaligned
# memory accesses.
# ========================================================================

# ========================================================================
# void decode_int(gf *d, const uint8_t *src)
# Decode value from the source (32 bytes, unsigned, big-endian) into
# the destination (five 54-bit limbs, little-endian). Output is
# normalized and non-negative.
# SPECIAL ABI: on output:
#    a0 = (uint8_t *)d + 40
#    a1 = src + 32
# Clobbers: a2..a5, t0
# ========================================================================

	.type	decode_int, %function
	# WARNING: IF THIS FUNCTION IS MODIFIED, THE BYTE ADJUSTMENT IN
	# INTERPRETER_BEGIN MUST BE CORRECTED.
decode_int:
	li	a5, -32      # loop counter
	sub	a1, a1, a5   # move source to end
	mv	t0, a1
	li	a3, 0        # source bits accumulate here
	li	a4, 0        # current bit offset within a3
Ldecode_int__loop:
	addi	t0, t0, -1
	lbu	a2, (t0)     # get next byte (in low-to-high order)
	sll	a2, a2, a4   # shift byte into position
	or	a3, a3, a2   # plug byte into bit accumulator
	addi	a4, a4, 8    # acount for 8 extra bits
	slti	a2, a4, 54   # check whether we have a full limb
	bnez	a2, Ldecode_int__cont
	slli	a2, a3, 10   # truncate limb to 54 bits (step 1)
	srli	a2, a2, 10   # truncate limb to 54 bits (step 2)
	sd	a2, (a0)     # store new limb
	addi	a0, a0, 8
	srli	a3, a3, 54   # update bit accumulator after limb removal
	addi	a4, a4, -54  # update bit count
Ldecode_int__cont:
	addi	a5, a5, 1
	bnez	a5, Ldecode_int__loop
	sd	a3, (a0)
	addi	a0, a0, 8
	ret
	.size	decode_int, . - decode_int

# ========================================================================
# INTEGER FORMATS
#
# All values are nominally signed integers, kept over five limbs in base
# 2^54 (little-endian order). Limbs are signed and may exceed the 54-bit
# range. Exact allowed range depends on the involved value (an extensive
# range analysis, done externally, shows that all the operations here
# remain within the allowed ranges).
#
# A value is said to be _normalized_ if limbs 0 to 3 are in [0, 2^54 - 1].
# For a normalized value:
#  - The value is negative if and only if the top limb (limb 4) is negative.
#  - The value is zero if and only if all five limbs are zero.
#
# These integers nominally represent values modulo a 256-bit prime m which
# is either p (for the coordinate field) or n (for the scalar field).
# Addition and subtraction are done limb-wise, and thus do not depend on
# the involved modulus. Multiplication is done via the Montgomery
# multiplication:
#  - Let R = 2^270.
#  - Montgomery multiplication of x and y computes (x*y)/R modulo m.
#  - The Montgomery representation of x is x*R mod m. The Montgomery
#    multiplication of the x*R and y*R yields (x*y)*R, i.e. the
#    Montgomery multiplication does compute modular multiplication as
#    long as inputs and outputs are in Montgomery representation.
#
# A _fully reduced value_ is one which is normalized and also such that
# it is (as an integer) in the [-m/2,+m/2] range. Montgomery multiplication
# returns a normalized value, but not necessarily fully reduced modulo m.
# _Montgomery reduction_ is a Montgomery multiplication with the value 1;
# it is equivalent to dividing the value by R. Montgomery reduction outputs
# a value which is not only normalized but also fully reduced.
#
# A _canonical_ value is one that is normalized and also in the [0, m-1]
# range. A canonical value can be obtained from a fully reduced value by
# adding m if and only if the fully reduced value is negative.
#
# Since Montgomery reduction is also division by R, it can be viewed as
# a function that converts the Montgomery representation x*R into x.
# Normally, generic functions for modular arithmetics also provide a way
# to do the conversion in the other direction, which can be done by
# doing a Montgomery multiplication with the (precomputed) constant
# R^2 mod m. This is not provided here because this is not really needed
# in our case: the conversion to Montgomery representation can be subsumed
# into the use of projective coordinates for elliptic curve points. Indeed,
# a point (x,y) is represented as a triplet (X:Y:Z) such that x = X/Z and
# y = Y/Z. In particular, we can consider that (x:y:1) uses the Montgomery
# representations of X = x*(1/R), Y = y*(1/R) and Z = 1*(1/R), respectively,
# so that the affine, plain integer coordinates can be used as is as the
# Montgomery representation of a valid triplet for the same point.
# ========================================================================

	.balign	2

# Curve constants, in that order:
#   Gx           curve generator point, X coordinate
#   Gy           curve generator point, Y coordinate
#   Bm           curve parameter b (Montgomery representation with R = 2^270)
#   mod_scalar   modulus n (scalar field)
#   n0i          (-1/n mod 2^54)*2^10 (one 64-bit word)
#   mod_coord    modulus p (coordinate field)
# All values (except n0i) use unsigned big-endian encoding (32 bytes per value).
# WARNING: values MUST NOT be separated or reordered.
# WARNING: the bytecode must follow immediately after the curve constants.
curve_constants:
	# Gx*2^270 mod p
	.byte	0x17, 0xDD, 0xAF, 0x71, 0xD5, 0x71, 0x98, 0x5A
	.byte	0xDC, 0xCA, 0xDD, 0xD8, 0x89, 0x44, 0x1D, 0x6E
	.byte	0xA5, 0x7F, 0x11, 0xD7, 0x6D, 0x80, 0x5E, 0x79
	.byte	0xCC, 0x35, 0x06, 0x2A, 0x45, 0x0F, 0x06, 0x24
	# Gy*2^270 mod p
	.byte	0x7F, 0xC6, 0x2A, 0xBE, 0x17, 0x61, 0x53, 0x5E
	.byte	0x21, 0xA2, 0x37, 0x48, 0x7C, 0xC9, 0x62, 0xD2
	.byte	0xAE, 0x39, 0x0D, 0x2A, 0x79, 0x17, 0x37, 0x7C
	.byte	0x94, 0xD5, 0xF3, 0xA5, 0x55, 0x82, 0xA1, 0x5C
	# n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
	.byte	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
	.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	.byte	0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84
	.byte	0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
	# n0i = (-1/n mod 2^54)*2^10
	.quad	0x4722ABB802F13C00
	# p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
	.byte	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01
	.byte	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	.byte	0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
	.byte	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
	# Value p0i = (-1/p mod 2^54)*2^10 is equal to 0x400, it is
	# hardcoded in the INTERPRETER_MAIN macro.

# -------------------------------------------------------------------------
# BEGIN BYTECODE
# -------------------------------------------------------------------------

# ========================================================================
# Custom virtual machine.
#
# We use an interpreter for a virtual machine with a few instructions.
# The instructions are specialized for the problem at hand. Each
# instruction fits on one byte (except CALL, which uses two bytes).
# The VM works with 32 values (numbered 0 to 31); each value holds an
# integer in 5-limb format:
#  - Value 0 is the accumulator; it is used as source and/or destination
#    operand by many of the instructions.
#  - Value 1 contains the current modulus (which can be set to either
#    mod_N or mod_P with the SMOD instruction); it can be read, but not
#    written to.
#  - Values 2 to 31 are other values. A few are preloaded with constants,
#    which in general should not be modified by code:
#       2    ONE (the integer value 1)
#       30   Gx (x coordinate of generator point, affine, Montgomery)
#       31   Gy (y coordinate of generator point, affine, Montgomery)
#    All other values are initialized at zero. Value 28 is conventionally
#    considered to be "the" constant ZERO.
# Symbolic names are defined for modifiable values; from the VM point of
# view, these values are nothing special, but the bytecode uses them to
# organize its ECDSA subroutines:
#        3       Kr         r (first signature half)
#        4       Ks         s (second signature half)
#        5       Ke         e (reduced hash value)
#        6       Qx         x coordinate of public key
#        7       Qy         y coordinate of public key
#        8       Wx         X coordinate of work point W (projective)
#        9       Wy         Y coordinate of work point W (projective)
#       10       Wz         Z coordinate of work point W (projective)
#       11       Hx         X coordinate of work point H (projective)
#       12       Hy         Y coordinate of work point H (projective)
#       13       Hz         Z coordinate of work point H (projective)
#       16..25   T0 to T9   temporaries
# The tv_ecdsa_p256_verify() function, when setting up the interpreter,
# loads Kr, Ks, Ke, Qx and Qy with the relevant values, freshly decoded
# from the paramters (signature, hash value and public key). The values
# are decoded into 5-limb format but not otherwise checked; the bytecode
# is responsible for verifying that:
#    0 < r < n
#    0 < s < n
#    0 <= Qx < p
#    0 <= Qy < p
#    (Qx,Qy) is a point on the curve
#
# Instructions are the following:
#
#    encoding   mnemonic     operation
#    --------   --------     ---------
#    xxxxx000   LD x         acc <- x
#    xxxxx001   ST x         x <- acc
#    xxxxx010   ADD x        acc <- acc + x
#    xxxxx011   SUB x        acc <- acc - x
#    xxxxx100   SMOD y       set modulus to mod_N (y = 26) or mod_P (y = 27)
#    xxxxx101   MUL x        acc <- (acc * x)/R (Montgomery multiplication)
#    xxxxx110   SKIPBITZ x   skip next if current bit in x is zero
#    00000111   CALL label   call subroutine (+immediate offset)
#    00001111   SKIPNZ       skip next is acc is non-zero
#    00010111   SKIPNEG      skip next is acc is negative
#    00011111   FNEXT        consume first iteration
#    00100111   RET          return from subroutine
#    00101111   FOR          initialize bit iterator
#    00110111   NEXT         loop back iterator
#    00111111   OK           exit with a success
#    01000111   FAIL         exit with a failure
#    01001111   NORM         normalize value in accumulator
#
# "LD x" copies value x (0 <= x <= 31) into the accumulator. "ST x" copies
# the accumulator into value x. "ADD x" (resp. "SUB x") adds x to (resp.
# subtracts x from) the accumulator. "MUL x" multiplies the accumulator with
# value x (Montgomery multiplication, i.e. it computes (acc*x)/R), using
# the currently set modulus. "SMOD y" switches the current modulus (parameter
# y must be 26 or 27, for n and p, respectively), as readable in value 1
# and used in Montgomery multiplications.
#
# "SKIPNZ" and "SKIPNEG" make the VM skip the next instruction if a
# condition on the accumulator is true; the condition is "accumulator is
# non-zero" and "accumulator is negative", respectively. Thus,
# "SKIPNEG ; SUB 1" will subtract the modulus from the accumulator only
# in case the accumulator is currently non-negative. These tests work
# reliably only if the value in the accumulator is normalized (i.e. four
# lower limbs are in [0, 2^54]); the "NORM" instruction normalizes the
# accumulator value.
#
# A single loop facility is provided; it cannot nest (the code cannot run
# an internal loop within an outer loop). "FOR" starts the loop, and
# "NEXT" triggers the next iteration. The loop runs for exactly 256
# iterations. There can be several "NEXT" opcodes matching a single "FOR".
# The "FNEXT" instruction is a "NEXT" that is triggered only on the first
# iteration, i.e. it can be used to skip that iteration. While the iteration
# runs, the "SKIPBITZ x" opcode uses the current iteration counter (255 to 0)
# as a bit index within value x, and tests whether the corresponding bit
# is set or cleared; if cleared, then the next instruction is skipped. This
# facility is meant to support square-and-multiply exponentiation as well
# as double-and-add point multiplication. For bit values to be meaningfull,
# tested value x should be canonicalized (i.e. normalized, non-negative,
# and less than the relevant modulus).
#
# Subroutines are supported: "CALL label" jumps to the subroutine located
# at the provided assembly label; "RET" returns from the current subroutine
# to the caller. Nested calls are supported. In the encoding, the subroutine
# offset is encoded as an 8-bit unsigned value that immediately follows the
# "CALL": this implies that the target of the CALL can only be located
# _after_ the call site in the bytecode (and it must not be farther than
# 255 bytes away). The "skip" instructions correctly skip the two bytes of
# a "CALL" function.
#
# The "OK" and "FAIL" instructions terminate the interpreter with an exit
# status of 1 or 0, respectively. They can be used within called subroutines,
# not just at the toplevel.
# ========================================================================

# VALUE ALLOCATION
# WARNING: code relies on Kr, Ks, Ke, Qx and Qy to be consecutive.

	# Symbolic identifiers for various slots.
	.equ	_M,     1    # current modulus
	.equ	_ONE,   2    # constant one
	.equ	_ZERO, 28    # constant zero
	.equ	_Bm,   29    # constant Bm (curve param b, Montgomery repr.)
	.equ	_Gx,   30    # constant Gx (x coordinate of generator)
	.equ	_Gy,   31    # constant Gy (y coordinate of generator)
	.equ	_T0,   16    # temporary 0
	.equ	_T1,   17    # temporary 1
	.equ	_T2,   18    # temporary 2
	.equ	_T3,   19    # temporary 3
	.equ	_T4,   20    # temporary 4
	.equ	_T5,   21    # temporary 5
	.equ	_T6,   22    # temporary 6
	.equ	_T7,   23    # temporary 7
	.equ	_T8,   24    # temporary 8
	.equ	_T9,   25    # temporary 9

	.equ	_Kr,    3    # r (first signature half)
	.equ	_Ks,    4    # s (second signature half)
	.equ	_Ke,    5    # e (reduced hash value)
	.equ	_Qx,    6    # Qx (x coordinate of public key)
	.equ	_Qy,    7    # Qy (y coordinate of public key)
	.equ	_Wx,    8    # Wx (X coordinate of work point W)
	.equ	_Wy,    9    # Wy (Y coordinate of work point W)
	.equ	_Wz,   10    # Wz (Z coordinate of work point W)
	.equ	_Hx,   11    # Hx (X coordinate of second point operand)
	.equ	_Hy,   12    # Hy (Y coordinate of second point operand)
	.equ	_Hz,   13    # Hz (Z coordinate of second point operand)

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
	.equ	OP_FAIL,      0x47
	.equ	OP_NORM,      0x4F

# Macros to help write bytecode.
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

# _MRED is a pseudo-instruction that maps to _MUL _ONE, i.e. Montgomery
# reduction.
.macro	_MRED
	_MUL _ONE
.endm

# _MODN is an alias for _SMOD 26, i.e. switching modulus to mod_N.
.macro	_MODN
	_SMOD 26
.endm

# _MODP is an alias for _SMOD 27, i.e. switching modulus to mod_P.
.macro	_MODP
	_SMOD 27
.endm

# BYTECODE ENTRY POINT
# WARNING: the code locates the entry point relatively to the
# constants: it must immediately follow the modulus p in the curve constants
# block.

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
	_MUL _Ke ; _CALL canonicalize ; _ST _Ke
	# Compute v = r/s (canonicalized, into Ks).
	_LD _Ks ; _MUL _Kr ; _CALL canonicalize ; _ST _Ks

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
	# the W is not the point-at-infinity.
	_LD _Wz ; _CALL invert_mod ; _MUL _Wx ; _CALL canonicalize

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
	_LD _M ; _SUB _ONE ; _SUB _ONE ; _ST _T1
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
	_MUL _T6 ; _ST _Wy ; _LD _T5 ; _MUL _T7 ; _ADD _Wy ; _ST _Wy

	# Z1 <- t4*t7 + t3*t0
	_LD _T4 ; _MUL _T7 ; _ST _Wz
	_LD _T3 ; _MUL _T0 ; _ADD _Wz ; _ST _Wz

	_RET

# -------------------------------------------------------------------------
# END BYTECODE
# -------------------------------------------------------------------------

	# RV64GC code must be 2-byte aligned
	.balign	2

# ========================================================================
# add_mul_wide()
#    d <- d + a*f
# Values are in 54-bit limbs; no bit propagation.
# SPECIAL API:
# Input:
#   a0   d (6 words)
#   a1   a (5 words)
#   a3   f (1 word, pre-shifted by 5 bits)
# Output:
#   d[] is updated (6 words)
#   a0   +40
#   a1   +40
# Clobbers: a4, a6, s0, s1
# ========================================================================

	.type	add_mul_wide, %function
add_mul_wide:
	li	a4, 5         # loop counter
	li	a6, 0         # carry word
Ladd_mul_wide__loop:
	ld	s1, (a1)      # s1 <- a_i
	ld	s0, (a0)      # s0 <- d_i
	slli	s1, s1, 5     # pre-shift a_i (5 bits)
	add	s0, s0, a6    # add delayed word to s0
	addi	a1, a1, 8     # update a[] pointer
	mulh	a6, s1, a3    # a6 <- delayed word for next round
	mul	s1, s1, a3    # s1 <- low word of multiplication
	addi	a4, a4, -1    # update loop counter
	srli	s1, s1, 10    # shift low word into correct position
	add	s0, s0, s1    # add low word to d_i
	sd	s0, (a0)      # store updated d_i
	addi	a0, a0, 8     # update d pointer
	bnez	a4, Ladd_mul_wide__loop
	ld	s0, (a0)      # s0 <- d_5
	add	s0, s0, a6    # add delayed word
	sd	s0, (a0)      # store updated d_5
	ret
	.size	add_mul_wide, . - add_mul_wide

# ========================================================================
# VM INTERPRETER
#
# The interpreter maintains a context structure on the stack, of size
# 1328 bytes. The a5 register points to that context.
# Value x (for 0 <= x <= 31) is at address a5+40*x; moduli n and p are
# located at a5+1280 and a5+1328, respectively (each modulus uses 48 bytes:
# the 5 limbs, followed by the value (-1/m mod 2^54)*2^10, which is used
# for Montgomery multiplication). Value 1 is special, in that instructions
# that read that value obtain the current modulus limbs; the storage space
# of value 1 is currently used to store some saved register values.
#
# The iteration counter is maintained in the physical bit offset format,
# which accounts for the fact that limbs contain 54 logical bits but use
# 64 bits in RAM. Thus, the start value is 295 (for the logical bit index
# 255).
#
# Instruction decoding uses first the translation_table (below), which
# points to the offset of the native routine for the instruction. The
# index consists of the three low bits of the instruction, and the
# offset is over one byte. This handles instructions LD, ST, ADD, SUB,
# SMOD, MUL, and SKIPBITZ (all instructions with a 5-bit parameter);
# other instructions are handled with op_extended, which does a secondary
# decoding with another table.
translation_table:
	.byte	op_ld - translation_table
	.byte	op_st - translation_table
	.byte	op_add - translation_table
	.byte	op_sub - translation_table
	.byte	op_smod - translation_table
	.byte	op_mul - translation_table
	.byte	op_skipbitz - translation_table
	.byte	op_extended - translation_table

# Instruction routine conventions:
#  - each routine is invoked with 'jalr' and ends with a ret opcode
#  - a1 contains the routine's own address
#  - a0 contains 8*x (for x = hi5(opcode))
#  - a2 points to the explicit operand value (i.e. a5+40*x)
#  - a5 points to the context
#  - t1 points to the current modulus
#  - t5 contains the instruction pointer (pointing to the byte that
#    follows the instruction); the interpreter will restart from there,
#    so it must be preserved (or possibly altered)
#  - t4 contains the exit flag, currently 0; if it becomes non-zero then
#    the interpreter will exit
#  - t2 is the current loop counter, and t3 the loop start address
#  - t6 is the pointer to the translation table
# a5, t1, t2, t3, t4, t5 and t6 are non-transient and must be preserved (or
# altered only along their ongoing semantics).
# The stack is used for subroutine calls; every such call involves pushing
# the current instruction pointer on the stack (to preserve 16-byte stack
# alignment, stack pointer is decreased by 16 in that case).

# LD x    copy value x into accumulator
op_ld:
	mv	a1, a5
# docopy is a shareable routine that copies 40 bytes (aligned) from a2 to a1.
docopy:
	li	a3, 5
Ldocopy__loop:
	ld	a4, (a2)
	addi	a2, a2, 8
	addi	a3, a3, -1
	sd	a4, (a1)
	addi	a1, a1, 8
	bnez	a3, Ldocopy__loop
	ret

# ST x    copy accumulator into value x
op_st:
	mv	a1, a2
	mv	a2, a5
	j	docopy

# ADD x   add value x to accumulator
op_add:
	li	a4, 0         # a4 = 0 for an addition
op_add__altentry:
	mv	s0, a5        # source pointer
	li	a3, 5         # loop counter
Lop_add__loop:
	ld	a1, (a2)      # a1 <- limb from second operand
	addi	a2, a2, 8     # update second operand pointer
	xor	a1, a1, a4    # conditional negation of a1 (first part)
	ld	a0, (s0)      # a0 <- limb from accumulator
	sub	a1, a1, a4    # conditional negation of a1 (second part)
	addi	a3, a3, -1    # update loop counter
	add	a0, a0, a1    # limb addition (or subtraction)
	sd	a0, (s0)      # store output limb
	addi	s0, s0, 8     # update accumulator pointer
	bnez	a3, Lop_add__loop
	ret

# SUB x   subtract value x from accumulator
op_sub:
	li	a4, -1        # a4 = -1 for a subtraction
	j	op_add__altentry

# SMOD y    switch current modulus (y = 26 for mod_N, y = 27 for mod_P)
op_smod:
	# &mod_N == a5+1280
	# &mod_P == a5+1328 == &mod_N + 48
	# we have 8*y in a0, and a5+40*y in a2, and:
	#    32 + (40*y) + 8*y = 1280 if y = 26, or 1328 if y = 27
	add	a0, a0, a2
	addi	t1, a0, 32
	ret

# MUL x   multiply accumulator with x
# This uses Montgomery multiplication, so that it really computes (x*acc)/R.
# The current modulus is used.
op_mul:
	# Save return address (in s2).
	mv	s2, ra

	# Allocate and initialize stack buffer (10 words).
	li	s0, 0
	li	a4, 5
Lop_mul__loop1:
	addi	a4, a4, -1
	c.addi16sp sp, -16
	sd	s0, 8(sp)
	sd	s0, (sp)
	bnez	a4, Lop_mul__loop1

	# t0 <- (-1/m mod 2^54)*2^10
	ld	t0, 40(t1)

	# Process second operand word by word.
	mv	a0, sp
	li	a7, 5      # loop counter
Lop_mul__loop2:
	# t <- t + a*b_i
	mv	a1, a5
	ld	a3, (a2)
	addi	a2, a2, 8
	slli	a3, a3, 5      # pre-shift b_i
	jal	add_mul_wide
	# a3 <- f = (-t/m mod 2^54)*2^5  (signed)
	addi	a0, a0, -40    # restore a0
	ld	a3, (a0)
	mul	a3, a3, t0
	srai	a3, a3, 5
	# t <- t + m*f
	mv	a1, t1
	jal	add_mul_wide
	# Propagate upper bits of dropped word
	addi	a0, a0, -32    # restore a0, dropping low word
	ld	a1, -8(a0)
	ld	a3, (a0)
	srai	a1, a1, 54
	add	a3, a3, a1
	sd	a3, (a0)
	# Loop control
	addi	a7, a7, -1
	bnez	a7, Lop_mul__loop2

	# Recover return address.
	mv	ra, s2

	# Size of t is now 5 words. We copy it to the destination,
	# with high bit propagation.
	# op_norm() also tail-calls here. API:
	#  - source address is a0 (consumed)
	#  - destination address is a5 (preserved)
	#  - after the move, sp is incremented by 80
normalize_limbs:
	li	a4, 5        # loop counter
	li	a3, 0        # propagated upper bits
Lnormalize_limbs__loop:
	addi	a4, a4, -1   # update loop counter
	ld	a1, (a0)     # load next word
	addi	a0, a0, 8    # adjust source pointer
	add	a1, a1, a3   # add propagated bits
	beqz	a4, Lnormalize_limbs__cont
	srai	a3, a1, 54   # prepare next propagated bits
	slli	a1, a1, 10   # truncate limb to 54 bits (step 1)
	srli	a1, a1, 10   # truncate limb to 54 bits (step 2)
	sd	a1, (a5)     # store limb
	addi	a5, a5, 8    # update output pointer
	j	Lnormalize_limbs__loop
Lnormalize_limbs__cont:
	sd	a1, (a5)     # store final limb
	addi	a5, a5, -32  # restore original a5
	c.addi16sp sp, 80
	ret

# SKIPBITZ x   skip next instruction if current bit is set in x
# The "current bit" relates to the iterator; this instruction makes sense
# only when an iteration is ongoing.
op_skipbitz:
	# Bit offset is a combined value: low 3 bits are the limb index
	# (0 to 4), bits 3+ are the bit offset within the limb.
	srli	a1, t2, 3     # extract bit offset
	andi	a0, t2, 0x07  # extract limb index j
	slli	a0, a0, 3
	add	a2, a2, a0    # a2 <- a2 + 8*j  (address of limb j)
	ld	a0, (a2)      # load limb
	srl	a0, a0, a1
	andi	a0, a0, 1     # a0 <- bit to test
	bnez	a0, Lret1
	# FALL THROUGH
# Common sequence for skipping the next instruction.
doskip:
	# Increment the instruction pointer to skip the next instruction;
	# take care that CALL instruction has size 2 bytes.
	lbu	a0, (t5)
Ldoskip__cont:
	addi	t5, t5, 1
	addi	a0, a0, -OP_CALL
	beqz	a0, Ldoskip__cont
Lret1:
	ret

# The extended translation table is used for opcodes that do not have
# a value operand. This table contains routine offsets relative to
# op_extended.
extended_translation_table:
	# WARNING: if table size is changed, the addi instruction
	# in op_extended MUST be altered accordingly.
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

	# RISC-V instructions need 16-bit alignment.
	.balign	2

# Pseudo-instruction invoked for extended opcodes.
op_extended:
	# a0 contains 8*x, where x designates the opcode. We use
	# the secondary translation table, which we locate from a1,
	# which contains the address of op_extended. The table size
	# is 10 bytes.
	# WARNING: if the table size is modified, the offset in the
	# movb instruction below MUST be modified. The offset is
	# hardcoded so that the addi instruction below may use the
	# compressed encoding.
	srli	a0, a0, 3
	addi	a0, a0, -10
	add	a0, a0, a1
	lbu	a0, (a0)
	add	a1, a1, a0
	jr	a1

# In extended opcodes, a0 no longer contains relevant data.

# NORM   normalize the accumulator
# Normalization does not change the value as an integer, but it
# ensures that the four low limbs are in [0, 2^54-1]. After normalization,
# the sign of the top limb matches the sign of the whole integer.
op_norm:
	# normalize_limbs has a special API
	c.addi16sp sp, -80
	mv	a0, a5       # source to normalize
	j	normalize_limbs

# SKIPNZ   skip next instruction if accumulator is non-zero
# This works correctly only if the accumulator has been normalized. This
# is a comparison over the plain integers; for a comparison over _modular_
# integers, the value must be fully reduced first.
op_skipnz:
	addi	a2, a5, 40
Lop_skipnz:
	addi	a2, a2, -8
	ld	a0, (a2)
	bnez	a0, doskip
	bne	a2, a5, Lop_skipnz
	ret

# SKIPNEG   skip next instruction if accumulator is negative
# This works correctly only if the accumulator has been normalized. This
# is a comparison over the plain integers.
op_skipneg:
	ld	a0, 32(a5)
	blt	a0, zero, doskip
	ret

# RET     return from subroutine
op_ret:
	ld	t5, (sp)
	c.addi16sp sp, 16
	ret

# FOR    start the iterator
# This sets the iterator counter to 255. Each NEXT instruction will
# decrement the iterator and loop back to immediately after the FOR,
# unless the counter reaches -1 (which terminates the loop).
op_for:
	# Save address of next instruction; this is where execution
	# will loop back upon NEXT.
	mv	t3, t5
	# Loop counter is stored as:
	#    floor(i/54) + 8*(i mod 54)
	# for i = 255 to 0. Start value is then 316.
	li	t2, 316
Lret2:
	ret

# FNEXT   consume first iteration
# This is like a NEXT which is performed only on first iteration.
op_fnext:
	addi	a0, t2, -316
	bnez	a0, Lret2
	# FALL THROUGH
# NEXT   decrement iterator counter and loop
# If the counter is at zero, then the loop exits. Otherwise, the counter
# is decremented, and execution jumps to right after the FOR instruction
# that started the iterator.
op_next:
	# Decrement bit offset.
	beqz	t2, Lret2     # Nothing to do if already at zero.
	addi	t2, t2, -8
	bge	t2, zero, Lop_next__cont
	# Value became negative, which means that we crossed a limb boundary.
	# Value was j (limb index) and is now j-8; we want (j-1) + 53*8,
	# so we add 53*8 + 7 = 431.
	addi	t2, t2, 431
Lop_next__cont:
	# Store new counter value and loop. Iteration start address
	# was stored in t3 by FOR.
	mv	t5, t3
	ret

# OK     exit the interpreter with a success status
op_ok:
	# Set the exit flag with a success status
	li	t4, -2
	# FALL THROUGH
# FAIL   exit the interpreter with a failed status
op_fail:
	# Set the exit flag with a failed status
	addi	t4, t4, 1
	ret

# CALL   call subroutine
# The target subroutine address is provided as one inline byte
# immediately following the instruction; the byte is the offset
# (unsigned) to add to the current instruction pointer to obtain the
# address of the called subroutine. Since the offset is unsigned,
# this can only call subroutines located after the call site.
op_call:
	# Fetch target offset.
	lbu	a0, (t5)
	addi	t5, t5, 1
	# Save instruction pointer.
	c.addi16sp sp, -16
	sd	t5, (sp)
	# Jump to the designated subroutine.
	add	t5, t5, a0
	ret

# Interpreter is built as three macros, so that the test code may use
# some interpreters to exercise subroutines.

# Interpreter initialization: allocate and setup the stack context.
# Outputs:
#    t1   points to mod_N
#    t5   points to the bytecode entry point
#    context is on top-of-stack
#    s0   points to decode_int()
# Clobbers: a0..a4, t0
# s0, s1, s2 and ra are saved, and will be restored by INTERPRETER_END.
# 1376 bytes are stored on the stack.
.macro	INTERPRETER_BEGIN
	# Allocate the context structure, filled with zeros.
	li	a3, 86         # 1376 = 86*16
1:
	c.addi16sp sp, -16
	sd	zero, 8(sp)
	sd	zero, (sp)
	addi	a3, a3, -1
	bnez	a3, 1b
	# Value 2 is ONE.
	li	a4, 1
	sd	a4, 80(sp)

	# Save registers that need saving.
	sd	s0, 40(sp)
	sd	s1, 48(sp)
	sd	s2, 56(sp)
	sd	ra, 64(sp)

	# Decode curve constants Gx, Gy, and mod_N.
	add	a0, sp, (40*_Gx)
	lla	s0, decode_int
	addi	a1, s0, 56    # BYTE ADJUSTMENT: size(decode_int) == 56
	jalr	ra, s0        # Gx
	jalr	ra, s0        # Gy
	mv	t1, a0        # t1 points to where mod_N will go
	jalr	ra, s0        # mod_N
	# Copy n0i
	ld	a2, (a1)
	addi	a1, a1, 8
	sd	a2, (a0)
	addi	a0, a0, 8
	# Decode mod_P
	jalr	ra, s0        # mod_P
	mv	t5, a1        # t5 points to the bytecode entry
	# p0i = (-1/p mod 2^54)*2^10 = 0x400
	li	a2, 0x400
	sd	a2, (a0)
.endm

# Main interpreter loop.
# Inputs:
#    a5   context pointer
#    t1   current modulus
#    t5   instruction pointer
# Outputs:
#    a5   context pointer
#    t4   -1 on success, 1 on failure
#    stack MAY have grown (use a5 to access stack elements)
# Clobbers:
#    a0..a7 (except a5), s0..s2, t0..t6, ra
.macro	INTERPRETER_MAIN
	# Set t6 to point to the translation table.
	lla	t6, translation_table
	li	t4, 0         # exit flag
1:
	# Load next instruction.
	lbu	a0, (t5)
	addi	t5, t5, 1
	# Split instruction into the opcode index (low 3 bits) and
	# the parameter (high 5 bits = 8*x).
	andi	a1, a0, 7     # a1 <- opcode index
	sub	a0, a0, a1    # a0 <- 8*x
	add	a1, a1, t6    # a1 <- &translation_table[opcode_index]
	slli	a2, a0, 2     # a2 <- 32*x
	lbu	a1, (a1)      # a1 <- translation_table[opcode_index]
	add	a2, a2, a0    # a2 <- 40*x
	li	a3, 8         # a3 <- 8
	add	a2, a2, a5    # a2 <- a5 + 40*x = address of value x
	add	a1, a1, t6    # a1 <- opcode routine address
	# If x == 1 then the operand is the special modulus value
	bne	a0, a3, 2f
	mv	a2, t1        # modulus pointer is in t1
2:
	# At this point:
	#   a0   8*x (for x = hi5(opcode))
	#   a1   opcode routine address
	#   a2   a5 + 40*x  (address of value x)
	# We call the opcode routine.
	jalr	ra, a1
	# Execute next instruction until the exit flag is set
	beqz	t4, 1b
.endm

# Wind down the interpreter. The stack, rbx and rbp are restored to the
# state when INTERPRETER_BEGIN was invoked. a0 is set to the code exit
# status.
# Input:
#    a5   points to context
#    t4   exit status (-1 = success, 1 = failure)
# Output:
#    a0   exit status (1 = success, 0 = failure)
# s0, s1, s2 and ra are restored to the values they had upon entry into
# INTERPRETER_BEGIN.
.macro	INTERPRETER_END
	# Retrieve exit status.
	srli	a0, t4, 63

	# Restore stack and saved registers.
	mv	sp, a5
	ld	s0, 40(sp)
	ld	s1, 48(sp)
	ld	s2, 56(sp)
	ld	ra, 64(sp)
	addi	sp, sp, 1376
.endm

# ========================================================================
# int tv_ecdsa_p256_verify(const void *sig, size_t sig_len,
#         const void *pub, size_t pub_len,
#         const void *hv, size_t hv_len)
# ========================================================================

# Small helper chunk located here so that some jumps are close.
Ltv_ecdsa_p256_verify__err:
	li	a0, 0
	ret

	.global	tv_ecdsa_p256_verify
	.type	tv_ecdsa_p256_verify, %function
tv_ecdsa_p256_verify:
	# Check input sizes.
	addi	a1, a1, -64       # sig_len must be 64
	bnez	a1, Ltv_ecdsa_p256_verify__err
	addi	a3, a3, -65       # pub_len must be 65
	bnez	a3, Ltv_ecdsa_p256_verify__err
	addi	a5, a5, -32       # hv_len must be in [32, 64]
	li	a1, 32
	bgtu	a5, a1, Ltv_ecdsa_p256_verify__err

	# Check that the public key leading byte is 0x04.
	lbu	a1, (a2)
	addi	a2, a2, 1
	addi	a1, a1, -0x04
	bnez	a1, Ltv_ecdsa_p256_verify__err

	# We need to allocate the interpreter context; this will not
	# clobber t2, t3 or t4.
	# It will also save ra, hence we can call sub-functions now.
	mv	t2, a0    # sig
	mv	t3, a2    # pub+1
	mv	t4, a4    # hv
	INTERPRETER_BEGIN

	# Decode r, s, e, Qx and Qy into the appropriate slots.
	# This uses the fact that the slots are consecutive.
	# INTERPRETER_BEGIN set s0 to the address of the decode_int()
	# function.
	c.addi4spn a0, sp, (40*_Kr)
	mv	a1, t2
	jalr	ra, s0   # r
	jalr	ra, s0   # s
	mv	a1, t4
	jalr	ra, s0   # e
	mv	a1, t3
	jalr	ra, s0   # Qx
	jalr	ra, s0   # Qy

	# t5 still contains the pointer to the bytecode.
	mv	a5, sp
	INTERPRETER_MAIN

	INTERPRETER_END
	# a0 was set according to the bytecode exit status
	ret
	.size	tv_ecdsa_p256_verify, . - tv_ecdsa_p256_verify

#ifdef TV_ECDSA_P256_TEST

# ========================================================================
# ========================================================================
# ========================================================================
# ###########################<<< TEST CODE >>>############################
#
# Everything below this line is test code which is used by external unit
# tests; this is not meant to be compiled in released builds. When the
# TV_ECDSA_P256_TEST macro is not defined, this code is omitted.
# ========================================================================
# ========================================================================
# ========================================================================

# This code uses an unreduced format, we return 1.
	.global	tv_gf_has_unreduced
	.type	tv_gf_has_unreduced, %function
tv_gf_has_unreduced:
	li	a0, 1
	ret
	.size	tv_gf_has_unreduced, . - tv_gf_has_unreduced

# We accept the value if its limbs are at most 5.5*2^t in absolute value,
# where t = 54 for limbs 0..3, and t = 40 for limb 4. We ignore the 'scalar'
# parameter (check is the same for both fields).
	.global	tv_gf_check
	.type	tv_gf_check, %function
tv_gf_check:
	# a4 <- 5.5*2^54
	li	a4, 11
	slli	a4, a4, 53
	li	a5, 5     # loop counter
Ltv_gf_check__loop:
	# Read next limb.
	ld	a1, (a0)
	addi	a0, a0, 8
	# a1 <- abs(a1)
	srai	a2, a1, 63
	xor	a1, a1, a2
	sub	a1, a1, a2
	# Loop control: exit for last limb.
	addi	a5, a5, -1
	beqz	a5, Ltv_gf_check__cont
	bltu	a1, a4, Ltv_gf_check__loop
	li	a0, 0
	ret
Ltv_gf_check__cont:
	# Max value for limb 4 is 5.5*2^40, not 5.5*2^54.
	srli	a4, a4, 14
	sltu	a0, a1, a4
	ret
	.size	tv_gf_check, . - tv_gf_check

# For additions, subtractions, multiplications and inversion, we fire up
# an interpreter and use the relevant bytecode.

bytecode_add:
	_ADD _T0 ; _RET
bytecode_sub:
	_SUB _T0 ; _RET
bytecode_mul:
	_MUL _T0 ; _RET
bytecode_ok:
	_OK
	.balign	2

# gf_copy(gf *dst, const gf *src)
# Output:
#   a0 is updated (+40)
#   a1 is updated (+40)
# Clobbers: a2, a3
gf_copy:
	li	a3, 5
Lgf_copy__loop:
	ld	a2, (a1)
	addi	a1, a1, 8
	sd	a2, (a0)
	addi	a0, a0, 8
	addi	a3, a3, -1
	bnez	a3, Lgf_copy__loop
	ret

# gf_op(gf *d, const gf *a, const gf *b, int scalar, const uint8_t *code)
	.type	gf_op, %function
gf_op:
	# Save parameters.
	c.addi16sp sp, -48
	sd	a0, (sp)
	sd	a1, 8(sp)    
	sd	a2, 16(sp)
	sd	a3, 24(sp)
	sd	a4, 32(sp)
	sd	s11, 40(sp)
	# None of the code modifies s11, we use it as a frame pointer.
	mv	s11, sp

	INTERPRETER_BEGIN

	# Copy operands:
	#  - If a != NULL then this is an add, sub or mul; the two source
	#    operands go to the accumulator and value T0, respectively.
	#  - If a == NULL then this is an inversion or an encoding, *d is
	#    copied into the accumulator.
	ld	a1, 8(s11)
	beqz	a1, Lgf_op__cont1
	# Copy a to accumulator
	mv	a0, sp
	jal	gf_copy
	# Copy b to T0
	c.addi4spn a0, sp, (40*_T0)
	ld	a1, 16(s11)
	jal	gf_copy
	j	Lgf_op__cont2
Lgf_op__cont1:
	# Copy d to accumulator
	mv	a0, sp
	ld	a1, (s11)
	jal	gf_copy
Lgf_op__cont2:
	# Set modulus according to the 'scalar' argument: it was set to
	# mod_N by INTERPRETER_BEGIN, but we change that to mod_P if
	# scalar = 0.
	ld	a3, 24(s11)
	bnez	a3, Lgf_op__cont3
	addi	t1, t1, 48     # &mod_P == &mod_N + 48
Lgf_op__cont3:
	# Simulate a call, with a return pointer leading to bytecode_ok,
	# then use the provided code pointer.
	mv	a5, sp
	c.addi16sp sp, -16
	lla	a0, bytecode_ok
	sd	a0, (sp)
	ld	t5, 32(s11)   # 'code' parameter
	INTERPRETER_MAIN

	# Copy result into destination.
	ld	a0, (s11)
	mv	a1, a5
	jal	gf_copy

	INTERPRETER_END

	ld	a0, (sp)
	ld	a1, 8(sp)    
	ld	a2, 16(sp)
	ld	a3, 24(sp)
	ld	a4, 32(sp)
	ld	s11, 40(sp)
	c.addi16sp sp, 48
	ret
	.size	gf_op, . - gf_op

# tv_gf_add() uses gf_op()
	.global	tv_gf_add
	.type	tv_gf_add, %function
tv_gf_add:
	lla	a4, bytecode_add
	j	gf_op
	.size	tv_gf_add, . - tv_gf_add

# tv_gf_sub() uses gf_op()
	.global	tv_gf_sub
	.type	tv_gf_sub, %function
tv_gf_sub:
	lla	a4, bytecode_sub
	j	gf_op
	.size	tv_gf_sub, . - tv_gf_sub

# tv_gf_mul() uses gf_op()
	.global	tv_gf_mul
	.type	tv_gf_mul, %function
tv_gf_mul:
	lla	a4, bytecode_mul
	j	gf_op
	.size	tv_gf_mul, . - tv_gf_mul

# tv_gf_invert() uses gf_op()
	.global	tv_gf_invert
	.type	tv_gf_invert, %function
tv_gf_invert:
	mv	a3, a1
	li	a1, 0
	li	a2, 0
	lla	a4, invert_mod
	j	gf_op
	.size	tv_gf_invert, . - tv_gf_invert

# This function applies conversion to Montgomery representation.
	.global	tv_gf_decode
	.type	tv_gf_decode, %function
tv_gf_decode:
	c.addi16sp sp, -16
	sd	ra, (sp)

	# Raw decode.
	mv	t2, a0
	mv	t3, a2
	jal	decode_int

	# Multiply by the appropriate constant R^2 (conversion to
	# Montgomery representation).
	lla	a2, gf_R2n
	bnez	t3, Ltv_gf_decode__cont
	lla	a2, gf_R2p
Ltv_gf_decode__cont:
	mv	a0, t2
	mv	a1, t2
	mv	a3, t3
	jal	tv_gf_mul

	ld	ra, (sp)
	c.addi16sp sp, 16
	ret
	.size	tv_gf_decode, . - tv_gf_decode

# tv_gf_encode() uses gf_op() to perform a canonical reduction.
	.global	tv_gf_encode
	.type	tv_gf_encode, %function
tv_gf_encode:
	c.addi16sp sp, -80
	sd	a0, 48(sp)
	sd	a1, 56(sp)
	sd	a2, 64(sp)
	sd	ra, 72(sp)

	# Copy source into stack buffer.
	mv	a0, sp
	jal	gf_copy
	# Use gf_op() to perform canonicalization.
	mv	a0, sp
	li	a1, 0
	li	a2, 0
	ld	a3, 64(sp)
	lla	a4, canonicalize
	jal	gf_op
	# Load the five output words and check that they are all non-negative
	# and in range.
	ld	a0, (sp)
	ld	a1, 8(sp)
	ld	a2, 16(sp)
	ld	a3, 24(sp)
	ld	a4, 32(sp)
	blt	a0, zero, Ltv_gf_encode__err
	blt	a1, zero, Ltv_gf_encode__err
	blt	a2, zero, Ltv_gf_encode__err
	blt	a3, zero, Ltv_gf_encode__err
	blt	a4, zero, Ltv_gf_encode__err
	srli	a5, a0, 54
	bnez	a5, Ltv_gf_encode__err
	srli	a5, a1, 54
	bnez	a5, Ltv_gf_encode__err
	srli	a5, a2, 54
	bnez	a5, Ltv_gf_encode__err
	srli	a5, a3, 54
	bnez	a5, Ltv_gf_encode__err
	srli	a5, a4, 40
	bnez	a5, Ltv_gf_encode__err

	# Reassemble the data into four 64-bit words.
	slli	a5, a1, 54
	or	a0, a0, a5
	srli	a1, a1, 10
	slli	a5, a2, 44
	or	a1, a1, a5
	srli	a2, a2, 20
	slli	a5, a3, 34
	or	a2, a2, a5
	srli	a3, a3, 30
	slli	a5, a4, 24
	or	a3, a3, a5
	# Write back words into the stack.
	sd	a0, (sp)
	sd	a1, 8(sp)
	sd	a2, 16(sp)
	sd	a3, 24(sp)

	# Copy bytes to output, byteswapped (output is big-endian).
	ld	a0, 48(sp)
	c.addi4spn a1, sp, 32
Ltv_gf_encode__loop:
	addi	a1, a1, -1
	lbu	a2, (a1)
	sb	a2, (a0)
	addi	a0, a0, 1
	bne	a1, sp, Ltv_gf_encode__loop

	li	a0, 1
Ltv_gf_encode__exit:
	ld	ra, 72(sp)
	c.addi16sp sp, 80
	ret
Ltv_gf_encode__err:
	li	a0, 0
	j	Ltv_gf_encode__exit
	.size	tv_gf_encode, . - tv_gf_encode

# tv_point_decode()
	.global	tv_point_decode
	.type	tv_point_decode, %function
tv_point_decode:
	c.addi16sp sp, -16
	sd	s11, (sp)
	mv	s11, a0     # output pointer

	# Skip leading byte.
	addi	t2, a1, 1

	INTERPRETER_BEGIN

	# Decode coordinates as integers into slots Qx and Qy
	c.addi4spn a0, sp, (40*_Qx)
	mv	a1, t2
	jal	decode_int
	jal	decode_int

	# Set modulus to mod_P  (&mod_P == &mod_N + 48)
	addi	t1, t1, 48

	# Set Bm.
	add	a0, sp, (40*_Bm)
	lla	a1, gf_Bm
	jal	decode_int

	# Simulate a call, with a return pointer leading to bytecode_ok.
	mv	a5, sp
	c.addi16sp sp, -16
	lla	a0, bytecode_ok
	sd	a0, (sp)
	lla	t5, check_point
	INTERPRETER_MAIN

	# Copy decoded x and y to destination P.X and P.Y; set P.Z to 1.
	mv	a0, s11
	c.addi4spn a1, sp, (40*_Qx)
	jal	gf_copy
	jal	gf_copy
	li	a1, 1
	sd	a1, (a0)
	li	a1, 0
	sd	a1, 8(a0)
	sd	a1, 16(a0)
	sd	a1, 24(a0)
	sd	a1, 32(a0)

	INTERPRETER_END
	ld	s11, (sp)
	c.addi16sp sp, 16
	ret
	.size	tv_point_decode, . - tv_point_decode

# tv_point_encode()
	.global	tv_point_encode
	.type	tv_point_encode, %function
tv_point_encode:
	c.addi16sp sp, -112
	sd	a0, 88(sp)
	sd	a1, 96(sp)
	sd	ra, 104(sp)

	# Copy Z coordinate to sp+0
	mv	a0, sp
	addi	a1, a1, 80
	jal	gf_copy
	# Invert Z
	mv	a0, sp
	li	a1, 0
	jal	tv_gf_invert
	# Multiply 1/Z with Y, into sp+40
	# (We use Montgomery multiplication but that still works: we
	# are multiplying the Montgomery representations of X/R and R/Z,
	# thus we get the Montgomery representation of X/Z.)
	c.addi4spn a0, sp, 40
	mv	a1, sp
	ld	a2, 96(sp)
	addi	a2, a2, 40
	li	a3, 0
	jal	tv_gf_mul
	# Multiply 1/Z with X, into sp
	mv	a0, sp
	mv	a1, sp
	ld	a2, 96(sp)
	li	a3, 0
	jal	tv_gf_mul
	# Encode x and y into sp+0 and sp+32, respectively.
	mv	a0, sp
	mv	a1, sp
	li	a2, 0
	jal	tv_gf_encode
	c.addi4spn a0, sp, 32
	c.addi4spn a1, sp, 40
	li	a2, 0
	jal	tv_gf_encode
	# If Z was zero then tv_gf_invert() returned zero, and both x and y
	# are zero. For non-neutral points, y is always non-zero since the
	# curve has odd order.
	ld	a0, 32(sp)
	ld	a1, 40(sp)
	ld	a2, 48(sp)
	ld	a3, 56(sp)
	or	a0, a0, a1
	or	a2, a2, a3
	or	a0, a0, a2
	bnez	a0, Ltv_point_encode__cont
	# Point-at-infinity encodes into a single byte of value 0x00.
	ld	a0, 88(sp)
	sb	zero, (a0)
	li	a0, 1
	j	Ltv_point_encode__exit
Ltv_point_encode__cont:
	# Non-infinity point encodes into 65 bytes.
	ld	a0, 88(sp)
	li	a1, 0x04
	sb	a1, (a0)
	addi	a0, a0, 1
	mv	a1, sp
	li	a3, 64
Ltv_point_encode__loop:
	lbu	a2, (a1)
	addi	a1, a1, 1
	sb	a2, (a0)
	addi	a0, a0, 1
	addi	a3, a3, -1
	bnez	a3, Ltv_point_encode__loop
	li	a0, 65

Ltv_point_encode__exit:
	ld	ra, 104(sp)
	c.addi16sp sp, 112
	ret
	.size	tv_point_encode, . - tv_point_encode

# tv_point_set_neutral()
	.global	tv_point_set_neutral
	.type	tv_point_set_neutral, %function
tv_point_set_neutral:
	# Clear all 120 useful bytes of the structure, then set Y to a
	# non-zero value.
	li	a3, 15
Ltv_point_set_neutral__loop:
	sd	zero, (a0)
	addi	a0, a0, 8
	addi	a3, a3, -1
	bnez	a3, Ltv_point_set_neutral__loop
	li	a1, 1
	sd	a1, -80(a0)
	ret
	.size	tv_point_set_neutral, . - tv_point_set_neutral

# point_addsub(point *p3, point *p1, point *p2, int sub)
# when sub == 0: p3 <- p1 + p2
# when sub != 0: p3 <- p1 - p2
	.type	point_addsub, %function
point_addsub:
	c.addi16sp sp, -48
	sd	a0, (sp)
	sd	a1, 8(sp)
	sd	a2, 16(sp)
	sd	a3, 24(sp)
	sd	s11, 32(sp)
	sd	ra, 40(sp)

	mv	s11, sp

	INTERPRETER_BEGIN

	# Copy source coordinates to _W* and _H*
	c.addi4spn a0, sp, (40*_Wx)
	ld	a1, 8(s11)
	jal	gf_copy
	jal	gf_copy
	jal	gf_copy
	c.addi4spn a0, sp, (40*_Hx)
	ld	a1, 16(s11)
	jal	gf_copy
	jal	gf_copy
	jal	gf_copy

	# If subtracting: negate _Hy (limb-wise)
	ld	a3, 24(s11)
	beqz	a3, Lpoint_addsub__cont
	c.addi4spn a0, sp, (40*_Hy)
	li	a3, 5
Lpoint_addsub__loop:
	ld	a2, (a0)
	sub	a2, zero, a2
	sd	a2, (a0)
	addi	a0, a0, 8
	addi	a3, a3, -1
	bnez	a3, Lpoint_addsub__loop
Lpoint_addsub__cont:

	# Set modulus to mod_P  (&mod_P == &mod_N + 48)
	addi	t1, t1, 48

	# Set Bm.
	add	a0, sp, (40*_Bm)
	lla	a1, gf_Bm
	jal	decode_int

	# Simulate a call, with a return pointer leading to bytecode_ok.
	mv	a5, sp
	c.addi16sp sp, -16
	lla	a0, bytecode_ok
	sd	a0, (sp)
	lla	t5, point_add_to_W
	INTERPRETER_MAIN

	ld	a0, (s11)
	addi	a1, a5, (40*_Wx)
	call	gf_copy
	call	gf_copy
	call	gf_copy

	INTERPRETER_END

	ld	s11, 32(sp)
	ld	ra, 40(sp)
	c.addi16sp sp, 48
	ret
	.size	point_addsub, . - point_addsub

# tv_point_add()
	.global	tv_point_add
	.type	tv_point_add, %function
tv_point_add:
	li	a3, 0
	j	point_addsub
	.size	tv_point_add, . - tv_point_add

# tv_point_sub()
	.global	tv_point_sub
	.type	tv_point_sub, %function
tv_point_sub:
	li	a3, 1
	j	point_addsub
	.size	tv_point_sub, . - tv_point_sub

	.balign	8
gf_R2p:
	.quad	0x00000030000000, 0x3FFFC000000000, 0x3EFFFFFFFBFFFF
	.quad	0x3FFFFFFFFFFFFF, 0x00004FFFFFFFDF
gf_R2n:
	.quad	0x3644694887AC57, 0x28AB84C1E17805, 0x19619076A9EA8C
	.quad	0x059212A4ADAFB1, 0x000055ABA83AFC
# b*2^270 mod p
gf_Bm:
	.byte	0x01, 0x87, 0x78, 0x2D, 0xD2, 0x0D, 0x02, 0x5C
	.byte	0x88, 0x2A, 0xFD, 0xC8, 0x4B, 0xB5, 0xAB, 0x3C
	.byte	0x01, 0x73, 0x27, 0x15, 0x0C, 0x24, 0x36, 0x27
	.byte	0x37, 0xD8, 0x8A, 0x71, 0x2F, 0x77, 0xF7, 0x0C

# ========================================================================
#endif

	# Special section to indicate that the stack is non-executable
	.section	".note.GNU-stack","",@progbits

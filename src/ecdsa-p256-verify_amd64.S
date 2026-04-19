	.arch	generic64
	.file	"ecdsa-p256-verify_amd64.S"
	.text

# ========================================================================
# PLATFORM COMPATIBILITY
#
# This code is meant for systems using the SysV EABI, e.g. Linux.
# Functions expect pointer/integer arguments to be provided in registers
# RDI, RSI, RDX, RCX, R8 and R9, in that order. To use this code on
# Windows, which uses a different convention, the externally callable
# functions must be adjusted (namely all functions whose name starts
# with 'tv_': the main API function tv_ecdsa_p256_verify(), and the
# test-only functions).
#
# Only standard 64-bit x86 instructions are used (no reliance on extensions
# such as BMI2). SSE instructions are not used at all. The code is
# self-contained and does not reference external functions; it is also
# position-independent.
#
# The code does NOT rely on the "red zone" which is part of the SysV EABI
# (the 128 bytes _below_ the stack pointer are guaranteed to remain
# unmodified, even by asynchronous code such as interruptions or signal
# delivery). This makes it compatible with more situations, e.g. as part
# a custom boot ROM.
# ========================================================================

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

# ========================================================================
# void decode_int(gf *d, const uint8_t *src)
# Decode value from the source (32 bytes, unsigned, big-endian) into
# the destination (five 54-bit limbs, little-endian). Output is
# normalized and non-negative.
# SPECIAL ABI: on output:
#    rdi = (uint8_t *)d + 40
#    rsi = src + 32
# Clobbers: rax, rcx, rdx
# ========================================================================

# WARNING: decode_int() has size 38 bytes and is immediately followed by
# curve_constants. This is used in the INTERPRETER_BEGIN macro (later on)
# and in particular the function size is hardcoded there (to get a more
# size-efficient opcode encoding).
# IF THIS FUNCTION IS MODIFIED, INTERPRETER_BEGIN MUST BE ADJUSTED.
	.type	decode_int, %function
decode_int:
	# WARNING: callers rely on r8-r10 not being modified

	# Split source words into limbs, pushed onto the stack.
	# Least significant limb is pushed last.
	xorl	%edx, %edx
	movb	$50, %cl
Ldecode_int__loop1:
	cmpb	$10, %cl
	je	Ldecode_int__cont
	lodsq
	bswapq	%rax        # source is big-endian
Ldecode_int__cont:
	xchgq	%rdx, %rax
	shldq	%cl, %rdx, %rax
	shrq	$10, %rax
	pushq	%rax
	subb	$10, %cl
	jnz	Ldecode_int__loop1

	# Move the limbs to the output. Thanks to the move through the
	# stack, they are in the right order.
	movb	$5, %cl
Ldecode_int__loop2:
	popq	%rax
	stosq
	loop	Ldecode_int__loop2
	ret
	.size	decode_int, . - decode_int

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
#       30   Gx (x coordinate of generator point, Montgomery)
#       31   Gy (y coordinate of generator point, Montgomery)
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
#    00000111   SKIPNZ       skip next is acc is non-zero
#    00001111   SKIPNEG      skip next is acc is negative
#    00010111   FNEXT        consume first iteration
#    00011111   RET          return from subroutine
#    00100111   FOR          initialize bit iterator
#    00101111   NEXT         loop back iterator
#    00110111   OK           exit with a success
#    00111111   FAIL         exit with a failure
#    01000111   NORM         normalize value in accumulator
#    01001111   CALL label   call subroutine (+immediate offset)
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
# lower limbs are in [0, 2^54-1]); the "NORM" instruction normalizes the
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
	.equ	OP_SKIPNZ,    0x07
	.equ	OP_SKIPNEG,   0x0F
	.equ	OP_FNEXT,     0x17
	.equ	OP_RET,       0x1F
	.equ	OP_FOR,       0x27
	.equ	OP_NEXT,      0x2F
	.equ	OP_OK,        0x37
	.equ	OP_FAIL,      0x3F
	.equ	OP_NORM,      0x47
	.equ	OP_CALL,      0x4F

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
bytecode_entry:
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

# ========================================================================
# add_mul_wide()
#    d <- d + a*f
# Values are in 54-bit limbs; no bit propagation.
# SPECIAL API:
# Input:
#   rsp+8   pointer to d (6 words)
#   rsi     pointer to a (5 words)
#   rbx     f (multiplier, 1 word, signed, pre-shifted by 5 bits)
# Output:
#   d[] is updated (6 words)
#   rsi is updated (+40)
#   rdx   extra word
# Clobbers: rax, rcx, rdx, rdi
# ========================================================================

	.type	add_mul_wide, %function
add_mul_wide:
	leaq	8(%rsp), %rdi
	movb	$5, %cl
Ladd_mul_wide__loop:
	lodsq
	shlq	$5, %rax
	imulq	%rbx
	shrq	$10, %rax

	addq	(%rdi), %rax
	stosq
	# Alternate for the two opcodes above: faster, but +2 bytes in size.
	#addq	%rax, (%rdi)
	#addq	$8, %rdi

	addq	%rdx, (%rdi)
	# We cannot use 'loop' here because the caller (op_mul()) stores
	# a secondary counter in %ch (also, 'loop' here would have a
	# large impact on performance because it is slow/microcoded on
	# modern CPUs, and this loop is one of the hottest in the
	# implementation).
	decb	%cl
	jnz	Ladd_mul_wide__loop
	ret
	.size	add_mul_wide, . - add_mul_wide

# ========================================================================
# VM INTERPRETER
#
# The interpreter maintains a context structure on the stack, of size
# 1376 bytes. The rbp register points to that context.
# Value x (for 0 <= x <= 31) is at address rbp+40*x; moduli n and p are
# located at rbp+1280 and rbp+1328, respectively (each modulus uses 48 bytes:
# the 5 limbs, followed by the value (-1/m mod 2^54)*2^10, which is used
# for Montgomery multiplication). Value 1 is special, in that instructions
# that read that value obtain the current modulus limbs; the storage space
# of value 1 is reused for some values collectively called "the flags":
#
#    rbp+40    (unused -- 32 bytes)
#    rbp+72    saved initial stack pointer (used for VM exits) (8 bytes)
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
#  - each routine is invoked with 'call' and ends with a ret opcode
#  - rax contains the routine's own address
#  - rbx points to translation_table
#  - rbp points to the VM context
#  - cl contains the top five bits of the current opcode and the rest of
#    rcx is zero (this is the 5-bit parameter value)
#  - rdx points to the explicit operand value (i.e. rbp+40*x, except for
#    x = 1, in which case rdx points to the current modulus value)
#  - rsi contains the instruction pointer (pointing to the byte that
#    follows the instruction)
#  - rsp+8 contains the saved instruction pointer (copy of rsi); this is
#    the value that the interpreter will use to reach the next instruction
#    when this one is finished
#  - r10 contains the current loop start address, and r8d contains the
#    current loop counter
#  - r11 points to the current modulus
#  - carry flag (CF) is cleared
# rbx, rbp, r8, r10 and r11 are non-transient; their values on output must
# match their semantics. rax, rcx, rdx, rsi, rdi and r9 are scratch. When
# the interpreter loop regains control, it uses the value on the top of
# the stack as new instruction pointer, not the contents of rsi at that
# time. Registers r12-r15 are not used; some of the unit test code relies
# on r15 not being modified.
#
# The stack is also used for subroutine calls to save caller's instruction
# pointers.

# LD x    copy value x into accumulator
op_ld:
	pushq	%rdx
	pushq	%rbp
# docopy is a shareable routine that copies 40 bytes (source and destination
# pointers are on the stack). Assumption: bits 8..63 of rcx are zero.
docopy:
	popq	%rdi
	popq	%rsi
	movb	$40, %cl
	rep movsb
	ret

# ST x    copy accumulator into value x
op_st:
	pushq	%rbp
	pushq	%rdx
	jmp	docopy

# SUB x   subtract value x from accumulator
op_sub:
	# We set the carry flag (CF) to turn addition into subtraction
	stc
	# FALL THROUGH
# ADD x   add value x to accumulator
op_add:
	# Move pointer to second operand into rsi
	pushq	%rdx
	popq	%rsi
	# Set rdx to 0 when CF is cleared, but to -1 if CF is set
	# (CF is cleared when entering opcode routines, but op_sub
	# sets CF explicitly).
	sbbq	%rdx, %rdx
	# Set rdi to point to the accumulator
	pushq	%rbp
	popq	%rdi
	movb	$5, %cl
Lop_add__loop:
	# Load limb from second operand.
	lodsq
	# Keep limb unchanged (rdx = 0) or negate it (rdx = -1)
	xorq	%rdx, %rax
	subq	%rdx, %rax
	# Add to acumulator limb and update accumulator pointer
	addq	(%rdi), %rax
	stosq
	loop	Lop_add__loop
	ret

# SMOD y    switch current modulus (y = 26 for mod_N, y = 27 for mod_P)
op_smod:
	# &mod_N == rbp+1280
	# &mod_P == rbp+1328 == &mod_N + 48
	# We have y in %rcx, and rbp+40*y in %rdx, and:
	#    32 + (40*y) + 8*y = 1280 if y = 26, or 1328 if y = 27
	leaq	32(%rdx,%rcx,8), %r11
	ret

# MUL x   multiply accumulator with x
# This uses Montgomery multiplication, so that it really computes (x*acc)/R.
# The current modulus is used.
op_mul:
	movq	%rdx, %r9      # second operand
	pushq	%rbx

	# Allocate a 10-word stack space, initialized at zero.
	xorl	%eax, %eax
	movb	$10, %cl
Lop_mul__loop1:
	pushq	%rax
	loop	Lop_mul__loop1

	movb	$5, %ch    # add_mul_wide() uses %cl, but we can use %ch
Lgf_mul__loop2:
	# t <- t + a*b_i
	movq	%rbp, %rsi    # We could use here a push/pop to gain 1 byte
	movq	(%r9), %rbx
	addq	$8, %r9
	shlq	$5, %rbx
	call	add_mul_wide
	# rbx <- (-t/p mod 2^54)*2^5  (signed)
	popq	%rbx
	pushq	%rbx
	movq	%r11, %rsi
	imulq	40(%rsi), %rbx
	sarq	$5, %rbx
	# t <- t + f*m
	call	add_mul_wide
	# Propagate upper bits of dropped word
	popq	%rax
	sarq	$54, %rax
	addq	%rax, (%rsp)
	decb	%ch
	jnz	Lgf_mul__loop2

	# Size of t is now 5 words. We copy it to the destination,
	# with high bits propagation.
	# op_norm() also tail-calls here. API:
	#  - destination address is rbp
	#  - source value is in the top five stack words
	#  - function removes the source value in the process
	#  - after value removal, rbx is popped from the stack
normalize_limbs:
	pushq	%rbp
	popq	%rdi
	movb	$4, %cl
	popq	%rax
Lnormalize_limbs__loop:
	pushq	%rax
	popq	%rdx
	shlq	$10, %rax
	shrq	$10, %rax
	stosq
	sarq	$54, %rdx
	popq	%rax
	addq	%rdx, %rax
	decb	%cl
	jnz	Lnormalize_limbs__loop
	stosq
	popq	%rbx
	ret

# SKIPBITZ x   skip next instruction if current bit is set in x
# The "current bit" relates to the iterator; this instruction makes sense
# only when an iteration is ongoing.
op_skipbitz:
	btl	%r8d, (%rdx)         # test bit value
	jc	Lret1
	# FALL THROUGH
# Common sequence for skipping the next instruction. This assumes that
# rsi contains the current instruction pointer; the saved instruction
# pointer (on the stack) is adjusted.
# WARNING: doskip requires rsi to still contain the instruction pointer.
doskip:
	# Increment the instruction pointer to skip the next instruction;
	# take care that CALL instruction has size 2 bytes.
	lodsb
	cmpb	$(OP_CALL), %al
	jne	Ldoskip__cont
	lodsb
Ldoskip__cont:
	popq	%rax
	popq	%rcx
	pushq	%rsi
	pushq	%rax
Lret1:
	ret

# The extended translation table is used for opcodes that do not have
# a value operand. This table contains routine offsets relative to
# op_extended.
extended_translation_table:
	# WARNING: if table size is changed, the movb instruction
	# in op_extended MUST be altered accordingly.
	.byte	op_skipnz - op_extended
	.byte	op_skipneg - op_extended
	.byte	op_fnext - op_extended
	.byte	op_ret - op_extended
	.byte	op_for - op_extended
	.byte	op_next - op_extended
	.byte	op_ok - op_extended
	.byte	op_fail - op_extended
	.byte	op_norm - op_extended
	.byte	op_call - op_extended

# Pseudo-instruction invoked for extended opcodes.
op_extended:
	# %cl contains the opcode.
	# Use the secondary translation table. rax currently contains
	# the address of op_extended, and the table size is 10 bytes.
	# WARNING: if the table size is modified, the offset in the
	# movb instruction below MUST be modified. The offset is
	# hardcoded so that it uses only one byte in the generated
	# instruction (if using symbol related expression, the assembler
	# generates a 32-bit offset).
	movb	-10(%rax,%rcx), %cl
	addq	%rcx, %rax
	jmpq	*%rax

# In extended opcodes, cl no longer contains relevant data (but
# bits 8..63 of rcx are still 0).

# NORM   normalize the accumulator
# Normalization does not change the value as an integer, but it
# ensures that the four low limbs are in [0, 2^54-1]. After normalization,
# the sign of the top limb matches the sign of the whole integer.
op_norm:
	pushq	%rbx
	movb	$5, %cl
Lop_norm__loop:
	pushq	-8(%rbp,%rcx,8)
	loop	Lop_norm__loop
	jmp	normalize_limbs

# SKIPNZ   skip next instruction if accumulator is non-zero
# This works correctly only if the accumulator has been normalized. This
# is a comparison over the plain integers; for a comparison over _modular_
# integers, the value must be fully reduced first.
op_skipnz:
	movb	$40, %cl
	pushq	%rbp
	popq	%rdi
	xorl	%eax, %eax    # clear al, and set ZF flag
	repe scasb
	# If ZF is still set, then all 40 bytes were 0.
	jnz	doskip
	ret

# SKIPNEG   skip next instruction if accumulator is negative
# This works correctly only if the accumulator has been normalized. This
# is a comparison over the plain integers.
op_skipneg:
	cmpb	$0, 39(%rbp)
	jl	doskip
	ret

# RET     return from subroutine
op_ret:
	popq	%rax    # return address for the opcode routine
	popq	%rsi    # saved instruction pointer
	pushq	%rax
	ret

# FOR    start the iterator
# This sets the iterator counter to 255. Each NEXT instruction will
# decrement the iterator and loop back to immediately after the FOR,
# unless the counter reaches -1 (which terminates the loop).
op_for:
	# Save address of next instruction; this is where execution
	# will loop back upon NEXT.
	movq	%rsi, %r10
	# In r8d, we store the actual bit offset, considering that
	# values are stored with 54-bit limbs: since 255 = 4*54 + 39,
	# bit 255 is really at offset 4*64 + 39 = 295.
	movl	$295, %r8d
Lret2:
	ret

# FNEXT   consume first iteration
# This is like a NEXT which is performed only on first iteration.
op_fnext:
	cmpl	$295, %r8d
	jne	Lret2
	# FALL THROUGH
# NEXT   decrement iterator counter and loop
# If the counter is at zero, then the loop exits. Otherwise, the counter
# is decremented, and execution jumps to right after the FOR instruction
# that started the iterator.
op_next:
	# Decrement bit offset.
	movl	%r8d, %eax
	testl	%eax, %eax
	je	Lop_next__cont2
	decl	%r8d
	# If the 6 low bits of the offset were zero before decrementation,
	# then we are at a word boundary and we must adjust the offset.
	andb	$0x3F, %al
	jnz	Lop_next__cont1
	subl	$10, %r8d
Lop_next__cont1:
	# Reset saved instruction pointer.
	popq	%rdx
	popq	%rsi
	pushq	%r10
	pushq	%rdx
Lop_next__cont2:
	ret

# OK     exit the interpreter with a success status
op_ok:
	# Set the success flag
	movb	$1, %ch
	# FALL THROUGH
# FAIL   exit the interpreter with a failed status
op_fail:
	# Set the exit flag
	xorl	%ebx, %ebx
	ret

# CALL   call subroutine
# The target subroutine address is provided as one inline byte
# immediately following the instruction; the byte is the offset
# (unsigned) to add to the current instruction pointer to obtain the
# address of the called subroutine. Since the offset is unsigned,
# this can only call subroutines located after the call site.
op_call:
	# Subroutine call. We must manipulate the stack so that the
	# interpreter begins fetching the instructions from the subroutine.
	# Current stack:
	#   rsp+8    saved instruction pointer (caller)
	#   rsp+0    opcode routine return address
	# New stack:
	#   rsp+16   saved instruction pointer (caller)
	#   rsp+8    saved instruction pointer (subroutine)
	#   rsp+0    opcode routine return address
	popq	%rdx    # remove native return address
	popq	%rsi    # remove saved instruction pointer
	# Load offset
	xorl	%eax, %eax
	lodsb
	# Push back the adjusted saved instruction pointer (caller)
	pushq	%rsi
	# Then the instruction pointer for the called routine
	addq	%rax, %rsi
	pushq	%rsi
	pushq	%rdx    # put back native return address
	ret

# Interpreter is built as three macros, so that the test code may use
# some interpreters to exercise subroutines.

# Interpreter initialization: allocate and setup the stack context.
# Current values of rbx and rbp are saved; they will be restored when
# INTERPRETER_END is called.
# Input:
#    rcx[8..63] MUST be zero
# Outputs:
#    rcx[8..63] are still zero
#    rbx   pointer to the decode_int() function
#    rbp   points to the allocated stack context
#    rsi   points to the bytecode entry point
# Clobbers: rax, rcx, rdx, rdi
# 1392 bytes are stored on the stack, and rbp is made equal to rsp. Previous
# top-of-stack can be accessed at 1392(%rbp).
.macro	INTERPRETER_BEGIN
	pushq	%rbx
	leaq	decode_int(%rip), %rbx

	# WARNING: value "38" is the size of the decode_int() function. This
	# is hardcoded here because uing a proper offset expression
	# 'curve_constants - decode_int' would lead the assembler to use
	# a 4-byte offset in the opcode, instead of a 1-byte offset.
	# THIS VALUE MUST BE ADJUSTED IF decode_int() IS MODIFIED.
	leaq	38(%rbx), %rsi

	# Allocate the interpreter context.
	# Context consists of 32 slots of 40 bytes each, for the 32 values
	# (slot 1 is "virtual" and contains the flag), and an extra 96 byts
	# for mod_N and mod_P (each decoded over 40 bytes, and followed by
	# the 8-byte n0i or p0i constant).

	# Reserve space for Gx, Gy, mod_N, n0i, mod_P and p0i.
	# The 'enter' opcode here is equivalent to:
	#   push  %rbp
	#   movq  %rsp, %rbp
	#   subq  $176, %rsp
	enter	$176, $0

	# Decode constants.
	movq	%rsp, %rdi
	callq	*%rbx        # decode_int() for Gx
	callq	*%rbx        # decode_int() for Gy
	movq	%rdi, %r11   # Initial modulus is mod_N
	callq	*%rbx        # decode_int() for mod_N
	movsq                # copy n0i = (-1/n mod 2^54)*2^10
	callq	*%rbx        # decode_int() for mod_P

	# p0i = (-1/p mod 2^54)*2^10 = 2^10
	xorl	%eax, %eax
	stosq
	movb	$0x04, -7(%rdi)
	# rax = 0 now

	# Now rsi points to mod_N (it follows the encoded Bm).
	# Clear space for values 29 to 2, except lowest limb, which we
	# set to 1 (value v2 is ONE).
	movb	$139, %cl    # 139 = 28*5 - 1
1:
	pushq	%rax
	loop	1b
	# Value v2 is ONE.
	incb	%al
	pushq	%rax

	# Push saved stack pointer (at offset 72 in context structure),
	# then allocate 72 bytes for unused area and accumulator.
	enter	$72, $0
	movq	%rsp, %rbp
.endm

# Main interpreter loop.
# Inputs:
#    rbp   points to the allocated stack context
#    rsi   instruction pointer
# Outputs:
#    rbp is unchanged
#    exit status is in ch (1 = success, 0 = failure)
#    stack MAY have grown (use rbp to access stack elements)
# Clobbers:
#    rax, rbx, rcx, rdx, rsi, rdi
.macro	INTERPRETER_MAIN
	# Set rbx to point to the translation table.
	leaq	translation_table(%rip), %rbx
1:
	# Load next instruction.
	xorl	%eax, %eax
	lodsb
	# Copy top 5 bits into cl; this also clears the rest of rcx.
	movl	%eax, %ecx
	shrl	$3, %ecx
	# Translate instruction (low 3 bits)
	andb	$0x07, %al
	xlatb
	# Assuming that the instruction has an explicit value operand,
	# set rdx to point to that operand.
	# Address of value x is rbp+40*x (x = 1 is the current modulus
	# and is accessed specially).
	imull	$40, %ecx, %edx
	addq	%rbp, %rdx
	# For x = 1, we access the current modulus, whose address is in r11.
	cmpb	$1, %cl
	cmove	%r11, %rdx
	# rax still contains the translated offset; call the routine.
	addq	%rbx, %rax     # addition does not overflow: CF is cleared
	pushq	%rsi
	callq	*%rax
	popq	%rsi
	# Execute next instruction until the exit flag is set
	testq	%rbx, %rbx
	jnz	1b
.endm

# Wind down the interpreter. The stack, rbx and rbp are restored to the
# state when INTERPRETER_BEGIN was invoked.
# No other clobbers.
.macro	INTERPRETER_END
	# Restore stack and saved registers.
	movq	72(%rbp), %rsp
	popq	%rbp
	popq	%rbx
.endm

# ========================================================================
# int tv_ecdsa_p256_verify(const void *sig, size_t sig_len,
#         const void *pub, size_t pub_len,
#         const void *hv, size_t hv_len)
# ========================================================================

# Small helper chunk located here so that some jumps are close.
Ltv_ecdsa_p256_verify__err:
	xorl	%eax, %eax
	ret

	.global	tv_ecdsa_p256_verify
	.type	tv_ecdsa_p256_verify, %function
tv_ecdsa_p256_verify:
	# Check input sizes.
	subq	$64, %rsi
	jnz	Ltv_ecdsa_p256_verify__err
	subq	$65, %rcx
	jnz	Ltv_ecdsa_p256_verify__err
	subq	$32, %r9
	cmpq	$32, %r9
	ja	Ltv_ecdsa_p256_verify__err
	# This also ensures that rcx = 0.

	# Check that the public key leading byte is 0x04.
	pushq	%rdx
	popq	%rsi
	lodsb
	cmpb	$0x04, %al
	jne	Ltv_ecdsa_p256_verify__err

	# We need to allocate the interpreter context; this will not
	# clobber r8, r9 or r10.
	movq	%rdi, %r9
	movq	%rsi, %r10
	# r8   hv
	# r9   sig
	# r10  pub+1

	# We still have rcx = 0.
	INTERPRETER_BEGIN

	# rsi points to the bytecode; we save it for now.
	pushq	%rsi

	# Decode r, s, e, Qx and Qy into the appropriate slots.
	# This uses the fact that the slots are consecutive.
	# rbx still contains the address of decode_int().
	leaq	(40*_Kr)(%rbp), %rdi
	movq	%r9, %rsi
	callq	*%rbx        # r
	callq	*%rbx        # s
	movq	%r8, %rsi
	callq	*%rbx        # e
	movq	%r10, %rsi
	callq	*%rbx        # Qx
	callq	*%rbx        # Qy

	# We previously saved the bytecode address.
	popq	%rsi
	INTERPRETER_MAIN

	INTERPRETER_END
	# %ch was set according to the bytecode exit status
	xorl	%eax, %eax
	movb	%ch, %al
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
	xorl	%eax, %eax
	movb	$1, %al
	ret
	.size	tv_gf_has_unreduced, . - tv_gf_has_unreduced

# This function applies conversion to Montgomery representation.
	.global	tv_gf_decode
	.type	tv_gf_decode, %function
tv_gf_decode:
	# Choose the correct modulus and constant R^2.
	testl	%edx, %edx
	leaq	gf_R2p(%rip), %rcx
	leaq	gf_R2n(%rip), %rax
	cmovnz	%rax, %rcx
	pushq	%rcx       # R^2
	pushq	%rdx       # scalar
	pushq	%rdi       # destination
	# Raw decode
	xorl	%ecx, %ecx   # decode_int() requires rcx[8..63] = 0
	call	decode_int
	# Multiply by R^2 to get the Montgomery representation.
	popq	%rdi
	movq	%rdi, %rsi
	popq	%rcx
	popq	%rdx
	call	tv_gf_mul
	xorl	%eax, %eax
	movb	$1, %al
	ret
	.size	tv_gf_decode, . - tv_gf_decode

# We accept the value if its limbs are at most 5.5*2^t in absolute value,
# where t = 54 for limbs 0..3, and t = 40 for limb 4. We ignore the 'scalar'
# parameter (check is the same for both fields).
	.global	tv_gf_check
	.type	tv_gf_check, %function
tv_gf_check:
	movq	%rdi, %rsi
	movb	$5, %cl
Ltv_gf_check__loop:
	# Read limb value.
	lodsq
	# Compute the limb absolute value.
	testq	%rax, %rax
	jns	Ltv_gf_check__cont1
	negq	%rax
Ltv_gf_check__cont1:
	# Divide absolute value by 2^39.
	shrq	$39, %rax
	decb	%cl
	jnz	Ltv_gf_check__cont2
	# Last limb: must be lower than 11*2^39
	cmpl	$11, %eax
	setb	%cl
	xorl	%eax, %eax
	movb	%cl, %al
	ret
Ltv_gf_check__cont2:
	# Not last limb: exit if not lower than 11*2^53; otherwise, loop.
	shrq	$14, %rax
	cmpl	$11, %eax
	jb	Ltv_gf_check__loop
	# Limb is too large, report an error.
	xorl	%eax, %eax
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

# gf_op(gf *d, const gf *a, const gf *b, int scalar, const uint8_t *code)
	.type	gf_op, %function
gf_op:
	pushq	%r15
	movq	%rsp, %r15
	pushq	%rdi
	pushq	%rsi
	pushq	%rdx
	pushq	%rcx
	pushq	%r8

	xorl	%ecx, %ecx
	INTERPRETER_BEGIN

	# Copy operands:
	#  - If a != NULL then this is an add, sub or mul; the two source
	#    operands go to the accumulator and value T0, respectively.
	#  - If a == NULL then this is an inversion or an encoding, *d is
	#    copied into the accumulator.
	movq	%rbp, %rdi
	movq	-16(%r15), %rsi
	testq	%rsi, %rsi
	jz	Lgf_op__cont1
	# Copy a to accumulator
	movb	$40, %cl
	rep movsb
	# Copy b to T0
	leaq	(40*_T0)(%rbp), %rdi
	movq	-24(%r15), %rsi
	movb	$40, %cl
	rep movsb
	jmp	Lgf_op__cont2
Lgf_op__cont1:
	# Copy d to accumulator
	movq	-8(%r15), %rsi
	movb	$40, %cl
	rep movsb
Lgf_op__cont2:
	# Set modulus according to the 'scalar' argument.
	movl	-32(%r15), %eax
	leaq	mod_P(%rip), %r11
	leaq	mod_N(%rip), %rdx
	testl	%eax, %eax
	cmovnz	%rdx, %r11

	# Simulate a call, with a return pointer leading to bytecode_ok,
	# then use the provided code pointer.
	leaq	bytecode_ok(%rip), %rax
	pushq	%rax
	movq	-40(%r15), %rsi
	INTERPRETER_MAIN

	# Copy result into destination.
	movq	-8(%r15), %rdi
	movq	%rbp, %rsi
	xorl	%ecx, %ecx
	movb	$40, %cl
	rep movsb

	INTERPRETER_END

	movq	%r15, %rsp
	popq	%r15
	ret
	.size	gf_op, . - gf_op

# tv_gf_add() uses gf_op()
	.global	tv_gf_add
	.type	tv_gf_add, %function
tv_gf_add:
	leaq	bytecode_add(%rip), %r8
	jmp	gf_op
	.size	tv_gf_add, . - tv_gf_add

# tv_gf_sub() uses gf_op()
	.global	tv_gf_sub
	.type	tv_gf_sub, %function
tv_gf_sub:
	leaq	bytecode_sub(%rip), %r8
	jmp	gf_op
	.size	tv_gf_sub, . - tv_gf_sub

# tv_gf_mul() uses gf_op()
	.global	tv_gf_mul
	.type	tv_gf_mul, %function
tv_gf_mul:
	leaq	bytecode_mul(%rip), %r8
	jmp	gf_op
	.size	tv_gf_mul, . - tv_gf_mul

# tv_gf_invert() uses gf_op()
	.global	tv_gf_invert
	.type	tv_gf_invert, %function
tv_gf_invert:
	movq	%rsi, %rcx
	xorq	%rsi, %rsi
	xorq	%rdx, %rdx
	leaq	invert_mod(%rip), %r8
	jmp	gf_op
	.size	tv_gf_invert, . - tv_gf_invert

# tv_gf_encode() uses gf_op() to perform a canonical reduction.
	.global	tv_gf_encode
	.type	tv_gf_encode, %function
tv_gf_encode:
	pushq	%rdi
	pushq	32(%rsi)
	pushq	24(%rsi)
	pushq	16(%rsi)
	pushq	8(%rsi)
	pushq	(%rsi)
	movq	%rsp, %rdi
	movq	%rdx, %rcx
	xorq	%rsi, %rsi
	xorq	%rdx, %rdx
	leaq	canonicalize(%rip), %r8
	call	gf_op

	# Verify that limbs are non-negative and in-range.
	movq	%rsp, %rsi
	xorl	%edx, %edx
	decq	%rdx
	shrq	$10, %rdx
	movb	$5, %cl
Ltv_gf_encode__loop:
	lodsq
	decb	%cl
	jnz	Ltv_gf_encode__cont1
	shrq	$14, %rdx
Ltv_gf_encode__cont1:
	cmpq	%rdx, %rax
	jb	Ltv_gf_encode__cont2
	# Off-range limb, this is an error.
	xorl	%eax, %eax
	ret
Ltv_gf_encode__cont2:
	cmpb	$0, %cl
	jne	Ltv_gf_encode__loop

	# Load limbs into registers.
	popq	%rax
	popq	%rcx
	popq	%rdx
	popq	%rsi
	popq	%rdi
	# Reassemble limbs into four words.
	shlq	$10, %rax
	shrdq	$10, %rcx, %rax
	shlq	$10, %rcx
	shrdq	$20, %rdx, %rcx
	shlq	$10, %rdx
	shrdq	$30, %rsi, %rdx
	shlq	$10, %rsi
	shrdq	$40, %rdi, %rsi
	bswapq	%rax
	bswapq	%rcx
	bswapq	%rdx
	bswapq	%rsi
	# Output words.
	popq	%rdi
	movq	%rsi, (%rdi)
	movq	%rdx, 8(%rdi)
	movq	%rcx, 16(%rdi)
	movq	%rax, 24(%rdi)

	xorl	%eax, %eax
	movb	$1, %al
	ret
	.size	tv_gf_encode, . - tv_gf_encode

# tv_point_decode()
	.global	tv_point_decode
	.type	tv_point_decode, %function
tv_point_decode:
	# Skip leading byte.
	incq	%rsi
	pushq	%r14
	pushq	%r15
	movq	%rsi, %r14
	movq	%rdi, %r15
	xorl	%ecx, %ecx
	INTERPRETER_BEGIN

	# Decode coordinates as integers into slots Qx and Qy
	movq	%r14, %rsi
	leaq	(40*_Qx)(%rbp), %rdi
	callq	*%rbx      # rbx points to decode_int()
	callq	*%rbx

	# Bm was not computed yet; since we skip that part of the bytecode,
	# we copy the value here.
	leaq	gf_Bm(%rip), %rsi
	leaq	(40*_Bm)(%rbp), %rdi
	call	*%rbx

	# Set modulus to mod_P
	leaq	mod_P(%rip), %r11

	# We mimick a _CALL to the check_point routine, and set back
	# the return address to a _OK.
	leaq	bytecode_ok(%rip), %rax
	pushq	%rax
	leaq	check_point(%rip), %rsi
	INTERPRETER_MAIN
	pushq	%rcx

	# Copy decoded x and y to destination P.X and P.Y; set P.Z to 1.
	movq	%r15, %rdi
	leaq	(40*_Qx)(%rbp), %rsi
	xorl	%ecx, %ecx
	movb	$80, %cl
	rep movsb
	xorl	%eax, %eax
	incb	%al
	stosq
	xorl	%eax, %eax
	stosq
	stosq
	stosq
	stosq

	popq	%rcx
	INTERPRETER_END
	xorl	%eax, %eax
	movb	%ch, %al
	popq	%r15
	popq	%r14
	ret
	.size	tv_point_decode, . - tv_point_decode

# tv_point_encode()
	.global	tv_point_encode
	.type	tv_point_encode, %function
tv_point_encode:
	pushq	%rdi
	pushq	%rsi
	subq	$80, %rsp

	# Copy Z coordinate to rsp+0
	movq	%rsp, %rdi
	leaq	80(%rsi), %rsi
	xorl	%ecx, %ecx
	movb	$40, %cl
	rep movsb
	# Invert Z
	movq	%rsp, %rdi
	xorl	%esi, %esi
	call	tv_gf_invert
	# Multiply 1/Z with Y, into rsp+40
	# (We use Montgomery multiplication but that still works: we
	# are multiplying the Montgomery representations of X/R and R/Z,
	# thus we get the Montgomery representation of X/Z.)
	leaq	40(%rsp), %rdi
	movq	%rsp, %rsi
	movq	80(%rsp), %rdx
	addq	$40, %rdx
	xorl	%ecx, %ecx
	call	tv_gf_mul
	# Multiply 1/Z with X, into rsp
	movq	%rsp, %rdi
	movq	%rsp, %rsi
	movq	80(%rsp), %rdx
	xorl	%ecx, %ecx
	call	tv_gf_mul
	# Encode x and y into rsp+0 and rsp+32, respectively.
	movq	%rsp, %rdi
	movq	%rsp, %rsi
	xorl	%edx, %edx
	call	tv_gf_encode
	leaq	32(%rsp), %rdi
	leaq	40(%rsp), %rsi
	xorl	%edx, %edx
	call	tv_gf_encode
	# y is never zero for a curve point, since the curve has odd order.
	# If we still get a zero, then this must be because Z was zero
	# (which tv_gf_invert() "inverted" into zero), i.e. this was the
	# point-at-infinity.
	leaq	32(%rsp), %rdi
	xorl	%ecx, %ecx
	movb	$32, %cl
	xorl	%eax, %eax
	repe scasb
	jnz	Ltv_point_encode__cont
	addq	$88, %rsp
	popq	%rdi
	stosb
	movb	$1, %al
	ret
Ltv_point_encode__cont:
	# Non-infinity point.
	movq	88(%rsp), %rdi
	movb	$0x04, %al
	stosb
	movq	%rsp, %rsi
	movb	$64, %cl
	rep movsb
	addq	$96, %rsp
	movb	$65, %al
	ret
	.size	tv_point_encode, . - tv_point_encode

# tv_point_set_neutral()
	.global	tv_point_set_neutral
	.type	tv_point_set_neutral, %function
tv_point_set_neutral:
	# Clear all 120 useful bytes of the structure, then set Y to a
	# non-zero value.
	xorl	%eax, %eax
	xorl	%ecx, %ecx
	movb	$120, %cl
	rep stosb
	movb	$1, %al
	movb	%al, -80(%rdi)
	ret
	.size	tv_point_set_neutral, . - tv_point_set_neutral

# point_double(point *p1)                p1 <- 2*p1
# point_addto(point *p1, point *p2)      p1 <- p1 + p2
	.type	point_double, %function
point_double:
	pushq	%rdi
	popq	%rsi
point_addto:
	pushq	%r14
	pushq	%r15
	movq	%rsi, %r14
	movq	%rdi, %r15
	xorl	%ecx, %ecx
	INTERPRETER_BEGIN

	# Copy source coordinates to _W* and _H*
	leaq	(40*_Wx)(%rbp), %rdi
	xorl	%ecx, %ecx
	movq	%r15, %rsi
	movb	$120, %cl
	rep movsb
	movq	%r14, %rsi
	movb	$120, %cl
	rep movsb

	# Set modulus to mod_P.
	leaq	mod_P(%rip), %r11

	# Bm was not computed yet; since we skip that part of the bytecode,
	# we copy the value here.
	leaq	gf_Bm(%rip), %rsi
	leaq	(40*_Bm)(%rbp), %rdi
	call	*%rbx

	# We mimick a _CALL to the point_add_to_W routine, and set back
	# the return address to a _OK.
	leaq	bytecode_ok(%rip), %rax
	pushq	%rax
	leaq	point_add_to_W(%rip), %rsi
	INTERPRETER_MAIN

	# Copy resulting point to output.
	movq	%r15, %rdi
	leaq	(40*_Wx)(%rbp), %rsi
	xorl	%ecx, %ecx
	movb	$120, %cl
	rep movsb

	INTERPRETER_END
	popq	%r15
	popq	%r14
	ret
	.size	point_double, . - point_double

# tv_point_add()
	.global	tv_point_add
	.type	tv_point_add, %function
tv_point_add:
	subq	$120, %rsp
	pushq	%rdi
	pushq	%rsi
	# Copy p2 into stack buffer.
	movq	%rdx, %rsi
	leaq	16(%rsp), %rdi
	xorl	%ecx, %ecx
	movb	$120, %cl
	rep movsb
	# Add p1 to stack buffer.
	popq	%rsi
	leaq	8(%rsp), %rdi
	call	point_addto
	# Copy result to p3.
	popq	%rdi
	movq	%rsp, %rsi
	xorl	%ecx, %ecx
	movb	$120, %cl
	rep movsb
	addq	$120, %rsp
	ret
	.size	tv_point_add, . - tv_point_add

# tv_point_sub()
	.global	tv_point_sub
	.type	tv_point_sub, %function
tv_point_sub:
	subq	$120, %rsp
	pushq	%rdi
	pushq	%rsi
	# Copy p2 into stack buffer.
	movq	%rdx, %rsi
	leaq	16(%rsp), %rdi
	xorl	%ecx, %ecx
	movb	$120, %cl
	rep movsb
	# Negate Y coordinate of stack point.
	leaq	56(%rsp), %rsi
	movb	$5, %cl
Ltv_point_sub__loop:
	negq	(%rsi)
	addq	$8, %rsi
	decb	%cl
	jnz	Ltv_point_sub__loop
	# Add p1 to stack buffer.
	popq	%rsi
	leaq	8(%rsp), %rdi
	call	point_addto
	# Copy result to p3.
	popq	%rdi
	movq	%rsp, %rsi
	xorl	%ecx, %ecx
	movb	$120, %cl
	rep movsb
	addq	$120, %rsp
	ret
	.size	tv_point_sub, . - tv_point_sub

	.align	8
gf_R2p:
	.quad	0x00000030000000, 0x3FFFC000000000, 0x3EFFFFFFFBFFFF
	.quad	0x3FFFFFFFFFFFFF, 0x00004FFFFFFFDF
gf_R2n:
	.quad	0x3644694887AC57, 0x28AB84C1E17805, 0x19619076A9EA8C
	.quad	0x059212A4ADAFB1, 0x000055ABA83AFC
mod_N:
	.quad	0x39CAC2FC632551, 0x2AB69C5E7A13CE, 0x3FFFFFFFFBCE6F
	.quad	0x0000003FFFFFFF, 0x0000FFFFFFFF00
	.quad	0x4722ABB802F13C00   # (-1/n mod 2^54)*2^10
mod_P:
	.quad	0x3FFFFFFFFFFFFF, 0x0003FFFFFFFFFF, 0x00000000000000
	.quad	0x00000040000000, 0x0000FFFFFFFF00
	.quad	0x0000000000000400   # (-1/p mod 2^54)*2^10
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

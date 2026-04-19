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

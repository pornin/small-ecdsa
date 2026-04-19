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

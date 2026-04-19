# BYTECODE: Check that a value (just decoded) is non-zero and less than
# the modulus. This is meant for scalars; it uses the current modulus.
# Input:
#    acc   value to check
# Output:
#    acc   x - m if source value is x and modulus is m
check_scalar:
        _SKIPNZ ; _FAIL ; _SUB _M ; _NORM ; _SKIPNEG ; _FAIL ; _RET

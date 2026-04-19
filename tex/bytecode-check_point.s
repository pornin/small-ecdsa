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

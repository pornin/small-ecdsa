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

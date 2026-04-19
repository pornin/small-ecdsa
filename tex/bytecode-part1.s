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

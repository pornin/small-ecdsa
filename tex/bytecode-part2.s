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

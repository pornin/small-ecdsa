# Add a curve point to point W. Point W is in projective coordinates
# in (Wx:Wy:Wz); the other operand is read from (Hx:Hy:Hz).
# Inputs:
#    Wx, Wy, Wz   first operand coordinates
#    Hx, Hy, Hz   second operand coordinates
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

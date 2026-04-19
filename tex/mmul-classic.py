# k limbs (unsigned), radix 2**w
# m0i = -1/m mod 2**w, for modulus m (odd)

# Add multi-limb integers a and b, with output carry (True on overflow).
def bigint_add_carry(a, b):
    d = [ZERO]*k
    carry = False
    for i in range(0, k):
        (d[i], carry) = add_carry(a[i], b[i], carry)
    return (d, carry)

# Subtract multi-limb integer b from a, with output borrow (True on overflow).
def bigint_sub_borrow(a, b):
    d = [ZERO]*k
    borrow = False
    for i in range(0, k):
        (d[i], borrow) = sub_borrow(a[i], b[i], borrow)
    return (d, borrow)

# d <- d + g*x
# g is 1 word, x is k words, d is at least k+1 words and large enough
def bigint_add_mul(d, g, x):
    delayed = ZERO
    for i in range(0, k):
        (cL, cH) = longmul_u(g, x[i])
        (cL, carry) = add_carry(cL, delayed, False)
        (cH, _) = add_carry(cH, ZERO, carry)
        (d[i], carry) = add_carry(cL, d[i], False)
        (delayed, _) = add_carry(cH, ZERO, carry)
    (d[k], carry) = add_carry(d[k], delayed, False)
    if carry:
        (d[k + 1], _) = add_carry(d[k + 1], ZERO, carry)

# Modular addition.
def mod_add(a, b):
    (d, carry) = bigint_add_carry(a, b)
    (e, borrow) = bigint_sub_borrow(d, m)
    return e if carry == borrow else d

# Modular subtraction.
def mod_sub(a, b):
    (d, borrow) = bigint_sub_borrow(a, b)
    (e, _) = bigint_add_carry(d, m)
    return e if borrow else d

# Montgomery multiplication.
def mod_montymul(a, b):
    t = [ZERO]*(2*k + 1)
    for i in range(0, k):
        bigint_add_mul(t, a[i], b)
        f = mul(t[0], m0i)
        bigint_add_mul(t, f, m)   # this ensures that t[0] = 0
        t = t[1:]                 # word shift: this is division by 2**w
    d = t[0:k]
    (e, borrow) = bigint_sub_borrow(d, m)
    return d if (is_zero(t[k]) and borrow) else e

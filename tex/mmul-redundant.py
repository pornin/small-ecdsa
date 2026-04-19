# k limbs (signed), radix 2**s, with s < w
# sh1 = floor((w - s)/2)
# sh2 = w - s - sh1
# m0i_sh = (-1/m mod 2**s)*2**(w-s), for modulus m (odd)
# Two possible variants, depending on whether multiplication output limbs
# are normalized to [0, 2**s - 1] or to [-2**(s-1), 2**(s-1) - 1].

# Limb-wise addition.
def mod_add(a, b):
    return [add(a[i], b[i]) for i in range(0, k)]

# Limb-wise subtraction.
def mod_sub(a, b):
    return [sub(a[i], b[i]) for i in range(0, k)]

# d <- d + g*x  (limb-wise)
# g is 1 word, x is k words, d is at least k+1 words
def rr_add_mul(d, g, x):
    delayed = ZERO
    for i in range(0, k):
        (cL, cH) = longmul_s(g, x[i])
        d[i] = add(rsh_u(cL, w - s), add(d[i], delayed))
        delayed = cH
    d[k] = add(d[k], delayed)

# d <- a
# Limbs 0 to k-2 are normalized to [-2**(s-1), 2**(s-1) - 1] (if signed = True)
# or [0, 2**s - 1] (if signed = False).
def normalize(a, signed):
    d = [ZERO]*k
    cc = ZERO
    for i in range(0, k - 1):
        cc = add(a[i], rsh_s(cc, s))   # VARIANT: add old cc to d[i], not a[i]
        z = lsh(cc, w - s)
        if signed:
            z = rsh_s(z, w - s)
            cc = sub(cc, z)
        else:
            z = rsh_u(z, w - s)
        d[i] = z
    d[k - 1] = add(a[k - 1], rsh_s(cc, s))
    return d

# Montgomery multiplication.
def mod_montymul(a, b):
    b_sh = [lsh(b[i], sh2) for i in range(0, k)]
    t = [ZERO]*(2*k)
    for i in range(0, k):
        rr_add_mul(t, lsh(a[i], sh1), b_sh)
        f = mul(t[0], m0i_sh)
        rr_add_mul(t, f, m)
        t[1] = add(t[1], rsh_s(t[0], s))
        t = t[1:]
    return normalize(t, False)         # VARIANT: normalize(t, True)

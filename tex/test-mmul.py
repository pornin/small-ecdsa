import sys
import hashlib

# For tests, we work with 64-bit words.
w = 64
mask_w = (1 << w) - 1
sign_w = 1 << (w - 1)

# A Word instance encapsulate an integer, always normalized in [0, 2**w - 1].
class Word:
    def __init__(self, value):
        assert (0 <= value) and (value <= mask_w)
        self.value = value

    # Get the word value as a Python integer in [-2**(w-1), 2**(w-1) - 1]
    def as_signed(self):
        return self.value - ((self.value & sign_w) << 1)

def add(a, b):
    return Word((a.value + b.value) & mask_w)

def add_carry(a, b, c_in):
    d = a.value + b.value
    if c_in:
        d += 1
    return (Word(d & mask_w), (d >> w) != 0)

def sub(a, b):
    return Word((a.value - b.value) & mask_w)

def sub_borrow(a, b, c_in):
    d = a.value - b.value
    if c_in:
        d -= 1
    return (Word(d & mask_w), d < 0)

def lsh(a, n):
    assert n >= 0
    return Word((a.value << n) & mask_w)

def rsh_s(a, n):
    assert n >= 0
    return Word((a.as_signed() >> n) & mask_w)

def rsh_u(a, n):
    assert n >= 0
    return Word(a.value >> n)

def mul(a, b):
    return Word((a.value * b.value) & mask_w)

def longmul_s(a, b):
    d = a.as_signed() * b.as_signed()
    return (Word(d & mask_w), Word((d >> w) & mask_w))

def longmul_u(a, b):
    d = a.value * b.value
    return (Word(d & mask_w), Word(d >> w))

def is_zero(a):
    return a.value == 0

# Load the code to test in a custom namespace, so that it may access the
# context values (modulus, number of limbs...) as global variables, thus
# matching the description in the paper (the tested code is used as
# explanatory pseudocode which is included as is in the paper, so it must
# follow the paper notations).
def exec_file_and_function(filename, params, target):
    glob = {
        'w': w,
        'add': add,
        'add_carry': add_carry,
        'sub': sub,
        'sub_borrow': sub_borrow,
        'lsh': lsh,
        'rsh_s': rsh_s,
        'rsh_u': rsh_u,
        'mul': mul,
        'longmul_s': longmul_s,
        'longmul_u': longmul_u,
        'is_zero': is_zero,
        'target_to_run': target,
    }
    for (name, val) in params.items():
        glob[name] = val
    with open(filename, "r") as fh:
        exec(fh.read() + "\n\ntarget_to_run(globals())\n", glob)

def int_to_limbs(x_int, k, s):
    assert (0 <= x_int) and (x_int < (1 << (s*k)))
    mask_s = (1 << s) - 1
    return [Word((x_int >> (s*i)) & mask_s) for i in range(0, k)]

def limbs_to_int(x, k, s):
    assert len(x) == k
    x_int = 0
    for i in range(k - 1, -1, -1):
        if s < w:
            xv = x[i].as_signed()
        else:
            xv = x[i].value
        x_int = (x_int << s) + xv
    return x_int

def mkrand(counter, m_int, k, s):
    sh = hashlib.shake_256()
    sh.update(int(counter).to_bytes(8, byteorder='little'))
    if s == w:
        mlen = (m_int.bit_length() + 71) >> 3
        x_int = int.from_bytes(sh.digest(mlen), byteorder='little') % m_int
        return (int_to_limbs(x_int, k, s), x_int)
    else:
        buf = sh.digest(8*k)
        x = []
        rlen = m_int.bit_length()
        for i in range(0, k):
            nb = min(s, rlen)
            rlen -= nb
            if nb == 0:
                x.append(Word(0))
                continue
            mav = min(5 << nb, 1 << (w - 1))
            u = int.from_bytes(buf[i:i+8], byteorder='little') % (2*mav)
            x.append(Word((u - mav) & mask_w))
        return (x, limbs_to_int(x, k, s))

def test_arith(pp):
    m_int = pp['m_int']
    k = pp['k']
    s = pp['s']
    f_add = pp['mod_add']
    f_sub = pp['mod_sub']
    f_montymul = pp['mod_montymul']
    # Populate some extra parameters for the tested code.
    pp['ZERO'] = Word(0)
    pp['m'] = int_to_limbs(m_int, k, s)
    x = m_int & mask_w
    y = 4 - (x & 3)
    ncb = 2
    while ncb < w:
        y = (y*(x*y + 2)) & mask_w
        ncb <<= 1
    assert ((x*y) & mask_w) == mask_w
    m0i = Word(y & ((1 << s) - 1))
    pp['m0i'] = m0i
    if s < w:
        pp['m0i_sh'] = lsh(m0i, w - s)
    for i in range(0, 300):
        (a, a_int) = mkrand(2*i, m_int, k, s)
        (b, b_int) = mkrand(2*i + 1, m_int, k, s)
        c = f_add(a, b)
        assert (limbs_to_int(c, k, s) - (a_int + b_int)) % m_int == 0
        d = f_sub(a, b)
        assert (limbs_to_int(d, k, s) - (a_int - b_int)) % m_int == 0
        e = f_montymul(a, b)
        xe = limbs_to_int(e, k, s)
        if s == w:
            assert xe < m_int
        assert ((xe << (k*s)) - (a_int*b_int)) % m_int == 0
        print('.', end='', flush=True)
    print('')

def run_tests():
    # Modulus for tests: a random 256-bit prime.
    m_int = 0xEA9D47601550D01CD68CB50702A70EDA897A2299D1BCC3B4456E177AA2CA236B
    pp = {
        'm_int': m_int,
        'k': 4,
        's': 64,
    }
    exec_file_and_function('mmul-classic.py', pp, test_arith)
    pp = {
        'm_int': m_int,
        'k': 5,
        's': 54,
        'sh1': 5,
        'sh2': 5,
    }
    exec_file_and_function('mmul-redundant.py', pp, test_arith)

run_tests()

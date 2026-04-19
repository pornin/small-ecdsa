# Size-Optimized ECDSA Implementations

This repository contains some size-optimized implementations of the
ECDSA verification algorithm over NIST curve P-256. The
[API](src/ecdsa-p256-verify.h) is a single function which expects the
signature value (IEEE p1363 format), the public key (encoded,
uncompressed format) and the hashed message (hash value, 32 to 64
bytes). The implementations are stand-alone (no use of the libc
functions). Message hashing is not included (the API expects an already
hashed message).

The [paper](tex/mmul.pdf) describes how these implementations work. They
leverage Montgomery multiplication with a signed redundant integer
representation, over 5 limbs of 54 bits, or 12 limbs of 22 bits,
depending on the variant. The paper also explains how to invoke the
range analysis framework which is located in the [python](python)
directory. The range analysis demonstrates that the computations
performed by the implementations cannot incur an integer overflow
condition for any possible inputs; this analysis is necessary for any
code that uses redundant integer representations with unreduced
limb-wise additions and subtractions (avoiding most carry propagation
operations, and allowing unreduced additions and subtractions, are the
main reasons redundant integer representations are desirable).

The [src](src) directory contains the C and assembly implementations; 6
flavours are provided:

  - `gen64`: portable C for 64-bit platforms which support 64x64->128
    signed multiplications.

  - `gen32`: portable C code, uses only 32x32->64 signed multiplications

  - `amd64`: size-optimized assembly implementation for 64-bit x86.

  - `amd64alt`: alternate size-optimized assembly implementation for
    64-bit x86 (a bit smaller than `amd64`, but substantially slower).

  - `arm64`: size-optimized assembly implementation for 64-bit Arm (Armv8-A).

  - `rv64`: size-optimized assembly implementation for 64-bit RISC-V (RV64
    with I, M and C instruction set extensions).

See the [Makefile](src/Makefile) for details on how to compile the code.
For each variant, a test program is produced, which runs the code
against 492 test vectors from the
[Wycheproof project](https://github.com/c2SP/wycheproof). If invoked
with the `-s` command-line parameter, it will also run speed benchmarks,
although this will most probably crash on your machine, since the
measurements use CPU performance counters that are normally not
accessible; see [cycle-counter](https://github.com/pornin/cycle-counter)
for details. In any case, the point of this code is size optimization,
not speed.

## Performance

The following code sizes and speed are obtained with the assembly
implementations:

  - `amd64` (64-bit x86): **875 bytes**, 4.59 Mcycles

  - `amd64alt` (64-bit x86): **848 bytes**, 13.64 Mcycles

  - `arm64` (64-bit Arm): **1136 bytes**, 4.01 Mcycles

  - `rv64` (64-bit RISC-V): **984 bytes**, 7.05 Mcycles

Runtime costs are in millions of clock cycles; the implementations are
certainly not breaking any speed records, but they are fast enough to be
potentially usable in practical situations: most of the cost of
signature verification will be in hashing the data, not in the elliptic
curve computations. Test platforms for these values are an Intel i5-8259U
(Coffee Lake core), a Broadcom BCM2712 (Arm Cortex A76 core, in a
Raspberry Pi 5 board), and a StarFive JH7110 (SiFive U74 core, in a
VisionFive2 board), all running an up-to-date Ubuntu 24.04 operating
system.

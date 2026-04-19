# Set the C compiler to use. Which compiler is better at size optimization
# depends on the architecture.
CC = clang
#CC = gcc

# Flags used for all C and assembly compilations.
#
# '-fno-builtin' instructs the compiler not to produce references to
# standard libc functions such as memcpy() or memset(); these operations
# have to be included in the generated code (this mimicks 'bare metal'
# targets, e.g. a boot ROM).
#
# '-fno-asynchronous-unwind-tables' avoids generating frame information
# meant to support frame unwinding in case of a C++ exception; these
# tables are included in the resulting binary and increase the reported
# size.
CFLAGS = -W -Wextra -g -Os -fno-builtin -fno-asynchronous-unwind-tables # -DTV_ECDSA_P256_TEST

# Flags used for some specific targets.
#
# RISC-V specific: to enable use of the Zba and Zbb CPU extensions (which
# are present in e.g. SiFive U74 cores):
#  - C code: add -march=rv64gc_zba1p0_zbb1p0 to CFLAGS_GEN32 and CFLAGS_GEN64
#  - Assembly: add -DTV_ARCH_RV64_ZBABB to CFLAGS_RV64
# Though in practice it changes very little for the C code, and nothing at
# all for the assembly implementation, which uses only plain RV64GC
# instructions.
CFLAGS_GEN32 = # -march=rv64gc_zba1p0_zbb1p0
CFLAGS_GEN64 = # -march=rv64gc_zba1p0_zbb1p0
CFLAGS_ARM64 =
CFLAGS_AMD64 =
CFLAGS_RV64 = # -DTV_ARCH_RV64_ZBABB

# Normal targets:
#   default    compiles C code (gen32 and gen64)
#   gen32      compiles C code (gen32 only)
#   gen64      compiles C code (gen64 only)
#   amd64      compiles assembly (64-bit x86)
#   amd64alt   compiles assembly (64-bit x86, alternate implementation)
#   arm64      compiles assembly (64-bit Arm)
#   rv64       compiles assembly (64-bit RISC-V)
# Each compiled target produces a test executable, and an independent .o
# file; the .o file is the one that could be integrated in an application,
# and on which binary code footprint may be measured. Compiling with the
# optional unit test hooks for internal function substantially increases
# the binary code size.

default: gen32 gen64

clean:
	-rm -f test_ecdsa-p256-verify_gen32 test_ecdsa-p256-verify_gen64 test_ecdsa-p256-verify_arm64 test_ecdsa-p256-verify_amd64 test_ecdsa-p256-verify_amd64alt test_ecdsa-p256-verify_rv64 ecdsa-p256-verify_gen32.o ecdsa-p256-verify_gen64.o ecdsa-p256-verify_arm64.o ecdsa-p256-verify_amd64.o ecdsa-p256-verify_amd64alt.o ecdsa-p256-verify_rv64.o

gen32: gen32test gen32lib

gen64: gen64test gen64lib

arm64: arm64test arm64lib

amd64: amd64test amd64lib

amd64alt: amd64alttest amd64altlib

rv64: rv64test rv64lib

gen32test: test_ecdsa-p256-verify_gen32

gen64test: test_ecdsa-p256-verify_gen64

arm64test: test_ecdsa-p256-verify_arm64

amd64test: test_ecdsa-p256-verify_amd64

amd64alttest: test_ecdsa-p256-verify_amd64alt

rv64test: test_ecdsa-p256-verify_rv64

gen32lib: ecdsa-p256-verify_gen32.o

gen64lib: ecdsa-p256-verify_gen64.o

arm64lib: ecdsa-p256-verify_arm64.o

amd64lib: ecdsa-p256-verify_amd64.o

amd64altlib: ecdsa-p256-verify_amd64alt.o

rv64lib: ecdsa-p256-verify_rv64.o

test_ecdsa-p256-verify_gen32: ecdsa-p256-verify.c ecdsa-p256-verify.h ecdsa-p256-verify-tests.c
	$(CC) $(CFLAGS) $(CFLAGS_GEN32) -DTV_ARCH_GEN32 -o test_ecdsa-p256-verify_gen32 ecdsa-p256-verify.c ecdsa-p256-verify-tests.c

test_ecdsa-p256-verify_gen64: ecdsa-p256-verify.c ecdsa-p256-verify.h ecdsa-p256-verify-tests.c
	$(CC) $(CFLAGS) $(CFLAGS_GEN64) -DTV_ARCH_GEN64 -o test_ecdsa-p256-verify_gen64 ecdsa-p256-verify.c ecdsa-p256-verify-tests.c

test_ecdsa-p256-verify_arm64: ecdsa-p256-verify.h ecdsa-p256-verify_arm64.S ecdsa-p256-verify-tests.c
	$(CC) $(CFLAGS) $(CFLAGS_ARM64) -DTV_ARCH_ARM64 -o test_ecdsa-p256-verify_arm64 ecdsa-p256-verify_arm64.S ecdsa-p256-verify-tests.c

test_ecdsa-p256-verify_amd64: ecdsa-p256-verify.h ecdsa-p256-verify_amd64.S ecdsa-p256-verify-tests.c
	$(CC) $(CFLAGS) $(CFLAGS_AMD64) -DTV_ARCH_AMD64 -o test_ecdsa-p256-verify_amd64 ecdsa-p256-verify_amd64.S ecdsa-p256-verify-tests.c

test_ecdsa-p256-verify_amd64alt: ecdsa-p256-verify.h ecdsa-p256-verify_amd64alt.S ecdsa-p256-verify-tests.c
	$(CC) $(CFLAGS) $(CFLAGS_AMD64) -DTV_ARCH_AMD64 -o test_ecdsa-p256-verify_amd64alt ecdsa-p256-verify_amd64alt.S ecdsa-p256-verify-tests.c

test_ecdsa-p256-verify_rv64: ecdsa-p256-verify.h ecdsa-p256-verify_rv64.S ecdsa-p256-verify-tests.c
	$(CC) $(CFLAGS) $(CFLAGS_RV64) -DTV_ARCH_RV64 -o test_ecdsa-p256-verify_rv64 ecdsa-p256-verify_rv64.S ecdsa-p256-verify-tests.c

ecdsa-p256-verify_gen32.o: ecdsa-p256-verify.c ecdsa-p256-verify.h
	$(CC) $(CFLAGS) $(CFLAGS_GEN32) -DTV_ARCH_GEN32 -c -o ecdsa-p256-verify_gen32.o ecdsa-p256-verify.c

ecdsa-p256-verify_gen64.o: ecdsa-p256-verify.c ecdsa-p256-verify.h
	$(CC) $(CFLAGS) $(CFLAGS_GEN64) -DTV_ARCH_GEN64 -c -o ecdsa-p256-verify_gen64.o ecdsa-p256-verify.c

ecdsa-p256-verify_arm64.o: ecdsa-p256-verify_arm64.S
	$(CC) $(CFLAGS) $(CFLAGS_ARM64) -c -o ecdsa-p256-verify_arm64.o ecdsa-p256-verify_arm64.S

ecdsa-p256-verify_amd64.o: ecdsa-p256-verify_amd64.S
	$(CC) $(CFLAGS) $(CFLAGS_AMD64) -c -o ecdsa-p256-verify_amd64.o ecdsa-p256-verify_amd64.S

ecdsa-p256-verify_amd64alt.o: ecdsa-p256-verify_amd64alt.S
	$(CC) $(CFLAGS) $(CFLAGS_AMD64) -c -o ecdsa-p256-verify_amd64alt.o ecdsa-p256-verify_amd64alt.S

ecdsa-p256-verify_rv64.o: ecdsa-p256-verify_rv64.S
	$(CC) $(CFLAGS) $(CFLAGS_RV64) -c -o ecdsa-p256-verify_rv64.o ecdsa-p256-verify_rv64.S

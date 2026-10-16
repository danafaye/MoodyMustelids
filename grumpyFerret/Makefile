CC ?= gcc
CFLAGS_RELEASE = -O2 -s
CFLAGS_DEBUG   = -O0 -g

.PHONY: all release debug static clean

all: release

# The actual crackme artifact: stripped, no debug symbols.
release: grumpyferret.c youtube_stage.h
	$(CC) $(CFLAGS_RELEASE) -o grumpyFerret grumpyferret.c
	strip --strip-all grumpyFerret

# A symbol-ful build for your own reference / verifying the solution.
debug: grumpyferret.c youtube_stage.h
	$(CC) $(CFLAGS_DEBUG) -o grumpyFerret_debug grumpyferret.c

# Optional: fully static build, for a more "embedded malware" flavor
# and to hand to Ghidra without a dynamic loader in the way. NOTE:
# glibc's getaddrinfo() relies on NSS modules that are not loadable
# from a static binary, so the DNS-probe / phone-home lines will just
# report failures in this build -- fine for a pure static-RE exercise,
# but use the dynamic `release` build if you want the DNS/network
# telemetry for a sandbox demo.
static: grumpyferret.c youtube_stage.h
	$(CC) $(CFLAGS_RELEASE) -static -o grumpyFerret_static grumpyferret.c
	strip --strip-all grumpyFerret_static

# To cross-build for ARM/MIPS (matching an IoT-botnet flavor) on a
# machine with the right cross toolchain installed, e.g.:
#   arm-linux-gnueabi-gcc   -O2 -s -static -o grumpyFerret_arm   grumpyferret.c
#   mipsel-linux-gnu-gcc    -O2 -s -static -o grumpyFerret_mipsel grumpyferret.c
# Same static-NSS caveat applies to these builds.

clean:
	rm -f grumpyFerret grumpyFerret_debug grumpyFerret_static

# Regenerate the embedded interpreted classroom stage after editing it.
youtube_stage.h: instructor_youtube/youtube_stage.py embed_youtube_stage.py
	python3 embed_youtube_stage.py

# Cross-compile from Linux/macOS with MinGW-w64 (recommended):
#   make release
#
# Produces a stripped, release-mode 64-bit Windows PE: soggyBadger.exe
#
# Requires mingw-w64 installed (e.g. `apt install mingw-w64` on Debian/
# Ubuntu, `brew install mingw-w64` on macOS with Homebrew).
#
# A prebuilt soggyBadger.exe is included. It has not been run on Windows
# in this project. Rebuild with `make release` and confirm the result
# matches the source before class; rehearse the exact executable on Windows.

CC = x86_64-w64-mingw32-gcc
CFLAGS_RELEASE = -O2 -s -Wall
CFLAGS_DEBUG   = -O0 -g -Wall
LIBS = -lws2_32 -lwininet -ladvapi32

.PHONY: all release debug clean

all: release

release: soggybadger.c
	$(CC) $(CFLAGS_RELEASE) -o soggyBadger.exe soggybadger.c $(LIBS)

debug: soggybadger.c
	$(CC) $(CFLAGS_DEBUG) -o soggyBadger_debug.exe soggybadger.c $(LIBS)

clean:
	rm -f soggyBadger.exe soggyBadger_debug.exe

# ---- Alternative: native build on Windows with MSVC ----
#
# From a "x64 Native Tools Command Prompt for VS":
#
#   cl /O2 /W3 soggybadger.c /link ws2_32.lib wininet.lib advapi32.lib
#
# (the #pragma comment(lib, ...) lines in the source also auto-link these
# for MSVC, so plain `cl /O2 soggybadger.c` should work too)
#
# Note: this source uses C99-style mixed declarations-and-code. Modern
# MSVC (2015+) handles this fine in C mode; a much older cl.exe may
# need `/TP` (compile as C++) instead.

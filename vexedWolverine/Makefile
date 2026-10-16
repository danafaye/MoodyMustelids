CC = gcc
WINCC = x86_64-w64-mingw32-gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -Werror -fno-ident -fno-asynchronous-unwind-tables
ROOT := $(abspath .)

.PHONY: all generate linux windows test clean
all: linux windows

generate:
	python3 instructor/generate.py

src/generated.h: instructor/generate.py
	python3 instructor/generate.py

linux: student/vexedWolverineLinux
student/vexedWolverineLinux: src/vexedwolverine.c src/crypto.h src/generated.h
	$(CC) $(CFLAGS) -fvisibility=hidden -pthread -s src/vexedwolverine.c -o $@

windows: instructor/dist/vexedWolverineWindows.exe
instructor/dist/vexedWolverineWindows.exe: src/vexedwolverine.c src/crypto.h src/generated.h
	mkdir -p instructor/dist
	$(WINCC) $(CFLAGS) -static-libgcc -s src/vexedwolverine.c -o $@

test: all
	python3 instructor/verify.py

clean:
	rm -f student/vexedWolverineLinux instructor/dist/vexedWolverineWindows.exe

# vexedwolverine

An expert reserve crackme built for the Recorded Future Ghidra AI MCP class.
It is meant for students who finish the three core exercises early, or as a
take-home challenge. It does not add another hour to the class schedule.

The difficulty comes from layered analysis: an encrypted container, two
different bytecode interpreters with shuffled opcode maps and masked operands,
a flattened state machine, reversible arithmetic on a 32-character ticket,
a flag key derived from that ticket, a debugger check, a timing check and
convincing decoys. It is designed to be much harder than the core exercises,
but it has not been benchmarked against experienced students.

The challenge is solvable by reconstructing and reversing its validation
logic. There is no need to brute-force a cryptographic preimage. The real
flag depends on the correct ticket, so patching the final validation result
alone does not recover it.

## Files

- `student/` - the handout: `vexedWolverineLinux` (stripped x86-64 ELF),
  `SHA256SUMS`, `student.md` (the guide) and `README.md`. The Windows build is
  not handed out.
- `src/` - `vexedwolverine.c` (the program), `crypto.h` (ChaCha20, SHA-256,
  FNV helpers) and `generated.h` (the generated container and shards). Spoilers.
- `instructor/` - `instructor.md` (answer key), `SOLUTION.md` (staged hints
  and walkthrough), `generate.py`, `solve_offline.py`, `verify.py`,
  `crypto_check.c`, `container.json`, `answers.json`, `validation.json`, and
  `dist/vexedWolverineWindows.exe`. Spoilers.
- `Makefile` - `make all` (Linux and Windows builds), `make linux`,
  `make windows`, `make generate`, `make test` and `make clean`.
  - `make all` overwrites `student/vexedWolverineLinux` and
    `instructor/dist/vexedWolverineWindows.exe`. A rebuild can change their
    SHA-256 hashes, so update `student/SHA256SUMS` and
    `instructor/validation.json` to match if you rebuild.
  - `make test` runs `make all` first, then `instructor/verify.py`. That script
    runs the binaries and rewrites `instructor/validation.json`.
  - `make generate` regenerates `src/generated.h`, `instructor/container.json`
    and `instructor/answers.json`. This changes the ticket and flag. Do not run
    it on a challenge that is already in students' hands.
  - Requirements: Python 3, `objdump`, GCC, and MinGW-w64 for the Windows build.
  - The last recorded `make test` run passed 57 checks. It covered the
    independent solve, 39 invalid tickets, missing input, container tampering,
    a forced validation build, crypto reference vectors and import inspection.
    The Linux binary was run. The Windows PE was cross-compiled and statically
    inspected, but not run (no Wine). macOS source branches are included, with
    no Mach-O binary and no macOS runtime validation. Details and binary hashes
    are in `instructor/validation.json`.

## Suggested demo flow

**1. First pass - `file` / `strings` (no tools yet)**

```
file student/vexedWolverineLinux
strings -n 6 student/vexedWolverineLinux
```

The binary is stripped and dynamically linked. The readable strings include
`VW{RAW_STRINGS_ARE_NOT_A_SOLUTION}`, `VW{THE_FAST_PATH_IS_A_DECOY}`,
`c2.vexedwolverine-demo.invalid` and an `already_unlocked=...` line. None of
them is the real flag, and the endpoint is never used. The banner, usage and
runtime messages are not in the plain strings at all, because they are encrypted
in the container. Good moment to say that a raw string dump is a start, not an answer.

**2. Static analysis - Ghidra via MCP**

Load `vexedWolverineLinux` (stripped, so students name every function). The
interesting path is: entry point -> `main` -> `pthread_create` -> state
machine -> interpreters -> reveal. The large `.vwdata` section holds the
container. Students should find the root key, the decrypted header, both
bytecode programs and the register-VM comparisons.

**3. Solve the ticket and flag**

The offline path is `python3 instructor/solve_offline.py`, which replays the
transform from `container.json` and prints the ticket and flag. Students do
this by reversing the register VM by hand or with scripts. See
`instructor/SOLUTION.md` for the layered walkthrough and staged hints.

**4. Confirm at runtime**

Run the Linux copy once with the recovered ticket:

```
./student/vexedWolverineLinux <recovered 32-character ticket>
```

A correct ticket prints the real `VW{...}` flag and exits 0. A wrong ticket
prints the "No valid ticket" message and exits 1. If a debugger gate gets in
the way during a demo, see `instructor/SOLUTION.md` before using the lab-mode
switch.

## Notes on the embedded indicators

The programs validate an argument, interpret their own embedded data and
print a result. They run one local worker thread and query debugger status.
They perform no networking, persistence, process injection, process spawning,
credential collection, privilege changes or file writes. The encrypted
programs are interpreter data; they are never native executable payloads.
The apparent endpoint strings are decoys and are never contacted.

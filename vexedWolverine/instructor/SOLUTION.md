# SOLUTION (spoilers)

Keep this one off the projector. This file, the source tree and everything in `instructor/` are spoilers. Distribute only `student/` or the student ZIP.

Students must recover the unique 32-character ticket and the genuine `VW{...}` flag, then explain the evidence connecting them. The literal flags in the executable are bait. The exact answers are in `answers.json`; avoid showing that file during the exercise.

`python3 instructor/solve_offline.py` prints the solution. It does not read `answers.json` or regenerate the secret ticket. It starts from `container.json`, an instructor convenience representation of the shards and encrypted bytes embedded in the executable. A student must first recover those bytes and their relationships through Ghidra or memory inspection.

Give the staged hints one at a time, under the finding they belong to. Use the challenge as independent analysis practice; it is too large to promise a complete walkthrough in the remaining minutes.

## Container and root key (Finding 1)

1. `assemble_root` combines two 32-byte shards using permuted indices, byte rotations and XOR. The result is the outer ChaCha20 key.
2. `unpack_container` checks the encrypted container's SHA-256 digest, decrypts it and parses its lengths, nonces, opcode tables, string offsets and flag digest. Runtime strings use a separate derived key.

The outer plaintext starts with `VWLAB01\0`. Its first 656 bytes hold the header and tables; the remaining slices are the encrypted stack program, register program, strings and flag. The generator and solver document the exact layout. Keys for the stack program and strings are SHA-256 of the root key followed by `/a` and `/s`, respectively. ChaCha20 starts at counter one with separate 12-byte nonces.

**Hint 2.** Look for a large data section, a digest comparison and a decoder. The apparent cryptographic barrier has recoverable key material.

**Hint 3.** A decoded container holds more encrypted data and two different interpreter instruction formats. Identify the dispatch loops.

## Decoys and runtime messages (Finding 2)

The readable `VW{...}` strings and endpoint-like literals are never printed on the path to a correct answer. The runtime messages come from the decrypted string table, which uses the strings key described above.

**Hint 1.** Strings are leads, not answers. Follow the result-printing path backward.

## Anti-debug and timing gate bypass (Finding 3)

The debugger gate reads Linux `TracerPid`, resolves Windows `IsDebuggerPresent` by a ROR13-plus-add export-name hash, or uses macOS `sysctl`/`P_TRACED` in the source branch. The timing gate trips after 90 seconds of elapsed `CLOCK_MONOTONIC` time, which a heavily paused debugger session can hit. Neither check crashes or modifies the host.

For an instructor demonstration, set `VW_LAB_MODE=1` to disable these two gates. Validation and flag-key binding still apply, so a wrong ticket still gets message 2 and no flag. Reveal this option only when it helps the lesson.

Patching validation alone is not a bypass. The forced-validation test build (`-DVW_INSTRUCTOR_FORCE_VALID`) makes `valid = 1` and prints message 5 for a wrong ticket, because the flag key is still wrong. That is the lesson to show.

## Stack VM key (Finding 4)

`stack_lane` decrypts and interprets 513 four-byte instructions. It reconstructs a 32-byte key, checks each instruction tag and verifies that all output bytes were produced. Its opcode map is randomized.

**Hint 4.** Execute or emulate the first interpreter to recover the second one's key.

## Register VM (Finding 5)

`register_lane` uses that key to decrypt 2,569 twelve-byte instructions. Operands and immediate values are masked, and instruction tags are checked. The real transform uses registers 0–7; registers 8–15 and some operations add noise. Eight comparisons constrain all input words.

**Hint 5.** Separate the real input registers from junk registers and identify the comparison targets. The arithmetic transforms are reversible.

## Ticket and flag (Findings 6 and 7)

- Ticket: `7C9QAQUKEV2G7F9GJ2RL7BWKRXAF8DUE`
- Flag: `VW{145f5ae89376cd6ab216878f1264fe994a0ff191}`

The input is 32 ASCII characters from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`, read as eight little-endian words. The real transform consists of 48 rounds of additions, XORs, rotations, swaps, multiplication by odd constants and right-shift XORs. Every operation on the real words is reversible modulo 2^32. Work backward from the eight comparison targets, using modular inverses for multiplication and successive doubled shifts to invert `x ^ (x >> n)`. The offline solver demonstrates this and checks the recovered ticket by replaying the forward transform before decrypting the flag.

`reveal_lane` derives the final key from the ticket, the first VM's output and the suffix `/f`. It decrypts the flag and verifies its SHA-256 digest. Returning success from validation without the correct input produces a decoy because the flag key is still wrong.

The flag key is `SHA-256(ticket || seed || "/f")`, so the flag is only correct with this ticket and this seed. Patching a branch to accept any ticket still derives the wrong key.

**Hint 6.** Recover the input by reversing the real operations. Use it to derive the final flag key rather than trying to patch a single branch.

## IOC labels (for the IOC table)

- Literal `c2.vexedwolverine-demo.invalid` and `127.0.0.1:0` (inside `already_unlocked=...`): decoys. Never used, so they are not indicators.
- `VW_LAB_MODE`: the environment variable that disables the gates. Record it as a control, not as a network indicator.
- `/proc/self/status`: the file read for the debugger check.

## Scope of the simulated techniques

This challenge demonstrates obfuscation and analysis obstacles. It does not implement malware deployment, command-and-control, persistence or injection. The worker thread runs the program's own function. Encrypted bytecode is interpreted in ordinary memory, with no RWX allocation or native payload execution. The fictional network strings are never used for communication.

## Rehearsal and debugging

`make test` runs `make all` first, then `instructor/verify.py`. The script runs both binaries and rewrites `instructor/validation.json`, which records the tests actually performed. It checks a correct ticket in normal and lab modes, 39 invalid inputs, missing input, container tampering and a test build that forces validation success. It also checks SHA-256 padding boundaries, ChaCha20 reference vectors, hidden answer strings and relevant imports.

Linux runtime and offline solving were tested. Windows was cross-compiled and statically inspected; rehearse the exact PE on Windows. macOS source support is untested, with no supplied Mach-O. Anti-debug and long-pause paths are implemented but were not exercised under each platform's debugger.

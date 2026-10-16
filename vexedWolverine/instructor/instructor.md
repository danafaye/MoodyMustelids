# vexedwolverine: Instructor Answer Key

Use this with `student/student.md`. Answers come from `src/vexedwolverine.c`, `src/crypto.h`, `src/generated.h` and the instructor data (`container.json`, `answers.json`). Results from the earlier runtime test are labelled as such.

> **Do not distribute this file.** It contains the ticket, the flag, and the decryption path. `README.md` says the same about `instructor/` and `src/`.

> **Build note:** The Linux binary is stripped (`-s`). Ghidra shows no function names, so students name every function themselves. Linux `student/vexedWolverineLinux`: SHA-256 `13ee1393cd7cedb06f94aea8cb23ac4c6cf6760a046fb1ab1c5662cc5fab4eae`, MD5 `f791d713d9fb03ad73c6b80bd15c9a2b`. The SHA-256 matches `student/SHA256SUMS`. Windows `instructor/dist/vexedWolverineWindows.exe`: SHA-256 `63de0af9731b6c79e07bb6fed5f8ccfc89d956ec0a97f6f43af0419562751e5a`, which matches `instructor/validation.json`. Its imports are only `KERNEL32.dll` and `msvcrt.dll`, and `IsDebuggerPresent` is resolved by hash (`0xa36dc676`, ROR13 plus add), which matches `VW_DEBUG_API_HASH` in `src/generated.h`.

> **Source/binary mismatch:** None found in the values checked. Message 6 is in the string table but never printed (see Notes for the instructor).

---

## Setup

**Step 1. SHA-256:** `13ee1393cd7cedb06f94aea8cb23ac4c6cf6760a046fb1ab1c5662cc5fab4eae` (Linux). This matches `student/SHA256SUMS`.

**Step 2. Imports and linkage:** Dynamically linked PIE, ELF64 x86-64, interpreter `/lib64/ld-linux-x86-64.so.2`, stripped. Imports checked with `objdump -T`:
- Threading: `pthread_create`, `pthread_join`. One worker thread.
- Files: `fopen`, `fgets`, `fclose` (reads `/proc/self/status`). No write-mode file calls.
- Environment: `getenv` (reads `VW_LAB_MODE`).
- Timing: `clock_gettime`.
- Output: `puts`, `putc`, `fwrite`.
- Other libc: `malloc`, `free`, `memchr`, `memcpy`, `strchr`, `strcmp`, `strlen`, `strncmp`, `strtoul`, `__stack_chk_fail`.
- Networking: none. No `socket`, `connect`, `send`, `recv`, `getaddrinfo`, or `inet_*` imports.
- Process control: none. No `fork`, `exec`, or `ptrace` imports.

**Step 3. `main` address:** `0x12c0` in the ELF file (Ghidra: `0x1012c0`). The entry point is at ELF `0x1540`. Its `lea` loads `0x12c0` into `rdi` as the first argument to `__libc_start_main`, so that is `main`. Ghidra shows `main` as a label, and students must create the function at that address.

**Step 4. Before and after the thread:**
- Before the thread: `main` derives a host cookie from the wall clock and the decoy literals, assembles the root key, unpacks the container, prints the banner, checks `argc` and the ticket length, checks each character against the alphabet, and reads `VW_LAB_MODE`.
- After the thread: the worker's result sets the exit code (0 for success, 1 otherwise).
- Thread function: `execute_worker`, a flattened `switch` over state values that are XORed with a salt.

**Check:** The banner is `Vexed Wolverine / expert reserve challenge`. The usage line is `Usage: vexedwolverine <32-character ticket>`. Neither string appears in the ELF file. Both are encrypted in the container. Students find them in the decrypted message table (Finding 2).

---

## Finding 1: The embedded container

- **Section:** `.vwdata`, file offset `0x4380`, size `0x8469` (33,897 bytes). Ghidra address `0x104380`.
- **Digest:** SHA-256 of the whole block must equal the 32-byte digest in the data (`container.json` `digest`, `q_digest` in the source).
- **Root shards** (in `.rodata`, ELF `0x4000`-`0x437f`):
  - Shard A (`q_a`): file offset `0x42c0`, 32 bytes (matches `container.json`).
  - Shard B (`q_b`): file offset `0x42a0`, 32 bytes (matches `container.json`).
- **Root key formula** (`assemble_root`), for `i` from 0 to 31:

  ```
  n = (i % 7) + 1
  b = q_b[(i * 13) & 31]
  root[i] = rotl8(b, n) ^ q_a[(i * 7) & 31] ^ ((i * 29 + 0x63) & 0xff)
  ```

- **Container nonce** (ChaCha20, counter starts at 1): `q_nonce`, 12 bytes, read from `container.json` `nonce`.
- **Decrypted header:** magic `VWLAB01\0` (bytes `56 57 4c 41 42 30 31 00`).

| Field | Offset | Value |
|---|---|---|
| Magic | 0 | `VWLAB01\0` |
| Program A length | 8 | 2052 (513 × 4) |
| Program B length | 12 | 30828 (2569 × 12) |
| Strings length | 16 | 317 |
| Flag length | 20 | 44 |
| Nonce A | 24 | `c8303d417a192cf6cad640b2` |
| Nonce B | 36 | `9877fa0f059e548976a742d0` |
| Nonce S | 48 | `cd6492ee927b17f433625120` |
| Nonce F | 60 | `ba478d659e47a5343ae07729` |
| Opcode map A | 72 | 256 bytes |
| Opcode map B | 328 | 256 bytes |
| String offsets | 584 | 10 × u32: 0, 43, 87, 139, 175, 209, 246, 276, 294, 305 |
| Flag digest | 624 | 32 bytes (SHA-256 of the flag) |
| Program A | 656 | 2052 bytes |
| Program B | 2708 | 30828 bytes |
| Strings | 33536 | 317 bytes |
| Flag | 33853 | 44 bytes |

Header total: 656 + 2052 + 30828 + 317 + 44 = 33897, which equals the block size.

**Key derivations:** `derive(key, label) = SHA-256(key || label)`.
- Program A key: `derive(root, "/a")`, with nonce A.
- Strings key: `derive(root, "/s")`, with nonce S.
- Program B key: the 32-byte output of Program A (the seed), with nonce B.
- Flag key: `SHA-256(ticket || seed || "/f")`, with nonce F.

**Expected tags:** Section, digest, shards, formula, and header are **[Code]**.

**Confidence tag for the container:** [Code]

---

## Finding 2: Decoys and runtime messages

**Literal decoys in the binary** (plain text in `.rodata`, read at startup to seed the host cookie, never printed):
- `VW{RAW_STRINGS_ARE_NOT_A_SOLUTION}`
- `VW{THE_FAST_PATH_IS_A_DECOY}`
- `c2.vexedwolverine-demo.invalid`
- `already_unlocked=true; endpoint=127.0.0.1:0`

All four are present in the ELF file. The endpoints are never used for communication, and they do not appear in the decoded message table.

**Runtime messages** (decrypted with the strings key, by index):

| Index | Text | Used for |
|---|---|---|
| 0 | `Vexed Wolverine / expert reserve challenge` | Banner, always printed |
| 1 | `Usage: vexedwolverine <32-character ticket>` | Wrong argument count or wrong length |
| 2 | `No valid ticket. The attractive answer was a decoy.` | Invalid character, wrong ticket, and gate failures |
| 3 | `VW{DEBUGGER_BRANCH_IS_NOT_THE_FLAG}` | Debugger detected (decoy) |
| 4 | `VW{TIMING_BRANCH_IS_NOT_THE_FLAG}` | Timing limit exceeded (decoy) |
| 5 | `VW{PATCHING_A_BOOLEAN_IS_NOT_ENOUGH}` | Flag digest mismatch (decoy) |
| 6 | `Container integrity mismatch.` | Not used. `main` prints the same text as a literal to stderr. |
| 7 | `/proc/self/status` | Debugger check file |
| 8 | `TracerPid:` | Debugger check line prefix |
| 9 | `VW_LAB_MODE` | Environment variable that disables both gates |

**Expected tags:** Literal decoys and the message table are **[Code]**.

---

## Finding 3: The gates

**Debugger check (Linux):**
- Opens `/proc/self/status`. Reads lines until one starts with `TracerPid:`. Parses the number after the prefix with `strtoul`. Traced when the number is nonzero.
- Runs in the state machine before the stack VM.
- If traced: prints message 3, then message 2. Result 0. Exit code 1.

**Timing check:**
- Reads `CLOCK_MONOTONIC` at worker start, and compares with the clock after the register VM returns valid.
- Limit: 90,000 ms (90 seconds). Tripped when elapsed time is strictly greater than the limit.
- Runs after the register VM accepts the ticket and before the flag reveal.
- If exceeded: prints message 4, then message 2. Result 0. Exit code 1.

**Lab mode:** `VW_LAB_MODE=1` turns both gates off (the value must be exactly `1`). Validation and flag-key binding still apply. Recorded on the Linux copy in the earlier runtime test: the correct ticket still prints the flag with exit code 0.

**Thread-local cookie:** `lane_cookie` is set by the worker and checked in the register VM against the host cookie. It always matches in an unmodified run. It does not change the answer.

**Expected tags:** The file path, prefix, limit, position, and outputs are **[Code]**. Whether a debugger attached during a student's run changes the output is **[Runtime]**, and only if you test it with a debugger. This challenge uses the **[Runtime]** tag where other courses use **[Sandbox]**, because there is no sandbox run in this exercise.

---

## Finding 4: Stack VM (Program A)

- **Program:** 513 instructions, 4 bytes each, at file offset `0x4610` (`0x4380 + 656`). Decrypted with ChaCha20, key `derive(root, "/a")`, nonce A.
- **Decode, for instruction index `pc`:**
  - `op = p[0]`, `kind = map_a[op]`
  - `arg = p[1] ^ root[pc & 31] ^ ((pc * 17) & 0xff)`
  - Check byte: `p[3]` must equal `(p[0] ^ arg ^ p[2] ^ pc) & 0xff`, or the program fails.
- **Kinds** (after the map):

| Kind | Action |
|---|---|
| 0 | Push `arg` |
| 1 | XOR the top two values, keep one |
| 2 | Add the top two values (mod 256), keep one |
| 3 | Rotate the top value left by `arg & 7` |
| 4 | Pop into `seed[arg]` (requires `arg < 32`) |
| 5 | Duplicate the top value |
| 6 | Swap the top two values |
| 7 | Drop the top value |
| 8 | No operation |
| 9 | Halt. Requires all 32 seed positions written, an empty stack, and this to be the last instruction. |

- **Output:** The 32-byte seed. All 32 positions are written exactly once, the stack is empty at halt, and the program reaches halt on its last instruction (checked by replaying the decoded program).

**Expected tags:** Program location, decoding formula, kinds, and seed requirements are **[Code]**.

---

## Finding 5: Register VM (Program B)

- **Program:** 2569 instructions, 12 bytes each, at data offset 2708. Decrypted with ChaCha20, key = the 32-byte seed, nonce B.
- **Record layout:** `op (u8), a (u8), b (u8), filler (u8), encoded (u32), tag (u32)`.
- **Decode, for index `pc`:**
  - `kw = seed word (pc & 7)` (little-endian u32)
  - Tag: FNV-1a-style hash of the first 8 bytes, seeded with `2166136261 ^ pc ^ kw`. Must equal the stored tag, or the program fails.
  - `kind = map_b[op]`
  - Register `a = record.a ^ seed[pc & 31]`, register `b = record.b ^ seed[(pc + 11) & 31]`. Both must be below 16.
  - Immediate: `imm = rotr32(encoded, (pc % 31) + 1) ^ kw`
- **Kinds** (after the map; `r` is the register file):

| Kind | Action |
|---|---|
| 0 | `r[a] =` little-endian u32 from the input ticket at byte offset `imm` (requires `imm <= 28`) |
| 1 | `r[a] += r[b]` |
| 2 | `r[a] ^= r[b]` |
| 3 | `r[a] += imm` |
| 4 | `r[a] ^= imm` |
| 5 | `r[a] = rotl32(r[a], imm)` |
| 6 | `r[a] = rotr32(r[a], imm)` |
| 7 | Swap `r[a]` and `r[b]` |
| 8 | `r[a] *= imm` (requires `imm` odd) |
| 9 | `r[a] ^= r[a] >> (imm & 31)` (requires `imm & 31` nonzero) |
| 10 | Compare `r[a]` with `imm`: accumulate the difference and count one comparison |
| 11 | `r[a] = imm` |
| 12 | Junk. Changes a local cookie only. |
| 13 | Halt. Requires the accumulated difference to be zero, exactly 8 comparisons, and this to be the last instruction. |

- **Real and noise registers:** Registers 0 to 7 carry the real transform. Registers 8 to 15 and any kind 12 operation are noise. All eight comparisons read registers 0 to 7, one each, and kind 12 appears 192 times.
- **Comparisons:** Eight, one for each real register 0 to 7. The solver asserts this set.

**Expected tags:** Layout, tag, decoding, kinds, and register split are **[Code]**. The eight comparison targets are **[Code]**. Don't post them to students.

---

## Finding 6: The ticket

- **Ticket:** `7C9QAQUKEV2G7F9GJ2RL7BWKRXAF8DUE`
- **Length:** 32 characters, each from `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`.
- **Word view:** Eight little-endian 32-bit words. Kind 0 reads each one from the input at a byte offset the program encodes. The eight loads are at offsets 0, 4, 8, ..., 28, one per real register 0 to 7, so they cover bytes 0 to 31 with no overlap.
- **Recovery method:** Reverse each real operation in reverse order, starting from the eight comparison targets:
  - Add: subtract. XOR: XOR again. Rotation: rotate the other way.
  - Multiplication by odd `imm`: multiply by `imm`'s modular inverse mod 2^32.
  - `x ^ (x >> n)`: repeat `x ^= x >> s` for `s = n, 2n, 4n, ...` until the shift is 32 or more.
  - Kind 0 (load): write the register back into the ticket bytes at offset `imm`.
- **Uniqueness:** The ticket is unique by construction. The eight loads cover the 32 bytes without overlap, and every real operation is invertible mod 2^32, so the reversal is deterministic. A student who recovers a different ticket has made an error.
- **Forward check:** Replaying Program B forward on this ticket satisfies all eight comparisons and halts on the last instruction. Changing one character makes the replay fail.
- **Printed output:**
  - Correct: banner, then the flag line.
  - Wrong: banner, then message 2.

**Expected tags:** The ticket is **[Code]** (reversal plus forward replay). A student who recovers it by reversal should cite the comparisons and the inverses they used.

**Confidence tag for the ticket:** [Code]

---

## Finding 7: The flag

- **Flag key:** `SHA-256(ticket || seed || "/f")`, with the 32-character ticket bytes and the 32-byte seed from Finding 4.
- **Decryption:** ChaCha20 with the flag key and nonce F, over the 44 flag bytes.
- **Digest check:** SHA-256 of the decrypted flag must equal the digest at header offset 624.
- **Flag:** `VW{145f5ae89376cd6ab216878f1264fe994a0ff191}` (44 characters, starts with `VW{`, ends with `}`).
- **Output on success:** the flag, then a newline.
- **Output when the digest fails** (the decoy path that a patched validation reaches): message 5, `VW{PATCHING_A_BOOLEAN_IS_NOT_ENOUGH}`.

**Why patching one branch fails:** The flag key depends on the ticket and the seed. A patch that forces `valid = 1` (the forced-validation build, `-DVW_INSTRUCTOR_FORCE_VALID`) still derives the wrong flag key, so the digest fails and message 5 prints. The forced-validation check in `instructor/verify.py` demonstrates this. It was not re-run for this key.

**Expected tags:** Key construction, digest, and flag are **[Code]**.

---

## What the runtime should show

The runtime check is the only place students see dynamic behavior, and this challenge has no sandbox report. Run the Linux copy on the lab machine before class and fill in the actual results. Expected behavior, from the source:

| Run | Expected behavior | Exit |
|---|---|---|
| No argument | Banner, then usage | 1 |
| 31-character argument | Banner, then usage | 1 |
| Correct ticket with the last character changed to lowercase | Banner, then message 2 | 1 |
| 32 valid characters, wrong ticket | Banner, then message 2 | 1 |
| Correct ticket | Banner, then the flag | 0 |
| Correct ticket with `VW_LAB_MODE=1` | Banner, then the flag | 0 |
| Debugger attached (`TracerPid` nonzero) | Banner, then message 3, then message 2 | 1 |
| Elapsed time over 90 seconds before the flag reveal | Banner, then message 4, then message 2 | 1 |

Notes for the runtime:
- Rows 1 to 5 were recorded in the earlier runtime test on the Linux copy and were not re-run for this key. Rows 6 and 7 are not tested. Treat them as expectations to check on the lab machine.
- The Linux binary makes no network connections, so there is nothing to observe on the network side.
- The debugger branch only fires when a tracer is attached. A plain run does not trigger it.
- The Windows build was not run (no Wine). Its anti-debug check is a hash-resolved `IsDebuggerPresent`, not `TracerPid`, so none of the Linux rows apply to it.

---

## IOCs (expected answers)

This challenge makes no network connections and writes no files. Students should record that and explain why the endpoint-like strings are decoys, not IOCs.

| Type | Value | Source | Tag |
|---|---|---|---|
| Hostname | `c2.vexedwolverine-demo.invalid` | Literal in `.rodata`. Never used. | Code |
| Endpoint | `127.0.0.1:0` | Literal inside `already_unlocked=...`. Never used. | Code |
| Environment variable | `VW_LAB_MODE` | Message 9. Read by `getenv`. Disables the gates. | Code |
| File read | `/proc/self/status` | Message 7. Debugger check. | Code |

---

## MITRE ATT&CK mapping (expected answers)

Verify these IDs against the ATT&CK version you use before class. They were not checked against the ATT&CK site (no network access when this key was written). They are the expected answers, not a verified list.

| Behavior | Expected technique | Evidence | Tag |
|---|---|---|---|
| Encrypted container decrypted at runtime | T1140 Deobfuscate/Decode Files or Information | `.vwdata`, root key, ChaCha20 | Code |
| Bytecode interpreted by two VMs | T1027 Obfuscated Files or Information | Program A and B, shuffled opcode maps | Inferred |
| Debugger check | T1622 Debugger Evasion | `/proc/self/status`, `TracerPid:` | Code |
| Timing check | T1497.003 Virtualization/Sandbox Evasion: Time Based Evasion | 90-second limit on `CLOCK_MONOTONIC` | Code |
| Ticket validation | No clean technique. Treat as a crackme check. | Register VM comparisons | Inferred |
| Flag decrypted at runtime | T1140 Deobfuscate/Decode Files or Information | Flag key from ticket and seed | Code |

Students may argue that the timing check is a plain runtime gate rather than an evasion technique. Accept it if they justify the choice.

---

## Analyst report: what good looks like

- **Summary:** The sample is a benign expert crackme. It unpacks an encrypted container, runs two interpreters on the bytecode in its own memory, and accepts only a 32-character ticket that passes both. The flag is genuine only with the right ticket, and it is verified by a digest. Good answers say so, and don't treat the readable `VW{...}` strings as the answer.
- **Obstacles:** Good answers name the root key, the two interpreters, and the reversibility of the register transform. They say why patching one branch fails: the flag key depends on the ticket.
- **Evidence:** Good answers trace the chain from the container, through Program A's seed, to the register comparisons, the ticket, and the flag key. They say which findings were confirmed by a second method.

---

## Grading rubric (suggested)

| Area | Points | Key evidence |
|---|---|---|
| 1. Container and root key | | Shards, root formula, header fields, digest |
| 2. Decoys and messages | | Decoy strings identified, message table, why they are not the flag |
| 3. Gates | | Debugger check position and prefix, timing limit, `VW_LAB_MODE` |
| 4. Stack VM | | Instruction count, decode formula, halt condition, seed |
| 5. Register VM | | Real versus noise registers, eight comparisons, halt condition |
| 6. Ticket | | Reversal steps, ticket, forward check |
| 7. Flag | | Key inputs and suffix, digest check, decoy on wrong key |
| Labeling | | `main`, thread function, container, both VMs, gates named |
| Confidence tags | | Each answer tagged correctly |
| Predictions | | Runtime prediction written before running, compared after |
| IOC table | | Complete, with sources and the no-network note |
| ATT&CK mapping | | Plausible IDs with evidence |
| Analyst report | | Three paragraphs, supported by the findings |

Set point values before grading. The rubric above does not include them.

---

## Notes for the instructor

- **Ghidra.** The Ghidra addresses (`0x1012c0`, `0x104380`, `0x1042a0`, `0x1042c0`) were checked in an earlier session and are carried forward. They were not re-checked for this key, and the Ghidra MCP server did not connect when this key was last reviewed. Ghidra shows `main` as a label; students create the function. Students using a different image base will see every Ghidra address shifted by that base. The ELF file offsets are the reference.
- **Message 6 is unused.** `main` prints the container-mismatch text as a literal to stderr, so the decrypted copy is never shown. Remove it from the string table, or keep it as a harmless duplicate. Changing the string table requires `make generate`, which changes the ticket and flag.
- **Student hints versus staged hints.** `SOLUTION.md` says to give one hint at a time. The student guide puts a hint at each step. Decide whether to keep those hints in the handout or hand them out one at a time.
- **Windows and macOS** are not covered by the Linux answers. The Windows copy's anti-debug check uses a hash of export names, not `TracerPid`. macOS source support is untested, and there is no supplied Mach-O.
- **Rebuilding changes hashes.** `make all` and `make test` rebuild both binaries, which can change their SHA-256 values. If you rebuild, update `student/SHA256SUMS` and `instructor/validation.json` to match. `make test` also rewrites `instructor/validation.json`.
- **ELF layout.** Entry point `0x1540`, `main` at `0x12c0`, `.rodata` at `0x4000`, `.vwdata` at `0x4380` (size `0x8469`), shard A at `0x42c0` and shard B at `0x42a0`. The container block appears once in the file.
- **Imports.** The Linux imports match the Setup list, with no networking, process-control or write-mode file imports. The Windows PE imports are `KERNEL32.dll` and `msvcrt.dll` only.
- **Plaintext.** The ticket and flag do not appear as plaintext in the Linux binary. The decoy literals do.
- **Not tested for this key.** The debugger and timing gates were not run under a live debugger. The Linux runtime rows 1 to 5 come from the earlier runtime test. The 57-check `make test` run is recorded in `instructor/validation.json`.

# vexedwolverine: Student Guide

**Goal:** Use your AI assistant and Ghidra (through the Ghidra MCP) to work out how `vexedwolverine` validates its ticket. Recover the unique 32-character ticket and the real `VW{...}` flag, explain the path that connects them, and write a short analyst report.

This is an expert challenge. It is much harder than the core exercises. Don't expect to solve it by searching strings or by changing one branch. A message that looks like a flag is not proof that you solved it. Be ready to show how the recovered flag depends on the recovered ticket.

## How to work through this

- Each step tells you **what to ask the assistant**. Type a version of it in your own words.
- When the assistant finds a function or data item, ask it to **label** it with a name that says what it does. Your labeled Ghidra project is part of your submission. The Linux binary is stripped, so the function names won't be there. You name them.
- Every answer gets a **confidence tag**:
  - **[Code]**: you can point to the exact instruction, data, or byte that shows it.
  - **[Inferred]**: you worked it out from code, but nothing in the binary states it directly.
  - **[Runtime]**: you confirmed it by running the Linux copy with a ticket you chose. This is the only dynamic evidence in this challenge.
- Each finding ends with a **Check**. Ask the assistant to confirm the answer a second way, such as reading raw bytes, re-running the transform forward, or checking a digest. If the two methods disagree, keep working until they match.
- Hints are included so you can get unstuck. Use them, but one at a time. Your instructor may give you staged hints as well.

> **Safety:** The static work never executes the program. You may run the Linux copy once you have a candidate ticket, to confirm it. Don't use runs to search for the answer. Don't use the Windows copy in the lab without your instructor. The challenge makes no network connections and writes no files. The strings that look like endpoints are decoys. Don't try to contact them.

---

## Setup: Get oriented

**Step 1.** Ask the assistant for the program's name, format, architecture, and SHA-256 hash. Compare the SHA-256 with the `SHA256SUMS` file in your handout.

SHA-256: ________________________________________________

**Step 2.** Ask the assistant which shared libraries the program uses, and which libc functions it imports. Ask which of them handle networking, process creation, threads, files, and environment variables.

*Hint:* Look at the dynamic symbol imports. Group them by purpose. Then ask whether any import could send or receive data over a network.

Threading: ________________ Files: ________________ Environment: ________________ Networking: ________________

**Step 3.** Ask the assistant to find `main`. The binary is stripped, so start at the entry point and find the function it passes to `__libc_start_main`. Ask the assistant to label `main`.

*Hint:* The entry point is short. Look at the arguments it sets up before the call. One of them is a function pointer, and that pointer is `main`.

`main` address: ________________

**Step 4.** Ask the assistant to walk through `main` in order and list what it does before it starts a thread, and what it does after the thread finishes. Ask which function runs on the thread.

*Hint:* `main` calls the thread library. The function the thread starts is a state machine: a large `switch` in a loop, with state values that change on each pass.

Before thread: ________________________________________________ After thread: ________________________________________________ Thread function: ________________

**Check:** Ask the assistant to confirm the banner string and the usage string are both printed from `main`, and to show their cross-references.

---

## Finding 1: The embedded container

**What's going on:** The program carries one large encrypted data block. Before it does anything else, it checks the block's SHA-256 digest, decrypts it, and parses the result. Everything the program needs is inside, including the bytecode for two interpreters.

*Why it matters:* the real logic is not in the program's code. It is in the decrypted data, so you need to find the key before you can read any of it.

**Step 1.** Ask the assistant to find the data section that holds the block, and report its file offset and size. Ask it to label the block.

*Hint:* The block is about 34 KB and sits in its own section, not in `.data` or `.rodata`. Check the section table. The size should match the length in the digest check.

Section: ________________ Offset: ________________ Size: ________________

**Step 2.** Ask the assistant to find the digest check that runs before anything else, and report which bytes it compares the digest against, and where those bytes are stored.

*Hint:* The check hashes the whole block with SHA-256 and compares it with 32 bytes stored elsewhere in the data.

Digest location: ________________ Function: ________________

**Step 3.** Ask the assistant to find the two 32-byte shards that the root key is built from. Ask it to describe how `assemble_root` combines them byte by byte. Ask it to label the function.

*Hint:* The loop builds one output byte per step. Each byte reads from two shards at positions that are multiplied by constants and masked to 5 bits. Look at the rotation, the XOR, and the constant that is added.

Shard A address: ________________ Shard B address: ________________ Steps per byte: ________________________________________________

**Step 4.** Ask the assistant to decrypt the block with ChaCha20, using the root key and the nonce stored in the data. Ask it to read the header and report the magic string and the four length fields.

*Hint:* The magic is 8 bytes. The four lengths are 32-bit little-endian integers after it. The lengths describe the two bytecode programs, the strings, and the flag.

Magic: ________________ Lengths (A, B, strings, flag): ________________

**Step 5.** Ask the assistant to report how many runtime strings the header describes, where their offsets are stored, and how the strings are decrypted. The strings use a key separate from the bytecode.

*Hint:* The key for the strings is derived from the root key with a short suffix. Look at how the derived key is built, and whether the suffix is the same as the one for the bytecode.

Number of strings: ________________ Offset table at: ________________ String key: ________________

**Check:** Ask the assistant to re-run the key derivation and the decryption on the bytes you read, and confirm that the header magic matches. Ask it to confirm that the four lengths add up to the total block size.

**Confidence tag for the container:** ________________

---

## Finding 2: Decoys and runtime messages

**What's going on:** The program has two kinds of text. Some strings are plain text in the binary and look like answers. Others are encrypted in the container and are printed at runtime. Neither kind is the real flag.

**Step 1.** Ask the assistant to list the readable strings that look like flags, endpoints, or settings. Ask which of them are never printed on the way to a correct answer.

*Hint:* Look for `VW{` and for a hostname, an IP address, and a `key=value` string. Check whether each one is printed, and whether anything reads it.

Strings found: ________________________________________________ Which are decoys: ________________________________________________

**Step 2.** Ask the assistant to decrypt the runtime strings from Finding 1, Step 5, and list them by index. Ask which indices `main` uses, and for what.

*Hint:* Look at each `message(index)` call, and what happens right after it. Some messages are printed on a failure path. Some name files or environment variables.

Index and meaning: ________________________________________________

**Step 3.** Ask the assistant which strings are used to check the environment and the debugger, and which string names the environment variable that changes the program's behavior.

Environment variable: ________________ Path checked: ________________ Prefix checked: ________________

**Check:** Ask the assistant to explain why the readable `VW{...}` strings are decoys. Ask it what the real flag depends on, and whether a readable flag could be the real one.

---

## Finding 3: The gates before the real check

**What's going on:** Before the real validation runs, the program checks two things: whether a debugger is attached, and how long the program has been running. If either check trips, the program prints a decoy and fails. Both checks can be turned off by an environment variable, which the instructor uses for demonstrations.

*Why it matters:* a program that runs under a debugger may behave differently. Knowing which branch was taken tells you whether the output is real.

**Step 1.** Ask the assistant to find the debugger check. Ask it to label the function and say how it detects a debugger on Linux.

*Hint:* The function opens a status file for the current process and looks for one line with a known prefix. The number after that prefix is a process ID. A nonzero number means something is tracing the program.

Function: ________________ File: ________________ Prefix: ________________ "Traced" means: ________________

**Step 2.** Ask the assistant when the state machine runs the debugger check, relative to the other stages. Ask what it prints if the check trips, and which message comes after.

Position: ________________________________________________ Output: ________________________________________________

**Step 3.** Ask the assistant to find the timing check. Ask what clock it uses, what limit it compares against, and at which point in the state machine it runs. Ask what it prints if the limit is exceeded.

Clock: ________________ Limit: ________________ Position: ________________ Output: ________________

**Step 4.** Ask the assistant what the environment variable does, what value turns the gates off, and which checks it turns off.

Turns off: ________________________________________________ Value: ________________

**Check:** Ask the assistant to confirm that the debugger and timing checks are the only places the program reads the clock or the status file. Ask it whether either check changes the ticket or the flag.

---

## Finding 4: The first interpreter (stack VM)

**What's going on:** The decrypted container holds two bytecode programs. The first runs on a stack machine. It builds a 32-byte key, which the second program uses. Each instruction has a shuffled opcode, a masked operand, and a check byte.

*Why it matters:* you can't read the second program until you have the key. The first program produces the key, so you have to run or emulate it.

**Step 1.** Ask the assistant to find the first bytecode program, label it, and report how many 4-byte instructions it contains.

*Hint:* The program is the first slice after the header. Its length is one of the four lengths you read in Finding 1. Divide by four.

Instruction count: ________________ Location: ________________

**Step 2.** Ask the assistant to explain how each instruction is decoded. Ask how the opcode is mapped, how the operand is unmasked, and what the check byte must equal.

*Hint:* There are two tables in the header, one per program. The opcode byte is an index into a 256-byte table. The operand is masked with bytes from the root key and the position.

Opcode map location: ________________ Operand formula: ________________ Check byte formula: ________________

**Step 3.** Ask the assistant to list each opcode kind the stack machine supports, after the mapping. Ask which kind halts it, and what that kind requires before it halts.

*Hint:* Look at the `switch` in the stack interpreter. Each case is a kind. Some kinds write to a 32-byte array. The halt case checks that every element of that array was written.

Kinds: ________________________________________________ Halt requires: ________________________________________________

**Step 4.** Ask the assistant what the stack machine outputs, and where it stores that output.

Output name: ________________ Size: ________________

**Check:** Ask the assistant to run the decoded stack program forward on its own and confirm the output is 32 bytes, with every position written once. Ask it to confirm the last instruction is the halt.

---

## Finding 5: The second interpreter (register VM)

**What's going on:** The second bytecode program runs on a register machine. It uses the key from Finding 4. Its instructions are 12 bytes each. Most operands and immediate values are masked. Some registers and some operations are noise. Eight comparison instructions test the real input.

*Why it matters:* the comparisons are where the ticket comes from. Each one fixes one of the real registers to a target value. The arithmetic is reversible, so you can work backward from the targets.

**Step 1.** Ask the assistant to find the second bytecode program, label it, and report how many 12-byte instructions it contains. Ask it to decrypt the program with the key from Finding 4.

*Hint:* The key is the 32-byte output from Finding 4. The nonce is in the header. The program is the slice after the first program.

Instruction count: ________________ Key source: ________________

**Step 2.** Ask the assistant how each 12-byte instruction is checked and decoded. Ask how the tag is computed, how the operands are unmasked, and how the immediate value is decoded.

*Hint:* The tag is a 32-bit hash of the first 8 bytes. It is seeded with the position and with one word from the key. The immediate is rotated by an amount based on the position, then XORed with that same key word.

Tag formula: ________________ Register formula: ________________ Immediate formula: ________________

**Step 3.** Ask the assistant to list each opcode kind the register machine supports, after the mapping. Ask which kinds read the input, which compare it, and which halt the program.

*Hint:* Look at the `switch` in the register interpreter. Some kinds read a 32-bit word from the input. One kind compares a register to an immediate value and counts the comparisons.

Input read kind: ________________ Comparison kind: ________________ Halt requires: ________________________________________________

**Step 4.** Ask the assistant which registers are real and which are noise. Ask how it tells them apart. Ask how many comparisons the program makes, and which registers they test.

*Hint:* Track which registers the comparisons read, and which registers any input-reading instruction writes. Anything that never affects a comparison is noise.

Real registers: ________________ Noise registers: ________________ Comparisons: ________________

**Check:** Ask the assistant to confirm the register program halts on the last instruction, after exactly the number of comparisons it expects. Ask whether any register outside the real set ever reaches a comparison.

---

## Finding 6: The ticket

**What's going on:** The comparisons give you target values for the real input registers. The input is a 32-character ticket, read as eight 32-bit little-endian words. Work backward from the targets through the reversible operations to recover the ticket.

*Hint on the operations:* addition and XOR can be reversed directly. Multiplication by an odd constant can be reversed with the constant's modular inverse. Rotations reverse with the opposite rotation. The `x ^ (x >> n)` operation can be reversed by repeating the shift at doubling distances.

**Step 1.** Ask the assistant to list each reversible operation in the register program, and the inverse it needs. Ask it to check that each inverse really undoes its operation.

Operations and inverses: ________________________________________________

**Step 2.** Ask the assistant to work backward from the eight comparison targets, reversing each operation in the opposite order. Ask it to report the recovered ticket.

Recovered ticket: ________________________________________________

**Step 3.** Ask the assistant to check the ticket against the alphabet the program allows, and to confirm that it is exactly 32 characters.

Alphabet: ________________ Length: ________________

**Step 4.** Ask the assistant what the program prints for a correct ticket, and what it prints for a wrong one.

- Correct: ________________________________________________
- Wrong: ________________________________________________

**Check:** Ask the assistant to run the register program forward on the recovered ticket, and confirm that every comparison is satisfied. Ask it to change one character and show that a comparison fails.

**Confidence tag for the ticket:** ________________

---

## Finding 7: The flag

**What's going on:** The flag is encrypted separately. Its key depends on the ticket and on the seed from Finding 4. Changing either one gives the wrong flag. The program checks the decrypted flag against a digest before it prints it.

*Why it matters:* this is why patching a single branch does not recover the flag. The flag needs the right ticket.

**Step 1.** Ask the assistant to explain how the flag key is built. Ask which inputs it hashes, in what order, and with what suffix.

*Hint:* Look at the call that builds the key, and at the bytes it hashes. There are three inputs: the ticket, the seed from Finding 4, and a short suffix.

Inputs: ________________________________________________ Suffix: ________________

**Step 2.** Ask the assistant to decrypt the flag with the derived key and the flag nonce from the header. Ask it to report the flag length and check its digest against the stored digest.

Length: ________________ Digest matches? ________________

**Step 3.** Ask the assistant what the program does if the digest does not match, and which runtime message it prints.

Output: ________________________________________________

**Check:** Ask the assistant to confirm the decrypted flag starts with `VW{` and ends with `}`. Ask it to explain why the flag would be wrong if you used the seed but a different ticket.

---

## Indicators of compromise (IOCs)

This challenge makes no network connections and writes no files. Record that as a finding, and explain why the readable endpoints are not IOCs.

| Type | Value | Source (address or string) | Confidence tag |
|---|---|---|---|
| Hostname | | | |
| Endpoint | | | |
| Environment variable | | | |
| File read | | | |

*Hint:* An endpoint string that is never used is a decoy, not an indicator. Say so in your notes.

---

## MITRE ATT&CK mapping

For each behavior, pick the technique ID and write the evidence. Ask the assistant to check your IDs against the ATT&CK site. Some behaviors may not have a clean match. Say so in the evidence column.

| Behavior | Technique ID and name | Evidence (address or string) | Confidence tag |
|---|---|---|---|
| Encrypted container decrypted at runtime | | | |
| Bytecode interpreted by two VMs | | | |
| Debugger check | | | |
| Timing check | | | |
| Ticket validation | | | |
| Flag decrypted at runtime | | | |

*Hint:* Look at the "Defense Evasion" and "Discovery" tactics, and see which sub-techniques fit. Consider the timing check carefully. Is it an evasion technique or a sandbox check?

---

## Analyst report

Write three short paragraphs. Keep each one under 120 words.

1. **Summary:** What does the program do, in plain language? What does the flag tell you about its goal, and what proves the flag is genuine?

   ________________________________________________

2. **Obstacles:** Name the two analysis obstacles you found hardest, and say how you got past each one. Which obstacle would a patch to a single branch miss?

   ________________________________________________

3. **Evidence:** Explain the chain from the container to the flag. Which findings did you confirm with a second method, and which did you only infer?

   ________________________________________________

---

## Submission checklist

- [ ] `main` and the thread function labeled, with addresses recorded
- [ ] Container, root key, and key derivations labeled
- [ ] Both interpreters labeled, with their instruction counts and opcode maps
- [ ] Gates labeled (debugger check, timing check, environment variable)
- [ ] Findings 1–7 answered, each with a confidence tag and a second-method check
- [ ] Decoys identified and explained
- [ ] IOC table filled in, including the note that the challenge makes no network connections
- [ ] ATT&CK mapping filled in with evidence
- [ ] Analyst report written
- [ ] Ticket and flag recorded, with the chain that connects them

# grumpyferret: Student Guide

**Goal:** Use your AI assistant and Ghidra (through the Ghidra MCP) to work out what `grumpyFerret` does. You'll find five findings, turn them into indicators of compromise (IOCs), map them to MITRE ATT&CK, and write a short analyst report.

## How to work through this

- Each step tells you **what to ask the assistant**. Type a version of it in your own words.
- When the assistant finds a function or data item, ask it to **label** it with a name that says what it does. Your labeled Ghidra project is part of your submission.
- Every answer gets a **confidence tag**:
  - **[Code]**: you can point to the exact instruction or string that shows it.
  - **[Inferred]**: you worked it out from code, but nothing in the binary states it directly.
  - **[Sandbox]**: it needs the sandbox report to confirm. Mark it this way and check it in the sandbox section.
- Each finding ends with a **Check**. Ask the assistant to confirm its answer a second way, such as reading raw bytes or cross-references. If the two methods disagree, keep working until they match.
- Hints are included so you can get unstuck. Use them.

> **Safety:** The static part of this exercise never executes `grumpyFerret`. Don't run it yourself or ask the assistant to run it. Dynamic behavior comes only from the sandbox report your instructor provides.

---

## Setup: Get oriented

**Step 1.** Ask the assistant for the program's name, architecture, and SHA-256 hash. Compare the SHA-256 with the `SHA256SUMS` file in your handout.

SHA-256: ________________

**Step 2.** Ask the assistant if the program is **dynamically** or **statically** linked, and what evidence it used.

*Hint:* Look for an interpreter path such as `/lib64/ld-linux-x86-64.so.2`, and for library names like `libc.so.6` in the strings. Dynamically linked programs import library functions instead of containing their code.

Answer: ________________ Evidence: ________________________________________________

**Step 3.** Ask the assistant to sort the functions into three groups: written by the author, compiler or linker boilerplate, and library code. Ask it to count unique names in each group.

*Hint:* Don't trust names alone. A name like `FUN_...` can be any of the three.

Author: ______ Boilerplate: ______ Library: ______

**Step 4.** Ask the assistant to find `main`. The binary doesn't name it, so start at the **entry point** and find which function it passes to `__libc_start_main`. Ask it to label that function `main`.

*Hint:* The entry point is short. Its first argument is a function pointer, and that pointer is `main`.

`main` address: ________________

**Check:** Ask the assistant to confirm `main` prints a banner. *Hint:* look for a `fwrite` call near the top.

---

## Finding 1: The embedded config

**What's going on:** The program hides five settings in a block of data. The data is scrambled with XOR, so you need the key to read it.

*XOR in one line:* each byte of data is XORed with a key byte. XORing again with the same key gives the original byte back.

**Step 1.** Ask the assistant to find the loop in `main` that unscrambles the config. Ask it to label the scrambled data and the key, and report their addresses and lengths.

*Hint:* The loop is about 124 steps long and reads two arrays. The key position is found with `& 3` or `% 4`.

Scrambled data address: ________________ Key address: ________________ Lengths: ________________

**Step 2.** Ask the assistant to read the raw bytes, unscramble the config, and list its settings.

*Hint:* The result is a list of `name=value` pairs separated by `;`.

- `ens` = ________________
- `ip` = ________________
- `domain` = ________________
- `safe` = ________________
- `campaign` = ________________

**Step 3.** Ask the assistant to find the text `GF_OFFLINE`, label the code that reads it, and explain what `main` skips when it's set.

*Hint:* `GF_OFFLINE` is in `Window > Defined Strings`. Its cross-reference is a `getenv` call in `main`.

What's skipped: ________________________________________________

**Check:** Ask the assistant to compare the first four scrambled bytes in the Listing with the raw bytes it read, and to unscramble the first three bytes again.

**Predict (before the sandbox):** Will the sandbox show DNS lookups for the config hostnames? Write your prediction: ________________

**Compare (sandbox report):** Did the sandbox show those lookups? ________________ Confidence tag for the config: ________________

---

## Finding 2: Network activity

**What's going on:** If `GF_OFFLINE` is not set, `main` looks up three config hostnames and then connects to `api.ipify.org`. The network code is inside `main`.

*Why it matters:* malware often checks an environment variable like this to skip its network activity, so it looks harmless to anyone watching the traffic.

**Step 1.** Ask the assistant to list every call in `main` that runs only when `GF_OFFLINE` is not set. Ask it to label each helper function the author wrote.

*Hint:* There are three calls to the same helper, plus a block of network calls.

Calls: ________________________________________________

**Step 2.** Ask the assistant which library function the DNS helper calls, and which config values it receives, in order.

*Hint:* Look at what the helper passes into the library function.

Library function: ________________ Hostnames in order: ________________, ________________, ________________

**Step 3.** Ask the assistant to label the address-hints struct, the timeout struct, and the request string. Then ask it to report:
- the address family and socket type in the hints
- the port number
- the request text
- the two timeout values

*Hint:* The hints struct is passed to `getaddrinfo`. The timeout struct is passed to `setsockopt`.

Family and socket type: ________________ Port: ________________

Request text: ________________________________________________

Timeout values: ________________

**Step 4.** Ask the assistant what happens after each of these fails: `getaddrinfo`, `socket`, `connect`, `write`, and `read`.

*Hint:* A block that skips the next call is a failure path. Look for `if` checks and early jumps.

- `getaddrinfo` fails: ________________________________________________
- `socket` fails: ________________________________________________
- `connect` fails: ________________________________________________
- `write` fails: ________________________________________________
- `read` returns nothing: ________________________________________________

**Step 5.** Ask the assistant to look up the `ens`, `domain`, `safe`, and `ip` values in Recorded Future and say whether each is reserved or an example name.

- ________________ → ________________________________________________
- ________________ → ________________________________________________
- ________________ → ________________________________________________
- ________________ → ________________________________________________

**Check:** Ask the assistant to confirm the `api.ipify.org` string and the `GET /` string are both used inside `main`. Ask it to run `strings` on the binary and confirm the host name appears.

**Predict (before the sandbox):** What network connections will the sandbox show, and in what order? Write your prediction: ________________

**Compare (sandbox report):** Which connections appeared, and in what order? ________________ Did the failure paths match your answers? ________________

---

## Finding 3: The hidden classroom stage

**What's going on:** `main` builds a Python script in memory and starts an external Python interpreter to run it. This happens whether or not the serial is correct.

**Step 1.** Ask the assistant to find the `fork` call and the program launch in its child branch. Ask what program path is launched and what arguments it gets.

*Hint:* The launch function is `execl`. Its first argument is the program path, and the rest are the arguments.

Program path: ________________ Arguments: ________________

**Step 2.** The third argument is a short string. Ask the assistant to label it and show its raw bytes.

*Hint:* The string is too short to appear in the normal string list. Find it through the launch call.

Address: ________________ Bytes say: ________________

**Step 3.** Ask the assistant to find the buffer `main` allocates before the `fork`. Ask it to label the buffer and the scrambled data it fills from, and report the loop length.

*Hint:* The buffer is allocated with `calloc`.

Scrambled data address: ________________ Loop length: ________________

**Step 4.** Ask the assistant to unscramble the buffer with the same key as Finding 1, keep the first byte unchanged, save the result to a file in your scratch directory, and label the script. Don't run it.

**Step 5.** Ask the assistant to read the decoded Python and report:
- the YouTube video ID it reads
- the rule it uses to pick a comment
- the URL it downloads the flag from
- the pattern the flag must match

Video ID: ________________

Comment rule: ________________________________________________

Flag URL: ________________________________________________

Required format: ________________

**Step 6.** Ask the assistant what decides whether the child process's output goes to `/dev/null`, and to label that variable.

*Hint:* Look at the branch around the `open("/dev/null")` and `dup2` calls.

What decides it: ________________________________________________

**Check:** Ask the assistant to unscramble the first 16 bytes again and confirm they look like Python source. Ask it to compare the output file's size with the loop length.

**Predict (before the sandbox):** Will the sandbox show a Python process started by `grumpyFerret`, and network requests to YouTube and GitHub? Write your prediction: ________________

**Compare (sandbox report):** Did the sandbox show those? ________________

---

## Finding 4: The anti-debugging check

**What's going on:** The program checks whether a debugger is attached. If one is, it prints different output.

**Step 1.** Ask the assistant to find the string `/proc/self/status` and the function that opens it. Ask it to label the function and report its address.

*Hint:* `/proc/self/status` is a Linux file that lists information about the running process.

Address: ________________

**Step 2.** Ask the assistant to find the text the function compares each line against, and show it as readable text.

*Hint:* The text is probably stored as a few large numbers, not as a string. Ask the assistant to convert those bytes to ASCII, and label the data.

Prefix: ________________

**Step 3.** Ask the assistant what value after the prefix makes the function return true.

*Hint:* The value is parsed with `strtol`. Check what result counts as "traced."

Condition: ________________________________________________

**Step 4.** Ask the assistant to list every call to this function in `main`, and what happens when each one returns true.

- First call: ________________________________________________
- Second call: ________________________________________________

**Step 5.** Ask the assistant to find every string that looks like a flag, plus any string starting with `backup_flag`. For each one, ask which branch prints it and whether it's real or a decoy. Ask it to label each string.

- ________________ → ________________ → ________________
- ________________ → ________________ → ________________
- ________________ → ________________ → ________________

**Check:** Ask the assistant to confirm, by reading the code, which output branch runs when the function returns true, and whether that matches what it reported above.

**Predict (before the sandbox):** Will the sandbox show the program checking for a tracer? How would you tell from the report? Write your prediction: ________________

**Compare (sandbox report):** Does the report show a debugger-triggered path? ________________

---

## Finding 5: The serial and the flag

**What's going on:** The program checks a 12-character serial byte by byte. If the serial is correct, it decodes and prints a flag.

**Step 1.** Ask the assistant to find the function `main` calls with the first command-line argument. Ask it to label the function and report the length it requires.

*Hint:* Look for a `strlen` call compared to a constant.

Length: ________________

**Step 2.** Ask the assistant to explain the check on each byte: the constant it XORs with, the value it adds, and the array it compares against. Ask it to label the constant and the array, and show their values.

*Hint:* The check is a 12-step loop. Each step XORs the input byte with a constant byte, adds the position, and compares the result to a byte in a data array.

Constant (ASCII): ________________ Target bytes (hex): ________________________________________________

**Step 3.** Ask the assistant to work out the one serial that passes every step, and show its reasoning. Don't run the program.

*Hint:* Reverse each step: subtract the position from the target, then XOR with the constant.

Serial: ________________

**Step 4.** Ask the assistant to find the flag loop in `main`, label the flag data and its key, and decode the flag.

*Hint:* This loop runs 21 times and uses a 5-byte key. It works the same way as the config decoding in Finding 1, with a different key length.

Key (hex): ________________ Flag: ________________

**Step 5.** Ask the assistant what `main` prints for a correct serial, and what it prints for a wrong one.

- Correct: ________________________________________________
- Wrong: ________________________________________________

**Check:** Ask the assistant to recompute the target bytes from your serial and confirm they match the array. Ask it to confirm the flag is 21 characters, starts with `GF{`, and ends with `}`.

---

## Indicators of compromise (IOCs)

Fill this in from your findings. Add the source for each one, which is the address or string where you found it.

| Type | Value | Source (address or string) | Confidence tag |
|---|---|---|---|
| Domain | | | |
| Domain | | | |
| Domain | | | |
| Hostname (phone-home) | `api.ipify.org` | | |
| HTTP request | | | |
| Video ID | | | |
| URL (Gist) | | | |
| Config key/value | | | |
| Environment variable | `GF_OFFLINE` | | |
| File read | `/proc/self/status` | | |

*Hint:* Config values are IOCs too. Ask the assistant to look up each domain and IP in Recorded Future and add a column for what it returns.

---

## MITRE ATT&CK mapping

For each behavior, pick the technique ID and write the evidence. Ask the assistant to check your IDs against the ATT&CK site.

| Behavior | Technique ID and name | Evidence (address or string) | Confidence tag |
|---|---|---|---|
| Config decoded with XOR at runtime | | | |
| `GF_OFFLINE` environment check | | | |
| DNS lookups and HTTP request to a public IP service | | | |
| Python script run from memory via `execl` | | | |
| Video comment and Gist used to find a flag URL | | | |
| `/proc/self/status` tracer check | | | |

*Hint:* Start from the technique families. Look at the "Defense Evasion" and "Command and Scripting Interpreter" tactics, and see which sub-techniques fit.

---

## Analyst report

Write three short paragraphs. Keep each one under 100 words.

1. **Summary:** What does the sample do, in plain language? What does the decoded flag tell you about the sample's goal?

   ________________________________________________

2. **Detection ideas:** Name two things a defender could alert on, using the IOCs and behaviors you found. Say why each one is reliable or fragile.

   ________________________________________________

3. **Sandbox comparison:** Which of your static findings did the sandbox confirm, and which did it not show? What does the difference tell you?

   ________________________________________________

---

## Submission checklist

- [ ] `main` labeled and its address recorded
- [ ] Helpers labeled (DNS probe, debugger check, serial check)
- [ ] Data labeled (config, key, stage, flag, serial, `-c` argument)
- [ ] Findings 1–5 answered, each with a confidence tag and a second-method check
- [ ] Predictions written before the sandbox report, and compared after
- [ ] IOC table filled in with sources
- [ ] ATT&CK mapping filled in with evidence
- [ ] Analyst report written
- [ ] Serial and flag recorded

# soggybadger: Student Guide

**Goal:** Use your AI assistant and Ghidra (through the Ghidra MCP) to work out what `soggyBadger.exe` does. You'll find five findings, turn them into indicators of compromise (IOCs), map them to MITRE ATT&CK, and write a short analyst report.

## How to work through this

- Each step tells you **what to ask the assistant**. Type a version of it in your own words.
- When the assistant finds a function or data item, ask it to **label** it with a name that says what it does. Your labeled Ghidra project is part of your submission.
- Every answer gets a **confidence tag**:
  - **[Code]**: you can point to the exact instruction, string, or import that shows it.
  - **[Inferred]**: you worked it out from code, but nothing in the binary states it directly.
  - **[Sandbox]**: it needs the sandbox report to confirm. Mark it this way and check it in the sandbox section.
- Each finding ends with a **Check**. Ask the assistant to confirm its answer a second way, such as reading raw bytes, cross-references, or the import table. If the two methods disagree, keep working until they match.
- Hints are included so you can get unstuck. Use them.

> **Safety:** The static part of this exercise never executes `soggyBadger.exe`. Don't run it yourself or ask the assistant to run it. Dynamic behavior comes only from the sandbox report your instructor provides.

---

## Setup: Get oriented

**Step 1.** Ask the assistant for the program's format, architecture, and SHA-256 hash. Compare the SHA-256 with the `SHA256SUMS` file in your handout.

SHA-256: ________________

**Step 2.** Ask the assistant to list the DLLs the program imports. Ask which of them handle networking, the registry, and synchronization.

*Hint:* Windows programs name their dependencies in the import table. Look in Ghidra's Symbol Tree under the imports, or ask the assistant to list the strings that end in `.dll`.

Imported DLLs: ________________________________________________

**Step 3.** Ask the assistant to find `main`. The binary may not name it, so start at the entry point. The startup code calls `main` after it sets up the C runtime. Ask the assistant to label `main`.

*Hint:* The entry point is short. Look for the call that passes a function pointer, and check that the function prints a banner near the top.

`main` address: ________________

**Step 4.** Ask the assistant to walk through `main` in order and list the stages it runs, with the function or call for each stage.

*Hint:* The stages are: banner, mutex, config build, registry check-in, DNS probes, phone-home, anti-debug gate, hash check, and flag reveal. Some stages may be inlined into `main`.

Stages (with function or call for each): ________________________________________________

**What to look for in Ghidra:**
- The entry point calls startup code, which eventually calls `main`. Follow the chain until you reach the function that prints the banner string.
- The PE has two TLS callbacks. They run before the entry point, so check them too. Ask the assistant what each one does.
- The imports appear in the Symbol Tree, grouped by DLL name. The DLL names tell you what kinds of behavior to expect.

**Check:** Ask the assistant to confirm the banner string and the build tag, and their cross-references into `main`.

---

## Finding 1: The hidden config (stack strings)

**What's going on:** The program's config values, such as the mutex name and the domains, are not stored as text anywhere in the file. The program builds each one one character at a time on the stack when it runs. A plain `strings` scan won't find them.

*Why it matters:* this technique defeats a basic string scan. Analysts have to read the code that builds the string.

**Step 1.** Ask the assistant to find the code in `main` that builds the config values. Ask it to label each block of code and say what value it builds.

*Hint:* The values are built inside `main`, not in separate functions. Look for long runs of single-character copies into local buffers. Each copy reads from a fixed address in the data section.

Builder functions and values: ________________________________________________

**Step 2.** Ask the assistant to rebuild each value from its builder code, in the order the characters are written.

*Hint:* Check whether the decompiler shows characters as `'x'` or as numeric values. Both work.

- Mutex name: ________________
- Domain (fake): ________________
- IP (fake): ________________
- Domain (safe): ________________
- Campaign: ________________

**Step 3.** Ask the assistant to search the strings for pieces of the config values. Ask what it finds, and whether any full value appears as one string.

*Hint:* Some of the config values show up in the string list, but as pieces joined together, not as the separate values. Work out where each value starts and stops.

Explanation: ________________________________________________

**What to look for in Ghidra:**
- Long runs of single-character copies in `main`. Each one reads from a fixed data address, and the decompiler shows each as its own assignment, such as `local_378[0] = s_SoggyBadgerSingleton_Mut_14000a370[0]`.
- Some values are copied from one data string that holds several values joined together. `strings` shows that joined string.
- The copies all happen in `main`, before the registry step.

**Check:** Ask the assistant to confirm that the values it rebuilt are the ones `main` prints on its config line.

---

## Finding 2: Host telemetry and network activity

**What's going on:** Before anything else, `main` creates a named mutex, writes a value to the registry, looks up two domains, and makes one HTTP request. All of this runs whether or not anything is watching the process.

**Step 1.** Ask the assistant to find the mutex call. Ask it to report the mutex name, and whether the program checks for an existing one.

*Hint:* `CreateMutexA` takes a name. `GetLastError` after the call tells the program whether the mutex already existed.

Mutex name: ________________ Checks for existing mutex? ________________

**Step 2.** Ask the assistant to find the registry calls. Ask it to report the key path, the value name, and whether the key is deleted before the program exits.

*Hint:* Look for `RegCreateKeyExA`, `RegSetValueExA`, and the cleanup calls. The registry root is `HKEY_CURRENT_USER`.

Key path: ________________ Value name: ________________ Cleaned up? ________________

**Step 3.** Ask the assistant which Winsock function the DNS probes use, and which two config values they look up, in order.

*Hint:* The probe is a helper that `main` calls twice, once for each domain.

Function: ________________ Hostnames in order: ________________, ________________

**Step 4.** Ask the assistant which WinINet functions make the HTTP request, and what URL the request goes to.

*Hint:* Look for `InternetOpenA` and `InternetOpenUrlA`. The URL is built with `snprintf` from one of the config values.

Functions: ________________ URL: ________________

**Step 5.** Ask the assistant to look up the domains and IP from the config in Recorded Future, and say whether each is reserved or an example name.

- ________________ → ________________________________________________
- ________________ → ________________________________________________
- ________________ → ________________________________________________

**What to look for in Ghidra:**
- `CreateMutexA` followed by a `GetLastError` check. The mutex name is the first argument.
- `RegCreateKeyExA` and `RegSetValueExA` early in `main`, and `RegDeleteValueA` and `RegDeleteKeyA` near the end. The cleanup calls show the key is removed before exit.
- A helper that `main` calls twice with config values. Inside it, `getaddrinfo` does the lookup.
- `InternetOpenA` and `InternetOpenUrlA`, with the URL built by a sprintf-style helper.

**Check:** Ask the assistant to confirm the mutex name and the registry key appear in `main` through their builder functions, and that the `snprintf` URL comes from the safe domain.

**Predict (before the sandbox):** Which host-based and network events will the sandbox show, and in what order? Write your prediction: ________________

**Compare (sandbox report):** Which events appeared? ________________ Confidence tag for the mutex: ________________

---

## Finding 3: The anti-debugging checks

**What's going on:** The program checks whether a debugger is attached in two ways. If either check says yes, it prints a decoy flag instead of checking the input.

**Step 1.** Ask the assistant to find the two anti-debug checks. Ask it to label each one and say how it detects a debugger.

*Hint:* One check calls a Windows API. The other reads a field from a Windows internal structure through the `gs` segment register.

Check 1: ________________ Check 2: ________________

**Step 2.** Ask the assistant which byte of the internal structure the second check reads, and what value means "being debugged."

*Hint:* This is the Process Environment Block (PEB). Ask the assistant to explain the offset, and to show which bytes it reads.

Offset: ________________ "Being debugged" means: ________________

**Step 3.** Ask the assistant what the program prints when either check says a debugger is attached, and which flag it shows.

Output: ________________________________________________

**Step 4.** Ask the assistant to find every place the anti-debug gate appears in `main`, and which steps run before it. Ask it to confirm that the gate protects only the final check.

*Hint:* Compare the order of calls in `main`. The registry, DNS, and phone-home steps should all run before the gate.

Steps before the gate: ________________________________________________

**What to look for in Ghidra:**
- A call to `IsDebuggerPresent`, and a direct read through the `gs` segment register at offset `0x60`, which is the PEB. Then a byte read at offset 2.
- The gate sits right before the hash comparison. The network and registry steps run before it, with no checks.
- The traced branch prints two decoy strings and returns.

**Check:** Ask the assistant to confirm the PEB read is a direct memory read, not an API call, and to compare it with the `IsDebuggerPresent` call next to it.

**Predict (before the sandbox):** Will the sandbox trigger the anti-debug branch? Why or why not? Write your prediction: ________________

**Compare (sandbox report):** Did the report show the decoy output? ________________

---

## Finding 4: The unlock check (rolling hash)

**What's going on:** The program takes one command-line argument and runs a rolling hash on it. If the hash matches a 32-bit target value, the program unlocks the flag. You don't need to reverse the hash. You need to find the candidate string that produces the target.

*Hint on the hash shape:* for each character, rotate the running value right by 13 bits, then add the character's value. Analysts use this style of hash to hide the names of Windows functions a program calls.

**Step 1.** Ask the assistant to find the hash function and label it. Ask it to describe the steps in plain language.

*Hint:* Look for a loop over the characters of a string, with a rotate and an add in each step.

Hash function: ________________ Steps: ________________________________________________

**Step 2.** Ask the assistant for the 32-bit target value the hash is compared against, and the code that compares them.

*Hint:* The target is a fixed constant in the code, not a string.

Target value: ________________

**Step 3.** Ask the assistant to find the candidate names for the answer. The program's own imports are the candidates. Ask it to list each candidate, then hash each one and compare it to the target.

*Hint:* The README's hint is that the answer is one of the imported DLLs. Try the uppercase base name, without `.dll`.

Matching candidate: ________________ Its hash: ________________

**Step 4.** Ask the assistant to tell you what `main` prints for the correct input, and what it prints for a wrong one.

- Correct: ________________________________________________
- Wrong: ________________________________________________

**What to look for in Ghidra:**
- A loop over the characters of the argument. Each step rotates the running value right by 13 bits, then adds the character. The decompiler may show the rotate as shifts and an OR.
- A 32-bit constant compared at the end of the loop. The matching branch reveals the flag, and the other branch prints a decoy.

**Check:** Ask the assistant to hash your matching candidate again with the same steps, and confirm it equals the target. Ask it to check that no other imported DLL name matches.

---

## Finding 5: The flag

**What's going on:** When the unlock check passes, the program decodes a flag from XOR-encoded data. The key is 6 bytes long.

**Step 1.** Ask the assistant to find the flag decode loop in the function that reveals the flag. Ask it to label the encoded data and the key, and report their lengths.

*Hint:* The loop uses the key's position with `% 6`. Work out the key length from that.

Encoded data: ________________ Key: ________________ Lengths: ________________

**Step 2.** Ask the assistant to read the raw bytes of both, and decode the flag.

Key (hex): ________________ Flag: ________________

**Step 3.** Ask the assistant to explain how the result is printed, including the text before the flag.

Output: ________________________________________________

**What to look for in Ghidra:**
- A loop of 21 iterations that XORs a data array with a 6-byte key. The key index uses `% 6`.
- The result is printed with a "hash matched" message before the flag.

**Check:** Ask the assistant to confirm the decoded flag is 21 characters, starts with `SB{`, and ends with `}`.

---

## Indicators of compromise (IOCs)

Fill this in from your findings. Add the source for each one (the address or string where you found it).

| Type | Value | Source (address or string) | Confidence tag |
|---|---|---|---|
| Mutex | | | |
| Registry key | | | |
| Domain | | | |
| Domain | | | |
| IP | | | |
| URL | | | |
| Imported DLL | | | |

*Hint:* Not every indicator needs a threat-intel lookup. A mutex name is a host indicator, so it doesn't get looked up in Recorded Future. Note the type and move on.

---

## MITRE ATT&CK mapping

For each behavior, pick the technique ID and write the evidence. Ask the assistant to check your IDs against the ATT&CK site.

| Behavior | Technique ID and name | Evidence (address or string) | Confidence tag |
|---|---|---|---|
| Config built on the stack | | | |
| Named mutex | | | |
| Registry check-in | | | |
| DNS probes and HTTP request | | | |
| Anti-debug checks | | | |
| Rolling-hash unlock | | | |
| Flag decoded at runtime | | | |

*Hint:* Look at the "Defense Evasion" tactic, and at the "Discovery" and "Command and Scripting Interpreter" tactics. Start with the broad technique and check whether a sub-technique fits better.

---

## Analyst report

Write three short paragraphs. Keep each one under 100 words.

1. **Summary:** What does the sample do, in plain language? What does the flag tell you about its goal?

   ________________________________________________

2. **Detection ideas:** Name two things a defender could alert on, using the IOCs and behaviors you found. Say why each one is reliable or fragile.

   ________________________________________________

3. **Sandbox comparison:** Which of your static findings did the sandbox confirm, and which did it not show? What does the difference tell you?

   ________________________________________________

---

## Submission checklist

- [ ] `main` labeled and its address recorded
- [ ] Config builder functions labeled
- [ ] Hash function, target, and matching candidate labeled
- [ ] Findings 1–5 answered, each with a confidence tag and a second-method check
- [ ] Predictions written before the sandbox report, and compared after
- [ ] IOC table filled in with sources
- [ ] ATT&CK mapping filled in with evidence
- [ ] Analyst report written
- [ ] Unlock candidate and flag recorded

# soggybadger: Instructor Answer Key

Use this with `student.md`. Static answers come from `soggybadger.c` and were checked against `soggyBadger.exe`. The sandbox section describes what the sample should do in the class sandbox. Verify them against an actual sandbox run before class.

> **Which binary:** the docs refer to `soggyBadger.exe`, the 64-bit Windows PE that students receive. This folder contains no Linux build. The Makefile's `make debug` target produces an unstripped `soggyBadger_debug.exe` for your own reference; it is not in the folder.
>
> **Binary identity:** MD5 `09c71fb061435a07d50c43f3bd31c37c`, SHA-256 `805bcde68c184e1dccbc5bc92a53313ff97d2803e261cc29463d0f4168fb9961`. The handout's `SHA256SUMS` file is not in this folder; add the SHA-256 above to it before distributing.
>
> **How this key was checked (update pass):** static only. The binary was not executed, and the Ghidra MCP was not connected, so no Ghidra project was opened. Checks performed: PE header and import-table parsing of `soggyBadger.exe`; a fresh MinGW-w64 build of `soggybadger.c` (GCC 13-win32, `-O2 -s -Wall`, linked with `-lws2_32 -lwininet -ladvapi32`) into a scratch directory, with every section compared byte-for-byte against the shipped binary; a script that recomputes the hashes and decodes the flag.
>
> **Source/binary result:** no mismatch in code or data. All of `.text`, `.rdata`, `.data`, `.pdata`, `.xdata`, `.idata` and `.tls` are identical to the local build. The one difference is cosmetic: the binary's import is `msvcrt.dll` (lowercase), where this key writes `MSVCRT`. This is a match for the local toolchain only; a different MinGW version may produce different bytes. Rehearse the exact `.exe` on Windows, as the Makefile says.
>
> **Ghidra labels:** the `FUN_` names below come from an earlier Ghidra session and were not re-opened. The addresses were re-derived from the PE, so they should hold, but a fresh Ghidra import may auto-name differently. Re-check them before grading.

---

## Setup

**Step 1. MD5:** `09c71fb061435a07d50c43f3bd31c37c`. SHA-256: `805bcde68c184e1dccbc5bc92a53313ff97d2803e261cc29463d0f4168fb9961`. Format: PE32+, x86-64, Windows console.

**Step 2. Imported DLLs:** `ADVAPI32.dll`, `KERNEL32.dll`, `msvcrt.dll`, `WININET.dll`, `WS2_32.dll`
- Registry: `ADVAPI32.dll` (`RegCreateKeyExA`, `RegSetValueExA`, `RegDeleteValueA`, `RegDeleteKeyA`, `RegCloseKey`)
- Networking: `WS2_32.dll` (`WSAStartup`, `getaddrinfo`, `freeaddrinfo`, `inet_ntop`, `WSACleanup`), `WININET.dll` (`InternetOpenA`, `InternetOpenUrlA`, `InternetReadFile`, `InternetCloseHandle`)
- Synchronization and process: `KERNEL32.dll` (`CreateMutexA`, `GetLastError`, `IsDebuggerPresent`, critical-section calls). The rest of the `msvcrt.dll` imports are C runtime boilerplate.

**Step 3. `main` address:** `0x140007d80` (`FUN_140007d80` in the earlier Ghidra session)
- Entry point: `0x140001410` (`mainCRTStartup`), which calls the CRT startup at `0x140001190`, which calls `main`.
- Banner string `"soggybadger v2.0 -- \"who's a good boy\"\n"` at `0x14000a060`. Its xref is in `main`.
- Two TLS callbacks are listed in the PE TLS directory: `0x1400017c0` and `0x1400017f0`. They are MinGW C runtime code (`__dyn_tls_dtor` and `__dyn_tls_init`). Both call `__mingw_TLScallback` (`0x140002290`), which dispatches on the callback reason. The author did not write them and they are not part of the stage list below. Students who report them as author code are wrong.

**Step 4. Stages in `main` (in order, from the source):**

| Stage | Function or call |
|---|---|
| Banner | `printf` wrapper at `0x140001480`, banner at `0x14000a060`, then build tag line |
| Winsock init | `WSAStartup`. On failure, prints a line and continues |
| Mutex | `CreateMutexA` with the stack-built name, then `GetLastError` |
| Config build | Inline in `main`. Character stores from `0x14000a370`, `0x14000a390` and `0x14000a3c0`, plus immediates |
| Config line | `printf` of domain, IP, safe domain and campaign |
| Registry check-in | `RegCreateKeyExA`, `RegSetValueExA` |
| DNS probes | `FUN_1400014d0` (`gf2_dns_probe`, a real separate function), called twice, `getaddrinfo` |
| Phone-home | `FUN_140001610` (`snprintf.constprop.0`, `"http://%s/"` at `0x14000a03d`), then `InternetOpenA`, `InternetOpenUrlA`, `InternetReadFile` |
| Usage check | `argc < 2` prints usage and exits with 0. This runs **before** the anti-debug gate |
| Anti-debug gate | `IsDebuggerPresent` plus PEB read (`gs:[0x60]`, byte `+2`) |
| Hash check | Inline loop in `main`, compared to `0xA2AC2ABD` (one immediate, in `main` at `0x1400081c2`) |
| Flag reveal | Inline XOR loop in `main` |
| Cleanup | `RegDeleteValueA`, `RegDeleteKeyA`, `RegCloseKey`, `CloseHandle`, `WSACleanup` |

**Check:** The banner string's xref is in `main`. The config fragments are read in `main`, and the `snprintf` URL uses the safe domain.

---

## Finding 1: The hidden config (stack strings)

**Step 1. Builder code:** No separate builder functions in the binary. The source defines `gf2_build_mutex_name`, `gf2_build_fake_domain`, `gf2_build_fake_ip`, `gf2_build_safe_domain` and `gf2_build_campaign`, but the compiler inlines them, so `main` contains all the copies.
- Mutex: copied from `0x14000a370` (`SoggyBadgerSingleton_Mut`), with the tail `"ex"` stored as the immediate `0x7865`.
- Fake domain, fake IP and safe domain: copied from `0x14000a390` (`c2.soggybadger-demo.inva` / `203.0.11` / `example.`), with tails stored as immediates in `main`. The `"com"` tail is the immediate `0x6d6f63`.
- Campaign: copied from `0x14000a3c0` (`operation-wet-bl`), with tail `"anke"` stored as the immediate `0x656b6e61`, plus a final `"t"`.

**Step 2. Rebuilt values:**
- Mutex name: `SoggyBadgerSingleton_Mutex`
- Domain (fake): `c2.soggybadger-demo.invalid`
- IP (fake): `203.0.113.9`
- Domain (safe): `example.com`
- Campaign: `operation-wet-blanket`

**Step 3. Explanation:** The string list shows `c2.soggybadger-demo.inva203.0.11example.`, `SoggyBadgerSingleton_Mut` and `operation-wet-bl` as joined fragments. No full value appears as one string. The fragments are still there, so a `strings` pass sees part of each value. Earlier text in this repo said none of the values appear at all. That was wrong.

**Check:** The rebuilt values match the `[*] config:` line that `main` prints (`domain=%s ip=%s safe=%s campaign=%s`). Verified in this pass: the fragments above exist in `.rdata` at the stated addresses, and the immediates `0x7865`, `0x6d6f63` and `0x656b6e61` appear in `main`.

**Confidence:** [Code]

**Sandbox note:** the config line is printed at runtime, so the sandbox report shows all five values. See the notes at the end.

---

## Finding 2: Host telemetry and network activity

**Step 1. Mutex:** `SoggyBadgerSingleton_Mutex`. Checks for an existing mutex: yes. `GetLastError() == 0xB7` (`ERROR_ALREADY_EXISTS`) selects the log text "already existed" versus "created". It does not change control flow. The handle is closed at cleanup, so a fresh run normally reports "created".

**Step 2. Registry:** Key path `Software\SoggyBadgerDemo` under `HKEY_CURRENT_USER`. Value name `Marker`, data `soggybadger-demo-marker`. Cleaned up: yes. `RegDeleteValueA` and `RegDeleteKeyA` run before exit, but only if `RegCreateKeyExA` succeeded. Note that the key path and value are plain text in `.rdata` (`0x14000a131`, `0x14000a17c`), not stack strings.

**Step 3. DNS function:** `getaddrinfo`, inside `FUN_1400014d0`. Hostnames in order: `c2.soggybadger-demo.invalid`, then `example.com`. Prints `failed (rc)` on failure and `resolved -> <ip>` on success. The IP from the config (`203.0.113.9`) is never resolved or connected to.

**Step 4. WinINet functions:** `InternetOpenA` (agent `soggybadger-demo/1.0`, direct access), then `InternetOpenUrlA` with `INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE`, then `InternetReadFile` into a 128-byte buffer. URL: `http://example.com/` (built with `"http://%s/"` from the safe domain). Prints `ok, got N bytes`, `no response`, or `connect failed (err)`.

**Step 5. Recorded Future lookups:** Not run in this pass, and the results depend on the live service, so run them yourself before class. Expected answers, from the RFC reserved-name standards:
- `c2.soggybadger-demo.invalid` → reserved `.invalid` TLD (RFC 2606). Not a live domain.
- `example.com` → reserved example domain (RFC 2606). Not a live domain. The `http://example.com/` request is to a real host, so expect a page there.
- `203.0.113.9` → TEST-NET-3 documentation range `203.0.113.0/24` (RFC 5737). Not routable.

**Check:** The mutex name and registry key are built or stored in `main`. The `snprintf` URL uses the safe domain (`example.com`), not the fake one.

**Predict and compare:** See the sandbox table. Fill in the sandbox result after the report is available.

**Confidence:** Mutex, registry, and DNS: [Code]. Sandbox confirmation: [Sandbox].

---

## Finding 3: The anti-debugging checks

**Step 1. Checks:**
- Check 1: `IsDebuggerPresent` (`KERNEL32.dll`), called in `main`.
- Check 2: Direct PEB read through `gs:[0x60]`, then a byte read at offset `+2` (`BeingDebugged`).

**Step 2. Offset and value:** Offset `2` in the PEB. "Being debugged" means the byte is nonzero.

**Step 3. Output:** `"\n[!] tracer detected. backup_hash=0xDEADBEEF\nSB{TRY_HARDER}\n"`. Return value 1.

**Step 4. Steps before the gate:** Banner, mutex, config build, registry check-in, DNS probes, phone-home, and the usage check. The gate sits before the hash comparison and protects only the final check. The usage check is a separate `if` that runs first, not part of the same branch. With no argument the program exits at the usage check, so the anti-debug output never appears.

**Check:** The PEB read is a direct memory read (`gs:[0x60]`, then byte `+2`), not an API call, and sits beside the `IsDebuggerPresent` call.

**Predict and compare:** A sandbox that does not attach a debugger or set `BeingDebugged` will not print the decoy. Fill in the sandbox result after the report is available.

**Confidence:** [Code]

---

## Finding 4: The unlock check (rolling hash)

**Step 1. Hash function:** The loop is inline in `main`, not a separate function. Each step rotates the running 32-bit value right by 13 bits, then adds the character: `h = ror32(h, 13) + c`, starting from `h = 0`.

**Step 2. Target:** `0xA2AC2ABD`, a fixed 32-bit constant compared at the end of the loop.

**Step 3. Matching candidate:** `ADVAPI32` (uppercase base name of an imported DLL), hash `0xA2AC2ABD`.
- Other candidates, none match: `KERNEL32` = `0x8CB0FCBB`, `MSVCRT` = `0x2E95413B`, `WININET` = `0x1588F3F9`, `WS2_32` = `0xE59D481D`. The binary's own spelling `msvcrt.dll` hashes to `0x6F97496B`, which also does not match, so the uppercase rule matters.

**Step 4. Output:**
- Correct: `"\n[+] hash matched.\n" + flag + "\n"` (flag is decoded in Finding 5).
- Wrong: `"\n[-] wrong. SB{NOT_TODAY}\n"`, exit code 1.

**Hint leak:** The usage text in the binary reads `(hint: the code is the uppercase base name of one of this binary's own imported DLLs)`. A plain `strings` pass finds it, so students get the hint without running anything. That is the design, since the README points the same way.

**Check:** Rehashing `ADVAPI32` with the same steps gives `0xA2AC2ABD`. No other imported DLL base name matches. Verified in this pass with a script, and the target appears as one immediate in `main`.

**Confidence:** [Code]

---

## Finding 5: The flag

**Step 1. Encoded data and key:**
- Encoded data: 21 bytes at `0x14000a350`.
- Key: 6 bytes at `0x14000a365`.
- Lengths: 21 and 6. The source loops 21 times and indexes the key with `i % 6`.

**Step 2. Raw bytes and decoded flag:**
- Key (hex): `2F C4 88 51 DA 06`
- Encoded (hex): `7C 86 F3 02 8E 47 6C 8F D7 02 8E 54 66 8A CF 02 85 51 66 8A F5`
- Flag: `SB{STACK_STRINGS_WIN}` (21 characters)

**Step 3. Output:** `"\n[+] hash matched.\n" + flag + "\n"`. The "hash matched" message comes before the flag, in the same branch as Finding 4.

**Check:** The decoded flag is 21 characters, starts with `SB{`, and ends with `}`. Verified by script in this pass.

**Confidence:** [Code]

---

## Indicators of compromise (IOCs)

| Type | Value | Source (address or string) | Confidence tag |
|---|---|---|---|
| Mutex | `SoggyBadgerSingleton_Mutex` (host indicator, not a network one) | Built in `main` from `0x14000a370` plus immediate `"ex"` | [Code] |
| Registry key | `HKCU\Software\SoggyBadgerDemo` (value `Marker` = `soggybadger-demo-marker`) | Strings at `0x14000a131`, `0x14000a17c` | [Code] |
| Domain | `c2.soggybadger-demo.invalid` (classroom decoy) | `0x14000a390` plus tail immediates | [Code] |
| Domain | `example.com` (shared service, not a live C2) | `0x14000a390` plus `"com"` immediate | [Code] |
| IP | `203.0.113.9` (classroom decoy, TEST-NET-3) | `0x14000a390` plus tail immediates | [Code] |
| URL | `http://example.com/` | `"http://%s/"` at `0x14000a03d` | [Code] |
| Imported DLL | `ADVAPI32.dll`, `KERNEL32.dll`, `msvcrt.dll`, `WININET.dll`, `WS2_32.dll` | Import name strings `0x14000f8a0` to `0x14000f9c4` | [Code] |
| Runtime output | `[*] config: domain=... ip=... safe=... campaign=...` | `printf` in `main` | [Code] (appears in sandbox output: [Sandbox]) |

---

## MITRE ATT&CK mapping

Verify these IDs against the ATT&CK version you use before class. They were not checked against the live ATT&CK site in this pass.

| Behavior | Technique ID and name | Evidence (address or string) | Confidence tag |
|---|---|---|---|
| Config built on the stack | T1027 Obfuscated Files or Information | Inline char copies in `main` from `0x14000a370`, `0x14000a390`, `0x14000a3c0` | [Inferred] |
| Named mutex | No dedicated technique | `CreateMutexA` with `SoggyBadgerSingleton_Mutex`. Record as a host indicator only | [Inferred] |
| Registry check-in | T1112 Modify Registry | `RegCreateKeyExA` / `RegSetValueExA`, cleanup via `RegDeleteValueA` / `RegDeleteKeyA` | [Code] |
| DNS probes | T1016 System Network Configuration Discovery (weak fit) | `getaddrinfo` in `FUN_1400014d0` | [Inferred] |
| HTTP request | T1071.001 Application Layer Protocol: Web Protocols | `InternetOpenUrlA` with `http://example.com/` | [Code] |
| Anti-debug checks | T1622 Debugger Evasion | `IsDebuggerPresent` and PEB `BeingDebugged` read (`gs:[0x60]+2`) | [Code] |
| Rolling-hash unlock | No direct match. T1027.007 Dynamic API Resolution is the closest pattern (hash-based name matching), but this hash gates a flag, not an API lookup | Rotate-and-add hash compared to `0xA2AC2ABD` | [Inferred] |
| Flag decoded at runtime | T1140 Deobfuscate/Decode Files or Information | 21-iteration XOR loop, key at `0x14000a365` | [Code] |

Students may argue for T1480 Execution Guardrails for the hash gate or the anti-debug logic. Accept it only with a clear justification, since the gate is about a flag, not the environment.

---

## What the sandbox should show

The sandbox is the only place students see dynamic behavior. Run the sample once before class and fill in the actual results. Expected behavior, from the source:

| Run | Expected behavior |
|---|---|
| No argument | Banner, build line, mutex line, config line, registry check-in line, DNS for `c2.soggybadger-demo.invalid` (fails), DNS for `example.com` (resolves if the sandbox has DNS), HTTP GET to `http://example.com/`, usage text including the hint, registry cleanup. Exit code 0. No anti-debug output, no hash output, no flag |
| Wrong argument, no debugger | Same as above, then `[-] wrong. SB{NOT_TODAY}`. Exit code 1 |
| `ADVAPI32`, no debugger | Same as above, then `[+] hash matched.` and `SB{STACK_STRINGS_WIN}`. Exit code 0 |
| Debugger attached, or PEB `BeingDebugged` set | Same network and registry lines, then `[!] tracer detected. backup_hash=0xDEADBEEF` and `SB{TRY_HARDER}`. Exit code 1, even with `ADVAPI32` |
| No network | DNS failure lines for both hosts, `connect failed (err)` from WinINet, and the usual anti-debug and hash output. The hash check does not depend on the network, so a correct argument still prints the flag |

Notes for the sandbox results:
- The mutex and registry steps run regardless of input, so they should appear on every run.
- The debugger check is not triggered by a standard sandbox that does not attach a debugger. Students should predict that and check it against the report.
- The `[*] config:` line makes the config values visible in the sandbox output. See the notes below.

---

## Analyst report: what good looks like

- **Summary:** The sample is a benign crackme that mimics a small implant. It creates a mutex and a registry marker, resolves two hostnames, makes one HTTP request to `example.com`, hides its config on the stack, and gates a flag behind a rolling-hash argument and an anti-debugging check. The flag is a classroom reward, not a real goal.
- **Detection ideas:** Good answers name specific indicators, such as the `HKCU\Software\SoggyBadgerDemo` marker, the `SoggyBadgerSingleton_Mutex` mutex, or the `IsDebuggerPresent` plus `gs:[0x60]` pattern. Fragile answers rely on the decoy strings or on the `example.com` request alone, since legitimate software could make either.
- **Sandbox comparison:** Good answers say which static findings the sandbox confirmed, and which it did not (for example, the decoy branch, or the network requests if the sandbox has no network). They explain the difference, such as "the sandbox doesn't attach a debugger" or "no outbound network."

Fill in the sandbox-comparison paragraph after the report is in. Do not grade a sandbox claim without a report to check it against.

---

## Grading rubric (suggested)

| Area | Points | Key evidence |
|---|---|---|
| 1. Config | | Five stack-built values, and why a `strings` pass sees only fragments |
| 2. Telemetry and network | | Mutex, registry check-in and cleanup, DNS order, `http://example.com/` request |
| 3. Anti-debug | | `IsDebuggerPresent`, PEB `+2` read, decoy output, gate placement |
| 4. Unlock | | Rotate-and-add hash, `ADVAPI32`, the uppercase-name rule |
| 5. Flag | | Key, 21-byte decode, `SB{STACK_STRINGS_WIN}` |
| Labeling | | `main` and helpers labeled, names describe purpose |
| Confidence tags | | Each answer tagged correctly |
| Predictions | | Written before the sandbox, compared after |
| IOC table | | Complete, with sources |
| ATT&CK mapping | | Plausible IDs with evidence |
| Analyst report | | Three paragraphs, supported by the findings |

Set point values before grading. The rubric above does not include them.

---

## Notes for the instructor

- **Config line leaks values at runtime.** `main` prints `[*] config: domain=... ip=... safe=... campaign=...`, and the mutex line prints the mutex name. Anyone who runs the sample, or reads a sandbox report, gets all five values without reversing anything. Decide before class whether that is intended. If not, remove those two `printf` calls in `soggybadger.c` and rebuild. Doing so changes the binary, so the byte-match above would no longer hold.
- **Usage hint.** The usage text contains the hint about uppercase DLL names, and `strings` shows it. The README's hint is the same, so this is consistent with the design.
- **No-argument run exits before the gate.** Students who run the sample with no argument see the sandbox behavior but no decoy and no hash output. This is not a bug.
- **TLS callbacks are CRT code.** See Setup, Step 3. Do not count them as author logic.
- **Source vs. earlier text.** Earlier docs said the config builders were "inline, not separate functions" (true for the binary, not the source) and that the TLS callbacks were part of the stage list (not true). The fragment claim in the README was also wrong. All three are corrected above.
- **Recorded Future and sandbox results** are not in this key. Fill them in after the live lookups and the sandbox run.

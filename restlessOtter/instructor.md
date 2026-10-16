# restlessotter: Instructor Answer Key

Use this with `student.md`. Static answers were checked on 2026-10-15 by reading `restlessotter.c` and the `Makefile`, and by static inspection of the shipped binary (SHA-256 `66cde9e0e9b3124667b4e676b9115ba10d72040cd9e8cf6e873f02bae59d5c13`): raw byte matching, Mach-O header parsing, and disassembly with `llvm-objdump` on a scratch copy. The binary was not executed and Ghidra was not used. Sandbox expectations describe what the sample should do. Verify them against an actual sandbox run before class.

> **Build note: symbols.** The shipped binary is not fully stripped. It was built with `make release`, which runs plain `strip restlessOtter` (Makefile line 8; there is no `-x`). The global `_main` symbol at `0x1000005b8` survives, so students will see `_main` in Ghidra's symbol list. The binary's own code is only two functions: `_main` and the decoder at `0x100001418`. Decide before class whether you want `_main` visible. If not, rebuild with different strip flags and check the result on a Mac. This changes the SHA-256, so update the hash in all four docs.

> **Source and binary agree on behavior.** Every encrypted blob in the binary matches the bytes and length in `restlessotter.c`. The decoder at `0x100001418` uses the same key stream as the source. The argument gate (`cmp w20, #2` at `0x100000654`), the `sysctl` `P_TRACED` test (`tbz w8, #0xb` at `0x100000c34`), the 16-byte length check (`cmp x0, #0x10` at `0x100000d60`), and the ticket table and checksum loop all match the source. A fresh macOS `make release` build reproduces the shipped binary byte for byte (same SHA-256).

> **Checksum compare constant.** The compiled final compare is `0x7c538b83`, not the source constant `0x7c539eb9`. This is not a behavior mismatch. The compiler folded the last loop iteration's index (15) and the `0x1337` constant into the compare: `0x7c539eb9 - 0x1336 = 0x7c538b83`. Students who compare against the source value will see a different number in Ghidra. Tell them that is expected.

> **Makefile check.** `make strings-check` does not fail on the shipped binary. Its pattern (`github|example\.com|ticket|RO\{|operation|decoded|phoning|User-Agent`) matches nothing in `strings` output (GNU `strings` tested). An earlier note that it fails on the code-signing identifier was wrong: the identifier is `restlessotter`, which the pattern does not match. macOS `strings` was not tested.

> **Linux builds.** `ro_is_debugged()` returns 0 on any platform except Apple, so a Linux build never takes the traced branch. Use only the macOS binary for class.

> **Sandbox build note.** This is an arm64 Mach-O. Confirm the class sandbox can run Mach-O arm64 before assigning the sandbox steps. If it can't, the dynamic sections will not be testable.

---

## Setup

**Step 1. Hashes:** SHA-256 `66cde9e0e9b3124667b4e676b9115ba10d72040cd9e8cf6e873f02bae59d5c13`. MD5 `51ac9b918abf82f0a89a3331fb8b60a9`. The file is `Mach-O 64-bit arm64 executable` (PIE).

**Step 2. Linking:** Dynamically linked. The strings `/usr/lib/dyld` (`0x1000004ac`) and `/usr/lib/libSystem.B.dylib` (`0x100000538`) are in the Mach-O load commands. Sixteen functions are imported from `libSystem`: `_getaddrinfo`, `_freeaddrinfo`, `_socket`, `_connect`, `_send`, `_recv`, `_close`, `_sysctl`, `_getpid`, `_inet_ntop`, `_write`, `_strlen`, `_bzero`, `_memcpy`, `___memcpy_chk`, `___stack_chk_fail`. There is no `setsockopt` import.

**Step 3. Function groups:**
- Author: 2. `_main` (`0x1000005b8`) and the decoder (`0x100001418`). The `__text` section is exactly these two functions (`0x1000005b8`–`0x100001458`). The compiler inlined every other helper into `_main`.
- Boilerplate: 0 functions the author has to label. There is no C runtime startup code; the Mach-O `LC_MAIN` entry point is `_main`. The linker stub helper and `dyld_stub_binder` are not author code.
- Library: 16 imports (stubs in `__stubs`, `0x100001458`–`0x10000150c`).

**Step 4. `main` address:** `0x1000005b8`. It is the Mach-O entry point (`LC_MAIN`, entryoff `0x5b8`). Its first call decodes the banner at `0x100000614`.

**Check:** The banner blob is at `0x1000015f8` (35 bytes, seed `0x31`). `_main` references it with `adrp x1` at `0x1000005f8` and `add x1, x1, #0x5f8` at `0x1000005fc`. Decoded: `restlessotter v3.0 -- "hold still"` plus a newline.

**Control flow in `main`:**
1. Decode and print the banner (always).
2. If `argc != 2`: print `usage: <argv[0]> <ticket>` plus newline, return 1. Nothing else runs.
3. If `argc == 2`: decode the config and the port, parse the config, run the two DNS probes, run the phone-home request, run the anti-debug check, then run the ticket check and print the result.

---

## Finding 1: Encrypted config

**Decoder:** the function at `0x100001418`, the source's `ro_decode`. Arguments are destination, source, length, and seed. The state is seeded with `seed`. For each byte `i`:

```
state = (33 * state + i + 0x11) & 0xff
key[i] = state ^ ((29 * i + 0x5a) & 0xff)
out[i] = in[i] ^ key[i]
```

The decoder writes a NUL after the last byte. The disassembly at `0x100001418`–`0x100001454` matches this.

**Config call in `main`:** only in the `argc == 2` branch, at `0x100000670`. Source `0x10000162c`, length `0x5e` (94), seed `0x77`.

**Decoded config:**

```text
host=github.com;path=/;dns=example.com;campaign=operation-tidepool;agent=restlessotter-lab/3.0
```

**Field offsets (in `struct ro_cfg`, from the source):** `host` at `+0x00`, `path` at `+0x40`, `dns` at `+0xa0`, `campaign` at `+0xe0`, `agent` at `+0x120`. Each field is 64 bytes except `path` (96 bytes). Offsets are from the source; not checked in the disassembly.

**Values:**
- `host` = `github.com`
- `path` = `/`
- `dns` = `example.com`
- `campaign` = `operation-tidepool`
- `agent` = `restlessotter-lab/3.0`

**Printed at runtime:** No. The config is never written to stdout (`RO_VERBOSE` is 0 by default, and the Makefile does not set it).

**Expected tags:** Decoder, key stream, blob address, and values are **[Code]**. Whether the sandbox shows the lookups is **[Sandbox]**.

---

## Finding 2: Network activity

**Order in `main` (only when `argc == 2`):**
1. DNS probe on `cfg.dns` (`example.com`): `getaddrinfo`, no connection.
2. DNS probe on `cfg.host` (`github.com`): `getaddrinfo`, no connection.
3. Phone-home to `cfg.host` on the port: `getaddrinfo`, then `socket` and `connect` for each address until one connects, then `send`, then `recv`.

The source has three `getaddrinfo` call sites, all inlined into `_main` (`0x1000009e0`, `0x100000b54`, `0x100000bd8`). Students will see these as calls in `_main`, not as named helpers.

- **DNS helper:** `_ro_dns_probe`, which calls `getaddrinfo`. Hostnames in order: `example.com`, `github.com`.
- **Connection helper:** `_ro_connect_first`, which calls `getaddrinfo`, then `socket` and `connect` for each address in turn.
- **Hints struct:** `ai_family = AF_UNSPEC (0)`, `ai_socktype = SOCK_STREAM (1)`. So the protocol is TCP, with IPv4 or IPv6 allowed. Source-verified; the hints struct itself was not traced in the disassembly.
- **Port:** `80`, decoded from the 2-byte blob at `0x10000168a` (seed `0x24`).
- **Timeouts:** None. The binary does not import `setsockopt`.
- **Request text:** built from four blobs, with `cfg.path` and `cfg.host` and `cfg.agent` inserted:

  | Piece | Blob address | Length | Decoded |
  |---|---|---|---|
  | 1 | `0x1000016e1` | 4 | `GET ` |
  | 2 | `cfg.path` | | `/` |
  | 3 | `0x1000016e5` | 17 | ` HTTP/1.0\r\nHost: ` |
  | 4 | `cfg.host` | | `github.com` |
  | 5 | `0x1000016f6` | 14 | `\r\nUser-Agent: ` |
  | 6 | `cfg.agent` | | `restlessotter-lab/3.0` |
  | 7 | `0x100001704` | 23 | `\r\nConnection: close\r\n\r\n` |

  Full request:

  ```
  GET / HTTP/1.0
  Host: github.com
  User-Agent: restlessotter-lab/3.0
  Connection: close

  ```

- **Response:** up to 256 bytes are read and then discarded. Nothing is printed.

**Failure paths (all silent):**

| Failure | What the program does |
|---|---|
| `getaddrinfo` fails in a DNS probe | Returns. Prints nothing. |
| `getaddrinfo`, `socket`, or `connect` fails in `_ro_connect_first` | Tries the next address. If none connects, returns -1 and the phone-home step does nothing. Prints nothing. |
| `send` fails | Closes the socket and returns. Prints nothing. |
| `recv` returns nothing | The result is ignored. Prints nothing. |

**Output on success:** None from the network steps. The only visible output on a run with one argument is the banner, then the ticket result.

**Expected tags:** Hostnames, request text, port, and "no timeouts" are **[Code]**. Whether the connection succeeds in the sandbox is **[Sandbox]**.

**Recorded Future (not yet looked up):** Results depend on the live service. Run the lookups yourself before class and record them here. Expected: `example.com` is a reserved documentation domain (RFC 2606), and `github.com` is a widely used shared service. The campaign and agent values are classroom labels, not infrastructure.

---

## Finding 3: Anti-debugging check

- **Code:** inlined into `_main`. It calls `getpid` at `0x100000c08`, then `sysctl` at `0x100000c28` with MIB `{CTL_KERN (1), KERN_PROC (14), KERN_PROC_PID (1), pid}`.
- **Bit tested:** `kp_proc.p_flag & 0x800` (`P_TRACED`). The disassembly tests bit 11 with `tbz w8, #0xb` at `0x100000c34`; when the bit is clear it branches to the not-traced path at `0x100000d54`. If `sysctl` fails, the check also takes the not-traced path.
- **Call site:** In `_main`, only in the `argc == 2` branch, after the DNS and phone-home steps.
- **Traced output:**

  ```text
  [!] debugger detected. RO{SLEEPY_DECOY}
  ```

  The decoy text is the blob at `0x1000016a3`. The traced branch returns 2 and the ticket check is skipped.
- **Decoy strings:** `RO{SLEEPY_DECOY}` at `0x1000016a3` (not the real flag). `[!] debugger detected. ` at `0x10000168c`.

**Expected tags:** The `sysctl` call, the MIB, the bit, and the output are **[Code]**. Whether the sandbox triggers the traced branch is **[Sandbox]**. The sandbox normally doesn't attach a debugger, so the branch should not run. Students should predict that and check it against the report.

---

## Finding 4: Ticket check

- **Length:** The ticket must be exactly 16 bytes (`cmp x0, #0x10` at `0x100000d60`).
- **Per-byte transform:** for position `i` with input byte `c`:

  ```
  v = c ^ ((13 * i + 0x41) & 0xff)
  v = (v + 7 * i + 0x23) & 0xff
  v = rol8(v, (i % 5) + 1)
  compare v with SERIAL[i]
  ```

  The disassembly computes `7*i` as `8*i - i`, which is the same value.

- **Serial table:** 16 bytes at `0x10000171b`:

  ```text
  70 c4 82 56 8c 26 34 21 fd ab d7 0c 3b 85 49 7d
  ```

- **Rolling checksum:** starts at `0x6d2b79f5`. For each passing byte `v`, `acc = ((acc ^ v) * 0x045d9f3b + i + 0x1337) & 0xffffffff`. The source's final compare value is `0x7c539eb9`. The compiled compare is `0x7c538b83` (see the checksum note at the top): the compiler folded the last iteration's index and the `0x1337` constant into the constant, and `0x7c539eb9 - 0x1336 = 0x7c538b83`.
- **Correct ticket:** `TIDEPOOL-MAC-026`. Solving the transform by reversal gives exactly this ticket, the only value that passes all 16 steps. Forward-checking it reproduces the table and the checksum.
- **Solving by reversal:** For each position, take the table byte, rotate right by `(i % 5) + 1`, subtract `7 * i + 0x23`, then XOR with `13 * i + 0x41`. Each position has exactly one answer.

**Output** (only in the `argc == 2` branch, when not traced):
- Correct: `\n[+] ticket accepted.\n`, then the flag (Finding 5), then a newline. Exit code 0.
- Wrong: `\n[-] incorrect ticket. RO{SLEEPY_DECOY}\n`. Exit code 0. The decoy is printed on a wrong ticket too, so it is not evidence of a debugger.

**Expected tags:** Transform, table, checksum, and ticket are **[Code]**.

---

## Finding 5: Flag

- **Blob:** 21 bytes at `0x10000172b`. Key-stream seed `0x9b`.
- **Per-byte calculation** (the decoder's key stream with seed `0x9b`):

  ```
  mask = ((ticket[i % 16] + 31 * i + 0xa7) & 0xff) ^ key[i]
  flag[i] = blob[i] ^ mask
  ```

  The disassembly computes `31*i + 0xa7` as `31*i - 0x59`, which is the same value mod 256.
- **Ticket bytes used:** `ticket[i % 16]`. The flag depends on the ticket, so a wrong ticket gives non-text output. (A wrong ticket never reaches this code, so the student's "wrong ticket" result is their own calculation.)
- **Decoded flag:** `RO{MAC_OTTER_CURRENT}` (21 characters, starts with `RO{`, ends with `}`).
- **Output on success:** the `[+] ticket accepted.` line, then `RO{MAC_OTTER_CURRENT}` on its own line.

**Expected tags:** Blob, seed, and calculation are **[Code]**. The flag value was computed statically from those, not from a run.

---

## What the sandbox should show

| Run | Expected behavior |
|---|---|
| No argument | Banner, then `usage: <name> <ticket>`. Exit code 1. **No network activity.** No flag. |
| One argument, not traced, wrong ticket | DNS lookups for `example.com` and `github.com` (the second probe, and again from the phone-home step). TCP connection to `github.com:80`, then `GET /` with `User-Agent: restlessotter-lab/3.0`. No network output printed. Ticket check runs and prints the decoy. Exit code 0. |
| One argument, traced | Same network activity. Prints `[!] debugger detected. RO{SLEEPY_DECOY}`. Ticket check skipped. Exit code 2. |
| Correct ticket `TIDEPOOL-MAC-026` | Network activity, then `[+] ticket accepted.` and `RO{MAC_OTTER_CURRENT}`. Exit code 0. |

Notes:
- A sandbox without network access makes `getaddrinfo` fail. The program prints nothing for that, so students will see no difference in stdout. They need the sandbox's network log to see the attempt.
- The debugger check normally doesn't trigger in a standard sandbox.
- Because the network steps are silent, the sandbox's network capture is the only evidence of them.
- The sandbox may cache DNS answers, so `github.com` may show one lookup rather than two.

---

## IOCs (expected answers)

| Type | Value | Source | Tag |
|---|---|---|---|
| Domain | `github.com` | config `host` (blob `0x10000162c`) | Code |
| Domain | `example.com` | config `dns` (blob `0x10000162c`) | Code |
| Hostname | `github.com` (phone-home, port 80) | config `host` | Code |
| HTTP request | `GET /` with `Host: github.com`, port 80 | request pieces at `0x1000016e1`–`0x100001704` | Code |
| User agent | `restlessotter-lab/3.0` | config `agent` | Code |
| Campaign label | `operation-tidepool` | config `campaign` | Code |
| Port | `80` | 2-byte blob at `0x10000168a` | Code |

**Shared services:** `github.com` and `example.com`. Not malicious infrastructure. **Classroom labels:** `operation-tidepool` and `restlessotter-lab/3.0`. These are useful only for lesson pivots.

---

## MITRE ATT&CK mapping (expected answers)

Verify these IDs against the ATT&CK version you use before class. They were not checked against the live ATT&CK site while preparing this key.

| Behavior | Expected technique | Evidence | Tag |
|---|---|---|---|
| Config decrypted at runtime | T1140 Deobfuscate/Decode Files or Information | decoder at `0x100001418`, config call at `0x100000670` | Code |
| DNS lookups and HTTP request | T1071.001 Application Layer Protocol: Web Protocols | `getaddrinfo` call sites; `GET /` request pieces | Code |
| Debugger check via `sysctl` | T1622 Debugger Evasion | `sysctl` at `0x100000c28`, `tbz` on bit `0x800` at `0x100000c34` | Code |
| Ticket validation | No clean technique. Treat as a crackme check and don't force a mapping. | ticket loop at `0x100000d68`–`0x100000e14` | Inferred |
| Flag decrypted at runtime | T1140 Deobfuscate/Decode Files or Information | flag loop at `0x100001264`, seed `0x9b` | Code |

Students may also argue for T1497 (Virtualization/Sandbox Evasion) for the debugger check. Accept it if they justify it.

---

## Analyst report: what good looks like

- **Summary:** The sample is a benign macOS crackme. With one argument, it decrypts its config, does two DNS lookups and one HTTP request to `github.com`, checks for a debugger with `sysctl`, and reveals a flag only when a 16-character ticket passes a per-byte transform and a checksum. With no argument, it prints a usage line and exits. The decoded flag is a classroom reward, not a real goal.
- **Detection ideas:** Good answers name specific, reliable indicators, such as the `GET /` request with the `restlessotter-lab/3.0` user agent, or the `sysctl` `P_TRACED` check together with the decoy string. Fragile answers rely on the DNS lookups or on `github.com` alone, since many legitimate programs make those. Good answers may also note that the program makes its network calls silently, so stdout gives no hint of them.
- **Sandbox comparison:** Good answers say which static findings the sandbox confirmed. They explain gaps, such as the traced branch not running, or the network steps failing without outbound access. They note that a no-argument run should show no network activity.

---

## Grading rubric (suggested)

| Area | Points | Key evidence |
|---|---|---|
| 1. Config | | Decoder, seed, and the five decoded values |
| 2. Network | | Argument count gate, order of DNS hosts, port 80, request text, silent failures |
| 3. Anti-debug | | `sysctl`, `P_TRACED`, decoy output, call position |
| 4. Ticket | | `TIDEPOOL-MAC-026`, checksum (accepting the compiled `0x7c538b83`), serial table |
| 5. Flag | | `RO{MAC_OTTER_CURRENT}`, seed `0x9b`, ticket dependence |
| Labeling | | Helpers and data labeled, names describe purpose |
| Confidence tags | | Each answer tagged correctly |
| Predictions | | Written before the sandbox, compared after |
| IOC table | | Complete, with sources |
| ATT&CK mapping | | Plausible IDs with evidence |
| Analyst report | | Three paragraphs, supported by the findings |

Set point values before grading. The rubric above does not include them.

---

## Notes for the instructor

- **Before class, rerun the sandbox.** The binary's hash matches a fresh macOS `make release` build of the current source. Rerun the sandbox against this file before class, and if you ever rebuild with different flags, update the hash in all four docs.
- **Re-check in Ghidra.** The addresses here came from static parsing and disassembly of the shipped file, not from Ghidra. Confirm `_main` at `0x1000005b8`, the decoder at `0x100001418`, the blobs above, and the `sysctl` `0x800` test in the Ghidra project before grading.
- **Decide on `_main`.** See the build note at the top.
- **Recorded Future lookups.** Not run while preparing this key. Run `github.com` and `example.com` yourself and record what the service returns.
- **Handout hash.** `student.md` asks students to compare the SHA-256 with the handout. No `SHA256SUMS` file is in this folder, so the handout must supply the hash.
- **Sandbox support for Mach-O arm64** must be confirmed before assigning the dynamic steps.
- **Verbose-only strings are absent.** Ten blobs used only under `RO_VERBOSE` (`S_RESOLVE`, `S_DOTS`, `S_RESOLVED`, `S_FAILED`, `S_PHONE`, `S_GOT`, `S_BYTES`, `S_NO_RESPONSE`, `S_SOCKET_FAILED`, `S_CONNECT_FAILED`) are not in the binary. The compiler dropped them. Students will not find them, which is expected.
- **Earlier build (MD5 `5901c284...`):** the previous version of this key said the config, DNS, phone-home, and anti-debug steps changed to run only with one argument, and that the config is no longer printed. Those statements were carried over from the old key and were not re-verified against the old binary, which is not in this folder. The current source and binary are consistent with them.

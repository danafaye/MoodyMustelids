# grumpyferret: Instructor Answer Key

Use this with `student.md`. Static answers come from `grumpyferret.c` and `instructor_youtube/youtube_stage.py`, and were checked against the data tables in the current binary. Sandbox expectations describe what the sample should do in the class sandbox. Verify them against an actual sandbox run before class.

> **Build note:** The binary on disk has MD5 `82e03f94a0494efe4396bc9ed92cd29c`. The Ghidra project was re-imported to this build, but data labels set earlier (config, key, flag, serial, stage, `-c` argument) may need to be re-applied. Check the project before grading.
>
> **Source/binary mismatch:** The usage message differs. `grumpyferret.c` prints `"\nusage: %s\n"` with `argv[0]`. The binary contains `"\nusage: %s <serial>\n"`. The binary is the reference for students, so either update the source to match or accept the difference.

---

## Finding 1: Embedded config

- Config blob: 125 bytes, at `CONFIG_BLOB` in `grumpyferret.c`. In the binary it is the array the decoding loop reads from `main`.
- Key: `13 37 c0 de` (4 bytes)
- Decode: `plain[i] = blob[i] ^ key[i % 4]`, for i in 0..124
- Decoded config:

  `ens=definitely-not-c2.eth;ip=203.0.113.7;domain=c2.grumpyferret-demo.invalid;safe=example.com;campaign=operation-ghidra-snack`

- Key/value pairs:
  - `ens` = `definitely-not-c2.eth`
  - `ip` = `203.0.113.7` (TEST-NET-3 documentation range; not routed)
  - `domain` = `c2.grumpyferret-demo.invalid` (`.invalid` is reserved and never resolves)
  - `safe` = `example.com` (reserved for documentation)
  - `campaign` = `operation-ghidra-snack`
- `GF_OFFLINE`: when set, `main` skips the three DNS probes and the `api.ipify.org` request. The YouTube stage (Finding 3) still runs.

**Expected tags:** Decoded values and `GF_OFFLINE` behavior are **[Code]**. Whether the sandbox shows the lookups is **[Sandbox]**.

**Grading notes:** The current build does not print the config, so students get the values only by reverse engineering.

---

## Finding 2: Network activity

- DNS lookups (silent, results not printed), in order:
  1. `domain` (`c2.grumpyferret-demo.invalid`)
  2. `ens` (`definitely-not-c2.eth`)
  3. `safe` (`example.com`)
- `ip` from the config is never used for a connection. It is only decoded.
- Public-IP service: `api.ipify.org`
- Protocol and port: TCP, port 80, IPv4 (`AF_INET`)
- Timeouts: 3 seconds on send and receive (`SO_SNDTIMEO`/`SO_RCVTIMEO`). The 16-byte struct is `tv_sec = 3, tv_usec = 0`.
- Request sent:

  ```
  GET / HTTP/1.0
  Host: api.ipify.org
  Connection: close
  ```

  The response is read into a 256-byte buffer and discarded.
- Failure paths: every failure returns silently. The build prints nothing on DNS, socket, connect, write, or read failure.
- Network code is inside `main`. `gf_dns_probe` is the only helper in this block, and it calls `getaddrinfo` and `freeaddrinfo`.

**Expected tags:** Hostnames, request text, and timeouts are **[Code]**. Whether the connection succeeds in the sandbox is **[Sandbox]**.

**Recorded Future:** Results depend on the live service. Check the lookups yourself before class. Expected: `.invalid` and `example.com` have no malicious history. `definitely-not-c2.eth` and `203.0.113.7` may return nothing.

---

## Finding 3: Hidden classroom stage

- The stage always runs, whether or not `GF_OFFLINE` is set and whether or not the serial is correct.
- Interpreter: `/usr/bin/python3`
- Arguments: `python3 -c <script>`. The `-c` is a literal `"-c"` string.
- Buffer: `GF_YT_STAGE` in `youtube_stage.h`, 9912 bytes (matches `instructor_youtube/youtube_stage.py`). Decode with `CONFIG_KEY[i % 4]`. The decoded script is `instructor_youtube/youtube_stage.py`.
- Script behavior:
  - Video ID: `4ok4e0Jvy_4`
  - Comment rule: the comment must have exactly six sentences, each starting with a letter. The first letters, uppercased, must spell `NEWBIE`.
  - Flag URL: `https://gist.githubusercontent.com/danafaye/8100c9037cdd799741c405d7b34a37f2/raw/710fef32e945a23fe1482de52dd446e54d1de7d8/newbie_notes.txt`
  - Format: the downloaded text must match `GF{[A-Z0-9_]{1,100}}`.
- Output control: when the serial is not accepted, the child process redirects stdout and stderr to `/dev/null`. The flag prints only when `solved` is true.
- Text flag: `GF{YOUTUBE_COMMENT_TO_GITHUB_FLAG}`, fetched from the public Gist `newbie_notes.txt` (the pinned revision in the stage). Re-fetch from the classroom network before class.

**Expected tags:** Interpreter, arguments, decoding, video ID, and rule are **[Code]**. The flag URL and its format are **[Code]**. Whether the stage's network requests appear is **[Sandbox]**.

**Grading notes:** The comment is the only input the stage uses. Students with network access can read the comment on YouTube and check the six first letters themselves.

---

## Finding 4: Anti-debugging check

- File read: `/proc/self/status`
- Line prefix: `TracerPid:`
- Traced when the parsed PID after the prefix is nonzero.
- Calls in `main`:
  1. The first call sets `solved`, and it is skipped if the program is being traced.
  2. The second call happens after the argument check. When traced, it prints:
     - `backup_flag=GF{NICE_TRY}`
     - `GF{TRY_AGAIN_LOSER}`

     and returns 1.
- Decoy strings: `GF{TRY_AGAIN_LOSER}`, `GF{404_FLAG_NOT_HERE}`, `backup_flag=GF{NICE_TRY}`. None of them are the real flag.
- Under a tracer: the program prints the traced message instead of checking the serial. `solved` is 0, so the stage's output is hidden.

**Expected tags:** The file read, prefix, and both branches are **[Code]**. Whether the sandbox triggers the traced branch is **[Sandbox]**.

---

## Finding 5: Serial and flag

- Serial length: 12 characters
- Check: `((input[i] ^ MAGIC[i]) + i) & 0xFF == TARGET[i]`
- `MAGIC` (ASCII): `MCP-RF-GHIDR`
- `TARGET` (hex): `0a 0c 1b 6c 04 0c 71 09 22 24 0b 11`
- Serial: **`GHIDRAFERRET`**
  - Check: `(0x47 ^ 0x4d) + 0 = 0x0a`, `(0x48 ^ 0x43) + 1 = 0x0c`, and so on for all 12 bytes.
- Flag key (5 bytes): `9c 5a e1 03 7f`
- Flag blob: 21 bytes, `db 1c 9a 47 2d c9 14 aa 5c 3e cf 05 a0 5c 39 d9 08 b3 46 2b e1`
- Decoded flag: **`GF{DRUNK_AS_A_FERRET}`**
- Correct serial output:

  ```
  [+] serial accepted.
  GF{DRUNK_AS_A_FERRET}
  ```

  The YouTube stage also prints its output at this point (Finding 3).
- Wrong serial output: `[-] incorrect serial. GF{404_FLAG_NOT_HERE}`

**Expected tags:** The check, target, key, and flag are **[Code]**.

---

## What the sandbox should show

The sandbox is the only place students see dynamic behavior. Run the sample once before class and fill in the actual results. Expected behavior, from the source:

| Run | Expected behavior |
|---|---|
| No `GF_OFFLINE`, no serial | DNS queries for `c2.grumpyferret-demo.invalid`, `definitely-not-c2.eth`, `example.com`. HTTP request to `api.ipify.org` port 80, if the sandbox allows it. Python process started. Requests to `youtube.com` and `gist.githubusercontent.com`. Usage message. No flag. |
| `GF_OFFLINE=1`, no serial | No DNS queries or `api.ipify.org` request from the program itself. Python process and YouTube/Gist requests still happen. |
| Wrong serial | Same as above, and the wrong-serial message. The stage's output is hidden. |
| Correct serial | The flag and the stage's output are shown. |

Notes for the sandbox results:
- A sandbox without network access makes `getaddrinfo` fail. Expect DNS failures and no connection to `api.ipify.org`. The program prints nothing for those failures.
- The debugger check looks at `TracerPid`. Standard sandboxes don't trace the sample, so the traced branch probably won't run. Students should predict that and check it against the report.
- The YouTube stage needs network access to `youtube.com` and `gist.githubusercontent.com`. Without it, the stage fails silently, so the flag can't be fetched.

---

## IOCs (expected answers)

| Type | Value | Source | Tag |
|---|---|---|---|
| Domain | `c2.grumpyferret-demo.invalid` | config `domain` | Code |
| Domain | `definitely-not-c2.eth` | config `ens` | Code |
| Domain | `example.com` | config `safe` | Code |
| Hostname | `api.ipify.org` | string in `main` | Code |
| HTTP request | `GET /` with `Host: api.ipify.org` | string in `main` | Code |
| IP | `203.0.113.7` | config `ip` (decoded but not used) | Code |
| Video ID | `4ok4e0Jvy_4` | stage script | Code |
| URL | Gist `newbie_notes.txt` (see Finding 3) | stage script | Code |
| Environment variable | `GF_OFFLINE` | `getenv` in `main` | Code |
| File read | `/proc/self/status` | check function | Code |

---

## MITRE ATT&CK mapping (expected answers)

Verify these IDs against the ATT&CK version you use before class. They are the expected answers, not a verified list.

| Behavior | Expected technique | Evidence | Tag |
|---|---|---|---|
| Config decoded with XOR at runtime | T1140 Deobfuscate/Decode Files or Information | config loop in `main` | Code |
| `GF_OFFLINE` environment check | T1480.001 Execution Guardrails: Environmental Keying | `getenv("GF_OFFLINE")` | Code |
| DNS lookups and HTTP request to a public IP service | T1071.001 Application Layer Protocol: Web Protocols | `getaddrinfo`, `GET /` string | Code |
| Python script run from memory | T1059.006 Command and Scripting Interpreter: Python | `execl("/usr/bin/python3", ...)` | Code |
| Video comment and Gist used to find a flag URL | T1102.001 Web Service: Dead Drop Resolver | stage script | Code |
| `/proc/self/status` tracer check | T1622 Debugger Evasion | `fopen("/proc/self/status")` | Code |

Students may also argue for T1497 (Virtualization/Sandbox Evasion) for the `GF_OFFLINE` check. Accept it if they justify it, since the variable is one way to detect an analysis environment.

---

## Analyst report: what good looks like

- **Summary:** The sample is a benign crackme that mimics malware. It decodes a config, checks its environment, sends a public-IP request, runs an embedded Python stage, and gates a flag behind a serial and an anti-debugging check. The decoded flag is only a classroom reward, not a real goal.
- **Detection ideas:** Good answers name specific, reliable indicators, such as the `GET /` request to `api.ipify.org`, or the `/proc/self/status` read combined with a Python child process. Fragile answers rely on the decoy strings or the public-IP request alone, since a legitimate program could make either.
- **Sandbox comparison:** Good answers say which static findings the sandbox confirmed, and which it didn't (for example, the traced branch, or the network requests if the sandbox has no network). They explain the difference, such as "the sandbox doesn't trace the process" or "no outbound network."

---

## Grading rubric (suggested)

| Area | Points | Key evidence |
|---|---|---|
| 1. Config | | Decoded string and key/value pairs, `GF_OFFLINE` effect |
| 2. Network | | Three DNS hosts, `api.ipify.org` request, failure behavior |
| 3. Stage | | Interpreter, `-c` script, video ID, `NEWBIE` rule, flag URL |
| 4. Anti-debug | | `TracerPid`, two call sites, decoy strings |
| 5. Serial and flag | | `GHIDRAFERRET`, `GF{DRUNK_AS_A_FERRET}` |
| Labeling | | Helpers and data labeled, names describe purpose |
| Confidence tags | | Each answer tagged correctly |
| Predictions | | Written before the sandbox, compared after |
| IOC table | | Complete, with sources |
| ATT&CK mapping | | Plausible IDs with evidence |
| Analyst report | | Three paragraphs, supported by the findings |

Set point values before grading. The rubric above does not include them.

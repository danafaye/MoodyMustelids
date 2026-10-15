# AI-Powered Malware Analysis with Recorded Future, Ghidra, and MCP: Student Handout

**Session:** October 16, 2026, Recorded Future DC office
**Format:** Six one-hour blocks mixing short explanations, demonstrations and hands-on work.

You will start in the Recorded Future Sandbox to see what the lab files do when they run. You will then use Ghidra with AI through MCP to find the code behind those observations. After the three core exercises, you will return to Recorded Future Malware Intelligence to search for more context. You will explain a file's behavior and support each claim with sandbox, code and intelligence evidence. Check every AI answer against the function, the data or the search result it refers to.

The core exercises are Grumpy Ferret, Soggy Badger and Restless Otter. Vexed Wolverine is an optional bonus challenge.

No reverse-engineering experience is assumed. You work in SOC triage: sandbox reports, DNS and HTTP events, IOCs and alert context. This handout gives you the vocabulary, the evidence rules and the files. It does not give answers. Work out the answers in the lab.

## Schedule

| Hour | Focus | What you produce |
| --- | --- | --- |
| 1 | Recorded Future Sandbox kickoff | A behavior timeline, an initial evidence table and questions for code analysis |
| 2 | Grumpy Ferret in Ghidra: orientation and execution flow | A labeled execution flow connected to sandbox observations |
| 3 | Grumpy Ferret in Ghidra: configuration and validation | Decoded configuration, the serial logic you recovered, and checked findings |
| 4 | Soggy Badger in Ghidra | A verified stack string, an explanation of the hash check, and one host artifact or anti-debug check |
| 5 | Restless Otter in Ghidra | Decoded runtime configuration, a verified anti-debug check, and the link between the ticket and the decryption |
| 6 | Recorded Future Malware Intelligence and wrap-up | Intelligence pivots based on verified findings and a concise analysis handoff |

The blocks include short breaks. Lunch is separate. Your instructor may shorten a block; the minimum outcomes below still apply.

## Key terms

| Term | Plain meaning |
| --- | --- |
| Sandbox | An isolated environment that runs a file and records what it does: processes, DNS lookups, HTTP requests, files and registry changes. |
| Ghidra | A free reverse-engineering tool. Its decompiler rewrites machine code as C-like pseudocode. |
| Machine code / disassembly | The raw CPU instructions in a program, shown in assembly-like form. |
| MCP (Model Context Protocol) | The connector that lets the AI assistant query the open Ghidra project. AI output is a lead until you check it in Ghidra. |
| Function address | Where a function sits in the program, written in hex (for example `0x00136bda`). |
| Cross-reference (xref) | A record of where a function or data item is called or used. "Show the callers" means list those places. |
| Argument | A value passed into a function. "Argument origin" means where that value was computed or read. |
| Consumer | The code that uses a value after it is decoded or computed. |
| Release binary | The compiled program you analyze. You get the binary, not the source code. |
| Checkpoint | A saved Ghidra project state with labels and notes, so a group can start from a known point. |
| Fixture | Made-up input data that stands in for a live service. Any result from a fixture is labeled synthetic. |
| Decoy | A fake value or path placed to mislead an analyst. It looks important but leads nowhere. |
| Configuration | The settings a sample stores internally, such as a server name or install path. Often hidden with simple encoding. |
| XOR | Bitwise exclusive-or. A reversible scramble: applying the same key a second time restores the original byte. |
| Repeating key | A short key applied across a run of bytes, cycling through the key. |
| mod 256 / mod 2^32 | Keep a number within one byte (0 to 255) or one 32-bit value. |
| ROR13 / ROR32 | Rotate right: shift the bits of a 13- or 32-bit value to the right and wrap the bits that fall off back onto the left. |
| Anti-debugging | Code that checks whether a debugger is attached and changes behavior if one is. |
| TracerPid (Linux) | A field in `/proc/self/status`. A non-zero value means a debugger is attached. |
| sysctl / P_TRACED (macOS) | `sysctl` queries kernel information. `P_TRACED` is the process flag the kernel sets when a debugger attaches. |
| PEB (Windows) | The Process Environment Block, an internal Windows data structure that includes a "being debugged" flag. |
| Stack string | Text the program builds one character at a time in memory, so it does not appear in a plain strings scan. |
| Mutex | A named marker that stops a second copy of a program from running. |
| Registry marker | A value written to the Windows registry, used here as a temporary host artifact that is later removed. |
| Imported DLL / API | Windows libraries (DLLs) and the functions they provide. The import list shows what a program calls. |
| PE / ELF / Mach-O | Executable formats: PE is Windows, ELF is Linux, Mach-O is macOS. |
| Byte order (endianness) | The order in which the bytes of a multi-byte value are stored. |
| Strings scan | Running `strings` on a file to list readable text. It finds plain text but not text built in memory. |
| Virtual machine (in Vexed Wolverine) | A small custom interpreter that runs the program's own hidden instructions (bytecode). |
| C2 (command and control) | A server that malware contacts to receive instructions or send data. |
| Indicator | A piece of evidence that can be searched for: a domain, IP address, file hash or string. |
| IOC (indicator of compromise) | An indicator tied to observed or recovered activity, recorded with its type, value, source, status and label. |
| Defanging | Writing a domain or URL so it cannot be clicked or resolved by accident, for example `example[.]com` or `hxxp://`. Use it in every shared handoff. |
| Shared service | A legitimate public service the code contacts, such as a public IP-check API. It is context for the code's behavior, not a blocklist entry. |
| Pivot | Moving from one indicator to related infrastructure, files or reports. |
| Entity | Something Recorded Future tracks, such as a domain, IP, file hash, malware family or threat actor. |
| No match | The platform has no record for that query. It does not establish that a value is safe. |
| Attribution | Linking activity to a named actor or family. Shared infrastructure alone does not prove it. |

## Evidence rules

Use the shared evidence template (`evidence_template.md`) for every finding. Record the finding, its source, the reference or address, its status, the operation outcome, your confidence and the reason for it, and the next question.

**Sources:** Sandbox observation, Ghidra/code, Malware Intelligence, or synthetic fixture.

**Status:**
- **Observed:** recorded directly in an identified sandbox run or runtime capture. Name the environment, report or capture reference, and date.
- **Attempted:** evidence shows an operation was started. Record its outcome separately: succeeded, failed (with the error), timed out or unknown. A DNS request with no answer is an attempt, not a confirmed connection.
- **Decoded:** output you reproduced from bytes and a transformation recovered from code, without running the sample. Cite the data and decoder locations.
- **Inferred:** an interpretation supported by code or other evidence but not yet reproduced or observed. State the basis and the uncertainty.
- **Unverified:** a claim, from a source or from AI, whose support you have not checked.

**Confidence needs a reason.** For example: "a checked call site and a matching event." A fluent AI explanation or a platform headline alone does not raise confidence.

**Fixture results** carry the source tag `synthetic fixture`. They show behavior with supplied inputs and never establish a live request or download.

**IOC rows** use the same template, with two more rules:
- Type is one of: domain, IP, URL or request line, file name, hash, registry key, mutex, user-agent or configuration string.
- Every row has a label: `malicious-candidate` (not yet proven), `classroom decoy` (a reserved or documentation value built into the exercise), or `shared service` (a legitimate public service). Only `malicious-candidate` rows are candidates for later Malware Intelligence searches.

Defang every domain and URL in shared handouts.

## Paired practice

Partner A operates the tools and Partner B challenges claims and records evidence. Switch roles after five minutes. If your station has only one MCP connection, share it.

| Hour | Paired task | Required output |
| --- | --- | --- |
| 1 | Choose a DNS event and a process or HTTP event from the report; separate what was recorded from your interpretation | Two evidence rows and one question for code analysis |
| 2 | Trace one sandbox network observation to an API call and find where its argument comes from | Event reference, call-site address and argument-source explanation |
| 3 | Reproduce one configuration field and follow it into its consumer | Decoder and data references, the recovered field, and the consuming call |
| 4 | Reconstruct one stack string and explain where it is used | Bytes in buffer-offset order, the builder address and the consumer |
| 5 | Recover two configuration fields and verify one consumer or the anti-debug gate | Decoded fields and supporting addresses, with runtime status kept separate |
| 6 | Look up one recovered network value and one contrasting artifact | Exact queries, actual outcomes, references and a revised interpretation |

At the ten-minute mark, pairs report what they established and what is still open.

## Working with AI

- The AI assistant is a lead generator. Verify each function name, address, role and value in Ghidra before you use it.
- Do not rename, patch or edit Ghidra annotations until a claim is verified.
- Ask for addresses and references, and for a statement of what is confirmed and what is inferred.
- A string or a name that sounds important is not proof of role. Trace its references and the branch that uses it.

## Exercises

### Grumpy Ferret (Hours 2–3, Linux)

Files: `grumpyFerret/grumpyFerret`, `grumpyFerret/student.md` (step-by-step guide) and `grumpyFerret/README.md`.

- Map the main execution path and connect at least one sandbox DNS or HTTP event to the code that makes it.
- Recover the configuration and explain how the value is decoded.
- Explain the serial check at a high level and locate the anti-debug gate.
- Label each finding as observed in sandbox, recovered from code, or present only as a string.
- Minimum IOC output: at least one configured or observed domain or IP, and the HTTP request line, each with its source and label.

The optional final stage reads a public web page and downloads a text resource. It runs on every launch if Python 3 is available, but its output, including any text flag, is shown only after the correct serial. Record what it attempted and what it actually retrieved, and keep those separate.

### Soggy Badger (Hour 4, Windows)

Files: `soggyBadger/soggyBadger.exe`, `soggyBadger/student.md` (step-by-step guide) and `soggyBadger/README.md`.

- Reconstruct one stack-built string and trace its consumer.
- Explain the hash check: what the routine does to each input byte, and how you would test candidate names against its comparison value.
- Identify one host artifact (mutex, or registry key and value) or one anti-debug check.
- Minimum IOC output: the mutex name, and the registry key and value, each with its code address or report reference.

### Restless Otter (Hour 5, macOS)

Files: `restlessOtter/restlessOtter`, `restlessOtter/student.md` (step-by-step guide) and `restlessOtter/README.md`. It is arm64 only and runs on Apple Silicon Macs.

- Locate the string decoder and recover two configuration fields.
- Find the sysctl anti-debug check and explain what it gates.
- Verify the length requirement and the per-character comparison in the ticket check.
- Minimum IOC output: the recovered host and DNS entries, and the HTTP request, each with its shared-service label and the address of the decoded configuration.

### Vexed Wolverine (bonus only)

Files: `vexedWolverineBonus/` (`student.md`, README, Linux build, checksum). See the README there. Start only after the core exercises. Document your validation path, and verify AI findings against functions and data. A listing of endpoint strings, each classified as a decoy, is enough for an IOC section; this challenge has no network activity.

## Hour 6: Malware Intelligence

Choose two values from your verified findings. Use the exact original value and note where it was found in the code. For each one:
- Record the exact query, the search method, the time, and the outcome.
- Separate **no record found**, **unsupported query**, **access denied** and **request failure**.
- Explain what the result does and does not establish about the sample.

A shared host or IP does not establish threat actor or malware-family attribution. A no-match result does not establish that a value is safe.

Finish with a handoff: sample identity, behavior, runtime and code evidence, your IOC table, intelligence outcomes, changes to your assessment, limits, and one next step. Your partner checks one code reference and one intelligence reference.

## Files in this handout

- `grumpyFerret/` – Grumpy Ferret release binary, `student.md` and README
- `soggyBadger/` – Soggy Badger Windows executable, `student.md` and README
- `restlessOtter/` – arm64 Mach-O `restlessOtter`, `student.md` and README
- `vexedWolverineBonus/` – optional bonus challenge (Linux build, `student.md`, README, checksum)
- `evidence_template.md` – one-page evidence and IOC template
- `SHA256SUMS` – checksums for the handed-out binaries

Verify the checksums before you start, so you know you are analyzing the release build:

```sh
sha256sum -c SHA256SUMS
```

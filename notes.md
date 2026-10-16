# AI-Powered Malware Analysis with Recorded Future, Ghidra, and MCP: Class Outline

**Instructor:** Dana Behling, Insikt Group  
**Planned session:** October 16, 2026, Recorded Future DC office  
**Format:** Six one-hour blocks combining short explanations, demonstrations and hands-on work.

We’ll start in Recorded Future Sandbox to see what the lab files do when they run and to capture questions for deeper analysis. We’ll then move into Ghidra and use AI through MCP to investigate the code behind those observations. After analyzing the three core crackmes, we’ll circle back to Recorded Future Malware Intelligence and use verified behavior, decoded configuration and other AI-assisted findings to search and pivot for additional context. Students will explain a file’s behavior and support their findings with sandbox, code and intelligence evidence, checking AI answers against the underlying functions and data.

The class packet includes all four crackme projects. Grumpy Ferret, Soggy Badger and Restless Otter are the three in-class exercises that we plan to cover during the scheduled session. Vexed Wolverine remains a bonus reserve challenge and is not part of the planned completion path for the class; it is for students who finish early or want a take-home extension.

This is a proposed teaching schedule based on the existing class slides and crackme notes. The six hours include short breaks within the blocks; lunch is additional. Confirm the audience’s starting experience and the event’s total time before finalizing the schedule. Send a short pre-class survey (Ghidra use, x86/ELF/Mach-O basics, MCP access) so Hour 2 can drop its orientation if the room is experienced.

## Key terms for this class

The audience works in SOC triage: sandbox reports, DNS and HTTP events, IOCs and alert context. They do not need reverse-engineering experience. The terms below are used throughout; each is written in plain language.

| Term | Plain meaning |
| --- | --- |
| Sandbox | An isolated environment that runs a file and records what it does: processes, DNS lookups, HTTP requests, files and registry changes. |
| Ghidra | A free reverse-engineering tool. Its decompiler rewrites machine code as C-like pseudocode so the logic can be read. |
| Machine code / disassembly | The raw CPU instructions in a program, shown in assembly-like form. |
| MCP (Model Context Protocol) | The connector that lets the AI assistant query the open Ghidra project. AI output is a lead until it is checked in Ghidra. |
| Function address | Where a function sits in the program, written in hex (for example `0x00136bda`). |
| Cross-reference (xref) | A record of where a function or data item is called or used. "Show the callers" means list those places. |
| Argument | A value passed into a function. "Argument origin" means where that value was computed or read. |
| Consumer | The code that uses a value after it is decoded or computed. |
| Release binary | The compiled program students analyze. Students get the binary, not the source code. |
| Checkpoint | A saved Ghidra project state with labels and notes, so a group can start from a known point. |
| Fixture | Made-up input data that stands in for a live service. Any result from a fixture is labeled synthetic. |
| Decoy | A fake value or path placed to mislead an analyst. It looks important but leads nowhere. |
| Configuration | The settings a malware sample stores internally, such as a server name or install path. Often hidden with simple encoding. |
| XOR | Bitwise exclusive-or. A simple reversible scramble: applying the same key a second time restores the original byte. |
| Repeating key | A short key applied across a run of bytes, cycling through the key (byte `i` uses key byte `i mod length`). |
| mod 256 / mod 2^32 | Keep a number within one byte (0 to 255) or one 32-bit value, like an odometer rolling over. |
| ROR13 / ROR32 | Rotate right: shift the bits of a 13- or 32-bit value to the right and wrap the bits that fall off back onto the left. |
| Anti-debugging | Code that checks whether a debugger is attached and changes behavior if one is. |
| TracerPid (Linux) | A field in `/proc/self/status`. A non-zero value means a debugger is attached. |
| sysctl / P_TRACED (macOS) | `sysctl` is the macOS interface for querying kernel information. `P_TRACED` is the process flag the kernel sets when a debugger attaches. |
| PEB (Windows) | The Process Environment Block, an internal Windows data structure that includes a "being debugged" flag. |
| Stack string | Text the program builds one character at a time in memory, so it does not appear in a plain strings scan. |
| Mutex | A named marker that stops a second copy of a program from running. |
| Registry marker | A value written to the Windows registry, used here as a temporary host artifact that is later removed. |
| Imported DLL / API | Windows libraries (DLLs) and the functions they provide. The program's import list shows what it calls. |
| PE / ELF / Mach-O | Executable file formats: PE is Windows, ELF is Linux, Mach-O is macOS. |
| Byte order (endianness) | The order in which the bytes of a multi-byte value are stored. It matters when a value is written piece by piece. |
| Strings scan | Running `strings` on a file to list readable text. It finds plain text but not text built in memory. |
| Virtual machine (in Vexed Wolverine) | A small custom interpreter that runs the program's own hidden instructions (bytecode). |
| C2 (command and control) | A server that a malware sample contacts to receive instructions or send data. |
| Indicator | A piece of evidence that can be searched for: a domain, IP address, file hash or string. |
| IOC (indicator of compromise) | An indicator tied to observed or recovered activity, recorded with its type, value, source, status and confidence. Classroom decoys and shared services are labeled, not treated as malicious. |
| Defanging | Writing a domain or URL so it cannot be clicked or resolved by accident, for example `example[.]com` or `hxxp://`. Used in every shared handoff. |
| Shared service | A legitimate public service the code contacts, such as a public IP-check API or GitHub. It is context for the code's behavior, not a blocklist entry. |
| Pivot | Moving from one indicator to related infrastructure, files or reports. |
| Entity | Something Recorded Future tracks, such as a domain, IP, file hash, malware family or threat actor. |
| No match | The platform has no record for that query. It does not establish that a value is safe. |
| Attribution | Linking activity to a named actor or family. Shared infrastructure alone does not prove it. |
| Gist | A GitHub service for sharing text snippets. The class uses one as a text resource. |
| Acrostic | A hidden message spelled by the first letters of successive words or lines. |
| YARA / Sigma | Detection-rule formats: YARA matches file content, Sigma matches log events. They are an extension, not part of the core hours. |

## Outline at a glance

| Hour | Focus | What students will produce |
| --- | --- | --- |
| 1 | Recorded Future Sandbox kickoff | A behavior timeline, initial evidence table and questions for code analysis |
| 2 | Grumpy Ferret in Ghidra: orientation and execution flow | A labeled execution flow connected to sandbox observations |
| 3 | Grumpy Ferret in Ghidra: configuration and validation | Decoded configuration, recovered serial logic and checked findings |
| 4 | Soggy Badger in Ghidra | A verified stack string, an explanation of the hash-check approach, and one host artifact or anti-debug check |
| 5 | Restless Otter in Ghidra | Decoded runtime configuration, a verified anti-debug check, and the ticket-to-decryption relationship |
| 6 | Recorded Future Malware Intelligence follow-up and wrap-up | Intelligence pivots based on verified findings and a concise analysis handoff |

## Hour 1 Recorded Future Sandbox kickoff

We’ll begin with the Recorded Future Sandbox so students have concrete behavioral evidence and questions to carry into Ghidra. Start with prepared reports to keep the class moving while any live submission runs. Grumpy Ferret is the main walkthrough; use Soggy Badger to introduce Windows artifacts and Restless Otter to set expectations for the macOS exercise.

- **10 minutes:** Class goals and Sandbox orientation. Explain what reports can establish, how to read execution settings and environment details, and what a run did or did not test.
- **20 minutes:** Walk through Grumpy Ferret process activity, signatures, DNS and HTTP observations, and available host artifacts. Demonstrate submission settings and execution arguments using a prepared report or live run.
- **15 minutes:** Compare the prepared Soggy Badger Windows report with the prepared Restless Otter macOS report or capture. Note platform limits. The Restless Otter evidence is prepared in advance, not produced live.
- **10 minutes:** Students draft a behavior timeline and evidence table, distinguishing observed activity from attempted lookups and unverified leads. Add a first IOC list from the report: domains, IPs, URLs, file names and hashes, each with type, value, source and status.
- **5 minutes:** Questions and a short break.

**Outcome:** Students can navigate Sandbox reports, create an initial behavior timeline, start an IOC list with type, value and source, and identify questions for static analysis. A requested domain, attempted connection or host artifact is not automatically a malicious indicator.

For the updated Grumpy Ferret, record only what the sandbox shows: the DNS/HTTP requests to YouTube and GitHub and the child process that makes them. The binary prints no decoded config and no host names, so the decoded values come only from code. Do not decode the Python stage here; it is revealed in Hour 3. Use the instructor fixture if the public-page reader is blocked in the classroom environment; identify fixture evidence as synthetic.

## Hour 2 Grumpy Ferret in Ghidra: orientation and execution flow

We’ll start the Ghidra portion with Grumpy Ferret, introducing the AI/MCP workflow while tracing the code behind the Sandbox observations. This is a guided walkthrough; students should verify AI answers against the decompiler, references and underlying data. Students use their own MCP connection only if it was smoke-tested before class. Otherwise they follow the instructor screen and run the same prompts.

- **10 minutes:** Import and analyze the prepared Grumpy Ferret project; introduce the decompiler, references and available Ghidra MCP tools. Cut to 5 minutes if the room is experienced.
- **25 minutes:** Use focused AI prompts to identify the main execution path and find DNS/HTTP routines. Ask for function addresses and supporting references, then verify them in Ghidra and compare with the Sandbox timeline. In plain terms: find the code that makes the DNS lookups and web requests we saw in the sandbox, note the address of each function involved, and list the places that call it.
- **20 minutes:** Use five minutes for the deliberate AI-error exercise below, ten minutes for paired observation-to-code tracing, and five minutes to apply checked names/comments and identify the next analysis targets.
- **5 minutes:** Questions and a short break.

**Outcome:** A labeled Grumpy Ferret execution flow connected to observed behavior; students can ask a focused AI-assisted RE question and validate the result.

## Hour 3 Grumpy Ferret in Ghidra: configuration and validation

We’ll continue the Grumpy Ferret analysis, focusing on selected functions that explain what Sandbox could not show directly. Use a prepared project and guided prompts to keep this achievable within the hour; treat the Python resolver stage as a demonstration or optional extension if the core tasks run long.

- **25 minutes:** Demonstrate configuration recovery for 15 minutes, then give pairs ten minutes to reproduce one decoded field and verify its consumer. Configuration recovery means decoding the hidden settings the program stores, such as its server name. Compare recovered values with the code and Sandbox evidence.
- **15 minutes:** Recover and explain the reversible serial transform, a math step that can be undone and that checks the serial the user types in. Locate the anti-debug gate (a check that changes behavior when a debugger is attached) and the decoy paths, noting which behavior can occur before the gate.
- **15 minutes:** Consolidate verified Grumpy Ferret findings and label each as observed in Sandbox, recovered from code, or only present as a string. Flag candidate values for later Malware Intelligence searches without treating reserved domains or intentional public-service requests as malicious infrastructure. Build the IOC table here: for each value, record type, source (Sandbox, code or string), status, and whether it is a classroom decoy or a shared service. The configured domain and IP are decoys; the public API host and example.com are shared-service context, not blocklist entries.
- **5 minutes:** Questions and a short break.

The updated Grumpy Ferret also contains an XOR-encoded Python resolver. If time permits, recover the stage, explain how a natural-language comment supplies a sentence acrostic, and trace how it selects the GitHub flag file. Separate the decoded resource URL from a confirmed live download.

**Outcome:** An evidence-backed explanation of Grumpy Ferret and an evidence table that distinguishes traffic observations, decoded configuration and strings.

Example questions to demonstrate:

- “Find the function responsible for this DNS request and show the supporting references.”
- “Explain this decoder and reproduce its output without executing the binary.”
- “Which behavior occurred before the anti-debug check, and which behavior does the check prevent?”
- “Summarize what is confirmed, what is inferred and what we still don’t know.”

## Hour 4 Soggy Badger in Ghidra

We’ll apply the same AI/MCP method to Soggy Badger, using the Windows Sandbox report as a reference. Focus on a prepared Ghidra project and selected learning goals rather than attempting to reverse every path.

- **10 minutes:** Revisit key Windows Sandbox findings, inspect PE imports and use AI/MCP to identify the main path and functions to investigate.
- **20 minutes:** Demonstrate stack-string reconstruction for ten minutes, then give pairs ten minutes to recover a selected string and trace its consumer. A stack string is text the program assembles one character at a time in memory, so a plain strings scan misses it. Cover registry check-in/cleanup in the later host-artifact segment.
- **15 minutes:** Identify and explain the ROR13-plus-add hash check. In plain terms, the program rotates a 32-bit number right by 13 bits, adds the next character, and repeats; it compares the final number with a fixed target. Test candidate imported DLL names (the Windows libraries the program calls) using the recovered algorithm. The hash is one-way, so we test candidate names rather than reversing it.
- **10 minutes:** Locate one anti-debug check (API or PEB; a PEB check reads Windows' internal process block for a debugger flag) and the registry check-in or cleanup routine. Full DNS/WinINet tracing and the second anti-debug check are optional. WinINet is the Windows web-request library. Record the mutex name and the registry key and value as host IOCs (types: mutex, registry key), labeled as classroom artifacts.
- **5 minutes:** Questions and a short break.

**Outcome:** Students recover and verify a selected stack-built string, explain the hash-check approach, and identify one host artifact or anti-debug gate in the execution flow. The mutex and registry entries become host IOCs in the table. Exact unlock inputs and flags stay in the separate instructor solution files. Full registry, networking and anti-debug path tracing is optional.

If the block runs long, cut in this order: full network tracing, then the second anti-debug check. Do not cut the stack-string recovery or the hash check.

## Hour 5 Restless Otter in Ghidra

We’ll apply the workflow to a macOS Mach-O using a prepared Ghidra checkpoint and staged hints. Focus on selected analysis goals and compare with the Linux and Windows examples.

- **10 minutes:** Introduce the Mach-O (the macOS executable format; Windows uses PE and Linux uses ELF) and the prepared project. Locate the main flow with AI/MCP and explain available macOS runtime evidence without assuming Sandbox supports this platform.
- **25 minutes:** Use 15 minutes to locate and demonstrate the string decoder (the routine that turns scrambled bytes back into readable text) and the sysctl anti-debug check (macOS asks the kernel whether a debugger is attached, via the `P_TRACED` flag), followed by ten minutes of paired configuration recovery and consumer verification. Identify further DNS/GitHub routines if time allows.
- **10 minutes:** Instructor demonstrates the 16-character ticket (the serial the user enters) and its transform from a prepared checkpoint. The transform scrambles each character and feeds a rolling checksum (a running total that validates the whole ticket). Show the call/data dependency connecting a validated ticket to the flag-decryption routine, meaning which function passes the ticket's data into the decryption. Students verify the required length and the per-character comparison; independently recovering the ticket and tracing the complete flag-key derivation/decryption are take-home work. Keep exact answers in the instructor solution file.
- **10 minutes:** Compare string hiding, validation and anti-debugging across the three core crackmes; identify which findings are observations versus code-derived. Finish the combined IOC table: network (domains, hosts, request lines), host (mutex, registry) and recovered configuration values, each with its decoy or shared-service label.
- **5 minutes:** Q&A and take-home next steps.

**Outcome:** Students can explain selected parts of Restless Otter’s decoder and configuration, identify the sysctl anti-debug gate, and compare these techniques with the other core projects. The instructor demonstrates the ticket-to-decryption dependency and students verify the required length and the per-character ticket comparison. Independent ticket recovery, full checksum reproduction and complete flag-key derivation/decryption are take-home extensions.

## Hour 6 Recorded Future Malware Intelligence follow-up and wrap-up

We’ll return to Recorded Future after the code analysis and use verified evidence from all three core crackmes to search for additional context. The goal is to practice evidence-led searches and pivots, not to imply that benign training samples will have threat records.

- **10 minutes:** Revisit the evidence table. Select suitable verified findings—such as observed or code-confirmed domains/IPs, file hashes, distinctive infrastructure or behaviors—and label the evidence source and confidence.
- **25 minutes:** Spend five minutes demonstrating an exact-entity lookup, ten minutes on paired searches, and ten minutes demonstrating/discussing a supported pivot from the separate prepared real-world example below. Document no-match results and distinguish platform context from proof about the sample.
- **15 minutes:** Students complete an analysis handoff separating Sandbox observations, Ghidra/code findings and Malware Intelligence context, with gaps and confidence noted. The handoff includes the final IOC table: type, defanged value, source, status, confidence and decoy or shared-service label.
- **5 minutes:** Identify one evidence-backed follow-up question or hunting hypothesis. YARA/Sigma development can follow as an extension.
- **5 minutes:** Q&A and take-home next steps.

**Outcome:** Students use verified analysis findings to search Recorded Future Malware Intelligence and produce a concise, evidence-based handoff.

## Teaching guardrails and success criteria

Treat each project as a guided analysis of selected learning goals, not a promise that every student will independently solve every component during the hour. Keep the core outcomes below in scope; defer optional details rather than rushing the class or dropping a core project.

| Exercise | Minimum in-class success criteria | Optional stretch |
| --- | --- | --- |
| Grumpy Ferret | Trace the main execution flow, connect at least one Sandbox observation to code, and explain the configuration decoder and serial check at a high level. | Fully recover and trace the embedded Python resolver stage and its external text retrieval. |
| Soggy Badger | Recover and verify selected stack strings, explain the hash-check approach, and identify one host artifact or anti-debug check in the execution flow. | Trace all registry, networking and anti-debugging paths. |
| Restless Otter | Locate the string decoder, explain selected runtime configuration and identify the sysctl anti-debug check. | Work through the ticket transform, checksum and ticket-derived flag decryption in detail. |

**Minimum IOC output per exercise:**
- **Grumpy Ferret:** at least one configured or observed domain or IP and the HTTP request line, each with its source and decoy or shared-service label.
- **Soggy Badger:** the mutex name and the registry key and value, each with its code address or report reference.
- **Restless Otter:** the recovered host and DNS entries and the HTTP request, each with its shared-service label and the decoded-config address.
- **Vexed Wolverine (bonus):** no IOC table is required. Students list apparent endpoint strings and classify each as a decoy.

Use one shared evidence template throughout the class. For each item, students record the finding, source (Sandbox observation, Ghidra/code, or Malware Intelligence), supporting evidence or reference, status (observed, attempted, decoded, inferred, or unverified), and confidence. Keep observations distinct from interpretation; an AI answer or platform result is a lead until checked against evidence.

Print the template as a one-page handout and give it out at the start of Hour 1. Record evidence source, analytical status and operation outcome separately; one label cannot describe all three.

- **Observed:** directly recorded in an identified sandbox run or runtime capture. Name the environment, capture/report reference and date. This includes prepared macOS captures.
- **Attempted:** evidence shows an operation was initiated. Record its outcome separately as succeeded, failed (with error), timed out or unknown. A DNS request without an answer supports an attempt, not a confirmed connection.
- **Decoded:** output independently reproduced from bytes and a transformation recovered from code, without running the sample executable. Cite the data and decoder locations.
- **Inferred:** an interpretation supported by identified code or other evidence but not independently reproduced or observed. State the basis and uncertainty.
- **Unverified:** a source or AI claim whose supporting evidence has not yet been checked.

**Fixture evidence:** Add an explicit `synthetic fixture` source tag to every fixture-derived result. It demonstrates behavior with supplied inputs and never establishes a live request or download. Status may be `observed in fixture execution` or `decoded`, but must retain the synthetic source tag. Label saved real runtime evidence `saved runtime capture`, and distinguish it from a current run.

| Finding/value | Sample and role | Source and date | Reference/address | Status | Operation outcome | Confidence and reason | Next question |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Student entry | Exact sample identity and demonstrated role | Live/saved runtime, code, intelligence or synthetic fixture | Evidence another analyst can locate | Observed, attempted, decoded, inferred or unverified | Succeeded, failed, timed out, unknown or not applicable | Explain the evidence strength | Specific unresolved question |

Confidence must have a reason: for example, a checked call site and matching event. Fluent AI prose or a platform headline alone does not increase confidence.

IOC rows use the same template, with two extra rules. First, the type is one of: domain, IP, URL or request line, file name, hash, registry key, mutex, user-agent or configuration string. Second, every row carries a label: `malicious-candidate` (not yet proven), `classroom decoy` (reserved or documentation value built into the exercise) or `shared service` (legitimate public service). Only `malicious-candidate` rows are candidates for later Malware Intelligence searches.

Prepare a checkpoint and a fallback for each live dependency: preloaded Ghidra projects and staged hints for analysis, prepared Sandbox reports or captures if a live run is delayed, and screenshots or a short instructor demonstration if the MCP connection or Malware Intelligence search is unavailable. Rehearse these fallbacks on the classroom setup.

The hourly blocks total 60 minutes including their listed Q&A and breaks, leaving little unallocated transition time. Include file loading and tool changes in the activity estimates. If a block runs long, cut in this order: Hour 3 Python resolver extension; Hour 4 full network tracing and second anti-debug check; Hour 5 ticket transform demonstration; Hour 2 Ghidra orientation (only if the room is experienced, otherwise keep it). Preserve the minimum outcomes for all three core crackmes and the Hour 6 Malware Intelligence search and handoff.




## Paired practice and staged hints

These ten-minute tasks fit inside the activity allocations above; they do not extend the six-hour schedule. Partner A operates the tools while Partner B challenges claims and records evidence. Switch roles after five minutes. With one working MCP connection, share that station; without one, inspect the prepared Ghidra project manually.

| Hour | Paired task | Required output | Hint 1 | Hint 2 / recovery checkpoint |
| --- | --- | --- | --- | --- |
| 1 | Choose a DNS event and a process or HTTP event from the supplied report; distinguish the recorded action from interpretation | Two evidence rows and one question for code analysis | Read the report's execution settings and event details | Instructor points to the relevant events; students still write the outcome and question |
| 2 | Trace one sandbox network observation to an API call and the origin of its argument | Event reference, call-site address and argument-source explanation | Start from the resolver or network imports and inspect callers | Provide the relevant caller address from the exact classroom build |
| 3 | Reproduce one configuration field and follow it into a consumer | Decoder/data references, recovered field and consuming call | Identify the repeating-key index and byte count | Supply the decoder/data checkpoint; students verify one field and its role |
| 4 | Reconstruct a selected stack string and explain where it is used | Bytes ordered by buffer offset, builder address and consumer | Track writes by destination offset, including multi-byte stores | Provide the builder checkpoint and ask students to check the terminator and consumer |
| 5 | Recover two configuration fields and verify one consumer or the anti-debug gate | Decoded fields and supporting addresses; runtime status retained | Find callers of the shared decoder | Provide a partially annotated checkpoint; students explain the selected values themselves |
| 6 | Look up one recovered network value and one contrasting artifact | Exact queries, actual outcomes, references and a revised interpretation | Verify entity type and the original code role before searching | Use the instructor's dated saved result, accurately labeled, if access fails |

**Stopping rule:** At ten minutes, ask pairs to report what they established and what remains unresolved. Move to the prepared checkpoint so slower pairs can join the next activity. Early finishers investigate the stretch goal or explain another pair's evidence before receiving the bonus challenge.

## Deliberate AI-error exercise — Hour 2

**Teaching goal:** Practice correcting an attractive but unsupported explanation before allowing the assistant to annotate the project. The "fabricated" answer below is a deliberately wrong AI answer: it sounds confident but cites nothing that can be checked.

**Five-minute sequence:** Spend one minute showing the following fabricated AI answer, two minutes tracing references, one minute rewriting the claim and one minute discussing why it mattered. Label the answer `instructor-written flawed AI-style answer`; do not suggest it was generated by the connected model.

> “The flag-like string found by the strings scan is the genuine success flag. Rename its referencing function `reveal_real_flag`.”

Choose a decoy string from the actual Grumpy Ferret binary and show its references or absence of references. Students inspect the branch using it and the separate validation/success path. A string can be unused or belong to a failure/anti-debug path; its appearance alone does not establish a successful reveal.

**Correction prompt:**

> Verify this proposed function role before editing Ghidra. Trace references to the selected string, the branch conditions that use it, and the separate validation/success path. Give addresses, state what is confirmed, and revise or reject the proposed name if the evidence does not support it. Make no edits yet.

**Student output:** One corrected sentence with a reference, such as “This string is used on the failure path at [checked address]; the success reveal is a separate routine reached after validation.” If the chosen string is unused, report that result and avoid assigning it a runtime role.

**Debrief:** Ask which evidence disproved the claim and which project annotation would have been misleading. Then apply only verified names/comments. If live references differ from the rehearsed example, use the saved checkpoint and identify the build it represents.

## Instructor delivery runbooks

These are read-and-verify workflows for the actual classroom tools. Program addresses, report IDs and MCP tool names must come from the exact rehearsed build and connection. The directory contains `ghidra/RE_class.gpr`; verify which programs it contains before relying on it as a checkpoint. The source and solution files are instructor references and are excluded from student handouts.

### Hour 1 — Sandbox evidence

**Start:** Prepared Grumpy Ferret report, Windows report and macOS capture; release-file identities recorded. Open the report details and execution settings before interpreting events.

**Demonstrate:** Show arguments/environment, then one process event, DNS attempt and HTTP result that are actually present. Live submission may run in the background; do not wait for it to complete before teaching.

**Prompt, if report access exists through MCP:**

> Summarize this report's execution environment and command line, then list the recorded process, DNS and HTTP events with references. Separate attempts, failures and successful responses. State missing evidence; do not insert expected behavior from the exercise notes.

**Expected finding / verify:** Students identify events with accurate outcomes and one unanswered question. Check one row against the displayed report. YouTube/Gist success is not required and must not be assumed.

**Fallback / stop:** Use saved reports or captures, with dates. Use fixtures only to demonstrate synthetic resolver behavior. Stop after the paired timeline task; defer decoding to Hour 3.

### Hours 2–3 — Grumpy Ferret

**Start:** `grumpyFerret/grumpyFerret`, prepared analyzed project, report timeline. Instructor references: `grumpyFerret/SOLUTION.md` and `grumpyFerret/grumpyferret.c`.

**Read-only terminal orientation:**

```sh
file grumpyFerret/grumpyFerret
sha256sum grumpyFerret/grumpyFerret
strings -n 6 grumpyFerret/grumpyFerret
```

**Hour 2 prompt:**

> Confirm the active program and map its main execution path. Locate the routines responsible for our observed DNS/HTTP activity, show callers and argument origins, and cite addresses. Distinguish verified roles from hypotheses. Do not rename, patch or run the file.

**Expected finding / verify:** A checked call sequence and one event-to-code connection. Navigate to the cited call and inspect its argument. Run the flawed-answer exercise before applying annotations.

**Hour 3 prompt:**

> Recover the configuration decoder's data location, byte count, key and index rule. Reproduce its output without running the executable, then trace one field into its consumer. Explain the serial-validation transform and anti-debug gate with addresses. Validate any recovered candidate by reapplying the original transform; keep exact inputs and flags out of the shared summary.

**Expected finding / verify:** Repeating XOR configuration recovery and the serial relationship `encoded[i] = ((input[i] XOR MAGIC[i]) + i) mod 256`. In words: each serial character is XOR'd with a fixed `MAGIC` byte, its position `i` is added, and the result is kept to one byte. Its inverse is `input[i] = ((TARGET[i] - i) mod 256) XOR MAGIC[i]`, which undoes the same steps in reverse order: subtract the position, then XOR with `MAGIC`. Confirm tables and length in the current binary, then reapply the forward transform. Locate the `TracerPid` branch (the Linux check for an attached debugger) and establish which calls precede it.

**Fallback / stop:** Provide a checkpoint identifying the decoder and data when navigation consumes practice time. Stop once students explain the decoder, serial check and at least one observed behavior. Embedded-stage recovery remains optional.

**Optional instructor fixture demonstration, run from `grumpyFerret/`:**

```sh
GF_OFFLINE=1 GF_YOUTUBE_FIXTURE=instructor_youtube/youtube_comments_fixture.json GF_FLAG_FIXTURE=instructor_youtube/newbie_notes.txt ./grumpyFerret '<recovered serial>'
```

Replace the placeholder with the instructor-verified serial. Label this run synthetic: all three environment variables are needed for the supplied offline path, and it does not prove live YouTube or Gist retrieval. Use only the rehearsed lab environment.

### Hour 4 — Soggy Badger

**Start:** `soggyBadger/soggyBadger.exe`, prepared PE project and Windows report. Instructor references: `soggyBadger/SOLUTION.md` and `soggyBadger/soggybadger.c`. Rehearse this exact executable on Windows before class.

**Prompt:**

> Reconstruct the selected stack-built configuration string. Show writes in destination-offset order, store widths, byte order and terminator, then trace the consumer. Explain the input hash routine and comparison constant with addresses. Hash candidate uppercase imported DLL base names without the .DLL suffix using the exact recovered bytes and 32-bit arithmetic. Do not assume automatic case normalization or unique inversion of the hash.

**Expected finding / verify:** The recovered string reaches the stated consumer. The hash starts at zero and repeatedly computes `h = (ROR32(h, 13) + input_byte) mod 2^32`. A supported imported-DLL candidate reproduces the checked target. Students also identify a host artifact or one anti-debug gate.

**Follow-up prompt:**

> Trace the registry marker's write and cleanup paths, or one anti-debug check. Cite addresses and controlling conditions. Compare with the Windows report without assuming all code paths ran.

**Fallback / stop:** Supply the builder/hash checkpoints and saved report. Preserve stack-string and hash practice; defer full networking and the second anti-debug check. A cleanup path explains intended lifecycle; do not claim cleanup was observed without the report event.

### Hour 5 — Restless Otter

**Start:** Native macOS-built Mach-O, prepared analyzed checkpoint and identified macOS capture. The compiled Mach-O is `restlessOtter/restlessOtter` (current SHA-256 `66cde9e0e9b3124667b4e676b9115ba10d72040cd9e8cf6e873f02bae59d5c13`, stripped, rebuilt on macOS; it is included in the handout). It is arm64 only, so it will not run on Intel Macs; confirm student hardware and rehearse it on the classroom Mac before class. Instructor references: `restlessOtter/SOLUTION.md`, `restlessOtter/instructor.md`, and `restlessOtter/restlessOtter.c`. The source now matches the build's behavior. The ticket checksum constant is still being checked on a Mac.

**Prompt:**

> Confirm the active Mach-O and architecture. Locate the shared string decoder and recover two configuration fields from the actual byte arrays. Show one consumer and the sysctl/P_TRACED gate with addresses. Distinguish decoded configuration from activity confirmed by our macOS capture.

**Expected finding / verify:** Fields decode coherently, their consumers support the assigned roles, and the anti-debug branch gates the identified reveal path. Students check one consumer directly.

**Ten-minute ticket demonstration:** Show the required 16-byte length, the loop that compares each transformed ticket byte, and the rolling checksum in the prepared checkpoint. Show that the ticket contributes to the decryption key by following the relevant call/data dependency. Students verify the length and comparison. Full inversion, complete checksum reproduction and flag-key derivation/decryption are take-home work; do not require an independently recovered flag for in-class success.

**Fallback / stop:** Use the prepared native-binary project and saved capture if live macOS access is unavailable. A Linux build can illustrate shared logic but cannot stand in for the Mach-O or macOS-specific gate. Stop after configuration, consumer and gate verification. If the native artifact remains unavailable, explicitly teach this as an instructor source walkthrough and identify the missing binary-analysis evidence.

## IOC extraction answer key (instructor only)

Exact values are in each exercise's `SOLUTION.md`. Do not copy them into student handouts. This section defines what a correct IOC table contains.

| Exercise | IOC types expected | Expected source | Classify as decoy or shared service |
| --- | --- | --- | --- |
| Grumpy Ferret | Configured domain and IP, the API host requested, the HTTP request line, the optional Gist resource | Sandbox event, configuration decoded from code, code address of the request | The configured domain and IP are classroom decoys. The public API host and example domain are shared services. The Gist resource is a classroom resource, not a live payload, unless verified. |
| Soggy Badger | Mutex name, registry key and value | Code address of the builder or writer; Windows report | Classroom artifacts. The imported DLL names and hash are resolution data, not IOCs by themselves. |
| Restless Otter | Decoded host and DNS names, HTTP host and path, configured campaign and agent strings | Decoded configuration address; macOS capture (if available) | GitHub and example.com are shared services. Campaign and agent strings are classroom labels, useful only for lesson pivots. |
| Vexed Wolverine (bonus) | None by design; apparent endpoint strings | Strings and decoded data | All are decoys. |

Grading rules: accept any correct format, but check that defanging is applied, that each row has type, source, status and label, and that no shared service is recommended for blocking. Students should not mark an observed DNS request as a confirmed connection without the status defined in the evidence template.

## Hour 6 runbook — Return findings to Recorded Future

### Queries and interpretations

Use the following exact classroom values to rehearse queries. Students choose two from their verified evidence; retain the original value and code location. The interpretation column describes the exercise's known design, not a prediction of today's platform records, risk assessments or scores. Record actual lookup outcomes.

| Query/value | Search approach if supported | Code-derived role | What students should conclude |
| --- | --- | --- | --- |
| `api.ipify.org` | Domain lookup | Grumpy Ferret public-IP check | Context about a shared service needs the code role; the domain alone is insufficient for sample attribution |
| `example.com` | Domain lookup | Classroom DNS/HTTP target | Explain the documented exercise use; retain actual platform results without converting benign training activity into threat evidence |
| `203.0.113.7` or `203.0.113.9` | IP lookup | Embedded documentation address | A placeholder can be recovered accurately while offering no operational infrastructure pivot |
| `c2.grumpyferret-demo.invalid` or `c2.soggybadger-demo.invalid` | Domain lookup if accepted | Classroom probe/decoy configuration | Record accepted/no-match/unsupported outcomes accurately and explain the training role |
| `github.com` | Domain lookup | Restless Otter HTTP host or broader shared-service context | Host reputation is broader than an exact resource; preserve the path and consuming routine separately |
| SHA-256 printed by `sha256sum` for the selected release binary | File/hash lookup | Exact sample identity | Use the computed hash, not a made-up example; no record found does not establish safety |
| Recovered mutex or registry marker | Supported artifact/report search, if available | Local Windows host artifact | Keep it in the evidence table; it may have no appropriate network-entity lookup |

For Grumpy Ferret's downloaded text resource, preserve the full Gist URL from the recovered stage. Search its host if only domain lookup is available, and state that host-level context does not establish the status of that particular resource.

### Prepare one meaningful real-world pivot

**Before class:** Choose a domain or IP from a real-world Recorded Future report accessible to the classroom account. Use an example with a relationship supported by report evidence and dates. Rehearse opening the entity and following one related entity or report. Save dated screenshots/exports so the demonstration survives an outage.

Fill in these instructor fields from the actual record:

```text
Selected indicator and entity type:
Originating Recorded Future report reference/link:
Opening assessment and question:
Supporting source and publication/observation dates:
Related entity or report and exact relationship:
Evidence reference supporting that relationship:
Follow-up question the pivot helps answer:
Saved evidence location and capture date:
```

These fields are intentionally pending selection; no live record or relationship has been verified in these notes. This example is separate from the crackmes. Never imply that a training file shares its threat association merely because the demonstration follows the classroom analysis.

### Deliver the full-circle exercise

**First ten minutes — qualify findings:** Reopen each pair's initial timeline and unanswered question from Hour 1. Choose two recovered values and state what code analysis added. If a selected value was never observed at runtime, retain that distinction. Normalize a search value without discarding the exact original value.

**Next five minutes — demonstrate a lookup:** Use the platform's available entity lookup/search, verify the exact result, inspect supporting evidence and dates, and compare it with the known code role. No rigid menu path is assumed; use the classroom account's actual capabilities.

**Next ten minutes — paired searches:** Partners switch operator/reviewer roles after five minutes. Record exact query, method, lookup time, outcome, available result/source references and dates, relevance and remaining uncertainty. Distinguish no record found, unsupported query, access denied and tool/request failure.

**Next ten minutes — prepared relationship pivot:** Demonstrate the separate real-world example, open the relationship's evidence and ask students what it supports. Discuss timeframe, shared infrastructure and alternative explanations. A shared host or IP alone does not establish actor or malware-family attribution.

**Next 15 minutes — handoff:** Spend eight minutes drafting, five minutes on partner review and two minutes revising. Include sample identity, behavior, runtime and code evidence, the IOC table, intelligence lookup outcomes, assessment changes, limits and one next step. The partner checks one code reference and one intelligence reference.

**Final ten minutes:** Use five minutes for an evidence-backed follow-up question or hunting hypothesis and five for Q&A. Rule development remains an extension. The full Hour 6 sequence totals 60 minutes.

### MCP prompts and browser alternative

**Capability check:**

> Identify the Recorded Future tools available in this session and the entity/report searches they actually support. If no suitable tools are connected, say so. Do not assume browser access or invent tool names.

**Lookup:**

> Look up [exact values and types] using the available Recorded Future tools. For each, our analysis establishes [code role, address and runtime status]. Return the exact query, lookup outcome, accessible evidence references and source dates. Explain relevance to this sample and mark missing fields unavailable. Distinguish an empty result from a failed or unsupported request.

**Pivot on the separate prepared example:**

> Starting from [prepared indicator/report], identify one relationship supported by accessible evidence. Show the related entity/report, relationship reference and dates. Explain what the evidence supports and what remains uncertain. Keep this example separate from the benign crackme findings and avoid attribution based only on shared infrastructure.

**Assessment revision:**

> Compare our initial assessment with the verified sandbox observations, code findings and actual Recorded Future results. Write four sentences: what we initially knew, what code/runtime analysis established, what intelligence follow-up added or failed to establish, and one evidence-backed next step. Cite references and preserve uncertainties.

If only browser access exists, perform the search in the browser and give the assistant the relevant record or export. It may summarize supplied evidence but must not claim it queried the platform. If no student access exists, pairs fill the worksheet from the instructor display. If the service is unavailable, use dated saved results and label them historical evidence rather than live lookups.

### Completion and debrief

A successful pair has two qualified values, an accurately recorded outcome for each, a revised assessment and a defensible next step. One result may legitimately be no match or unsupported. Students can explain the prepared instructor pivot when their own artifacts yield no useful relationships.

Ask:

- **What changed after code analysis?** Students name a supported role or branch condition and its address.
- **What did intelligence follow-up add?** Students identify a sourced finding, supported relationship or justified limit—not merely repeat a headline assessment.
- **Does no match establish safety?** No; distinguish missing intelligence from the behavior already established.
- **What makes a pivot defensible?** A cited relationship relevant to the question and timeframe, with uncertainty preserved.
- **What closes the loop?** The revised assessment connects the opening question, runtime evidence, code findings and intelligence follow-up, then specifies the next investigation action.

## Final rehearsal before delivery

Do one timed pass through the exact classroom workflow, including the paired-task stopping points and a fallback transition. Verify the Grumpy Ferret child-stage dependency/fixture path, runtime behavior of the exact Soggy Badger executable on Windows, and the native Restless Otter Mach-O plus macOS capture. Confirm active-program selection in MCP and rehearse the Hour 6 queries and real-world relationship example with the classroom account. Record file hashes, project/program names, report/capture references, commands/arguments and saved evidence locations in the runbooks above. This section requests rehearsal; it does not claim these checks have been completed.

## Bonus challenge: Vexed Wolverine

Keep [Vexed Wolverine](vexedWolverine/README.md) in your back pocket as a bonus challenge for students who finish early. Do not plan to complete it during the core class time. Offer it during independent practice only after the current exercise is complete, or as a take-home extension after Hour 6. It is separate from the core lesson and does not require the rest of the class to move ahead.

Students recover a unique 32-character ticket and prove that they have the genuine flag. It combines encrypted configuration and bytecode, two different virtual machines, shuffled opcodes, masked operands, a flattened execution flow, reversible arithmetic, integrity checks, thread-local state, anti-debug checks and decoys. The difficulty comes from reconstructing these layers; the intended solution does not require brute-forcing cryptography. It is designed to be substantially harder than the core crackmes, but student completion time has not been benchmarked. Here a "virtual machine" is a small custom interpreter that runs the program's own hidden instructions (bytecode); "opcodes" are the instruction codes that interpreter reads, and "masked operands" are instruction values hidden by a mask.

Ask students to document the validation path and verify important AI findings against functions and data in Ghidra. Recovering one decoder or interpreter is useful progress even if they do not finish. Give hints in stages rather than turning the remainder of the class into a full walkthrough.

Distribute only the handout at `student/vexedWolverineBonus/` (Linux build, README, checksum). `vexedWolverine/student/` is the build staging folder and holds the Windows build; do not hand it out. Keep the source, answers, solver and [instructor hints](vexedWolverine/instructor/SOLUTION.md) separate.

The Linux executable passed 57 qualification checks, including an independent solve, invalid inputs, tampering and flag-key binding. The Windows executable compiled and passed static checks, but still needs a Windows runtime rehearsal. There is no supplied or tested macOS build. The challenge has no network activity, persistence, injection or credential collection; its encrypted programs are interpreted data, and its apparent endpoints are decoys. Early finishers can list those endpoint strings and classify each as a classroom decoy; no IOC table is required, because the challenge has no network activity by design.

## Crackme roles

- **Grumpy Ferret:** Hours 2–3 guided example. Linux ELF, XOR configuration, DNS/HTTP activity, anti-debugging, decoy strings and a reversible serial check. The local class folder contains an updated release binary with an embedded Python stage that extracts a sentence acrostic from a YouTube comment and retrieves a GitHub text flag. The flag now uses a public Gist. The stage runs on every launch, so its network requests show in the sandbox, but its output (including the Gist flag) appears only after the correct serial. The binary prints no decoded config, no host names, no lock string, and no serial length hint. The public-page reader requires no supplied API key or login. Live comment decoding and the Gist download were verified in this environment; rehearse the classroom sandbox and retain fixtures.
- **Soggy Badger:** Hour 4 Windows practice. Stack strings, named mutex, temporary registry marker, WinINet/Winsock calls (Windows web and socket networking libraries), API/PEB anti-debugging and a ROR13 hash check. A local Windows executable is present; the README’s original build warning does not establish its current runtime status. Rehearse the exact executable before class.
- **Restless Otter:** Hour 5 macOS exercise, part of the core class. Encrypted strings/configuration, sysctl anti-debugging, a transformed ticket with a checksum and a ticket-derived encrypted flag. Source, Makefile, README and instructor solution are included in [restlessOtter](restlessOtter/README.md). The compiled arm64 Mach-O is in `restlessOtter/` (see the Hour 5 runbook). Prepare a Ghidra checkpoint before class.

- **Vexed Wolverine:** Optional expert reserve exercise (uses the "virtual machine" term defined in Key terms; the Bonus challenge section defines the rest). Hand out the Linux build only; the Linux build is runtime-tested and the Windows build is static-validated only, so offer it only after a Windows runtime rehearsal. Layered encryption, two custom bytecode interpreters, control-flow obfuscation and input-bound flag recovery. Give it to early finishers or use it as a take-home challenge; it is outside the six-hour core.

## Preparation to finish before class

- Hand out only `student/` (see the index in `README.md`). It holds the student guides, the evidence template, the Grumpy Ferret and Soggy Badger binaries with checksums, and the Linux-only bonus build. The Restless Otter binary is included; it was rebuilt stripped on macOS. Rebuild and recopy binaries after any source change, then regenerate `student/SHA256SUMS`.
- Confirm student experience, attendance, class timing and whether lunch is inside the event’s allotted time.
- Smoke-test the complete classroom workflow: student and instructor Ghidra/MCP access, prepared projects, Recorded Future Sandbox reports/submission access, Malware Intelligence search and pivot permissions, and required files on the classroom machines.
- Rehearse the three core crackmes using the exact binaries, arguments and lab environments students will use. Confirm the Soggy Badger Windows run and the Restless Otter Mach-O on a macOS machine. Do not substitute a Linux build when demonstrating the macOS format and sysctl check. Vexed Wolverine is a bonus exercise and is not part of the in-class completion plan.
- Prepare Grumpy Ferret and Soggy Badger Ghidra projects for Hours 2–4, and the Restless Otter Ghidra checkpoint for Hour 5. Confirm actual Sandbox platform support; if macOS execution is unavailable, use a prepared macOS lab capture and static analysis.
- Set up the shared evidence template and prepare instructor checkpoints, staged hints and fallback materials for each core exercise. Rehearse the fallback path for a delayed Sandbox run, unavailable MCP connection or unavailable Malware Intelligence search.
- Rehearse the Vexed Wolverine Windows executable only if you plan to offer the bonus. Review the staged hints, and verify that source and answers are excluded from `student/vexedWolverineBonus/`. The Linux version is runtime-tested; Windows currently has build and static validation only.
- Prepare Grumpy Ferret’s YouTube stage (re-verify from the classroom network, not only from the prep machine): use the [public Gist flag](https://gist.githubusercontent.com/danafaye/8100c9037cdd799741c405d7b34a37f2/raw/710fef32e945a23fe1482de52dd446e54d1de7d8/newbie_notes.txt), use the prepared natural-language comment on [the current video](https://youtu.be/4ok4e0Jvy_4), verify the public-page reader (the stage's method for reading a public YouTube comment without logging in) in the classroom environment, and optionally pin `GF_YOUTUBE_COMMENT_ID`. No supplied API key or login is required. Rehearse the live flow and keep the synthetic fixture run available. Python 3 is required by the embedded stage.
- Save prepared Sandbox reports, traffic captures, screenshots and Ghidra checkpoints so the class can continue if a live service or tool is unavailable. Prepare a short list of verified findings and corresponding Malware Intelligence search pivots for Hour 6, including expected no-match cases for benign crackmes. Run each pivot before class and save the results, so the no-match outcome is shown from a saved record if the live search fails.
- Keep solution files and source code separate from the student release-binary handout; make hints available in stages.
- Run the benign exercises in the agreed lab environment and confirm expected outbound requests in advance.
- Confirm that every attendee may run the Hour 6 Malware Intelligence searches, and that the internal-use-only slides are shown only to attendees. Check the slide deck against the rehearsed workflow. Present automated annotation, function mapping and rule generation as demonstrated capabilities with analyst verification; do not promise automatic attribution or production-ready detections.

## Supporting material

- [Existing class slide deck](AI-Powered%20Malware%20Analysis%20with%20Recorded%20Future,%20Ghidra,%20and%20MCP.pdf)
- [Grumpy Ferret notes](grumpyFerret/README.md)
- [Soggy Badger notes](soggyBadger/README.md)
- [Restless Otter notes](restlessOtter/README.md)
- [Vexed Wolverine reserve challenge](vexedWolverine/README.md)
- [Crackme collection](/home/marasi/github/MoodyMustelids/README.md)

Internal class planning notes. The existing slide deck is marked internal use only; confirm the intended class audience before distributing it.

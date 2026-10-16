# soggybadger

A benign Windows "crackme" for the same three-tool demo (Ghidra via MCP,
Recorded Future Sandbox, Recorded Future MCP indicator triage), built around
Windows-native techniques: a PE executable, a named mutex, WinINet for HTTP,
and a rolling-hash unlock check. It does nothing harmful: no persistence
that outlives the process, no destructive behavior, only one real, safe
outbound HTTP call.

**Build status:** a prebuilt 64-bit Windows executable, `soggyBadger.exe`
(SHA-256 `805bcde68c184e1dccbc5bc92a53313ff97d2803e261cc29463d0f4168fb9961`),
is included. Its code and data sections match a fresh MinGW-w64 release
build of `soggybadger.c` (GCC 13, `-O2 -s -Wall`, same libraries), checked
statically. It has not been run on Windows in this project. Rehearse the
exact executable on a Windows lab machine before class. To rebuild from
Linux or macOS, run `make release` (MinGW-w64); the MSVC command is in the
Makefile.

## Terms

- **PEB**: the Process Environment Block, Windows' internal per-process data.
  It includes a "being debugged" flag.
- **ROR13**: rotate right by 13 bits.
- **WinINet**: the Windows web-request library (`InternetOpenA`, `InternetOpenUrlA`).
- **Stack string**: text built one character at a time in memory.

Every recon, network, and telemetry step runs regardless of whether anything
is inspecting the process. The anti-debug checks only gate the last step
(the hash check itself).

## Files

- `soggybadger.c` - full source
- `soggyBadger.exe` - prebuilt 64-bit Windows executable (PE format)
- `Makefile` - `make release` cross-compiles the stripped challenge binary
  with MinGW-w64; `make debug` builds an unstripped copy (`soggyBadger_debug.exe`)
  for your own reference; the MSVC command is in a comment

## Suggested demo flow

**1. First pass - strings / import table (no tools yet)**

A plain `strings` pass turns up the banner, the build tag
`soggybadger_v2_build`, and three decoys: `SB{TRY_HARDER}`,
`SB{NOT_TODAY}`, and `backup_hash=0xDEADBEEF` (a fake target value --
the real one is a raw 32-bit constant in the code, not printable text).
The registry path, the user-agent string, and the `http://%s/` format
string are also plain text. The config values are not: the mutex name,
the fake domain/IP, the safe domain, and the campaign are built one byte
at a time on the stack. Only fragments of them appear in the data
(`SoggyBadgerSingleton_Mut`, `c2.soggybadger-demo.inva`, `203.0.11`,
`example.`, `operation-wet-bl`), joined together, so no full value is a
single string. Good moment to point out that this hides the config from a
naive string scan, and that a simple `strings` pass cannot recover the
complete values.

A look at the import table (via a PE viewer, or Ghidra's symbol tree)
shows the imported DLLs, including the one that's the answer to the
unlock check.

**2. Static analysis - Ghidra via MCP**

Suggested labeling pass:

- `main` - call order: banner -> mutex create -> stack-string config
  build -> registry check-in -> DNS probes -> phone-home -> (anti-debug
  gate) -> hash check -> flag reveal
- the stack-string code in `main` - long runs of single-byte stores into a
  local buffer. In the source the builders are separate static functions,
  but in the shipped `.exe` they are inlined into `main`, so there are no
  builder symbols to find. Reconstructing the string just means reading
  the immediate values in order; a good moment to show that Ghidra's
  decompiler view makes this much faster than reading raw assembly.
- the hash check - recover the ROR13-plus-add loop and the 32-bit target
  constant it's compared against. It is also inlined into `main`.
- the PEB-read code in `main` - point out the direct `gs:0x60` read as the
  "doesn't rely on any Win32 API" anti-debug variant, contrasted with
  the plain `IsDebuggerPresent()` call sitting right next to it.

**3. Solving the hash - without inverting it**

This is the point of using a rolling hash instead of a reversible
transform: you don't invert it, you recognize what it's shaped like
(walk a string, ROR13, add) and confirm candidates. The intended
candidate list is short and sits in the binary's own import table --
try hashing the uppercase base name of each imported DLL with the same
algorithm and compare against the target constant. This mirrors the
actual professional technique for breaking hash-based dynamic API
resolution in real malware: analysts don't invert the hash either, they
hash the ~200-ish exported names from the relevant DLLs (or in this
case, a candidate list of the five imported DLL base names) and look for a match.

**4. Indicator triage - Recorded Future MCP**

The config indicators are recovered this time by tracing the stack-string
builders, not by decoding an XOR blob. Record
each in your IOC table with its label (the mutex is a host IOC; the
`.invalid` domain and TEST-NET IP are classroom decoys; `example.com` is a
shared service):

- the mutex name - a host-based indicator, not a network one; worth
  noting that not every "indicator" in a sample is something you look up
  in a threat intel feed
- `c2.soggybadger-demo.invalid` - RFC 2606 reserved `.invalid` TLD,
  guaranteed unregistrable
- `203.0.113.9` - IANA TEST-NET-3 (RFC 5737), reserved for documentation
- `example.com` - real, RFC 2606 reserved-for-documentation domain,
  clean reputation

**5. Dynamic behavior - Recorded Future Sandbox**

Detonate with a plausible guess as the argument. Expect to see:

- mutex creation (`SoggyBadgerSingleton_Mutex`)
- the config line the program prints at runtime
  (`[*] config: domain=... ip=... safe=... campaign=...`). The program
  prints its own config in plain output, so a sandbox report shows these
  values even though a static strings pass does not.
- a registry write under `HKCU\Software\SoggyBadgerDemo\Marker`
  (cleaned up again before the process exits, so re-running looks
  identical each time)
- DNS resolution attempts for the fake `.invalid` domain (failure
  expected) and for `example.com` (should resolve)
- an HTTP request to `example.com` over WinINet
- if your sandbox platform attaches a debugger/tracer to the process,
  the anti-debug branch fires and you'll see the decoy flag
  (`SB{TRY_HARDER}`) instead of the real one, even with the correct
  input. The teaching point: a debugger-based dynamic pass can walk right
  into a check built specifically to detect it.

**6. The reveal**

Run it directly, no debugger attached, with the DLL name recovered from
step 3:

```
soggyBadger.exe <recovered DLL base name>
```

Correct input prints the real flag. Running with no argument prints a
usage line and exits before the anti-debug gate and the hash check, so
the usage text is not a way to reach the flag. See `SOLUTION.md` for the
answer key.

## Notes on the embedded indicators

Every network-looking value in this binary is deliberately either
IANA/IETF-reserved for documentation (`203.0.113.0/24`, `.invalid`,
`example.com`) or a classroom label. The only network activity is the
intentional HTTP request to `http://example.com/` and the DNS lookups that
come before it. Nothing in this binary contacts or affects real
infrastructure. For IOC tables, label the values as classroom decoys or
shared services.

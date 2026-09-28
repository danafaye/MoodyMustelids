# soggybadger

A benign Windows "crackme," a companion to grumpyferret for the same
three-tool demo (Ghidra via MCP, Recorded Future Sandbox, Recorded Future
MCP indicator triage), built around Windows-native techniques instead of
the Linux ones grumpyferret used. It does nothing harmful: no persistence
that outlives the process, no destructive behavior, only one real, safe
outbound HTTP call.

**Build status:** this was written and hand-checked for brace/paren
balance and correct WinAPI call signatures, but it was NOT compiled or
run in the environment that produced it -- there was no Windows/MinGW
toolchain available there. Do a quick test build (`make -f Makefile.win
release`, or the MSVC command in that file) before you rely on it in
class.

## What's different from grumpyferret (on purpose)

| | grumpyferret (Linux) | soggybadger (Windows) |
|---|---|---|
| format | stripped ELF | PE, imports visible as DLL names |
| single-instance marker | plaintext lock string | a real named mutex (`CreateMutexA`) |
| host telemetry | none | a self-cleaning registry check-in (`HKCU\Software\SoggyBadgerDemo`) |
| anti-debug | one check (`/proc/self/status` TracerPid) | two checks (`IsDebuggerPresent` + manual PEB `BeingDebugged` read) |
| config storage | one static XOR blob | four values built byte-by-byte on the stack -- nothing contiguous for `strings` to find |
| unlock check | per-byte transform against a target array | ROR13 rolling hash against a target 32-bit value, the same style real Windows malware uses for hash-based API resolution |
| network | libc sockets (`getaddrinfo`, raw `connect`) | WinINet (`InternetOpenA`/`InternetOpenUrlA`) for HTTP, Winsock2 (`getaddrinfo`) for DNS |

Same design principle carried over: every recon/network/telemetry step
runs regardless of whether anything's inspecting the process. The
anti-debug checks only gate the very last step (the hash check itself).

## Files

- `soggybadger.c` - full source
- `Makefile.win` - MinGW-w64 cross-compile target, plus the MSVC command
  in a comment

## Suggested demo flow

**1. First pass - strings / import table (no tools yet)**

A plain `strings` pass turns up the banner, the build tag
`soggybadger_v2_build`, and three decoys: `SB{TRY_HARDER}`,
`SB{NOT_TODAY}`, and `backup_hash=0xDEADBEEF` (a fake target value --
the real one is a raw 32-bit constant in the code, not printable text).
None of the mutex name, the fake domain/IP, or the real safe domain show
up at all -- they're stack strings, built one byte at a time at runtime.
Good moment to contrast this with grumpyferret's single static blob:
same goal (hide the config from a naive string scan), different
technique, and this one defeats `strings` completely rather than just
requiring an XOR.

A look at the import table (via a PE viewer, or Ghidra's symbol tree)
shows the imported DLLs, including the one that's the answer to the
unlock check.

**2. Static analysis - Ghidra via MCP**

Suggested labeling pass:

- `main` - call order: banner -> mutex create -> stack-string config
  build -> registry check-in -> DNS probes -> phone-home -> (anti-debug
  gate) -> hash check -> flag reveal
- the stack-string builder functions - each one is a long run of single-
  byte stores into a local buffer. Reconstructing the string just means
  reading the immediate values in order; a good moment to show that
  Ghidra's decompiler view makes this much faster than reading raw
  assembly.
- the hash-check function - recover the ROR13-plus-add loop and the
  32-bit target constant it's compared against.
- the PEB-read function - point out the direct `gs:0x60` read as the
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
case, a candidate list of three) and look for a match.

**4. Indicator triage - Recorded Future MCP**

Same four-indicator pattern as grumpyferret, recovered this time from
tracing the stack-string builders instead of decoding an XOR blob:

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
- a registry write under `HKCU\Software\SoggyBadgerDemo\Marker`
  (cleaned up again before the process exits, so re-running looks
  identical each time)
- DNS resolution attempts for the fake `.invalid` domain (failure
  expected) and for `example.com` (should resolve)
- an HTTP request to `example.com` over WinINet
- if your sandbox platform attaches a debugger/tracer to the process,
  the anti-debug branch fires and you'll see the decoy flag
  (`SB{TRY_HARDER}`) instead of the real one, even with the correct
  input -- same teaching point as grumpyferret: a ptrace/debugger-based
  dynamic pass can walk right into a check built specifically to detect
  it.

**6. The reveal**

Run it directly, no debugger attached, with the DLL name recovered from
step 3:

```
soggybadger.exe <recovered DLL base name>
```

Correct input prints the real flag. See `SOLUTION.md` for the answer key.

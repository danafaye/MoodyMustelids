# restlessotter

A small, benign macOS "crackme" built for the Recorded Future Ghidra MCP class. It does nothing harmful. It has no persistence, no destructive behavior, and no real C2. Its network calls are two DNS lookups and one plain HTTP request to `github.com` on port 80.

It behaves like a miniature commodity bot: a banner, an encrypted runtime config with network-looking indicators, DNS probes and one HTTP request to generate sandbox telemetry, a `sysctl` debugger check that gates the final reveal, and a 16-character ticket check that gates a flag decrypted with a key derived from the ticket. Solving it takes static recovery (the config key stream, the ticket transform, the flag key) and dynamic confirmation (watching the DNS and HTTP calls happen in a sandbox).

The ticket check runs whether or not the network steps succeed, so the request does not need to work to solve the challenge.

## Files

- `restlessotter.c` - full source
- `Makefile` - `make release` (stripped binary, the challenge), `make debug` (builds `restlessOtter_debug` with symbols and `-O0`), `make strings-check` (greps the release binary for challenge strings), `make clean`
- `restlessOtter` - prebuilt Mach-O 64-bit arm64 executable (PIE), ready to hand out or detonate on Apple Silicon
- `student.md`, `instructor.md`, `SOLUTION.md` - the student guide, the instructor key, and the spoiler notes

## Build

The prebuilt binary is arm64 only, so it runs on Apple Silicon Macs. On an Intel Mac, rebuild with `make release` before use.

On macOS:

```sh
make release
```

Debug build:

```sh
make debug
```

Quick string hygiene check:

```sh
make strings-check
```

The `strings-check` target looks for challenge strings that should not appear in the stripped release binary. System and library strings may still appear, especially in the debug build.

## Suggested demo flow

**1. First pass - `file` / `strings` (no tools yet)**

```
file restlessOtter
strings -n 6 restlessOtter
```

`file` reports a 64-bit arm64 Mach-O executable. `strings` shows only linker and system names, the library paths, a lowercase `restlessotter` identifier, and the names of the imported functions. The imports already hint at the behavior: `_getaddrinfo`, `_connect`, `_send`, `_recv`, `_sysctl`, and `_getpid`. There is no banner, config, usage text, ticket, or flag in plain text, because the application strings are stored encrypted. A raw dump is a start, not an answer.

**2. Static analysis - Ghidra via MCP**

Load `restlessOtter`. Only the entry point and the imports carry names. Suggested labeling pass:

- `main` - the entry point. Call order: banner, then an argument-count check, then (with one argument only) config decode and port decode, two DNS probes, the phone-home request, the debugger check, the ticket check, and the flag reveal.
- The shared decoder - the only other function in the program's own code. It takes a destination, a source, a length, and a seed, and it runs a running key stream.
- The encrypted blobs - banner, config, port, serial table, flag blob, and the strings used by the request and the messages.
- The ticket check - a 16-byte length test, a per-byte transform against a 16-byte table, and a rolling checksum.
- The debugger check - a `getpid` and `sysctl` call, then a bit test on the process flags.

The config decodes to five `name=value` pairs. They are the host, path, DNS probe target, campaign, and HTTP user agent. The ticket and the flag are the answers; see `SOLUTION.md` if you want them without the reversing.

**3. Indicator triage - Recorded Future MCP**

Take the decoded config values, record each in your IOC table with its label (shared service or classroom label), and look up the ones that need it:

- `github.com` - the HTTP host and one of the DNS probe targets. A shared service, not a blocklist entry.
- `example.com` - the other DNS probe target. A reserved documentation domain (RFC 2606).
- `operation-tidepool` and `restlessotter-lab/3.0` - the campaign label and the user agent. Classroom labels, not infrastructure.

The teaching point: triage shows which indicators are worth pivoting on and which are shared services or placeholders, before you spend analyst time on them.

**4. Dynamic behavior - Recorded Future Sandbox**

Detonate `restlessOtter` twice: once with one argument (a wrong ticket is fine), and once with no argument. With one argument you should see:

- DNS lookups for `example.com` and `github.com`
- a TCP connection to `github.com` on port 80, and a `GET /` request with `User-Agent: restlessotter-lab/3.0`
- no output from the network steps; the only visible output is the banner and the ticket result

With no argument you should see the banner and the usage line, and no network activity. If your sandbox attaches a debugger, the traced branch prints the decoy `RO{SLEEPY_DECOY}` and skips the ticket check. That is expected in a traced run and is worth calling out: a debugger-based pass can change what the program does. The sandbox must be able to run arm64 Mach-O files; see `instructor.md`.

**5. The reveal**

On a Mac with no debugger attached, run the program with the ticket recovered in step 2:

```
./restlessOtter <recovered ticket>
```

A correct ticket prints the acceptance line and the flag. See `SOLUTION.md` if you want the answers without doing the reversing. It is kept separate so it doesn't spoil the `strings` pass.

## Notes on the embedded indicators

Every network value in this binary is either a reserved or widely used public name (`example.com`, `github.com`) or a classroom label (`operation-tidepool`, `restlessotter-lab/3.0`). The only network traffic is the two DNS lookups and one HTTP/1.0 `GET /` on port 80 to `github.com`. Nothing else is contacted. For IOC tables, label the hostnames as shared services and the campaign and agent values as classroom labels.

The config is stored encrypted. To point the traffic somewhere else, change the config in source, re-encode the blob with the same key stream, and rebuild. Don't point it at infrastructure you don't control.

Run this binary only in a sandbox, or on a Mac you control, and only after the static part of the exercise.

# Restless Otter (student)

Benign macOS crackme, compiled as a Mach-O arm64 executable. It runs on Apple Silicon Macs only. On an Intel Mac it will not run, so tell the instructor before class.

Run it from Terminal with exactly one argument, as `./restlessOtter <input>`. With no argument, it prints a usage line and stops.

It has no persistence and no destructive behavior. Its network request goes to a public service, and the program does not need that request to succeed to finish the check.

## What to establish

1. **Format and architecture.** Confirm the file type and architecture, and that you are analyzing this exact binary. Run `strings` and note that the readable application text is hidden.
2. **String decoder.** Find the shared routine that turns the encrypted byte arrays back into text. Identify its callers.
3. **Configuration.** Decode the configuration. Recover the host, the path, the DNS probe target, the campaign label, and the HTTP User-Agent value. Record the address where each one is decoded.
4. **Anti-debug gate.** Find the macOS check that asks the kernel whether a debugger is attached (`sysctl`, then the `P_TRACED` flag). Say what it controls. Check which behavior happens before it.
5. **Ticket check.** Find the routine that checks your 16-character input. Verify the length requirement and the per-character comparison, with addresses. Describe the rolling checksum at a high level.
6. **Ticket to decryption.** Trace the data flow from the validated ticket to the routine that decrypts the flag. Explain which function passes the data, and why it matters.

The full inversion of the ticket transform, the checksum reproduction and the flag decryption are take-home work. You do not need them in class.

## Indicators

- `github.com` and `example.com` are `shared service` entries, not blocklist items.
- The campaign label and the User-Agent value are `classroom decoy` entries. Record the address where each was decoded.
- The host and DNS entries are labeled as decoys or shared services. Give the address of the decoded configuration for each.

## Files

- `restlessOtter` – the arm64 Mach-O release executable. 
- `student.md` – the step-by-step guide for this exercise.
- `README.md` – this file.

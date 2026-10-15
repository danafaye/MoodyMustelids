# Soggy Badger (student)

Benign Windows 64-bit crackme. It is a PE file, so Ghidra, PE viewers and the import table are all useful.

**Before class:** the instructor will confirm this exact file runs on the classroom Windows machine. If it does not run for you, tell the instructor.

Run it as `soggyBadger.exe <input>`.

It creates a named mutex, writes a short-lived registry value, makes DNS and HTTP requests, and runs anti-debug checks. It does not persist after the process exits, and its only outbound request goes to a public, documentation-safe host.

## What to establish

1. **First pass.** Run `strings` and look at the import table. Note what is visible and what is not. Some configuration is missing from a plain strings scan. Work out why.
2. **Stack strings.** Find the routines that build text one byte at a time in a local buffer. Reconstruct one string: put the bytes in buffer-offset order, check where it ends, and find the code that consumes it.
3. **Input check.** Describe what the routine does to each character of your input and how it compares the result to a fixed constant. Give the addresses. The routine is a one-way hash, so do not try to invert it. Test candidate names instead: write down how you would apply the same arithmetic to a candidate name and compare the output with the constant.
4. **Host artifacts.** Find where the mutex is created and where the registry value is written and removed. Record the mutex name, and the registry key and value, each with its address.
5. **Anti-debug.** Find one check (a Windows API call or a direct read of the process block). Say what it controls and whether it guards the reveal.

Do not assume every path ran. Check the controlling conditions.

## Indicators

- The mutex name and the registry key and value are host indicators, labeled `classroom decoy`. Record them with their code addresses.
- Domains and IPs the code uses: label each one. Reserved documentation names are `classroom decoy`. Public services are `shared service`.

## Files

- `soggyBadger.exe` – the 64-bit Windows release executable.
- `student.md` – the step-by-step guide for this exercise.
- `README.md` – this file.

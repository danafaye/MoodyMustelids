# SOLUTION (spoilers) - soggybadger

Keep this one off the projector too.

## Stack-string config (reconstruct from the stack-string code in `main`)

In `soggybadger.c` the builders are separate static functions. In the shipped `soggyBadger.exe` they are inlined into `main`, so reconstruct each value from the immediate stores and the data fragments in `.rdata`.

- mutex name: `SoggyBadgerSingleton_Mutex`
- fake domain: `c2.soggybadger-demo.invalid`
- fake IP: `203.0.113.9`
- safe domain: `example.com`
- campaign tag: `operation-wet-blanket`

The program also prints these values at runtime in its config line, so a sandbox report shows them as well.

## Registry check-in

`HKCU\Software\SoggyBadgerDemo\Marker` = `soggybadger-demo-marker`
(written, then deleted again before the process exits)

## The hash gate

Algorithm:
```
h = 0
for each character c in the input string:
    h = ROR32(h, 13)
    h = h + (unsigned char)c
```

Target constant: `0xa2ac2abd`

The five imported DLL base names and their hashes under this algorithm
(the import table stores `msvcrt.dll` in lowercase; the hint asks for
uppercase base names, so the candidate here is `MSVCRT`):

| Candidate | Hash | Match? |
|---|---|---|
| `KERNEL32` | `0x8cb0fcbb` | no |
| `MSVCRT`   | `0x2e95413b` | no |
| `WININET`  | `0x1588f3f9` | no |
| `WS2_32`   | `0xe59d481d` | no |
| `ADVAPI32` | `0xa2ac2abd` | **yes** |

Correct input: `ADVAPI32`

## Flag

XOR key: `2f c4 88 51 da 06` (repeating, 6 bytes)

```
SB{STACK_STRINGS_WIN}
```

## Anti-debug bypass

Two independent checks both have to be defeated to reach the hash check
while live-debugging:

1. `IsDebuggerPresent()` - the well-known one; a lot of naive
   anti-anti-debug advice stops here.
2. Manual PEB `BeingDebugged` read (`gs:[0x60]` then `+2`) - survives a
   simple IAT hook or breakpoint on `IsDebuggerPresent`, since it never
   calls that API at all.

Simplest path for a live demo: don't attach a debugger, just run the
binary directly with the recovered argument (this is what step 6 in
README.md does). If you want to demo an actual bypass: patch both
comparison branches in Ghidra, or, in a debugger once attached, set the
`BeingDebugged` byte read at PEB+2 back to 0 and make `IsDebuggerPresent`
return 0 (for example with a breakpoint on it, or an IAT hook).

## IOC labels (for the IOC table)

- Mutex `SoggyBadgerSingleton_Mutex`: host IOC (mutex). Classroom artifact.
- Registry key and value under `HKCU\Software\SoggyBadgerDemo`: host IOC (registry). Classroom artifact; the value is removed before exit.
- `c2.soggybadger-demo.invalid` and `203.0.113.9`: classroom decoys (reserved `.invalid` TLD and TEST-NET-3 documentation range).
- `example.com`: shared service. The only HTTP request goes to `http://example.com/`.
- `operation-wet-blanket`: classroom label; useful only for lesson pivots.
- Imported DLL names and the `0xa2ac2abd` constant: resolution data, not IOCs.

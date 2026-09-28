# SOLUTION (spoilers) - soggybadger

Keep this one off the projector too.

## Stack-string config (reconstruct by reading each builder function)

- mutex name: `SoggyBadgerSingleton_Mutex`
- fake domain: `c2.soggybadger-demo.invalid`
- fake IP: `203.0.113.9`
- safe domain: `example.com`
- campaign tag: `operation-wet-blanket`

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

The three real imported DLLs and their hashes under this algorithm:

| Candidate | Hash | Match? |
|---|---|---|
| `KERNEL32` | `0x8cb0fcbb` | no |
| `WININET`  | `0x1588f3f9` | no |
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
comparison branches in Ghidra (or in a debugger, once attached, flip the
flag PEB reads back to 0 after the fact), or use a debugger/plugin that
clears `PEB.BeingDebugged` and doesn't trip `IsDebuggerPresent` (several
common RE debugger plugins do this specifically to defeat this exact
pair of checks).

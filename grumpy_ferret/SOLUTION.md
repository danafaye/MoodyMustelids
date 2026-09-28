# SOLUTION (spoilers)

Keep this one off the projector.

## Config blob

XOR key: `13 37 c0 de` (repeating, 4 bytes)

Decoded config string:
```
ens=definitely-not-c2.eth;ip=203.0.113.7;domain=c2.grumpyferret-demo.invalid;safe=example.com;campaign=operation-ghidra-snack
```

## Serial

- `MAGIC`  = `4d 43 50 2d 52 46 2d 47 48 49 44 52` (ASCII: `MCP-RF-GHIDR`)
- `TARGET` = `0a 0c 1b 6c 04 0c 71 09 22 24 0b 11`
- Transform: `enc[i] = ((input[i] ^ MAGIC[i]) + i) & 0xFF`
- Inverse:   `input[i] = ((TARGET[i] - i) & 0xFF) ^ MAGIC[i]`

Correct serial: `GHIDRAFERRET`

## Flag

XOR key: `9c 5a e1 03 7f` (repeating, 5 bytes)

```
GF{DRUNK_AS_A_FERRET}
```

## Anti-debug bypass

The tracer check reads `/proc/self/status`, looks for the `TracerPid:`
line, and takes the decoy branch if that PID is nonzero. Two easy ways
around it for a live demo:

1. Don't attach via `ptrace` at all - run it directly with the recovered
   serial (no debugger), which is the simplest path and the one the
   README's step 5 uses.
2. If you want to demo an actual live bypass: patch the conditional jump
   following the `TracerPid` compare in Ghidra (flip it or NOP it) and
   re-run under a debugger, or use an LD_PRELOAD shim that intercepts
   `fopen("/proc/self/status", ...)` and returns a stream containing
   `TracerPid: 0`.

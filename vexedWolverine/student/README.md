# Vexed Wolverine

Expert bonus challenge for the Recorded Future Ghidra AI MCP class.

Recover the unique 32-character ticket and the genuine flag. A message that
looks like a flag is not proof that you solved the challenge. Be ready to
explain the validation path and show why the recovered flag is genuine.

The ticket alphabet is uppercase `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`.

Linux:

```sh
./vexedWolverineLinux YOUR_32_CHARACTER_TICKET_HERE
```

Use Ghidra, scripts, a debugger or AI assistance as you see fit. A debugger
is a tool that pauses a program and lets you inspect its memory and registers. Document
important functions, data structures and transformations. This is intended
to be substantially harder than the three core exercises; do not expect to
solve it by searching strings or changing a single conditional branch.

These are benign educational programs. They interpret their own embedded
data, run one worker thread and may query debugger status. They have no
network activity, persistence, process injection, credential collection or
destructive actions. Analyze them in the course lab.

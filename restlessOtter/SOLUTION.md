# SOLUTION (spoilers)

Keep this one off the projector.

These notes follow the current binary (`restlessOtter`, SHA-256 `66cde9e0e9b3124667b4e676b9115ba10d72040cd9e8cf6e873f02bae59d5c13`). `instructor.md` has the addresses and the verification notes.

## Running the program

- No argument (or more than one): prints the banner and a usage line, then exits with code 1. No config, network, or ticket steps run.
- Exactly one argument: decodes the config, runs the DNS and HTTP steps, runs the anti-debug check, then checks the ticket.

## Key stream

The shared decoder uses this key stream, with the seed given for each blob:

```text
state = seed
for each byte i:
    state = (33 * state + i + 0x11) & 0xff
    key   = state ^ ((29 * i + 0x5a) & 0xff)
    out[i] = in[i] ^ key
```

## Runtime config

The encrypted config blob (seed `0x77`) decodes to:

```text
host=github.com;path=/;dns=example.com;campaign=operation-tidepool;agent=restlessotter-lab/3.0
```

The program does not print the decoded config. Students recover it from the code.

## Network

With one argument, the binary resolves `example.com`, resolves `github.com`, then opens a TCP connection to `github.com:80` and sends this request:

```text
GET / HTTP/1.0
Host: github.com
User-Agent: restlessotter-lab/3.0
Connection: close

```

It reads up to 256 bytes of the reply and discards them. There are no socket timeouts. The program prints nothing for these steps, whether they succeed or fail. The only evidence of them is the network traffic in a sandbox capture.

## Ticket

The correct ticket is:

```text
TIDEPOOL-MAC-026
```

The validation requires exactly 16 bytes. For each byte `i`:

```c
v = ticket[i] ^ (0x41 + i * 13);
v = v + i * 7 + 0x23;
v = rol8(v, (i % 5) + 1);
/* must equal SERIAL_TABLE[i] */
```

The loop also updates a rolling checksum, starting at `0x6d2b79f5`, using multiplier `0x45d9f3b` and adding `i + 0x1337`. The compiled compare uses `0x7c538b83`, which is the source value `0x7c539eb9` after the compiler folds in the last iteration's index. Students who compare with the source value will see the difference in Ghidra. It is expected.

## Flag

With the correct ticket, the flag blob (seed `0x9b`) decrypts to:

```text
RO{MAC_OTTER_CURRENT}
```

For each byte, the mask is `((ticket[i % 16] + 31 * i + 0xa7) & 0xff) ^ key`, and the output byte is the blob byte XORed with the mask. Output on success is `[+] ticket accepted.` followed by the flag. Exit code 0.

## Anti-debug

If the process is being traced on macOS, the `sysctl` check reads the `P_TRACED` (`0x800`) bit of the process flags. The program prints `[!] debugger detected. RO{SLEEPY_DECOY}` and skips the ticket check. Exit code 2. The decoy `RO{SLEEPY_DECOY}` is not the flag.

A wrong ticket prints `[-] incorrect ticket. RO{SLEEPY_DECOY}` and exits with code 0. The decoy appears on a wrong ticket too, so it is not evidence of a tracer.

Two easy ways around the check for a live demo:

1. Don't attach a debugger. Run the program directly with the recovered ticket. This is the simplest path.
2. In a copy you own, change the bit test so the traced branch is never taken (for example, replace the conditional branch after the `sysctl` call with an unconditional branch to the not-traced path).

## IOC labels (for the IOC table)

- `github.com` (host and HTTP request on port 80): shared service.
- `example.com` (DNS probe): reserved for documentation, shared service.
- `operation-tidepool` and `restlessotter-lab/3.0`: classroom labels; useful only for lesson pivots.
- The `P_TRACED` check is behavior, not an IOC.

## Source note

`restlessotter.c` matches the current binary's behavior and blob contents. The network helpers print nothing unless the program is built with `RO_VERBOSE` set to 1, which the Makefile does not do.

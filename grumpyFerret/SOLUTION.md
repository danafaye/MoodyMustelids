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


## Additional YouTube acrostic stage

The original serial and final embedded flag are unchanged. A separate
downloaded classroom flag is obtained before serial validation. Identify
`gf_youtube_stage`, recover its repeating XOR key and decode `GF_YT_STAGE`.
The recovered Python code reveals the video, comment search, acrostic
decoder and fixed GitHub resource. Each sentence initial gives one letter:
**N E W B I E**. Lowercase that identifier and add `_notes.txt` below the
configured public Gist revision root.

The natural-language draft is `instructor_youtube/youtube_comment.txt`.
The flag is published as `newbie_notes.txt` in the public Gist. The decoder
appends that filename to the pinned gist.githubusercontent.com revision
root, downloads a small ASCII flag and prints it only after the correct serial is accepted. Downloaded bytes are never
treated as Python, shellcode or native executable content.

The reader now uses the public watch page and its comment-loading
continuations. It does not read a developer API key or account credentials.
`page_config` extracts initial JSON and selected browser-context fields;
`public_comments` follows bounded continuations; `normalize_comments`
handles the old renderer and current entity schemas. No static page key is
copied into the reader. After posting the draft, optionally set
`GF_YOUTUBE_COMMENT_ID` to the ID in its comment link to pin the selection.

The live check found the expected comment and verified the Gist download.
Keep the fixture available for sandbox connectivity failures and schema
changes. Refer to the stored live and offline verification records rather
than treating a fixture run as proof of a current public response.

## IOC labels (for the IOC table)

- Configured `ens`, `ip` and `domain` values: classroom decoys. `203.0.113.7` is a documentation address and `.invalid` is a reserved TLD.
- `example.com`: shared service (reserved for documentation, clean reputation).
- `api.ipify.org` (requested at runtime): shared service. Context for the recon behavior, not a blocklist entry.
- GitHub Gist resource and the `GF_YOUTUBE` comment stage: classroom resource. Report it as a fetched text file, not as a live payload.
- `campaign=operation-ghidra-snack`: classroom label; useful only for lesson pivots.

# grumpyferret

A small, benign "crackme" built to demo three tools together on one target:
Ghidra (via MCP) for static analysis, Recorded Future Sandbox for dynamic
behavior, and Recorded Future MCP for indicator triage. It does nothing
harmful. No real C2, no persistence, no destructive behavior. The optional
YouTube-comment stage retrieves a public GitHub Gist text flag and prints it only
after the correct serial; it does not execute downloaded content.

It behaves like a miniature commodity bot: a banner, an
XOR-encoded config with network-looking indicators, real DNS/HTTP calls to
generate sandbox telemetry, a lightweight anti-debug gate, and a
serial-check gating a hidden flag. Solving it end to end takes both static
recovery (the config XOR key, the serial transform) and dynamic
confirmation (watching the DNS/HTTP calls actually happen), which is the
same static+dynamic correlation habit real sample triage uses.

## Files

- `grumpyferret.c` - full source
- `Makefile` - `make release` (stripped, the actual challenge binary),
  `make debug` (symbols, for your own reference), `make static` (optional,
  see the caveat in the Makefile about DNS in static builds)
- `grumpyFerret` - prebuilt stripped x86_64 ELF (the Linux executable format), ready to hand out
  or detonate

## Suggested demo flow

**1. First pass - `file` / `strings` (no tools yet)**

```
file grumpyFerret
strings -n 6 grumpyFerret
```

This surfaces the banner and three decoy strings that look like flags (`GF{TRY_AGAIN_LOSER}`,
`GF{404_FLAG_NOT_HERE}`, `backup_flag=GF{NICE_TRY}`). None of them are the
real flag. Good moment to make the point that a raw string dump is a start,
not an answer, and it's the same reason real samples carry dead code and
red-herring strings.

You'll also spot a 12-byte run that reads `MCP-RF-GHIDR`. That's the
transform's magic constant, sitting there in plain ASCII. Worth pausing on:
this is deliberately the same kind of "the magic bytes matched a known
value" moment that real triage relies on when a constant matches a known tool or family.

**2. Static analysis - Ghidra via MCP**

Load `grumpyFerret` (stripped, so no function names to lean on).
Suggested labeling pass, mirroring how you'd triage an unknown sample:

- `main` - identify the call order: banner -> config decode -> DNS probes
  -> phone-home -> (debug check) -> serial validate -> flag reveal
- the config-decode function - recover the 4-byte repeating XOR key and
  the encoded blob; decode it by hand or by scripting the same transform
  Ghidra shows you. It resolves to `ens=...;ip=...;domain=...;safe=...;
  campaign=...` - four indicators worth pivoting on.
- the serial-validate function - recover the 12-byte `MAGIC` array and the
  12-byte `TARGET` comparison array, and the per-byte transform
  `enc[i] = ((input[i] ^ MAGIC[i]) + i) & 0xFF`. Inverting it recovers the
  correct 12-character serial.
- the tracer-check function - point out the `/proc/self/status` /
  `TracerPid` read as the anti-debug gate, and that it only guards the
  final serial-check step, not the recon/network behavior before it.

**3. Indicator triage - Recorded Future MCP**

Take the four values recovered from the config blob, record each in your IOC table with its label (classroom decoy or shared service), and look each one up:

- `definitely-not-c2.eth` - an ENS-style name, not a real on-chain record
- `203.0.113.7` - IANA TEST-NET-3 (RFC 5737), reserved for documentation,
  never real infrastructure
- `c2.grumpyferret-demo.invalid` - `.invalid` is an RFC 2606 reserved TLD,
  guaranteed unregistrable
- `example.com` - real, RFC 2606 reserved-for-documentation domain, clean
  reputation

The teaching point: RF lookups let you immediately triage which of a
sample's "indicators" are worth pivoting on and which are placeholders or
decoys, before you burn analyst time on infrastructure that was never
real. Real samples rarely make this obvious; this one makes it obvious on
purpose so the lesson lands.

**4. Dynamic behavior - Recorded Future Sandbox**

Detonate `grumpyFerret` with a plausible serial as the argument
(or with none, to see the recon-only path). You should see:

- DNS resolution attempts for all three fake/placeholder indicators
  (expect NXDOMAIN / no-such-host style failures)
- a successful DNS resolution and HTTP request to `api.ipify.org` (a real,
  safe public-IP-check service - the same recon trick a lot of commodity
  malware uses. Label it a shared service in your IOC table, not a blocklist entry)
- if your sandbox platform instruments the process via `ptrace` (the Linux
  debugger interface), the
  tracer-check branch will fire and you'll see the decoy path
  (`GF{TRY_AGAIN_LOSER}`) instead of the real flag, even with the correct
  serial. That's expected and worth calling out live: it's the same reason
  a debugger-based dynamic pass on a real sample can miss behavior that a
  non-ptrace approach (or static analysis) would have caught.

**5. The reveal**

Run it directly, no tracer attached, with the serial recovered from step 2:

```
./grumpyFerret <recovered serial>
```

Correct input prints the real flag. See `SOLUTION.md` if you want the
answer without doing the reversing (kept separate so it doesn't spoil the
`strings` pass on this file).

## Notes on the embedded indicators

Every network-looking value in this binary is deliberately either
IANA/IETF-reserved for documentation (`203.0.113.0/24`, `.invalid`,
`example.com`) or a fictional ENS-style string with no real on-chain
record. Nothing in this binary will contact or affect real infrastructure
except the intentional public-IP request to `api.ipify.org`, the optional
public YouTube page and comment requests (no API key) and the fixed GitHub classroom text-file download. For IOC tables, label these values as classroom decoys or shared services.


## YouTube-comment classroom stage

The executable contains an XOR-encoded Python reader. Before serial
validation, it decodes that reader and starts `/usr/bin/python3 -c` without
a shell. Python 3 is the only additional runtime dependency. No separate
helper script, supplied API key, GitHub token or account login is required.

It opens the public watch page for video `4ok4e0Jvy_4`, parses the initial
JSON and browser context, and follows YouTube's comment-loading requests (the next-page requests that fetch more comments).
It supports both legacy comment renderers and newer comment entities, and
selects newest-first ordering when that menu is available. It scans at most
six continuation responses. Each network request has a ten-second timeout;
the watch page is capped at 4 MiB and comment responses at 2 MiB.

The first letters of six sentences in the prepared comment spell `NEWBIE`.
The reader turns that into `newbie_notes.txt` under the configured public
Gist revision. `GF_YOUTUBE_COMMENT_ID` optionally pins a particular comment.
The exact Gist URL is allowlisted. Redirects are rejected and the download
is limited to an 8 KiB ASCII `GF{...}` text flag. The bytes are printed only
after the correct serial, never saved or executed.

Live verification found the matching comment on the selected video and
downloaded the public Gist without authentication. These are observations
from this environment, not a guarantee that YouTube will accept requests
from every sandbox. Consent pages, filtering and page/schema changes can
block automated reading. Use the fixture for a repeatable class rehearsal.
Missing remote evidence is reported as a failure, not simulated success.

The draft and verification records are in `instructor_youtube/`. The
offline suite passed 31 checks for parsing, comment selection,
format limits, the compiled embedded stage and the existing serial paths.
See `public_page_live_verification.json` and `native_live_verification.json`
for the live results actually obtained.

For a fully offline run from this directory:

```sh
GF_OFFLINE=1 \
GF_YOUTUBE_FIXTURE=instructor_youtube/youtube_comments_fixture.json \
GF_FLAG_FIXTURE=instructor_youtube/newbie_notes.txt \
./grumpyFerret '<serial>'
```

`GF_OFFLINE` skips only the original DNS/public-IP probes. Both fixture
variables are also needed to keep the embedded reader offline. For a live
comment demonstration without the original probes, set only `GF_OFFLINE=1`
and leave the fixture variables unset. Synthetic output is labeled as such.
The fixture uses normalized comment records; it is not evidence of a live
YouTube response. Rebuild after editing the stage with `make release`.

The public browser interface is undocumented and can change. Reference for
the current renderer and continuation shapes:
[yt-dlp's YouTube extractor](https://github.com/yt-dlp/yt-dlp/blob/master/yt_dlp/extractor/youtube/_video.py).

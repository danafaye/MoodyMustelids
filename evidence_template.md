# Evidence and IOC template (one page)

## Evidence row

| Finding / value | Sample and role | Source and date | Reference / address | Status | Operation outcome | Confidence and reason | Next question |
| --- | --- | --- | --- | --- | --- | --- | --- |
| | | Sandbox / Ghidra-code / Malware Intelligence / synthetic fixture | | Observed / Attempted / Decoded / Inferred / Unverified | Succeeded / Failed (error) / Timed out / Unknown / N/A | | |

## IOC row

| Type | Defanged value | Source | Reference / address | Status | Label | Confidence and reason |
| --- | --- | --- | --- | --- | --- | --- |
| domain / IP / URL or request line / file name / hash / registry key / mutex / user-agent / configuration string | | | | | `malicious-candidate` / `classroom decoy` / `shared service` | |

## Status definitions

- **Observed:** recorded directly in a named sandbox run or runtime capture (environment, reference, date).
- **Attempted:** an operation was started. The outcome is recorded separately. A DNS request with no answer is an attempt, not a confirmed connection.
- **Decoded:** reproduced from bytes using a transformation recovered from code. The sample was not run. Cite the data and decoder.
- **Inferred:** an interpretation supported by evidence but not yet reproduced or observed. State the basis and the uncertainty.
- **Unverified:** a claim whose support you have not checked, including AI output.

## Rules

- Defang every domain and URL in a shared handout.
- Fixture results carry the tag `synthetic fixture`.
- A no-match result does not establish that a value is safe.
- Shared services are context, not blocklist entries.
- Only `malicious-candidate` rows go forward to Malware Intelligence searches.

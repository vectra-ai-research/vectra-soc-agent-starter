---
name: vectra-pcap
description: Pulls the PCAP attached to a Vectra network detection via the MCP server, which writes it to disk and returns the file path, then runs a structured tshark triage pass against that file — TLS Client Hello tuples (SNI, JA3, cipher, ALPN, JA4), HTTP auth, NTLM/Kerberos, SMB shares, RPC bindings, DNS history, SSH, and ProcessCommandLine strings — to feed evidence back into the detection verdict. Use when the user asks for the PCAP, raw packets, or wire-level evidence for a detection. Cloud and log-based detections (M365, Azure AD, AWS) have no PCAP — route those to vectra-investigator.
---

# Vectra PCAP — Detection PCAP Retrieval & Local Triage

This skill bridges Vectra's per-detection PCAP attachment to a local
`tshark` triage pass. It does **two** things:

1. **Pull** the PCAP for a given `detection_id` by calling the Vectra
   MCP tool `vectra-ai-mcp:get_detection_pcap`, which writes the capture
   to disk server-side and returns its path, size and sha256. The packet
   bytes never pass through the conversation.
2. **Triage** the resulting capture file with `scripts/pcap-context.sh`
   — a single tshark-driven helper that emits TLS metadata plus HTTP /
   Windows / SSH auth, SMB shares, RPC, DNS, and `ProcessCommandLine`
   indicators in one pass, formatted for analyst review and pipe-friendly
   JSON.

The output feeds back into the detection's verdict (the
`vectra-investigator` Step 5 / matching `playbook-<category>.md`
evidence column). PCAP-derived signals do **not** override Vectra's
behavioral verdict — they corroborate or refute it.

---

## Use this skill when

- The user names a specific Vectra detection and asks "show me the
  packets" / "pull the PCAP" / "what's actually on the wire".
- A `vectra-investigator` `playbook-<category>.md` needs a 5-tuple
  confirmation, a TLS SNI, an SMB share name, or a Kerberos principal
  that the Vectra metadata view doesn't surface directly.
- A `vectra-hunt` recipe lands on a suspicious detection and the user
  wants to confirm the conversation contents (e.g. failed NTLM auth,
  unusual ALPN, large HTTP POST) before escalating.
- The user has a PCAP on disk already (from another tool) and wants the
  same structured triage (`scripts/pcap-context.sh <file>` works
  standalone — the MCP fetch is optional).

Do **not** use this skill to:

- Pull a PCAP for a **cloud / log-based** detection (M365, Azure AD,
  AWS, Entra). Those have no underlying capture — the Vectra API
  returns `406 Not Acceptable`. Route back to
  [`vectra-investigator`](../vectra-investigator/SKILL.md) (which will
  load the matching cloud `playbook-<category>.md`).
- Do live capture. Local `tshark`/`tcpdump` against the analyst host is
  out of scope here.
- Override the Vectra behavioral verdict. PCAP evidence is corroboration,
  not a kill switch.
- Hunt across the tenant. Use [`vectra-hunt`](../vectra-hunt/SKILL.md)
  for metadata-level queries that often answer the same question
  without leaving the platform.

---

## Known limitation — requires a shared filesystem

**This skill only works where the MCP server and your shell run on the same
machine.** That is true in Claude Code (terminal) and false in Cowork, where
bash runs in an isolated Linux VM. Verified 2026-08-24:

| | Claude Code | Cowork |
|---|---|---|
| MCP server writes the capture to | the Mac's `/tmp/vectra-pcap/` | the Mac's `/tmp/vectra-pcap/` |
| `pcap-context.sh` runs on | the Mac — same host, path resolves | a Linux VM whose `/tmp` is its own |
| `tshark` available | yes, via `brew install wireshark` | **no, and cannot be installed** — no root, `no_new_privs` set |

Two independent blockers in Cowork, so no configuration rescues it: the capture
is unreachable *and* the analysis binary cannot be installed. Sharing the
capture through a connected folder would fix the first and not the second.

Historical note, because it explains a design that otherwise looks wrong: the
tool used to return base64 of the whole capture inline, and this skill told you
to `echo` it into `base64 -d`. That was a workaround for exactly this host
split — re-emitting the bytes was the only way to get them across a filesystem
boundary. It was abandoned because it only worked on trivially small captures
and because the chain-of-custody `shasum` ran *downstream* of the
transcription, fingerprinting whatever came through rather than what Vectra
sent. The path-based contract is correct on a shared host and removes the
Cowork path entirely rather than pretending to support it.

**Open for future discussion**, not currently blocking: a pure-Python triage
fallback (scapy or dpkt, installable without root) would make the skill work in
sandboxed hosts, at the cost of reimplementing the tshark field extraction. Not
worth doing until someone actually needs PCAP triage from Cowork.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **Vectra MCP server connected** | `vectra-ai-mcp` tools must be visible — specifically `vectra-ai-mcp:get_detection_pcap`. If MCP is missing, fall back to downloading the PCAP from the Vectra UI manually and run the analysis pass on the local file. |
| **`tshark`** | Wireshark CLI. Install: `brew install wireshark` (macOS) or `apt install tshark` (Debian/Ubuntu). |
| **`jq`** | Used by `pcap-context.sh` for output assembly. |
| **`python3`** | Used by `pcap-context.sh` for tabular field parsing. |
| **JA4 plugin** *(optional)* | If a JA4 / JA4+ tshark dissector is installed (FoxIO, ThreatRelay), `pcap-context.sh` will surface JA4 fingerprints automatically. Without it, the TLS section still emits tuples, SNI, ALPN, JA3, and cipher info. |

---

## Workflow

### 1. Confirm the detection has a PCAP

PCAPs are only attached to **network-based** detections (Vectra Brain,
sensor-derived). Cloud/log detections (`category: ACCOUNT*`, `M365`,
`AAD`, `AWS`, `Azure`) have none. A quick check before fetching:

- The detection's `category` is one of the network categories
  (Command & Control, Exfiltration, Lateral Movement, Reconnaissance,
  Botnet, Info, etc.).
- The detection's host / source / destination is an internal IP, not a
  cloud account.

If unsure, just call `get_detection_pcap`; the MCP tool returns a clean
"no PCAP available" message on `404` and "not generated for cloud /
log-based detections" on `406`.

### 2. Pull the PCAP via MCP

Call the MCP tool directly:

```
vectra-ai-mcp:get_detection_pcap  detection_id=<id>
```

The server writes the capture to disk and returns **metadata only** — the
packets never enter the conversation:

```json
{
  "detection_id": 19574,
  "pcap_available": true,
  "path": "/tmp/vectra-pcap/detection-19574.pcap",
  "size_bytes": 481203,
  "sha256": "9f2c…",
  "format": "pcap"
}
```

Take `path` and go straight to step 3. **Do not read the file into context**
and do not try to reconstruct it — there is nothing to decode.

> Earlier versions returned base64 of the whole capture inline, and this step
> told you to `echo` that body into `base64 -d`. That meant re-emitting every
> byte of a packet capture as a shell argument: unusable beyond a trivial size,
> and it put the chain of custody *downstream* of the transcription. The
> `sha256` above is taken on the bytes as received from Vectra, so verifying it
> now proves the file matches what Vectra sent:
>
> ```bash
> shasum -a 256 /tmp/vectra-pcap/detection-19574.pcap
> ```
>
> A mismatch means the file changed after download — not that the copy is fine.

Two fields are worth checking before spending time on analysis:

- **`pcap_available: false`** — the detection has no PCAP. See
  [Cloud vs. network detections](#cloud-vs-network-detections).
- **`format: "unrecognised"`** with a `warning` — the file does not start with
  a pcap/pcapng magic number, so it is probably truncated or an error body
  saved verbatim. `tshark` will fail confusingly on it; re-pull instead of
  debugging the filter.

If the returned `path` does not exist from your shell, the MCP server is
running on a different host or container than your tools. That is a deployment
issue, not a PCAP issue — fall back to downloading the capture from the Vectra
UI and run step 3 against the local file.

### 3. Run the structured triage pass

```bash
# Human-readable summary plus full JSON dump at the end:
./scripts/pcap-context.sh /tmp/vectra-pcap/detection-19574.pcap

# JSON only — pipe to jq / a hunt pipeline / a report:
./scripts/pcap-context.sh --json /tmp/vectra-pcap/detection-19574.pcap | jq .
```

The script emits one capture-wide JSON document with these top-level
sections:

| Section | What it captures |
|---------|------------------|
| `tls` | TLS Client Hello tuples, SNI, ALPN, ciphers, JA3/JA3S (and JA4 when the plugin exposes the field). Top-N concentrations and tuple counts. |
| `http_auth` | Requests carrying `Authorization` / Basic auth headers, with method, URI, host, user-agent, status code. |
| `windows_auth` | Merged NTLM and Kerberos exchanges — usernames, domains, realms, target servers, principals, KDC hosts. |
| `ssh` | SSH userauth requests — username, service, method. |
| `dns` | Queries with type / response code / TTL, NXDOMAIN counts, fast-flux candidates. |
| `shares` | SMB2 TreeConnect events — share names, tree paths, authenticated user. Flags admin shares (`ADMIN$`, `C$`, `IPC$`). |
| `rpc` | DCE/RPC interface bindings — UUID, name, version, endpoint. |
| `process_command_lines` | Any frame containing the literal `ProcessCommandLine:` string (Sysmon-over-the-wire artifacts, etc.). |

The human-readable summary block ends with a `Next Steps` section that
points at the natural follow-ups (feed TLS tuples into `virustotal`,
push DNS / share / cmdline observables into a SIEM hunt or
`vectra-hunt`).

### 4. Pivot back into the detection verdict

Take the structured output and fold the relevant rows back into the
investigation:

- **Confirms TP** — admin-share access, NTLM auth from an unexpected
  source, large HTTP POST to a suspicious host, NXDOMAIN bursts on
  high-entropy domains, ProcessCommandLine substrings (`whoami`,
  `Invoke-WebRequest`, etc.).
- **Suggests BTP** — known internal SNI/ALPN baseline, expected service
  account doing scheduled NTLM, DNS pointing at corporate resolvers.
- **Need-more-data** — capture window doesn't cover the alert window,
  TLS-only payloads with no SNI hits, or PCAP truncated.

Cite the `frame_number` and the section's `pcap_file` (and the
sha256 hash from step 2) when writing the verdict so another analyst
can re-derive the evidence.

---

## Operational notes

### Cloud vs. network detections

The MCP `get_detection_pcap` tool maps directly to
`GET /detections/{id}/pcap` on the Vectra Brain. The endpoint returns:

| HTTP | Meaning | What the agent should do |
|------|---------|--------------------------|
| `200` | PCAP body returned (binary). | Decode and proceed. |
| `404` | Detection exists but no PCAP attached (rare on network detections; expected on older / aged-out alerts). | Tell the user no capture is available; route to `vectra-hunt` for metadata-level pivots. |
| `406` | Detection is cloud/log-based — no PCAP is generated for M365, Azure AD, AWS, etc. | Tell the user, route to `vectra-investigator` (which will load the matching cloud `playbook-<category>.md`). |

### Chain of custody

- Always sha256-fingerprint the decoded file (`shasum -a 256 <file>`).
  Quote the hash in the case notes alongside the detection ID and
  timestamp.
- Treat the `.pcap` like any other forensic artifact — don't push it
  back to Vectra, don't share it outside the case scope, don't commit
  it to the repo.

### Privacy / data handling

- PCAPs may carry plaintext credentials, internal hostnames, document
  fragments, and PII. Keep them on the analyst host or in the case
  bucket only.
- Never submit a raw PCAP (or extracted credential strings) to a public
  TI service. The `virustotal` skill's standard-intel guard short-
  circuits private IOCs by design — keep that guard in place if you
  feed observables forward.

### Field availability quirks

`tshark` field names drift across versions and dissector plugins. The
`pcap-context.sh` script preflights `tshark -G fields` and only emits
fields that are actually exposed in the local install. Missing
dissectors degrade the matching section to empty rather than failing
the whole run. If a section is empty when you expected hits, run the
preflight commands in `references/tshark-usage.md` to confirm the
field name is present, then re-run with the alternate filter from
`references/query-corpus.md`.

### Scope discipline

- Don't pivot from the PCAP into broader hunts without confirming with
  the user. A capture often shows neighbors (the same VLAN, the same
  conversation partners) — those are *not* in scope unless the user
  asked for a wider sweep.
- Vectra captures are 5-tuple-scoped to the detection; if you need
  east-west visibility beyond the alert window, that's a `vectra-hunt`
  question, not a PCAP question.

---

## Files

- [`scripts/pcap-context.sh`](scripts/pcap-context.sh) — single-pass
  tshark triage emitting TLS / auth / lateral-movement / DNS context
  as JSON plus a human summary.
- [`references/tshark-usage.md`](references/tshark-usage.md) —
  preflight commands, common filters, recovery patterns.
- [`references/query-corpus.md`](references/query-corpus.md) — ATT&CK-
  aligned filter library (C2, DNS, lateral movement, credential access,
  exfiltration, recon).
- [`references/tshark-examples.json`](references/tshark-examples.json)
  — same corpus in machine-readable form for the agent to lift command
  strings from.

---

## Cross-skill orchestration

| If you need… | Use… |
|--------------|------|
| Detection / entity context, queue triage, the "is this real?" workflow | [`vectra-investigator`](../vectra-investigator/SKILL.md) (loads the matching `playbook-<category>.md`) |
| Tenant-wide pivots that don't need raw packets (DNS / TLS / HTTP / sessions metadata) | [`vectra-hunt`](../vectra-hunt/SKILL.md) |
| External reputation on an IOC pulled out of the capture (TLS SNI, contacted IP, file hash if extracted) | [`virustotal`](../virustotal/SKILL.md) |
| A canned report once the PCAP triage produces a finding worth sharing | [`vectra-reports`](../vectra-reports/SKILL.md) / [`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md) |

---
name: virustotal
description: Enriches Vectra findings with VirusTotal threat intelligence — IOC reputation lookup for IPs, domains, URLs, and file hashes via the VirusTotal v3 API. Ships two paths — a standalone Bash CLI (scripts/vt-lookup.sh) for one-off lookups that needs only curl/jq, and a sourced framework adapter (scripts/virustotal.sh) for multi-IOC enrichment runners. Both call the v3 /files, /urls, /ip_addresses, /domains endpoints and emit a normalized JSON result with a compact summary (malicious and suspicious counts, plus reputation/country/ASN for IPs). Use when the user asks to look up a hash, IP, domain, or URL in VirusTotal, or to enrich detection or hunt hits with external TI. Reputation never overrides Vectra's behavioral verdict — VirusTotal is for corroboration only.
---

# VirusTotal — IOC Lookup & TI Enrichment

This skill wires the agent into the **VirusTotal v3 API** for IOC
enrichment. It ships a Bash adapter (`scripts/virustotal.sh`) that exposes
a single function — `virustotal_enrich` — designed to be **sourced** by a
host IOC-enrichment workflow (the agent's outer `set -euo pipefail` Bash
runner that loops over a list of IOCs and dispatches per-IOC to multiple
intel sources).

The adapter handles: API-key presence check → IOC-type guard →
type-specific URL construction (file hash / IP / domain / URL) →
authenticated `GET` → JSON parse → normalized result emission with a
compact one-line summary.

---

## Use this skill when

- The user pastes an IOC (IPv4 / IPv6, domain, URL, file hash) and asks
  "is it known bad?" / "look it up in VirusTotal".
- A `vectra-investigator` `playbook-<category>.md` lands a TP-leaning
  verdict and the analyst wants external corroboration before
  escalating.
- A `vectra-hunt` TI-driven hunt produces hits whose IOCs need
  reputation context for the final report.
- You're building or running a multi-source IOC-enrichment workflow that
  sources this adapter alongside other vendor adapters (the function is
  drop-in compatible with any framework that provides the helper
  contract documented below).

Do **not** use this skill to:

- Override Vectra's behavioral verdict — reputation **does not** make a
  TP into a BTP or vice versa.
- Hunt across the Vectra tenant — that's
  [`vectra-hunt`](../vectra-hunt/SKILL.md).
- Triage a Vectra detection end-to-end — that's
  [`vectra-investigator`](../vectra-investigator/SKILL.md) (which
  loads the matching `playbook-<category>.md`).

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| **VirusTotal API key** | Public (free, low rate) or Premium. Exposed to the adapter as the `VT_API_KEY` environment variable. **Never** hard-code the key in scripts or commit it. |
| **`curl`** | Used by the host framework's `adapter_fetch_json_or_error`. |
| **`jq`** | Used inline for response summarization. |
| **`base64`** | Required only for URL IOCs (VirusTotal expects URL IOCs as URL-safe base64 of the canonical URL). The adapter degrades gracefully and emits a `base64 utility missing` error if absent. |
| **Bash 4+** | `[[ ]]`, arrays, `local` declarations. |
| **Host workflow framework** | The adapter calls helper functions (see "Framework contract" below). It **does not** stand alone. |

The agent host that sources this adapter is responsible for everything
the adapter doesn't do: parsing user input into `(ioc, ioc_type,
ioc_subtype, ioc_private)`, looping over multiple IOCs, fanning out to
other adapters (e.g. Shodan, GreyNoise, AbuseIPDB), aggregating the JSON
results, and rendering them back to the analyst.

---

## What the adapter does

```
┌────────────────────────────┐
│ virustotal_enrich(...)     │
│                            │
│ 1. adapter_has_key check   │
│ 2. IOC guard (type/private)│
│ 3. Resolve VT object URL   │
│    file → /files/<sha256>  │
│    ip   → /ip_addresses/IP │
│    dom  → /domains/<fqdn>  │
│    url  → /urls/<b64>      │
│ 4. GET v3 endpoint w/ key  │
│ 5. jq → compact summary    │
│ 6. emit JSON result        │
└────────────────────────────┘
```

### Function signature

```bash
virustotal_enrich <ioc> <ioc_type> <ioc_subtype> <ioc_private>
```

| Arg | Purpose |
|-----|---------|
| `ioc` | Raw IOC value (e.g. `1.2.3.4`, `evil.com`, `https://x.y/z`, `5e8c9...a31f`) |
| `ioc_type` | `ip` / `domain` / `url` / `hash` / `file` / `email` / etc. — the framework's vocabulary; this adapter routes on it via `workflow_ioc_vt_set_object_parts`. |
| `ioc_subtype` | Refinement (e.g. `ipv4` vs `ipv6`, `sha256` vs `md5`). Surfaced in the result for downstream filtering. |
| `ioc_private` | Boolean-ish flag: `true` if the IOC is internal (RFC1918, internal domain). The adapter respects the framework's standard-intel guard, which short-circuits private IOCs that have no public-reputation meaning. |

### Outputs

The function never `return`s a non-zero exit code on operational errors
— it always emits a structured JSON result via the framework helpers.
Three terminal states:

| State | Trigger | Emitter |
|-------|---------|---------|
| **No key** | `VT_API_KEY` unset (per `adapter_has_key`) | `missing_key_result` |
| **Skipped** | IOC private / unsupported by VT (per `workflow_ioc_guard_standard_intel`) | `json_result … false false …` |
| **Type unsupported** | Adapter's URL resolver rejected this `ioc_type` | `json_result … false false "unsupported IOC type" …` |
| **Base64 missing** | URL IOC but no `base64` utility | `json_result … false false "base64 utility missing" …` |
| **Fetch failed** | curl error / non-JSON response (per `adapter_fetch_json_or_error`) | helper emits its own structured error and the function returns |
| **Success** | VirusTotal returned a `data.attributes.last_analysis_stats` block | `adapter_emit_success_with_summary` with the compact summary |

### Summary fields (success path)

`jq` distills the v3 payload to a one-line array of `key=value` strings:

| Field | Always present | Source |
|-------|----------------|--------|
| `malicious=N` | yes | `data.attributes.last_analysis_stats.malicious` (default 0) |
| `suspicious=N` | yes | `data.attributes.last_analysis_stats.suspicious` (default 0) |
| `reputation=N` | IPs only | `data.attributes.reputation` (signed, can be negative) |
| `country=XX` | IPs only | `data.attributes.country` |
| `asn=N` | IPs only | `data.attributes.asn` |

The full v3 response is preserved in the JSON result (`response`
parameter to `adapter_emit_success_with_summary`) for callers that need
deeper fields (`last_analysis_results`, `categories`, `sandbox_verdicts`,
`crowdsourced_yara_results`, etc.).

### What's intentionally **not** in the summary

- Full vendor-by-vendor verdicts → in the `response` blob, not the
  summary line.
- Sandbox / behavioral / YARA hits → in the `response` blob.
- Related-files / communicating-files / contacted-domains pivots → in
  the `response` blob; the host framework can pull them out for
  follow-up enrichment passes.

---

## Framework contract

The adapter is **not** standalone — sourcing it requires the host
framework to provide these symbols:

| Symbol | What it does |
|--------|--------------|
| `adapter_has_key <source_name>` | Returns 0 if the source's API key env var is set / non-empty. |
| `missing_key_result <source> <ioc> <type> <subtype>` | Emit a structured "missing key" result. |
| `workflow_ioc_guard_standard_intel <source> <ioc> <type> <subtype> <private>` | Returns 0 if the IOC is in scope for standard public-intel sources (skips private / non-public-reputation IOCs). |
| `workflow_ioc_vt_set_object_parts <ioc> <type>` | Resolves the VirusTotal object path components for this IOC. Exit codes: `0` = ok, `1` = unsupported type, `2` = base64 missing for URL IOC. |
| `workflow_ioc_vt_object_base_url` | Returns the fully-qualified VT v3 object URL (e.g. `https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4`). |
| `adapter_fetch_json_or_error <source> <label> <ioc> <type> <subtype> <url> <fetch_err> <parse_err> [curl args...]` | Performs the GET, parses JSON, sets `ADAPTER_FETCH_RESPONSE`, returns 0 on success and emits a structured error otherwise. |
| `json_result <source> <ioc> <type> <subtype> <hit:bool> <success:bool> <reason> <summary_obj> <data_obj>` | Generic structured result emitter for non-success terminal states. |
| `adapter_emit_success_with_summary <source> <vendor_id> <ioc> <type> <subtype> <response_json> <summary_json>` | Success emitter — wraps the response + summary in the framework's standard JSON envelope. |
| `VT_API_KEY` (env) | The API key. The adapter reads it directly when building the `x-apikey` header. |
| `TIMEOUT_OVERRIDE` (env, optional) | curl `--max-time` override (default 30 s). |

Any host framework that satisfies this contract can drop the adapter in
unchanged. The current production framework is the agent's
`codex-ioc-workflow/1.0` Bash runner (referenced in the User-Agent
header).

---

## How to use

There are **two supported paths**. Pick whichever matches your
deployment.

### Path A — Standalone CLI (no host framework)

Use this when you just need a one-off lookup, or when there is no
multi-source IOC-enrichment runner sourcing the adapter. Ships as
`scripts/vt-lookup.sh` — a self-contained Bash CLI that re-implements
the framework contract internally.

```bash
export VT_API_KEY=<your-vt-v3-key>

# Single IOC lookups
skills/virustotal/scripts/vt-lookup.sh ip     1.2.3.4
skills/virustotal/scripts/vt-lookup.sh domain evil.example.com
skills/virustotal/scripts/vt-lookup.sh url    "https://x.example/path"
skills/virustotal/scripts/vt-lookup.sh hash   5e8c9abcd...a31f

# Pipe to jq for just the summary
skills/virustotal/scripts/vt-lookup.sh ip 1.2.3.4 | jq -c '.summary'
# → ["malicious=12","suspicious=2","reputation=-37","country=RU","asn=12345"]

# Loop over IOCs from a file
while read -r artifact type; do
  skills/virustotal/scripts/vt-lookup.sh "$type" "$artifact"
done < iocs.tsv > vt-results.jsonl
```

Output is a single-line JSON document on stdout:

```json
{
  "ioc": "1.2.3.4",
  "ioc_type": "ip",
  "found": true,
  "summary": ["malicious=12","suspicious=2","reputation=-37","country=RU","asn=12345"],
  "data": { /* full v3 /ip_addresses/1.2.3.4 response */ }
}
```

Exit codes: `0` success / known IOC (HTTP 200) or unknown IOC (HTTP 404
with `found:false`), `2` usage, `3` missing dependency, `4`
unsupported IOC type, `5` curl failure, `6` 401/403 (key), `7` 429
(rate-limit), `8` other HTTP error.

> Rate-limit on the public tier (4 req/min, 500 req/day) — the
> standalone CLI does **not** sleep between calls. Add your own
> backoff in the calling loop, or upgrade to a premium key.

### Path B — Source the adapter into a host framework

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Source the host framework that provides the helper contract above.
# shellcheck source=/dev/null
source "${WORKFLOW_HOME}/lib/adapter.sh"
# shellcheck source=/dev/null
source "${WORKFLOW_HOME}/lib/ioc.sh"

# 2. Source this adapter.
# shellcheck source=skills/virustotal/scripts/virustotal.sh
source "${SKILLS_HOME}/virustotal/scripts/virustotal.sh"

# 3. Make sure the key is in the environment (never hard-coded).
: "${VT_API_KEY:?VT_API_KEY must be set}"

# 4. Call per IOC (or in a loop).
virustotal_enrich "1.2.3.4"        ip     ipv4   false
virustotal_enrich "evil.com"       domain fqdn   false
virustotal_enrich "https://x/y"    url    full   false
virustotal_enrich "5e8c9...a31f"   hash   sha256 false
```

The function appends a structured JSON result to whatever sink the
framework wires up (typically a JSONL file under
`${WORKFLOW_RUN_DIR}/results.jsonl`).

### Example: enrich the hits from a Vectra TI hunt

```bash
# Pull the IOCs that landed hits from the vectra-hunt run output.
jq -r '.hits[] | [.artifact, .type] | @tsv' hunt-report.json \
  | while IFS=$'\t' read -r artifact type; do
      virustotal_enrich "$artifact" "$type" "" false
    done
```

The host framework then aggregates `results.jsonl` and the agent renders
the enrichment back into the hunt report's "External reputation" column.

### Output shape (illustrative, not authoritative)

```json
{
  "source": "virustotal",
  "vendor": "VirusTotal",
  "ioc": "1.2.3.4",
  "ioc_type": "ip",
  "ioc_subtype": "ipv4",
  "hit": true,
  "success": true,
  "summary": ["malicious=12", "suspicious=2", "reputation=-37", "country=RU", "asn=12345"],
  "data": { /* full v3 /ip_addresses/1.2.3.4 response */ }
}
```

(Exact envelope shape is owned by `adapter_emit_success_with_summary` in
the host framework, not this adapter.)

---

## Operational notes

### Rate limits

- **Public API:** 4 req/min, 500 req/day, 15.5K req/month per key. The
  adapter does **not** rate-limit on its own — the host framework is
  expected to throttle (sleep / backoff) across IOCs.
- **Premium:** higher and contractual; check the key's tier before
  bulk-enriching a hunt's worth of IOCs.

### Secret hygiene

- Pass `VT_API_KEY` via the host's secret store / env injection — never
  in `.env` files committed to the repo, never in shell history, never
  in logs.
- The adapter does not log the key. If you wrap it, do not echo the
  curl command line (`set -x` will leak the header).
- Rotate the key on a schedule and on offboarding.

### Privacy / data sharing

- VirusTotal sees every IOC you submit. Treat lookups as **publishing**
  the IOC to a third-party multi-tenant TI feed.
- Never submit internal hostnames, internal IPs (RFC1918), or sensitive
  filenames to the public API. The `workflow_ioc_guard_standard_intel`
  guard short-circuits private IOCs by design — keep that guard in
  place.
- Review your contract before submitting customer-tied IOCs.

### Reputation interpretation

- **High `malicious`** (≥ ~5 vendors) — strong external corroboration.
  Add it to the verdict but do not let it *replace* the behavioral
  evidence.
- **Low / zero `malicious`** — does **not** mean clean. Targeted /
  fresh / customer-specific infrastructure will be unknown to VT.
- **Negative `reputation` on an IP** — community downvotes; weak signal
  on its own.
- **Country / ASN context** — useful for narrative ("egress to a host in
  RU AS12345 known for bulletproof hosting") but never as the *sole*
  justification for a verdict.

---

## Cross-skill orchestration

| If you need… | Use… |
|--------------|------|
| The Vectra-side picture (detections, host context, behavioral evidence) | [`vectra-investigator`](../vectra-investigator/SKILL.md) (loads the matching `playbook-<category>.md`) |
| To hunt the IOC across the tenant (DNS / TLS / HTTP / sessions) | [`vectra-hunt`](../vectra-hunt/SKILL.md) (ad-hoc query mode) |
| To run a structured IOC sweep against a TI report and enrich each hit with VT | [`vectra-hunt`](../vectra-hunt/SKILL.md) (TI hunt mode) → loop hits through `virustotal_enrich` |
| The raw packets behind a finding | [`vectra-pcap`](../vectra-pcap/SKILL.md) (when it ships) |

---

## Files

- [`scripts/vt-lookup.sh`](scripts/vt-lookup.sh) — **Standalone CLI**.
  Self-contained one-off lookup. Depends only on `curl` / `jq` (and
  `base64` for URL IOCs). Reads `VT_API_KEY` and prints normalized
  JSON on stdout. Use this when no host enrichment framework is
  available.
- [`scripts/virustotal.sh`](scripts/virustotal.sh) — **Framework
  adapter**. Sourced-only; exposes `virustotal_enrich`. Depends on the
  host-framework contract above (`adapter_*`, `workflow_ioc_*`
  helpers). Use this when you have a multi-source IOC-enrichment
  runner that loops over IOCs and aggregates results.

# Mode 2 — TI-Driven Hunt Campaign

Use this mode when the user supplies a **Threat Intelligence
report** — URL, file, paste, IOC list, or a named APT / malware /
campaign / CVE — and asks whether the environment is affected. The
hunt orchestrates many ad-hoc queries (Mode 1) around the report's
artifacts and produces a consolidated hunt report.

> Companion files for this mode:
> [`ti-hunt-ttp-map.md`](ti-hunt-ttp-map.md) for the MITRE ATT&CK and
> tool-family recipe lookup,
> [`ti-hunt-report-template.md`](ti-hunt-report-template.md) for the
> Phase 6 output layout,
> [`query-construction.md`](query-construction.md) when authoring SQL
> beyond the recipe library,
> [`table-gotchas.md`](table-gotchas.md) for per-table quirks. A
> fully-worked example lives in [`../examples.md`](../examples.md).

---

## Inputs

The TI report can arrive as:

- A **URL** to a vendor blog / advisory → fetch with the available
  web tool.
- A **local file** (PDF, HTML, MD, TXT) → read with the file tool.
- **Pasted text** in the conversation → use as-is.
- A **bare IOC list** (CSV, newline-separated, STIX/TAXII bundle) →
  parse directly.

Always confirm with the user which input you are using before
extracting.

---

## Six-phase methodology

```
TI Hunt Progress:
- [ ] Phase 1: Ingest the TI report
- [ ] Phase 2: Extract artifacts (IOCs + tools + TTPs)
- [ ] Phase 3: Map artifacts to Vectra data sources
- [ ] Phase 4: Build and run hunting queries
- [ ] Phase 5: Triage hits and pull context
- [ ] Phase 6: Produce the hunt report
```

### Phase 1 — Ingest the TI report

- Resolve the source (URL, file, paste).
- Capture metadata: title, vendor / author, publish date, threat
  actor / malware / campaign name, referenced CVEs.
- Note the **observation window** the report covers — this informs
  the hunt's lookback (default: 14 days, max Vectra retention = 336
  hours for most tables, longer for some).

### Phase 2 — Extract artifacts

Pull every hunting-grade artifact and bucket it by type:

| Bucket | Examples |
|--------|----------|
| Network IOCs | IPv4 / IPv6, domains, FQDNs, URLs, ports |
| File IOCs | MD5 / SHA1 / SHA256, file names, file paths |
| Host IOCs | Mutexes, registry keys, services, scheduled tasks, process names |
| Crypto IOCs | X.509 subjects / issuers / serials, JA3 / JA3S, SSH HASSH |
| Identity IOCs | Email addresses, UPNs, usernames, SaaS app IDs |
| HTTP IOCs | User-agent strings, URI paths, Host headers, referrers |
| Tools / malware | Binary names, framework names (Cobalt Strike, Sliver, Mimikatz, …) |
| Actor / campaign | APT label, group alias, campaign codename |
| MITRE TTPs | Tactic + Technique IDs (e.g. `TA0008` / `T1021.002`) |

Defang IOCs as needed (`hxxp://`, `evil[.]com`) before feeding them
to queries.

### Phase 3 — Map artifacts to Vectra data sources

| Artifact | Vectra table(s) | Field(s) |
|----------|-----------------|----------|
| IPv4 / IPv6 | `network.isession._all`, `network.beacon._all`, `network.ssl._all`, `network.http._all`, `entra.signins._all`, `aws.cloudtrail._all` | `id.orig_h`, `id.resp_h`, `dest_ip`, `ip_address`, `source_ip` |
| Domain / FQDN | `network.dns._all`, `network.ssl._all`, `network.http._all`, `network.beacon._all`, `network.x509._all` | `query`, `server_name`, `host`, `resp_domains`, `certificate.subject` |
| URL / URI path | `network.http._all` | `uri`, `host` |
| File hash | (Vectra does not store file hashes) | — fall back to detection metadata or external EDR |
| File name | `network.smb_files._all`, `m365.sharepoint._all`, `network.http._all` | `name`, `source_file_name`, `uri` |
| User-agent | `network.http._all` | `user_agent` |
| JA3 / JA3S | `network.ssl._all` | `ja3`, `ja3s` |
| HASSH | `network.ssh._all` | `hassh` |
| X.509 subject / issuer | `network.x509._all` | `certificate.subject`, `certificate.issuer` |
| Username / UPN | `network.kerberos._all`, `network.ntlm._all`, `network.radius._all`, `entra.signins._all`, `m365.*`, `aws.cloudtrail._all` | `client`, `username`, `user_id`, `user_principal_name`, `user_identity` |
| MITRE TTP | Vectra detection types + protocol-specific recipes | map technique → recipe via [`ti-hunt-ttp-map.md`](ti-hunt-ttp-map.md) |
| Tool / malware name | Heuristic mapping → behaviors that tool produces | see [`ti-hunt-ttp-map.md`](ti-hunt-ttp-map.md) |

Artifacts with **no Vectra coverage** (file hashes, registry keys,
mutexes, process command lines) must be called out as gaps in the
final report — do not silently drop them.

### Phase 4 — Build and run hunting queries

For each mapped artifact:

1. Pick the closest recipe in the recipe-library files (catalog in
   [`../SKILL.md`](../SKILL.md)).
2. Substitute the IOC value, time window, and any host scope.
3. Submit via `run_investigation`.
4. Poll `get_investigation_results` until status is `SUCCESS`.
5. Capture `request_id`, query, hit count, and a sample of rows.

Batching rules:

- **Group artifacts by data source** so one query sweeps many IOCs at
  once (e.g. all C2 domains → single `network.dns._all` query with
  `IN (...)` or `ANY_MATCH`).
- **Default lookback:** 14 days (`hours=336`). Reduce only if the
  report's observation window is shorter; never exceed Vectra
  retention.
- **LIMIT 500** for sweeps, **LIMIT 100** for targeted lookups.

### Phase 5 — Triage hits and pull context

For every non-empty result:

1. De-duplicate by `(host, artifact, day)`.
2. Pull host context with `get_host_details(host_id)`.
3. Cross-check Vectra detections on those hosts via
   `get_detection_details`.
4. Note whether the hit is a **confirmed match** (artifact +
   behavior + matching Vectra detection), a **partial hit**
   (artifact only), or a **weak hit** (common IOC, low-confidence).

### Phase 6 — Produce the hunt report

Render using [`ti-hunt-report-template.md`](ti-hunt-report-template.md).
Always include the gap list (artifacts that could not be hunted) and
the next-step recommendations.

---

## Hunt execution rules

- **Always include a time filter** on every query (see
  [`query-construction.md`](query-construction.md)).
- **Defang → refang** before substituting an IOC into SQL.
- **Batch IOCs of the same type** into one query (`IN (...)` or
  `ANY_MATCH`) to stay within rate limits.
- **Hard limit: 5 query submissions per minute.** When a hunt needs
  more than ~4 queries, submit them sequentially with a short pause
  rather than in one parallel batch — parallel batches of 5+ will
  trip `429 Too Many Requests` on the excess calls (see
  [`query-construction.md`](query-construction.md)).
- **Score each hit:** confirmed (artifact + behavior + Vectra
  detection) > partial (artifact only) > weak (common IOC, low
  confidence).
- **Never claim "no exposure" without listing the gaps** — the
  absence of hits in queryable data sources does not cover hashes,
  mutexes, registry keys, or other host-level artifacts.

---

## When to escalate findings out of TI-hunt mode

For each affected host / account from Phase 5, decide whether to
escalate into a full entity deep-dive. Hand the entity off to
[`vectra-investigator`](../../vectra-investigator/SKILL.md) (Workflow 2 —
Entity Deep-Dive) — a confirmed TI hit on a host typically warrants
the full deep-dive plus EDR correlation.

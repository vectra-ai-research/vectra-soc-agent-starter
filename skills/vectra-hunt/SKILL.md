---
name: vectra-hunt
description: Searches and hunts over Vectra metadata in two modes — (1) ad-hoc Investigation Query SQL using pre-validated recipes for network sessions, DNS, HTTP, TLS/X.509, SMB, Kerberos, NTLM, LDAP, RDP, DCE-RPC, SSH, SMTP, DHCP, RADIUS, beacons, IDS matches, and Entra/M365/AWS CloudTrail/Azure CP; (2) threat-intelligence-driven hunt campaigns that turn a TI report, advisory, IOC list, or any named or currently-circulating threat (ransomware family in the news, named APT group, public CVE) into a structured multi-query sweep with a consolidated hunt report. Use when the user asks an investigation or hunting question needing custom SQL — including sweep, correlate, pivot on, hunt for, look for, find every — or supplies a TI report / asks whether the environment is affected by a named threat. Falls back to custom SQL via query-construction rules when no recipe matches.
---

# Vectra Hunt — Metadata Search & Threat-Intel Hunting

This skill is the **search and hunt layer** over Vectra metadata. It
runs in two modes:

| Mode | Trigger | Output | Reference |
|------|---------|--------|-----------|
| **Ad-hoc query** | "Did host X talk to evil.com last night?", "Find RC4 TGS requests", "Show me POST exfil traffic" | Single Investigation Query result, summarized in chat | [`references/mode-ad-hoc.md`](references/mode-ad-hoc.md) |
| **TI-driven hunt** | "Hunt this CISA advisory", "Sweep our tenant for APT-9999", "Are we affected by this Cobalt Strike campaign?" | Multi-query sweep + consolidated hunt report (IOC hits, TTP coverage, gaps, recommendations) | [`references/mode-ti-hunt.md`](references/mode-ti-hunt.md) |

Both modes draw on the same library of pre-validated SQL recipes
(catalog below). Ad-hoc mode runs **one** recipe. TI mode batches
**many** of them around a report's IOCs and TTPs.

This is **not**:

- A canned dashboard / KPI report — that's
  [`vectra-reports`](../vectra-reports/SKILL.md) (Python) or
  [`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md) (MCP).
- A detection-triage playbook ("how do I triage a Smash and Grab?")
  or queue-triage workflow ("walk me through tier 1") — that's
  [`vectra-investigator`](../vectra-investigator/SKILL.md) (loads the
  matching `playbook-<category>.md`).

---

## How this skill is organized

The detail for each piece lives in [`references/`](references/) —
load only what the current task needs (see
[`references/MANIFEST.md`](references/MANIFEST.md) for the required
per-mode and per-domain load set; progressive load is **mandatory**).
Two distinct kinds of reference file:

**Orchestration / methodology** (how to run the skill):

| Sub-area | Reference |
|----------|-----------|
| Mode 1 — Ad-hoc workflow + decision guide | [`references/mode-ad-hoc.md`](references/mode-ad-hoc.md) |
| Mode 2 — TI-hunt 6-phase methodology + execution rules | [`references/mode-ti-hunt.md`](references/mode-ti-hunt.md) |
| MITRE TTP & tools/malware → recipe lookup (used by both modes) | [`references/ti-hunt-ttp-map.md`](references/ti-hunt-ttp-map.md) |
| TI Hunt Report markdown template (Phase 6 of TI-hunt) | [`references/ti-hunt-report-template.md`](references/ti-hunt-report-template.md) |
| Query Construction Rules (SQL — used when no recipe matches) | [`references/query-construction.md`](references/query-construction.md) |
| Table-specific gotchas (per-table quirks to check before authoring) | [`references/table-gotchas.md`](references/table-gotchas.md) |

**Recipe libraries** (the actual SQL — see catalog further down):

- [`references/network_sessions.md`](references/network_sessions.md)
- [`references/network_dns_http.md`](references/network_dns_http.md)
- [`references/network_tls_certs.md`](references/network_tls_certs.md)
- [`references/network_lateral_movement.md`](references/network_lateral_movement.md)
- [`references/network_infra.md`](references/network_infra.md)
- [`references/cloud_investigations.md`](references/cloud_investigations.md)

A fully-worked TI hunt example lives in
[`examples.md`](examples.md).

---

## Prerequisites

The **Vectra MCP server** must be connected and authenticated. It
provides the tools used to execute every query in this skill:

| MCP tool | Purpose |
|----------|---------|
| `run_investigation` | Submit Investigation Query SQL, returns a `request_id` |
| `get_investigation_results` | Poll / fetch results for a `request_id`, page through large result sets |
| `get_investigation_schema` | Inspect available tables / columns before authoring SQL |
| `get_investigation_sql_reference` | Look up the SQL grammar (functions, time helpers, etc.) supported by Investigation Query |

Schemas for every queryable table live as MCP resources at
`vectra://resources/schemas/<domain>/<table>.md`. **Read the
relevant schema before authoring SQL that goes beyond the supplied
recipes** — see
[`references/query-construction.md`](references/query-construction.md).

If the MCP server is not connected, tell the user to configure it
before proceeding (see `install/<HOST>.md`).

---

## Pick your mode

| User asks for… | Mode | Reference |
|----------------|------|-----------|
| A single, narrow question — pivot from a detection, hunt one IOC, characterize a host | Mode 1 — Ad-hoc | [`references/mode-ad-hoc.md`](references/mode-ad-hoc.md) |
| "Are we affected by this advisory?" / "Hunt this APT/malware" / a TI report or IOC list | Mode 2 — TI hunt | [`references/mode-ti-hunt.md`](references/mode-ti-hunt.md) |
| One named MITRE technique or one tool / malware family ("look for T1558.003", "are we seeing Cobalt Strike?") | Mode 1 (start there) | [`references/ti-hunt-ttp-map.md`](references/ti-hunt-ttp-map.md) for the lookup, then run via Mode 1 |

**Read the matching reference file before running anything** — each
is a numbered checklist that names the right recipe / MCP call at
every step.

---

## Recipe library catalog

Each reference file below contains complete, copy-pasteable SQL
recipes with security context. The recipes are a **starting set of
common analyst queries**, not the full list of what the platform
supports — copy and adapt freely (using
[`references/query-construction.md`](references/query-construction.md)
and [`references/table-gotchas.md`](references/table-gotchas.md) when
you go off-recipe).

### Network — Core traffic
**Reference:** [`references/network_sessions.md`](references/network_sessions.md)

| Table | Recipes | Key investigations |
|-------|---------|--------------------|
| `network.isession._all` | 5 | Host sessions, traffic summary, large transfers, failed connections (S0 / REJ), detection-window pivot |

### Network — Application protocols
**Reference:** [`references/network_dns_http.md`](references/network_dns_http.md)

| Table | Recipes | Key investigations |
|-------|---------|--------------------|
| `network.dns._all` | 4 | Host queries, domain blast radius, NXDOMAIN/DGA hunting, DNS tunneling |
| `network.http._all` | 4 | Host activity, host-header hunt, POST exfiltration, user-agent hunt |

### Network — Encryption & certificates
**Reference:** [`references/network_tls_certs.md`](references/network_tls_certs.md)

| Table | Recipes | Key investigations |
|-------|---------|--------------------|
| `network.ssl._all` | 4 | Host TLS sessions, SNI hunt, weak TLS, JA3 fingerprint hunt |
| `network.x509._all` | 4 | Host certs, self-signed (C2), expiring certs, subject hunt |

### Network — Lateral movement & authentication
**Reference:** [`references/network_lateral_movement.md`](references/network_lateral_movement.md)

| Table | Recipes | Key investigations |
|-------|---------|--------------------|
| `network.smb_mapping._all` | 2 | Share connections, admin-share access (ADMIN$/C$/IPC$) |
| `network.smb_files._all` | 2 | File operations, writes/deletes/renames (ransomware) |
| `network.kerberos._all` | 4 | Host activity, Kerberoasting (RC4 TGS), failed auth, user tracking |
| `network.ntlm._all` | 4 | Host auth, failures (spraying), user tracking, Pass-the-Hash |
| `network.ldap._all` | 4 | Host queries, recon (large results), base-object hunt, sensitive attrs (LAPS / SPN) |
| `network.rdp._all` | 4 | Host sessions, internal lateral movement, client-name hunt, unencrypted |
| `network.dce_rpc._all` | 4 | Host activity, endpoint hunt (svcctl / drsuapi / samr), operation hunt, lateral movement RPC |

### Network — Infrastructure & detection
**Reference:** [`references/network_infra.md`](references/network_infra.md)

| Table | Recipes | Key investigations |
|-------|---------|--------------------|
| `network.ssh._all` | 4 | Host sessions, inbound SSH, HASSH hunt, cipher hunt |
| `network.smtp._all` | 4 | Host activity, sender hunt, recipient hunt, unencrypted SMTP |
| `network.dhcp._all` | 4 | By hostname, by IP, by MAC, by server (rogue DHCP) |
| `network.radius._all` | 3 | Host auth, failures (VPN brute force), user tracking |
| `network.beacon._all` | 4 | Host beacons, domain hunt (ANY_MATCH), high-frequency, dest IP hunt |
| `network.match._all` | 4 | Host IDS alerts, critical alerts, signature hunt, category hunt |

### Cloud & identity
**Reference:** [`references/cloud_investigations.md`](references/cloud_investigations.md)

| Table | Recipes | Key investigations |
|-------|---------|--------------------|
| `aws.cloudtrail._all` | 5 | Principal events, access denied, event-name hunt, IP hunt, IAM changes |
| `entra.signins._all` | 4 | User sign-ins, failed sign-ins, risky sign-ins, country hunt |
| `entra.directoryaudits._all` | 2 | User directory activity, privileged role changes |
| `m365.sharepoint._all` | 3 | User activity, bulk downloads, external sharing |
| `m365.exchange._all` | 2 | User activity, forwarding rules (email exfiltration) |
| `m365.general._all` | 1 | User activity (Teams, Power Automate, Copilot) |
| `m365.active_directory._all` | 1 | User AAD activity (auth, MFA, device registration) |
| `azurecp.operations._all` | 5 | Actor operations, failures, operation hunt, IP hunt, role assignments |

---

## Limitations

- Vectra does not store **file hashes**, **mutexes**, **registry
  keys**, or **process command lines** — these must be hunted in
  EDR / SIEM and reported as gaps (see
  [`references/ti-hunt-ttp-map.md`](references/ti-hunt-ttp-map.md)
  for the full coverage-gap list).
- Maximum lookback is bounded by Vectra retention (≈ 14 days for
  most tables; longer for some cloud tables).
- TTP coverage is **best-effort**: a recipe miss does not prove the
  technique is absent, only that the network / identity telemetry
  Vectra collects shows no evidence.

---

## Cross-skill orchestration

| If you need… | Use… |
|--------------|------|
| A detection-category triage playbook (Exfiltration, Lateral Movement, …) **or** the full tier-1 SOC workflow (queue triage, entity deep-dive, single-detection pivot) | [`vectra-investigator`](../vectra-investigator/SKILL.md) (owns both — `playbook-<category>.md` references for the playbooks, `workflow-*.md` references for the workflows) |
| A canned analytic dashboard (top talkers, beacon report, etc.) | [`vectra-reports`](../vectra-reports/SKILL.md) (Python) or [`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md) (MCP) |
| The PCAP behind a network detection (TLS / JA3 / JA4 / HTTP auth / SMB / RPC / DNS …) | [`vectra-pcap`](../vectra-pcap/SKILL.md) |
| External reputation on an IOC pulled from a hunt hit | [`virustotal`](../virustotal/SKILL.md) — corroboration only, never overrides behaviour |

> **Universal SOC rules** (read-only by default, human-in-the-loop
> for mutations, scope discipline, evidence preservation, output
> expectations) live in [`../../AGENTS.md`](../../AGENTS.md) and
> apply to every query and every hunt run from this skill.

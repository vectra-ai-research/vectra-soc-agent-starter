# Vectra TI Hunt — Worked Example

A single fully-worked hunt to illustrate the methodology in `SKILL.md`. The
threat, IOCs, and results are illustrative — values are not from a real
incident. Use this as a template for your own hunts.

---

## Scenario

The user pastes the following advisory snippet and asks:

> "Sweep our Vectra tenant for this Cobalt Strike campaign. Last 14 days."

```text
Vendor advisory: APT-9999 — Cobalt Strike Activity
Published: 2026-04-22
Observation window: 2026-03-15 → 2026-04-20

Network indicators
  C2 domains:        cdn-update[.]net, telemetry-api[.]org
  C2 IPs:            185.220.101.42, 45.95.169.7
  Default JA3:       a0e9f5d64349fb13191bc781f81f42e1   (CS 4.x default profile)
  HTTP host header:  cdn-update.net
  HTTP URI paths:    /load, /j.ad, /push.ad
  User-agent:        Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko

Host indicators
  SHA256:            5e8c9...a31f, 2ac4b...90de
  Mutex:             Global\\CSAgentMutex
  Named pipe:        \\.\pipe\msagent_*

Tactics, Techniques and Procedures
  TA0011 / T1071.001 — Application Layer Protocol: Web
  TA0011 / T1573.002 — Encrypted Channel: Asymmetric Cryptography
  TA0008 / T1021.002 — Lateral Movement: SMB / Admin Shares
  TA0006 / T1003.006 — OS Credential Dumping: DCSync
  TA0005 / T1055.012 — Process Injection: Process Hollowing
```

---

## Phase 1 — Ingest

```
Source           : pasted text
Threat name      : APT-9999 — Cobalt Strike Activity
Vendor           : (unspecified)
Published        : 2026-04-22
Observation win  : 2026-03-15 → 2026-04-20  (~36 days, exceeds Vectra retention)
Hunt window      : last 14 days (2026-04-20 → 2026-05-04, capped by retention)
Tenant           : production
```

The advisory's 36-day window is wider than Vectra retention. Cap the hunt at
14 days and call this out as a coverage gap in the final report.

---

## Phase 2 — Extract artifacts

| Bucket | Artifacts |
|--------|-----------|
| Domains | `cdn-update.net`, `telemetry-api.org` |
| IPs | `185.220.101.42`, `45.95.169.7` |
| JA3 | `a0e9f5d64349fb13191bc781f81f42e1` |
| HTTP host headers | `cdn-update.net` |
| HTTP URI paths | `/load`, `/j.ad`, `/push.ad` |
| User-agents | `Mozilla/5.0 (... Trident/7.0; rv:11.0) like Gecko` |
| File hashes | `5e8c9…a31f`, `2ac4b…90de` (no Vectra coverage) |
| Mutexes | `Global\CSAgentMutex` (no Vectra coverage) |
| Named pipes | `\\.\pipe\msagent_*` (partial coverage via DCE-RPC named-pipe traffic) |
| MITRE TTPs | T1071.001, T1573.002, T1021.002, T1003.006, T1055.012 |
| Tool / framework | Cobalt Strike 4.x |

---

## Phase 3 — Map artifacts → Vectra data sources

| Artifact | Table | Recipe (in `references/`) |
|----------|-------|--------------------------------------------------|
| Domains | `network.dns._all`, `network.ssl._all`, `network.http._all`, `network.beacon._all` | DNS host queries, TLS SNI hunt, HTTP host header hunt, beacon domain hunt |
| IPs | `network.isession._all`, `network.beacon._all` | Sessions to dest IP, beacon dest IP hunt |
| JA3 | `network.ssl._all` | JA3 fingerprint hunt |
| HTTP host header | `network.http._all` | HTTP host header hunt |
| HTTP URI paths | `network.http._all` | Generic HTTP recipe with `CONTAINS(uri, '/load')` |
| User-agent | `network.http._all` | User-agent hunt |
| Named pipe (msagent_*) | `network.dce_rpc._all` | DCE-RPC endpoint hunt (named-pipe binding) |
| TTP T1071.001 | `network.dns._all`, `network.http._all`, `network.ssl._all` | already covered by IOC sweeps above |
| TTP T1573.002 | `network.tls_certs.md` | self-signed / weak TLS / JA3 hunts |
| TTP T1021.002 | `network.lateral_movement.md` | admin-share access (ADMIN$/C$/IPC$) |
| TTP T1003.006 | `network.lateral_movement.md` | DCE-RPC drsuapi (DCSync) |
| TTP T1055.012 | (host-only — no Vectra coverage) | gap |
| File hashes | (no Vectra coverage) | gap → EDR sweep |
| Mutex `Global\CSAgentMutex` | (no Vectra coverage) | gap → EDR sweep |

---

## Phase 4 — Build and run hunting queries

Batch IOCs of the same type into one query each. Time window
`hours = 336` on every query.

### Query 1 — DNS sweep (2 domains)

```sql
SELECT id.orig_h AS src_ip, orig_hostname.name AS host, query, COUNT(*) AS hits
FROM network.dns._all
WHERE dt > date_add('hour', -336, now())
  AND timestamp BETWEEN date_add('hour', -336, now()) AND now()
  AND LOWER(query) IN ('cdn-update.net', 'telemetry-api.org')
GROUP BY 1, 2, 3
ORDER BY hits DESC
LIMIT 500
```

Result: **3 hits** — host `wks-finance-04` resolved `cdn-update.net` 47 times.

### Query 2 — TLS SNI sweep (2 domains)

```sql
SELECT id.orig_h AS src_ip, orig_hostname.name AS host, server_name, COUNT(*) AS sessions
FROM network.ssl._all
WHERE dt > date_add('hour', -336, now())
  AND timestamp BETWEEN date_add('hour', -336, now()) AND now()
  AND LOWER(server_name) IN ('cdn-update.net', 'telemetry-api.org')
GROUP BY 1, 2, 3
LIMIT 500
```

Result: **1 hit** — `wks-finance-04` → `cdn-update.net` (12 sessions).

### Query 3 — JA3 fingerprint sweep

```sql
SELECT id.orig_h AS src_ip, orig_hostname.name AS host, ja3, server_name, COUNT(*) AS sessions
FROM network.ssl._all
WHERE dt > date_add('hour', -336, now())
  AND timestamp BETWEEN date_add('hour', -336, now()) AND now()
  AND ja3 = 'a0e9f5d64349fb13191bc781f81f42e1'
GROUP BY 1, 2, 3, 4
LIMIT 500
```

Result: **0 hits** (the operator may have customized the malleable C2 profile).

### Query 4 — HTTP host + URI sweep

```sql
SELECT id.orig_h AS src_ip, orig_hostname.name AS host, host AS http_host, uri, user_agent, COUNT(*) AS hits
FROM network.http._all
WHERE dt > date_add('hour', -336, now())
  AND timestamp BETWEEN date_add('hour', -336, now()) AND now()
  AND (
        LOWER(host) = 'cdn-update.net'
     OR uri IN ('/load', '/j.ad', '/push.ad')
     OR user_agent = 'Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko'
  )
GROUP BY 1, 2, 3, 4, 5
LIMIT 500
```

Result: **2 hits** — `wks-finance-04` POST `/load` to `cdn-update.net`.

### Query 5 — IP sweep (sessions)

```sql
SELECT id.orig_h AS src_ip, id.resp_h AS dest_ip, COUNT(*) AS sessions, SUM(orig_bytes + resp_bytes) AS total_bytes
FROM network.isession._all
WHERE dt > date_add('hour', -336, now())
  AND timestamp BETWEEN date_add('hour', -336, now()) AND now()
  AND id.resp_h IN ('185.220.101.42', '45.95.169.7')
GROUP BY 1, 2
LIMIT 500
```

Result: **0 hits** (IPs are not seen on the wire — possible the actor
rotated infra, or the host already migrated).

### Query 6 — DCE-RPC named-pipe sweep

```sql
SELECT id.orig_h AS src_ip, orig_hostname.name AS host, named_pipe, endpoint, operation, COUNT(*) AS hits
FROM network.dce_rpc._all
WHERE dt > date_add('hour', -336, now())
  AND timestamp BETWEEN date_add('hour', -336, now()) AND now()
  AND CONTAINS(LOWER(named_pipe), 'msagent_')
GROUP BY 1, 2, 3, 4, 5
LIMIT 500
```

Result: **0 hits**.

### Queries 7–9 — TTP recipes

- T1021.002 SMB admin-share recipe (scoped to hosts already flagged) → 0 hits.
- T1003.006 DCSync (drsuapi) recipe → 0 hits.
- T1573.002 self-signed cert recipe → 0 hits.

---

## Phase 5 — Triage

`wks-finance-04` is the only host with hits. Pull context:

- `get_host_details(host_id=4321)` → `wks-finance-04`, IP `10.21.4.78`,
  tags `["finance", "windows"]`, last seen 2 hours ago.
- `get_detection_details` for any open detections on this host →
  one **Hidden HTTPS Tunnel** detection (severity Major), opened 2026-05-01.

Hit scoring:

| Hit | Score | Reason |
|-----|-------|--------|
| `wks-finance-04` → `cdn-update.net` (DNS + TLS + HTTP POST `/load`) | 🔴 confirmed | Three independent recipes converge + an open Vectra detection on the same host |
| `wks-finance-04` UA `Trident/7.0; rv:11.0` | 🟡 partial | Common UA; only meaningful in combination with the above |

---

## Phase 6 — Hunt report

```markdown
# TI Hunt Report — APT-9999 Cobalt Strike Activity

## Source
- **Report:** APT-9999 — Cobalt Strike Activity
- **Vendor / Author:** (unspecified vendor advisory)
- **Published:** 2026-04-22
- **Hunt window:** last 14 days (2026-04-20 → 2026-05-04 UTC)
- **Tenant:** production

## Executive summary
- **1 confirmed match.** Host `wks-finance-04` (10.21.4.78, `finance`, `windows`)
  is communicating with the C2 domain `cdn-update.net` via DNS, TLS, and HTTP
  POST `/load`, matching three independent IOCs from the advisory.
- An **open Major-severity Hidden HTTPS Tunnel detection** on the same host
  (opened 2026-05-01) supports a confirmed-compromise hypothesis.
- The advisory's JA3 fingerprint, C2 IPs, and named-pipe pattern were not
  observed — consistent with profile customization or infra rotation.
- File-hash, mutex, and process-injection IOCs cannot be hunted in Vectra
  and require an EDR sweep on `wks-finance-04` and peers in the finance zone.

## Artifacts ingested
| Type | Count | Examples |
|------|-------|----------|
| Domains | 2 | cdn-update.net, telemetry-api.org |
| IPs | 2 | 185.220.101.42, 45.95.169.7 |
| JA3 | 1 | a0e9f5d6… |
| HTTP host headers | 1 | cdn-update.net |
| HTTP URI paths | 3 | /load, /j.ad, /push.ad |
| User-agents | 1 | Trident/7.0; rv:11.0 |
| Hashes | 2 | (no Vectra coverage) |
| Mutexes | 1 | (no Vectra coverage) |
| Named pipes | 1 | msagent_* |
| TTPs | 5 | T1071.001, T1573.002, T1021.002, T1003.006, T1055.012 |

## Hits
| Severity | Artifact | Type | First seen | Last seen | Hosts | Vectra evidence |
|----------|----------|------|------------|-----------|-------|-----------------|
| 🔴 | cdn-update.net | domain | 2026-04-29 11:14Z | 2026-05-04 09:02Z | wks-finance-04 | 47 DNS queries, 12 TLS sessions, 2 HTTP POST `/load` |
| 🔴 | (open detection) | detection | 2026-05-01 | live | wks-finance-04 | Hidden HTTPS Tunnel — Major |
| 🟡 | Trident/7.0 user-agent | user-agent | 2026-04-30 | 2026-05-03 | wks-finance-04 | 2 HTTP transactions to cdn-update.net |

## TTP coverage matrix
| MITRE | Technique | Hunted via | Result |
|-------|-----------|------------|--------|
| T1071.001 | App-layer C2 — Web | DNS / TLS / HTTP IOC sweeps | **3 hits** on wks-finance-04 |
| T1573.002 | Encrypted Channel | JA3 hunt + self-signed cert recipe | 0 hits (likely customized profile) |
| T1021.002 | SMB / Admin Shares | admin-share access recipe | 0 hits |
| T1003.006 | DCSync | DCE-RPC drsuapi recipe | 0 hits |
| T1055.012 | Process Hollowing | (no Vectra coverage) | gap |

## Affected hosts / identities
| Entity | Type | Hits | Active detections | Notes |
|--------|------|------|-------------------|-------|
| wks-finance-04 (10.21.4.78) | host | 3 | Hidden HTTPS Tunnel (Major) | Finance zone, last seen 2h ago |

## Gaps (artifacts not hunted)
| Artifact | Reason | Recommended action |
|----------|--------|--------------------|
| SHA256 hashes (×2) | No file-hash coverage in Vectra | EDR sweep across the fleet |
| Mutex `Global\CSAgentMutex` | Not collected by Vectra | EDR sweep |
| T1055.012 process hollowing | Host-only behavior | EDR sweep |
| Days 2026-03-15 → 2026-04-20 | Outside Vectra retention (14 days) | Pull from long-term SIEM if available |

## Recommendations
1. **Isolate `wks-finance-04`** and trigger an EDR-led forensic acquisition.
2. **Pivot from the Hidden HTTPS Tunnel detection** in Vectra — review the
   full session timeline for parallel C2 channels.
3. **Sweep file hashes / mutex / process-injection patterns** on all finance-
   zone hosts via EDR (Vectra cannot answer this).
4. **Block** `cdn-update.net`, `telemetry-api.org`, `185.220.101.42`,
   `45.95.169.7` at the egress perimeter.
5. **Re-run this hunt** after 14 days to catch any IOCs that re-appear after
   actor infra rotation.

## Appendix — Queries run
| # | Target table | Time window | IOCs in batch | request_id | Hits |
|---|--------------|-------------|---------------|------------|------|
| 1 | network.dns._all | 336h | 2 domains | `req_abc123` | 3 |
| 2 | network.ssl._all (SNI) | 336h | 2 domains | `req_abc124` | 1 |
| 3 | network.ssl._all (JA3) | 336h | 1 JA3 | `req_abc125` | 0 |
| 4 | network.http._all | 336h | 1 host + 3 URIs + 1 UA | `req_abc126` | 2 |
| 5 | network.isession._all | 336h | 2 IPs | `req_abc127` | 0 |
| 6 | network.dce_rpc._all | 336h | 1 named-pipe pattern | `req_abc128` | 0 |
| 7 | network.smb_mapping._all | 336h | T1021.002 recipe | `req_abc129` | 0 |
| 8 | network.dce_rpc._all | 336h | T1003.006 (drsuapi) recipe | `req_abc130` | 0 |
| 9 | network.x509._all | 336h | T1573.002 self-signed recipe | `req_abc131` | 0 |
```

---

## Variants

The same workflow handles other report types with minor adjustments:

| Report shape | Adjustment |
|--------------|------------|
| Pure IOC list (no TTPs, no narrative) | Skip Phase 2 TTP extraction; render TTP coverage matrix as "N/A — IOC-only sweep". |
| TTP-heavy advisory (e.g. MITRE write-up, no IOCs) | Phase 2 yields TTPs only; Phase 4 runs the TTP recipe map; the hits table is replaced by per-technique findings. |
| Cloud-only campaign (Entra / AWS / M365) | Replace the network recipes with `cloud_investigations.md` recipes; gap list typically shrinks (cloud telemetry has fewer host-only blind spots). |
| CVE-driven exploitation report | Hunt for the **post-exploitation behaviors**, not the CVE itself — pivot via the relevant TTP recipes (web shell HTTP, DCE-RPC, lateral movement). |

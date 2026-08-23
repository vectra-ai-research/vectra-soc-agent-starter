# Exfiltration — Tier 1 Analyst Playbook

This playbook tells you how to triage a Vectra detection in the **Exfiltration**
category (and Exfiltration-adjacent C&C tunnels that double as data egress).
It is a decision guide, not a SQL library — when you need queries, this
playbook routes you into the matching recipe in
[`vectra-hunt`](../../vectra-hunt/references/).

> Companion references: [`playbooks-overview.md`](playbooks-overview.md)
> for the playbook six-section shape and how-to-use guidance,
> [`verdict-framework.md`](verdict-framework.md) for the per-entity
> verdict rubric and write-up template.

---

## What Vectra is detecting

The Exfiltration category models **data leaving the environment** in shapes
that look like attacker behavior: bulk grabs, slow drains, covert channels,
or unusual cloud storage / mailbox movement. The signal is **the shape of
the egress**, not the destination IP reputation. A first-time benign cloud
sync and a low-and-slow C2 exfil can both ride HTTPS — Vectra differentiates
on volume, timing, ratio of outbound vs inbound bytes, and prior baseline
for the entity.

You are not asking *"is this destination known bad?"* You are asking:

1. Is this entity actually moving an unusual amount of data right now?
2. Does the channel match a known benign baseline (backup, BI export, cloud
   sync, software update reverse)?
3. Or does it match an attacker pattern (paired with C&C, off-hours,
   sensitive source, novel destination)?

---

## Detection types in scope

| Detection | What it sees | Channel |
|-----------|--------------|---------|
| **Smash and Grab** | Large, fast outbound transfer (typically gigabytes in minutes) over HTTP/HTTPS or unusual port to external dst | Network |
| **Data Smuggler** | Unusual outbound : inbound byte ratio for an entity over time, suggesting a slow drain | Network |
| **Hidden DNS Tunnel** | Encoded data inside DNS query labels / TXT responses | Network |
| **Hidden HTTP/S Tunnel** | Encoded data inside HTTP request bodies, headers, or query strings (also catches some C2 — read both lenses) | Network |
| **Suspicious Cloud Storage Activity** (AWS) | Anomalous S3 access patterns: unusual `GetObject` volume, cross-account, or new principal | Cloud (CloudTrail) |
| **M365 — Suspicious Download Activity** | SharePoint / OneDrive bulk downloads vs the user's baseline | Cloud (M365) |
| **M365 — Suspicious Mail Forwarding / Inbox Rule** | Auto-forward to external; mailbox-as-exfil channel | Cloud (M365 / Exchange) |
| **Logging Disabled** *(precursor, not exfil itself)* | Attacker turning off CloudTrail / unified audit log to hide exfil — treat as a critical exfil-precursor signal | Cloud |

If the detection is **Hidden DNS/HTTP Tunnel**, also read this playbook even
though Vectra may classify it under C&C — tunnels frequently carry data out,
not just commands in.

---

## Benign baselines (rule these out before calling TP)

Most exfil-shaped traffic in a real enterprise is benign. Walk this list
**before** escalating:

| Baseline | What it looks like | How to confirm |
|----------|-------------------|----------------|
| **Backup software** (Veeam, Rubrik, Cohesity, Druva, Code42) | Scheduled, large, off-hours, repeats nightly to the same destination | Check entity tags / hostname; pull last 7 days same time-window for the same dst — if it's identical, it's the backup job |
| **Cloud sync / DLP / EDR upload** | OneDrive, Dropbox, Google Drive, Box; CrowdStrike sample upload; Defender telemetry | Sweep TLS via `vectra-hunt` (`network_tls_certs.md` SNI-hunt recipe) for the SaaS hostname over the detection window; corroborate with HTTP host (`network_dns_http.md` host-header hunt). For long-term posture, the named `saas_reachability` canned report covers it — but only if the analyst explicitly asks for that report. |
| **Software updates pulling files in reverse** (vendor uploads) | One-shot, signed binary host, regular schedule | TLS cert subject; X.509 issuer is the vendor |
| **BI / analytics export** | Tableau, Power BI, Snowflake unloads; large outbound to known SaaS analytics | User context; SaaS dst; not off-hours |
| **Vulnerability scanner posting results** | Qualys / Rapid7 / Nessus reporting back to its console | Entity tag = scanner; dst = scanner SaaS |
| **CI/CD artifact push** | Jenkins, GitHub Actions runners pushing build artifacts | Hostname matches build-agent naming convention |
| **Genuine bulk download by a user** (HR pulling reports, Finance month-end) | Daytime, single user, expected SaaS app | M365 audit log normal pattern; user role matches |

Every BTP verdict needs one of these named explicitly. *"Looked benign"* is
not a baseline.

---

## Malicious indicators (what flips this to TP)

Stack-rank — any **two or more** in combination strongly favors TP:

- **Off-hours / off-baseline timing** — egress at 03:00 local from an entity
  that doesn't normally transmit then.
- **Co-occurring C&C detection** on the same entity in the same window
  (Hidden Tunnel + Smash and Grab on `WIN-FILESVR` is a textbook chain).
- **Co-occurring Lateral Movement** earlier in the kill chain (Suspicious
  Admin → file-server access → exfil).
- **Sensitive source** — file server, code repo host, DB server, finance
  workstation, executive endpoint, key-asset tag.
- **Novel destination** — first time this entity has talked to that domain /
  ASN / cloud account; freshly-registered domain; cert subject mismatch with
  SNI; self-signed cert.
- **Suspicious channel shape** — long-lived TLS with high outbound : inbound
  byte ratio; DNS TXT volume anomaly; HTTP POST with large bodies and no GET
  pairs; unusual JA4 fingerprint for the source.
- **Identity anomaly** — bulk M365 download by user from a country / device /
  IP not in their baseline; mail forwarding rule created shortly before the
  download spike.
- **Logging disabled** in the same window — treat as malicious-by-default
  unless an audited change ticket explains it.

---

## Pivot pipeline

Run these in order. Each step refers to a SQL recipe in
[`vectra-hunt/references/`](../../vectra-hunt/references/) —
copy the SQL, substitute the parameters from `get_detection_details`, and
execute through the Vectra MCP `run_investigation` /
`get_investigation_results` tools.

### Network exfil (Smash and Grab, Data Smuggler, Hidden HTTP/S Tunnel)

0. **(Optional) Pull the PCAP** for the detection via
   [`vectra-pcap`](../../vectra-pcap/SKILL.md) — `get_detection_pcap`
   through MCP, decode with `scripts/fetch-detection-pcap.sh`, then
   `scripts/pcap-context.sh` for a one-pass triage. Most useful when
   you need the actual TLS SNI / ALPN, the HTTP request body or
   `Authorization` header, or the destination certificate; less useful
   for purely high-volume detections where the metadata pivot below
   already answers the volume question.
1. **Detection-window sessions** for the entity →
   `network_sessions.md` recipe **5 (Detection Window Sessions)**.
   Confirm the volume, identify the destination IP / domain, capture
   JA4 / first-packet payload.
2. **Top outbound flows ordered by `orig_ip_bytes`** for that entity
   in the same window → `network_sessions.md` recipe **2 (Traffic Summary)**
   or recipe **3 (Large Outbound Transfers)** with `min_bytes` lowered to
   the smallest transfer you care about.
3. **TLS / SNI** for the destination → `network_tls_certs.md` recipe
   **2 (SNI hunt)** + recipe **4 (JA3 fingerprint hunt)** to characterize
   the channel and check for self-signed / mismatched certs.
4. **HTTP host / URI / POST hunt** → `network_dns_http.md` recipes
   **2 (Host header hunt)** and **3 (POST exfiltration)** if HTTP-shaped.
5. **Beacon overlap** — check whether the same destination shows up in
   `network.beacon._all` in the prior 24–168h → `network_infra.md` beacon
   recipes. A confirmed beacon to the same dst before the burst is a
   strong TP signal.

### DNS tunnel (Hidden DNS Tunnel)

0. **(Optional) Pull the PCAP** via
   [`vectra-pcap`](../../vectra-pcap/SKILL.md). The triage script's
   `dns` section emits the full query list with response codes,
   NXDOMAIN counts, and fast-flux candidates — exactly what you need
   to confirm the tunneling shape (long encoded labels, TXT-record
   abuse, NXDOMAIN scaffolding) when the metadata pivot below is
   ambiguous.
1. **DNS volume + domain blast radius for the entity** →
   `network_dns_http.md` recipes **1–2** (host queries, domain volumes).
2. **Hunt for DGA / NXDOMAIN spikes** → `network_dns_http.md` recipe
   **3 (NXDOMAIN/DGA hunt)** — even successful tunnels often leak NXDOMAIN
   scaffolding.
3. **Long-label / TXT-record patterns** — extend the DNS recipe to filter
   `LENGTH(query) > 50` or `qtype_name = 'TXT'`. Use the DNS schema and
   the SQL construction rules in `vectra-hunt/SKILL.md` to
   author the variant if no canned recipe matches.
4. **Co-occurrence** — does the same entity show C&C-category beacons in
   the same window? (`network.beacon._all` recipes.)

### Cloud exfil (AWS Suspicious Cloud Storage / M365 Download / Mail Forwarding)

> **No PCAP available.** Cloud / log-based detections are derived
> from CloudTrail / Unified Audit Log / Graph API events — there is
> no underlying packet capture to pull. The `vectra-pcap` skill will
> return a `406 Not Acceptable` for these. Stay on the metadata
> pivots below.

1. **Principal activity in the detection window** →
   `cloud_investigations.md` AWS recipe **1 (Principal CloudTrail Events)**
   filtered by the resolved identity from the detection. Look at
   `event_name` distribution: `GetObject` flood vs balanced reads/writes.
2. **Source IP hunt** → `cloud_investigations.md` AWS recipe **4 (Hunt
   from IP)** — is this principal calling from a new geography / ASN?
3. **Co-occurring IAM changes** → `cloud_investigations.md` AWS recipe
   **5 (IAM Changes)** in the prior 168h. New access key, attached
   policy, or assumed role just before the spike is a kill-chain.
4. **M365 download spike** → `cloud_investigations.md` SharePoint recipe
   **2 (Bulk Downloads)** for the user. Compare to the user's prior
   weeks.
5. **Mail forwarding / inbox rule** → `cloud_investigations.md` Exchange
   recipe **2 (Forwarding Rules)** for the user — recent rule creations
   pointing at external addresses are the signal.
6. **Sign-in context** → `cloud_investigations.md` Entra recipes
   **1 (User sign-ins)** and **3 (Risky sign-ins)** in the same window —
   a risky sign-in immediately preceding a download spike is a strong TP.

### Always also run

- `list_entity_detections(entity_id=<id>, state="active")` — pull
  *every* open detection on the entity. A tunnel detection with no
  surrounding chain is a different verdict than the same tunnel
  paired with Suspicious Admin and Kerberoasting.
- For the destination IP / domain, run a **blast-radius sweep via
  `vectra-hunt`** to see whether other entities in the tenant are also
  talking to the same infrastructure:
  - Domain → `network_dns_http.md` "Domain blast radius" recipe (DNS),
    `network_tls_certs.md` "SNI hunt" recipe (TLS), `network_dns_http.md`
    "host-header hunt" recipe (HTTP).
  - IP → `network_sessions.md` "Failed / large-transfer pivot" filtered by
    `id.resp_h`, `network_tls_certs.md` SNI hunt cross-checked by IP.
  - Beaconing destination → `network_infra.md` "Beacon dest IP/domain" recipe.

  These run through the Vectra MCP `run_investigation` tool — same
  channel as every other detection pivot. Do **not** reach for the
  `c2_beacon_report` canned dashboard for this question; the dashboard is
  for posture / KPI views, not for entity / IOC investigation.

---

## Verdict rubric

Apply per detection, then roll up per entity per the global rubric in
[`verdict-framework.md`](verdict-framework.md).

### Smash and Grab

| Pattern | Verdict |
|---------|---------|
| Backup agent or named DLP/EDR upload, scheduled window match | **BTP**. Document the agent + dst + schedule; scope suppression to (host, dst, time-of-day). |
| Single user pulling expected SaaS report at expected time | **BTP**. Document user + SaaS app + business reason. |
| Off-hours from a sensitive source to a novel external dst, no co-occurring detections | **TP-Low** if low entity priority and no other chain — assign + monitor. **TP-High** if entity is a key asset or has tags like `file-server`, `db-server`, `code-host`. |
| Co-occurring C&C or LM detections on the same entity in window | **TP-High**. Escalate. Recommend isolating the host and preserving session evidence. |

### Data Smuggler

| Pattern | Verdict |
|---------|---------|
| Steady ratio anomaly traceable to a long-lived legitimate sync (cloud sync, sensor, telemetry agent) | **BTP**. Tag the agent. |
| Ratio anomaly + novel destination + JA4 not matching any known baseline JA4 for this host class | **TP-Low → TP-High** depending on entity sensitivity. Investigate cert / SNI. |
| Ratio anomaly + co-occurring tunnel detection (HTTP/S or DNS) | **TP-High**. The drain *is* the channel. Escalate. |

### Hidden DNS Tunnel

| Pattern | Verdict |
|---------|---------|
| EDR / DLP product known to use DNS for telemetry (rare; needs vendor confirmation) | **BTP**. Document. |
| Internal misconfigured app generating long DNS labels but only to internal resolvers / known infra | **BTP**. Tag and scope. |
| Long-label / high-frequency / NXDOMAIN-rich queries to a single external authoritative server, persistent over hours | **TP-High**. DNS tunnels are rarely benign; default to escalation. |

### Hidden HTTP/S Tunnel

| Pattern | Verdict |
|---------|---------|
| Known legitimate tunnel-shaped product (Slack, Teams, screen-share) on the entity, dst matches vendor SNI | **BTP**. Confirm SNI + JA4 match vendor baseline. |
| Persistent outbound + high outbound:inbound bytes + novel SNI / self-signed cert | **TP-High**. Treat as C&C with exfil potential. Escalate. |
| Bursty exfil-shaped POSTs to an unusual host with no prior reachability | **TP-High**. Pull HTTP recipes #2/#3. |

### Suspicious Cloud Storage Activity (AWS)

| Pattern | Verdict |
|---------|---------|
| Known data-engineering principal (ETL pipeline, replication tool) within its baseline | **BTP**. Document principal + bucket. |
| New access key created in window + GetObject burst + new source IP / region | **TP-High**. Likely compromised credential. Escalate, recommend key revocation. |
| Anomaly without IAM changes, but principal is a known service role accessed from a new IP | **TP-Low**. Assign + monitor; check for stolen role assumption. |

### M365 Suspicious Download / Mail Forwarding

| Pattern | Verdict |
|---------|---------|
| HR / Finance / Legal user pulling expected files during a known business event | **BTP**. Note user + business reason. |
| User download spike with no risky sign-in, no inbox rule, no permission grant | **TP-Low** (monitor) unless asset tag escalates it. |
| Risky sign-in (Entra) → mail forwarding rule created → download spike, all within hours | **TP-High**. Classic BEC / cloud account takeover. Escalate, recommend session revocation + rule deletion. |

---

## Verdict write-up template

```
Verdict: [BTP | TP-Low | TP-High | Need more data]

Entity: <name> (priority <score>, tags: <tags>, key_asset: <yes/no>)
Detections in scope: <list of detection ids/types in this window>

Behavior observed:
  - Vectra detection summary: <one line>
  - Pivot evidence: <one line per recipe run, with row counts / key values>

Reasoning:
  - <kill-chain or benign-baseline match>
  - <co-occurring or absent context>

Disposition:
  - Action: <assign / escalate / close as BTP>
  - Triage rule scope (if BTP): (host=<id>, detection_type=<type>, dst=<ip|domain>)
  - Tier 2 escalation note (if TP-High): <one paragraph for IR handoff>
  - Proposed entity note: <create_entity_note call, or "none — prior note stands">
    (read existing notes first; see verdict-framework.md § Persisting the verdict)
```

> The full per-entity verdict template (with multi-tenant scope, key-asset
> flags, gap section, etc.) lives in
> [`verdict-framework.md`](verdict-framework.md).

---

## Quick reference — which `vectra-hunt` recipe for what

| Need | Recipe file → recipe |
|------|----------------------|
| Detection-window sessions for an entity | `network_sessions.md` → 5 |
| Top outbound by bytes for an entity | `network_sessions.md` → 2 |
| Environment-wide large transfers | `network_sessions.md` → 3 |
| TLS/SNI characterization | `network_tls_certs.md` → 1, 2 |
| Self-signed / weak TLS | `network_tls_certs.md` → 3, 4 |
| HTTP POST exfiltration shape | `network_dns_http.md` → 3 |
| HTTP host header hunt | `network_dns_http.md` → 2 |
| DNS volume / domain blast | `network_dns_http.md` → 1, 2 |
| NXDOMAIN / DGA spikes | `network_dns_http.md` → 3 |
| Beacon co-occurrence | `network_infra.md` → beacon 1, 2 |
| AWS principal events | `cloud_investigations.md` → AWS 1 |
| AWS IAM changes | `cloud_investigations.md` → AWS 5 |
| AWS source-IP hunt | `cloud_investigations.md` → AWS 4 |
| M365 SharePoint bulk downloads | `cloud_investigations.md` → SharePoint 2 |
| M365 Exchange forwarding rules | `cloud_investigations.md` → Exchange 2 |
| Entra risky sign-ins | `cloud_investigations.md` → Entra 3 |

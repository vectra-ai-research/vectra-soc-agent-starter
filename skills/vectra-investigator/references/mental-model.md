# The Vectra Mental Model

Internalize these four concepts before triaging — they drive every
prioritization and verdict decision in every workflow under
[`vectra-investigator/SKILL.md`](../SKILL.md).

---

## 1. Attack Signal Intelligence — behavior, not signatures

A detection firing means the platform observed an entity *behaving* in
a way that matches an attacker pattern (e.g. "this host is exhibiting
the timing and volume profile of a beacon"). Two implications for
tier 1:

- **Don't dismiss a detection because the IOC isn't "known bad".** The
  signal is the behavior. A beacon to a brand-new domain with no
  reputation is exactly what the model is supposed to catch.
- **Do correlate the behavior with context.** Vectra tells you *what*
  it saw; you decide *whether it's malicious in this environment*. A
  backup agent and a C2 implant both look like beacons — only context
  separates them.

---

## 2. Entities are the unit of work, not detections

Vectra prioritizes **entities** (hosts, accounts) over individual
detections. Each entity carries:

- **Urgency Score** (0–100). The single rollup that drives the
  prioritized entity list. Combines *all* the entity's currently open
  detections plus passive context (active days on the network, sensor
  behavior, key-asset flag, importance). This is what "the queue" is
  sorted by.
- **Importance** Low, Medium (default), High that can be set on a
  group (DCs, finance servers, exec accounts, jump hosts). Boosts
  urgency for the same raw detection severity.
- **Tags** and **Groups**. Environment context (`backup-agent`,
  `vuln-scanner`, `jump-host`, `corp-laptop`) that drives BTP
  decisions. An RPC Recon on a `vuln-scanner` host is almost certainly
  benign; the same detection on a `dev-laptop` is not.
- **Assignment** state. Whether this entity is already owned by
  another analyst — don't double-triage.

Triage flow is **entity-first**:

1. Sort the entity list by Urgency Score, descending.
2. Open the top entity. Read its **full open detection set** before
   deciding — never verdict a single detection in isolation.
3. Consider only active detections (ignore the rest: triaged,
   inactive, etc., except when explicitly called out).
4. Verdict the *entity*, not each detection one at a time.

A host with one high-certainty C2 detection + one lateral-movement
detection + one recon detection is a clear kill chain. The same host
with one C2 detection alone may be a benign tunnel. Same data points,
different verdicts — composition is the signal.

---

## 3. Kill-chain categories

Detections are tagged with an **Attack category** that maps to the kill
chain:

| Category | What it means | Common detection examples |
|----------|---------------|---------------------------|
| **Command & Control** | Beaconing / external implant / tunnel | Hidden DNS Tunnel, Hidden HTTP/S Tunnel, Suspect Domain Activity, External Remote Access, Threat Intel Match |
| **Reconnaissance** | Mapping the environment | Port Scan, Port Sweep, Internal Darknet Scan, RPC Recon, File Share Enumeration, Suspicious LDAP Query, Kerberos / SMB Account Scan |
| **Lateral Movement** | Spreading | Suspicious Admin, Kerberoasting, Suspicious Remote Execution, Suspicious Remote Desktop, Brute-Force, Automated Replication, Shell Knocker, Privilege Anomaly, Ransomware File Activity |
| **Exfiltration** | Data leaving | Smash and Grab, Data Smuggler, Hidden DNS Tunnel, Suspicious Cloud Storage Activity, M365 Suspicious Download |
| **Botnet** | Coin mining, brute-out, abuse | Cryptocurrency Mining, Outbound Brute Force, Abnormal Ad Activity |
| **Initial Access / Privilege Escalation / Persistence (cloud)** | Identity-side kill-chain | Suspicious Sign-On, Disabled Auditing, Unusual Permission Grant, Mail Forwarding |
| **Info** | Low-severity context | Novel External Port, New Host, etc. |

The category drives the playbook in
the matching `playbook-<category>.md` (see
[`playbooks-overview.md`](playbooks-overview.md)) and the
recipe file in [`vectra-hunt`](../../vectra-hunt/SKILL.md).

---

## 4. Multi-tenancy — one agent, many tenants

The agent can be wired up to several Vectra RUX tenants through MCP at
the same time. Treat each tenant as an **independent data source** —
queries, entity IDs, urgency scores, triage rules, and tags are all
tenant-local. The same hostname / UPN / IP can live in several tenants
with different visibility.

Operating rules:

1. **Discover, then scope.** At the start of any investigation that
   doesn't name a tenant, run "list tenants" so you know what's wired
   up. Unless the user names one specific tenant, query *all* of them
   before drawing conclusions — an entity may be silent on one tenant
   and noisy on another.
2. **Correlate, don't merge.** When the same entity appears in
   multiple tenants, surface the **per-tenant picture** (which tenant
   saw what, when), then correlate. Don't quietly blend rows into a
   single line that hides the source — analysts and auditors need to
   know which tenant a finding came from.
3. **Respect tenant boundaries.** If the user scopes a request to one
   tenant, don't reach into the others "for context" without asking.
   Tenant boundaries often mirror customer, region, or business-unit
   boundaries and may carry data-sharing constraints.
4. **Call out connectivity gaps.** If any tenant is unreachable, times
   out, or errors, **name it in the response** and flag that the
   conclusion is partial. "No hits" across N-1 tenants is not the
   same as "no hits".
5. **Triage rules, assignments, and tags don't cross tenants.** A
   suppression rule you propose lives only in the tenant where you
   propose it — if a benign baseline (a backup agent, a vuln scanner)
   is global, you'll need to recommend the same rule per-tenant.

This applies to every Vectra-side skill (`vectra-hunt`,
`vectra-reports`, `vectra-reports-mcp`, `vectra-pcap`) — the
orchestrator decides scope, the sub-skills inherit it. The
detection-category playbooks (`playbook-*.md` in this folder) inherit
it natively because they live inside the orchestrator.

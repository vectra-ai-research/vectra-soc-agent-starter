# Lateral Movement — Tier 1 Analyst Playbook

This playbook tells you how to triage a Vectra detection in the **Lateral
Movement** category (and tightly-related Reconnaissance detections that
typically chain into LM). It is a decision guide, not a SQL library — when
you need queries, this playbook routes you into the matching recipe in
[`vectra-hunt`](../../vectra-hunt/references/).

> Companion references: [`playbooks-overview.md`](playbooks-overview.md)
> for the playbook six-section shape and how-to-use guidance,
> [`verdict-framework.md`](verdict-framework.md) for the per-entity
> verdict rubric and write-up template.

---

## What Vectra is detecting

The Lateral Movement category models an attacker (or compromised credential)
**spreading through the environment** after initial access: probing internal
services, abusing admin protocols, harvesting credentials, executing on
remote hosts, and elevating privileges. The signal is **internal east-west
behavior on auth and admin protocols** (SMB, Kerberos, NTLM, LDAP, RDP,
DCE-RPC, WinRM/WMI), shaped in a way that doesn't match the entity's
historical baseline.

You are not asking *"is this connection allowed by firewall?"* You are
asking:

1. Did this *specific entity* normally do this admin-shaped behavior?
2. Is the target set wider than its baseline (one source → many targets)?
3. Does it pair with a credential abuse signal (Kerberoasting, RC4, NTLM
   spray, password change immediately before)?
4. Is there an entry point upstream (C&C / risky sign-in) that explains
   *why* this entity is moving?

Lateral Movement is the **highest-leverage triage category** for tier 1 —
catching it here stops the kill chain before exfil or impact.

---

## Detection types in scope

### Lateral Movement (primary)

| Detection | What it sees | Protocol |
|-----------|--------------|----------|
| **Suspicious Admin** | Account using admin-shaped protocols (SMB ADMIN$/C$/IPC$, RPC svcctl, WinRM) on hosts the account hasn't historically administered | SMB / DCE-RPC / WinRM |
| **Suspicious Remote Execution** | Remote command execution patterns: PsExec, WMI, scheduled task, service creation, WinRM | DCE-RPC (svcctl, atsvc), SMB |
| **Suspicious Remote Desktop** | RDP from a host that doesn't normally initiate RDP, or to many internal targets | RDP |
| **Kerberoasting** | TGS-REQ for service tickets with weak (RC4/DES) ticket cipher → offline crack of service-account passwords | Kerberos |
| **Brute-Force** (SMB / Kerberos / NTLM / RDP variants) | High-rate failed auths from a single source, or low-rate spray across many accounts | Kerberos / NTLM / SMB / RDP |
| **Automated Replication** | One source replicating files/objects to many targets at machine speed | SMB / generic |
| **Shell Knocker** | Reverse-shell-shaped behavior between internal hosts | TCP |
| **Privilege Anomaly: Unusual Account on Host** | Account observed authenticating to a host outside its normal access scope | Kerberos / NTLM |
| **Privilege Anomaly: Unusual Account on Service** | Account using a service / RPC interface it doesn't normally use | DCE-RPC / Kerberos |
| **Privilege Anomaly: Unusual Service** | Service principal being used in an unusual way | Kerberos |
| **Ransomware File Activity** | Mass file write / delete / rename matching ransomware shapes | SMB |
| **SQL Injection Activity** | App-server-shaped SQL anomalies suggesting compromised app pivoting to DB | DB protocols |
| **SMB Brute-Force** | NTLM-over-SMB brute force | SMB |

### Reconnaissance (chains into LM — read together)

| Detection | What it sees | Protocol |
|-----------|--------------|----------|
| **RPC Recon** | Enumeration over named pipes / RPC interfaces (`samr`, `lsarpc`, `wkssvc`, `srvsvc`, `winreg`) | DCE-RPC |
| **File Share Enumeration** / **SMB Account Scan** | One source touching many shares or auth-probing many accounts via SMB | SMB |
| **Kerberos Account Scan** | One source TGT/TGS-probing many principals | Kerberos |
| **Suspicious LDAP Query** | LDAP queries with unusually wide result sets, sensitive attributes (`ms-Mcs-AdmPwd`, `servicePrincipalName`, `userPassword`), or BloodHound-shaped enumeration | LDAP |
| **Port Scan** / **Port Sweep** / **Internal Darknet Scan** | One source touching many internal ports / hosts; or any source touching unallocated address space | TCP |

If a Recon detection lands together with an LM detection on the same entity
in the same window, treat them as a single chain — the recon is the *map*,
the LM is the *move*.

---

## Benign baselines (rule these out before calling TP)

LM detections fire heavily on legitimate admin and tooling behavior. Walk
this list **before** escalating:

| Baseline | What it looks like | How to confirm |
|----------|-------------------|----------------|
| **Domain admins / sysadmins doing real work** | Known admin account, daytime, business reason in change ticket | Check entity tag `admin-jumpbox` / account membership; look at the user's prior-week pattern via Kerberos / NTLM recipes |
| **Vulnerability scanner** (Qualys, Tenable, Rapid7, Nessus) | One source touching many internal hosts on many ports — looks identical to a port sweep + recon chain | Tag/group on the source; consistent schedule; matches scanner's published scan window |
| **Configuration management** (SCCM, Intune, Ansible Tower, Salt, Puppet) | Source pushes payloads/config to many endpoints over SMB/WinRM/RPC | Source hostname matches mgmt convention; targets are the managed estate |
| **Backup software** | Walks SMB shares to back up files; can look like file enumeration / mass read | Tag on source; off-hours; same dst pattern repeats nightly |
| **EDR / AV agents** | Talk to many endpoints / push signatures via SMB/RPC | Source = central management server for the EDR |
| **Service accounts running expected services** | High-volume Kerberos to known SPNs | Account is in `service_accounts` group; SPN matches the service |
| **Domain controllers and AD infra talking to each other** | DCs replicate via DRSUAPI; can look exactly like DCSync | Source AND destination are DCs; replication partner is the other DC, not a workstation |
| **Print/file servers, terminal servers** | Receive lots of inbound SMB/RDP from many users — looks like fan-in lateral movement when viewed from the dst side | Confirm the dst is an expected centralized service |
| **Pen-test / red-team window** | Identical shape to a real intrusion | Confirm against the engagement schedule before any verdict |
| **Migration / mass deployment events** | Bulk reads/writes/renames over SMB | Confirm via change calendar |

Every BTP needs a named source — *"looked like a scanner"* is not a baseline.
Pull `get_host_details` / tags / groups and confirm.

---

## Malicious indicators (what flips this to TP)

Stack-rank — any **two or more** in combination strongly favors TP:

- **Source is a workstation / endpoint, not a server** — admin-shaped
  protocols originating from a user laptop is rarely benign.
- **Source is one host, target set is wide** — fan-out from a single endpoint
  to many internal hosts on admin protocols.
- **RC4 or DES ticket cipher in TGS-REQ** — Kerberoasting; modern Windows
  defaults to AES, so RC4 is a strong indicator unless the SPN is on a
  legacy service.
- **DRSUAPI / DsGetNCChanges from non-DC source** — DCSync. Almost never
  benign from anything that isn't a domain controller.
- **`samr` / `lsarpc` / `winreg` enumeration from a workstation** — recon
  before move; especially if it precedes a Suspicious Admin detection.
- **LDAP query for sensitive attributes** (`ms-Mcs-AdmPwd` = LAPS,
  `servicePrincipalName`, `userPassword`, `unicodePwd`,
  `ntPwdHistory`) — there are very few legitimate reasons.
- **Kill-chain composition** on the same entity in the same window — Recon
  detection + LM detection + (optional) C&C upstream = textbook intrusion.
- **Privilege anomaly without a recent role / group change ticket** —
  account suddenly accessing things it never has before.
- **Off-hours admin activity** from an account whose owner is not on-call.
- **Failed-then-succeeded auth pattern** — spray followed by a single success
  is credential takeover.
- **Mass SMB writes / renames matching ransomware extensions** or with
  `delete_on_close=true` on many files — pre-ransomware staging.
- **NTLM hostname mismatch** — `hostname` field in NTLM doesn't match the
  expected source hostname for the IP — Pass-the-Hash relay.
- **Pulled credentials immediately before the LM** — co-occurring
  Kerberoasting / LSASS-shaped activity / LAPS LDAP query.

---

## Pivot pipeline

Run these in order. Each step refers to a SQL recipe in
[`vectra-hunt/references/`](../../vectra-hunt/references/) —
copy the SQL, substitute parameters from `get_detection_details`, and
execute through the Vectra MCP `run_investigation` /
`get_investigation_results` tools.

### For any LM detection — start here

0. **(Optional) Pull the PCAP** for the detection via
   [`vectra-pcap`](../../vectra-pcap/SKILL.md) — `get_detection_pcap`
   through MCP, decode with `scripts/fetch-detection-pcap.sh`, then
   `scripts/pcap-context.sh`. Lateral-movement detections are *the*
   best fit for the PCAP triage: the structured output gives you
   NTLM/Kerberos exchanges (usernames, domains, target servers,
   principals), SMB TreeConnect events with admin-share flagging
   (`ADMIN$` / `C$` / `IPC$`), DCE/RPC interface bindings, and any
   `ProcessCommandLine` strings on the wire — all evidence the
   metadata pivots below approximate. Skip if the PCAP isn't
   available (aged-out detection, identity-only LM signals).
1. **Detection-window sessions** for the entity →
   `network_sessions.md` recipe **5 (Detection Window Sessions)**.
   Confirm the source-target pairs and the timing.
2. **Failed connections** in the same window →
   `network_sessions.md` recipe **4 (Failed Connections, S0 / REJ)**.
   Scanning shape (S0 fan-out) is a recon precursor; lots of REJ to one host
   is a vertical port scan.
3. **Pull the entity's full open detection set** —
   `list_entity_detections(entity_id=<id>, state="active")`. Build the
   kill-chain map (Recon → LM → C&C / Exfil) before deciding.

### Suspicious Admin / Suspicious Remote Execution

1. **SMB share + admin-share access** →
   `network_lateral_movement.md` recipes **1 (Host Share Connections)**
   and **2 (Admin Share Access — ADMIN$/C$/IPC$)**.
2. **DCE-RPC activity** for the source →
   `network_lateral_movement.md` recipes **1 (Host DCE-RPC Activity)** and
   **4 (Lateral Movement RPC: svcctl + drsuapi + atsvc)**.
3. **DCE-RPC operations** — hunt for `CreateService`, `StartService`,
   `SchRpcRegisterTask`, `OpenSCManager` →
   `network_lateral_movement.md` recipe **3 (Hunt by Operation)**.
4. **NTLM auth** from the source — confirm hostname / username + check
   for hostname mismatch (PtH) → `network_lateral_movement.md` recipes
   **1 (Host NTLM Auth)** and **4 (Pass-the-Hash Indicators)**.

### Kerberoasting

1. **TGS with RC4 / DES ticket cipher** →
   `network_lateral_movement.md` recipe **2 (Kerberoasting — TGS with
   weak RC4 encryption)**.
2. **Same source's full Kerberos activity** →
   `network_lateral_movement.md` recipe **1 (Host Kerberos Activity)**
   to see the SPN distribution.
3. **Track the requesting user across the environment** →
   `network_lateral_movement.md` recipe **4 (Kerberos for User)**.
4. **LDAP SPN enumeration** from the same source in the prior 48h →
   `network_lateral_movement.md` recipe **4 (Sensitive Attribute Requests)**
   (looking specifically for `servicePrincipalName`).

### Brute-Force (Kerberos / NTLM / SMB / RDP)

1. **Failed auths** for the protocol →
   `network_lateral_movement.md` Kerberos recipe **3 (Failed Kerberos)** /
   NTLM recipe **2 (NTLM Failures — Password spraying)**.
2. **Then a successful auth from the same source** — change `success = true`
   in the same recipe with the same source filter and look for the success
   immediately following the failure burst. That's the takeover moment.
3. **Track the compromised user** post-success →
   `network_lateral_movement.md` Kerberos recipe **4** / NTLM recipe **3**.
4. **RDP follow-up** if applicable → `network_lateral_movement.md` RDP
   recipe **2 (Internal RDP Lateral Movement)** filtered by the
   newly-compromised user.

### RPC Recon (and File Share Enumeration / SMB Account Scan)

1. **Hunt by endpoint** — `samr`, `lsarpc`, `srvsvc`, `wkssvc`, `winreg` →
   `network_lateral_movement.md` recipe **2 (Hunt by Endpoint)**.
2. **DRSUAPI from non-DC source** — `network_lateral_movement.md` recipe
   **2** with endpoint = `drsuapi`. If source is not a DC: **TP-High,
   DCSync**.
3. **SMB share enumeration** — `network_lateral_movement.md` SMB recipes
   **1 (Host Share Connections)** with the source filter to see how wide
   the touch is.
4. **Look for the *next move*** — same entity within the next few hours
   showing Suspicious Admin / Remote Execution.

### Suspicious LDAP Query

1. **LDAP recon** (large result sets) →
   `network_lateral_movement.md` recipe **2 (LDAP Reconnaissance)**.
2. **Sensitive attribute requests** (LAPS / SPN / passwords) →
   `network_lateral_movement.md` recipe **4 (Sensitive Attribute Requests)**.
3. **Hunt by base object** to see whether it's targeted at a specific OU
   (e.g. Domain Admins) → `network_lateral_movement.md` recipe **3 (Hunt
   by Base Object)**.

### Suspicious Remote Desktop

1. **RDP sessions** for the source → `network_lateral_movement.md` RDP
   recipe **1 (Host RDP Sessions)**.
2. **Internal lateral RDP** (`local_orig=true AND local_resp=true`) →
   `network_lateral_movement.md` RDP recipe **2 (Internal RDP Lateral
   Movement)**.
3. **Unencrypted RDP** → `network_lateral_movement.md` RDP recipe
   **4 (Unencrypted RDP)** — strong indicator of either misconfig or
   relay/MITM.
4. **RDP client name hunt** — Mimikatz / hacking tools sometimes leave
   distinct client name strings → `network_lateral_movement.md` RDP recipe
   **3 (Hunt by Client Name)**.

### Ransomware File Activity

1. **File writes / deletes / renames** →
   `network_lateral_movement.md` SMB Files recipe **2 (File
   Writes/Deletes/Renames)** filtered to the source.
2. **Volume burst** — count operations per minute; a true ransomware
   burst is hundreds-to-thousands of operations in seconds.
3. **Targets** — many distinct shares / many distinct file servers from
   one source = fan-out impact. **Treat as TP-High, contain immediately.**

### Privilege Anomaly (Unusual Account/Host/Service)

1. **Track the account** across Kerberos and NTLM →
   `network_lateral_movement.md` Kerberos recipe **4** + NTLM recipe **3**
   filtered by the unusual account.
2. **Co-occurring Kerberoasting / RC4 TGS** in the prior 48h.
3. **Cloud sign-in side** → `cloud_investigations.md` Entra recipes
   **1 (User sign-ins)**, **3 (Risky sign-ins)** for the same UPN —
   identity-side entry would explain the on-prem anomaly.
4. **Recent permission grant** in M365 / AWS / Entra in window →
   `cloud_investigations.md` AWS IAM recipe **5**, Azure CP recipe **5
   (Role assignments)**, Entra Directory Audits recipe **2 (Privileged
   role changes)**.

### Always also run

- `list_entity_detections(entity_id=<host_id>, state="active")` and
  `list_entity_detections(entity_id=<account_id>, state="active")` —
  the *full* detection picture on both the host AND the account
  drives the verdict.
- For any account-side LM detection, also pull the matching cloud
  detections via
  `list_detections_with_basic_info(category="Initial Access" |
  "Privilege Escalation")` — east-west on-prem moves often start with
  a cloud identity compromise.

---

## Verdict rubric

Apply per detection, then roll up per entity per the global rubric in
[`verdict-framework.md`](verdict-framework.md).

### Suspicious Admin / Suspicious Remote Execution

| Pattern | Verdict |
|---------|---------|
| Source is tagged `admin-jumpbox` / SCCM / Ansible / Intune mgmt server, target set matches the managed estate | **BTP**. Document the mgmt tool. Scope rule to (source_host, dst_set, protocol). |
| Source is a known sysadmin's workstation, daytime, change ticket exists | **BTP**. Document user + ticket. |
| Source is a regular workstation, fan-out to multiple internal targets on ADMIN$/C$/svcctl, no ticket | **TP-High**. Likely active intrusion. Escalate, recommend host isolation. |
| Source is a server but the target set is novel (not in its baseline) | **TP-Low** if no other detections; **TP-High** if paired with Recon / Kerberoasting / risky sign-in. |

### Kerberoasting

| Pattern | Verdict |
|---------|---------|
| RC4 TGS for SPNs on confirmed legacy systems (older Windows / appliance) requested by an expected service account | **BTP**. Document the SPN + reason. Scope rule to (account, SPN). |
| RC4 TGS burst across many SPNs from a single workstation | **TP-High**. Classic Kerberoasting. Escalate, recommend service-account password rotations + AES-only enforcement where possible. |
| Single RC4 TGS, single SPN, no other context | **Need more data**. Pull SPN enumeration recipe before deciding. |

### Brute-Force

| Pattern | Verdict |
|---------|---------|
| High-rate failed auths from a known stale service / app with bad creds, single account | **BTP**. Open ticket with app owner; suppression scope: (source, account). |
| Low-rate failures across many accounts from a single source (spray) | **TP-High**. Almost never benign. Escalate. |
| Failures + immediate success from the same source on one of the sprayed accounts | **TP-High, escalate immediately**. Account is taken over. Recommend session revocation, password reset, MFA enforcement. |

### Automated Replication / Ransomware File Activity

| Pattern | Verdict |
|---------|---------|
| Source = backup agent, target set matches the backup estate, scheduled window | **BTP**. Document the agent. |
| Source = workstation, mass file writes/deletes/renames over SMB at machine speed | **TP-High, contain NOW**. Recommend isolating the host immediately and preserving evidence. |
| Source = file server, mass renames with ransomware-shaped extensions | **TP-High**. Pre-encryption staging. Same containment urgency. |

### RPC Recon / SMB Account Scan / File Share Enumeration

| Pattern | Verdict |
|---------|---------|
| Source = vulnerability scanner, schedule and target set match its config | **BTP**. Document scanner. |
| Source = workstation, broad RPC enumeration of `samr` / `wkssvc` / `srvsvc` | **TP-Low → TP-High** depending on chain. If LM detection follows in window: **TP-High**. |
| Source = non-DC, DRSUAPI / `DsGetNCChanges` calls | **TP-High, DCSync**. Escalate. Recommend DC log review and credential rotation for KRBTGT if confirmed. |

### Suspicious LDAP Query

| Pattern | Verdict |
|---------|---------|
| App / IAM tool with known wide-result LDAP queries on a defined schedule | **BTP**. Document app. |
| Workstation querying for `servicePrincipalName` across the directory | **TP-High** (paired with Kerberoasting precursor). |
| Workstation querying for `ms-Mcs-AdmPwd` (LAPS) | **TP-High**. Almost no legitimate workstation reason. |
| BloodHound-shaped wide queries (large `objectClass=*` etc.) | **TP-High**. Recon for AD attack path. |

### Suspicious Remote Desktop

| Pattern | Verdict |
|---------|---------|
| Known sysadmin workstation, RDP into expected jumpbox / server | **BTP**. Document admin + dst. |
| Unencrypted RDP to many internal targets from one source | **TP-High**. Either misconfig (still a finding) or relay/MITM. |
| RDP from an endpoint that has *never* initiated RDP, into many internal targets | **TP-High**. Lateral move. Escalate. |

### Privilege Anomaly

| Pattern | Verdict |
|---------|---------|
| Account recently added to a new group / role per ticketed change | **BTP**. Document the change. |
| Account suddenly accessing systems outside its scope, no change ticket, paired with Kerberoasting / risky sign-in | **TP-High**. Identity compromise. Escalate, recommend session revocation + password reset. |
| Account anomaly with no other context | **Need more data**. Pull cloud sign-in side before deciding. |

---

## Verdict write-up template

```
Verdict: [BTP | TP-Low | TP-High | Need more data]

Entity: <name> (priority <score>, tags: <tags>, key_asset: <yes/no>)
Account (if applicable): <UPN>
Detections in scope: <list of detection ids/types in this window>

Behavior observed:
  - Vectra detection summary: <one line>
  - Pivot evidence: <one line per recipe run, with row counts / key values>
  - Kill-chain map (if multiple detections): Recon → LM → C&C/Exfil

Reasoning:
  - <kill-chain or benign-baseline match>
  - <co-occurring or absent context>
  - <identity-side correlation if relevant>

Disposition:
  - Action: <assign / escalate / close as BTP / contain immediately>
  - Triage rule scope (if BTP): (source_host=<id>, detection_type=<type>, dst_set=<...>) OR (account=<UPN>, detection_type=<type>, target=<service>)
  - Tier 2 escalation note (if TP-High): <one paragraph for IR handoff>
  - Containment recommendation (if TP-High): <isolate host? disable account? rotate KRBTGT? reset service-account passwords?>
```

> The full per-entity verdict template (with multi-tenant scope, key-asset
> flags, gap section, etc.) lives in
> [`verdict-framework.md`](verdict-framework.md).

---

## Quick reference — which `vectra-hunt` recipe for what

| Need | Recipe file → recipe |
|------|----------------------|
| Detection-window sessions for an entity | `network_sessions.md` → 5 |
| Scanning / failed conn shape | `network_sessions.md` → 4 |
| SMB share access (incl. ADMIN$/C$/IPC$) | `network_lateral_movement.md` → SMB Mapping 1, 2 |
| SMB file writes/deletes/renames | `network_lateral_movement.md` → SMB Files 1, 2 |
| Kerberos host activity | `network_lateral_movement.md` → Kerberos 1 |
| Kerberoasting (RC4 TGS) | `network_lateral_movement.md` → Kerberos 2 |
| Failed Kerberos | `network_lateral_movement.md` → Kerberos 3 |
| Track Kerberos for a user | `network_lateral_movement.md` → Kerberos 4 |
| NTLM auth + Pass-the-Hash | `network_lateral_movement.md` → NTLM 1, 4 |
| NTLM spray (failures) | `network_lateral_movement.md` → NTLM 2 |
| LDAP recon (wide results) | `network_lateral_movement.md` → LDAP 2 |
| LDAP base-object hunt | `network_lateral_movement.md` → LDAP 3 |
| LDAP sensitive attrs (LAPS / SPN / pwd) | `network_lateral_movement.md` → LDAP 4 |
| RDP host sessions | `network_lateral_movement.md` → RDP 1 |
| Internal lateral RDP | `network_lateral_movement.md` → RDP 2 |
| Unencrypted RDP | `network_lateral_movement.md` → RDP 4 |
| DCE-RPC host activity | `network_lateral_movement.md` → DCE-RPC 1 |
| DCE-RPC endpoint hunt (svcctl/drsuapi/samr) | `network_lateral_movement.md` → DCE-RPC 2 |
| DCE-RPC operation hunt (DsGetNCChanges/CreateService) | `network_lateral_movement.md` → DCE-RPC 3 |
| Lateral movement RPC composite | `network_lateral_movement.md` → DCE-RPC 4 |
| Cloud identity-side correlation (sign-in side) | `cloud_investigations.md` → Entra 1, 3 |
| Cloud privileged role changes | `cloud_investigations.md` → Entra Directory Audits 2 |
| Cloud IAM changes (AWS / Azure CP) | `cloud_investigations.md` → AWS 5, Azure CP 5 |

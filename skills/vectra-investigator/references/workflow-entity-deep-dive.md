# Workflow 2 — Entity Deep-Dive

**Goal:** the user names one host or account ("investigate
`WIN-FILESVR-03` end-to-end").

> Read alongside [`mental-model.md`](mental-model.md) (entity-first
> triage, multi-tenancy) and
> [`verdict-framework.md`](verdict-framework.md) (the rubric and
> write-up template).

> **Routing rule.** Every log / metadata pivot inside this workflow —
> the entity's sessions, DNS, HTTP, TLS, lateral-movement protocols,
> Entra sign-ins, M365 audit, AWS CloudTrail, Azure CP — goes through
> [`vectra-hunt`](../../vectra-hunt/SKILL.md) (ad-hoc Investigation
> Query SQL via the Vectra MCP server). Do **not** reach for
> [`vectra-reports`](../../vectra-reports/SKILL.md) /
> [`vectra-reports-mcp`](../../vectra-reports-mcp/SKILL.md) to
> investigate an entity — those are dashboards, not investigation
> tools, and they only run when the analyst explicitly names a report
> from the catalogue.

---

## Pipeline

1. **Resolve the entity.** `get_host_details` /
   `get_account_details` (use `lookup_entity_info_by_name` or
   `lookup_host_by_ip` to resolve the entity ID first, or
   `list_entities` filtered by name when the lookup tools don't
   match). In a multi-tenant deployment, search every wired tenant
   unless the user scoped to one — see
   [`mental-model.md`](mental-model.md) §4.
2. **Pull all open detections on this entity.**
   `list_entity_detections(entity_id=<id>, state="active")` for the
   resolved host; if it's a hybrid attack, also call
   `list_entity_detections` on the matching account (and vice-versa)
   when investigating a host.
3. **Build the kill-chain story** (as in
   [`workflow-queue-triage.md`](workflow-queue-triage.md) §3) — group
   detections by category and look at the *composition*, not each
   detection in isolation.
4. **Per detection, open the matching `playbook-<category>.md`** in
   this folder (catalogue:
   [`playbooks-overview.md`](playbooks-overview.md)). Run the pivot
   pipeline. Use timestamps from `get_detection_details` to *narrow*
   every SQL query to the actual detection window — not "last 24h".
5. **Optional baseline pivot.** Even with no open detections, an
   entity can be worth investigating. Pull recent traffic / auth /
   DNS via [`vectra-hunt`](../../vectra-hunt/SKILL.md) recipes (host
   sessions, host DNS, host Kerberos, etc.) and look for shape
   changes.
6. **Verdict per entity** using
   [`verdict-framework.md`](verdict-framework.md). Always include the
   benign baseline (BTP), the kill-chain composition (TP), or the
   specific evidence gap (NMD).

---

## Hybrid attacks — never stop at one entity type

If the entity is a **host**, also check the account(s) most active on
that host (resolve account IDs via `lookup_entity_info_by_name`, or
`list_entities` filtered to account type, then call
`list_entity_detections` and `get_account_details`) and look for
Entra / M365 / AWS detections in the same time window. Cloud recipes
live in
[`vectra-hunt/references/cloud_investigations.md`](../../vectra-hunt/references/cloud_investigations.md).

If the entity is an **account**, pivot the other way — pull every
host the account authenticated to in the window and check for
network-side detections on those hosts.

A host-side detection paired with an identity-side anomaly on the
same user, in the same window, is a much stronger TP than either
alone.

---

## When to escalate from this workflow

- Confirmed kill-chain across multiple categories → **TP-High**,
  escalate per [`verdict-framework.md`](verdict-framework.md).
- Network-side TP on a key asset paired with cloud-side anomaly →
  **TP-High**, escalate.
- Single low-threat detection with clean baseline → **TP-Low** or
  **BTP**, document and recommend a triage rule (BTP only) or owner
  (TP-Low).
- Insufficient evidence after ~15 min → **NMD**, name the gap and the
  next pivot (EDR, SIEM, identity, ticket the asset owner).

---

## Close the gaps before you report them

**A gap you have named is a task, not a caveat.** Before writing "need more
data", check whether the data is reachable with the tools already connected. On
2026-09-01 this step was missing, and an investigation of jump-station5 shipped
three open questions — two of which closed on the first attempt, and one of which
**overturned the containment advice**. The report told the operator to revoke an
AWS access key that CloudTrail showed the intruder had deleted themselves one
minute after it failed.

### The loop

For each gap you are about to report:

1. **Name the telemetry that would close it** — a table, an endpoint, a tool.
2. **Try it.** One query or one call. Do not ask permission to *read*.
3. **Record the outcome as one of four:**

| Outcome | Meaning |
|---|---|
| **CLOSED** | You got the answer. Fold it into the findings — and re-check whether it changes the verdict or the recommended action. |
| **NO DATA** | The query worked and returned nothing. **Prove it with a control query** on the same table over a window where you expect rows. An empty result you cannot distinguish from a broken feed is not a finding. |
| **BLOCKED** | A permission or scope error. **Quote the scope verbatim** — "requires `NGSIEM:write`" is actionable; "insufficient permissions" is not. |
| **OUT OF REACH** | No connected telemetry could answer it. Say which telemetry would. |

4. **Stop after two attempts per gap.** A third is a research project, not
   triage. Report it as OUT OF REACH with what you tried.

### What is automatic and what is not

**Automatic — any read.** Investigation Query over any table, entity and
detection reads, posture findings, read-only queries against other connected
security products.

**Never automatic:**
- Anything that changes state anywhere, in any product
- Live endpoint interaction — remote shell, script execution, file collection —
  even when the tool is available and the operator is present
- Anything a destructive or additive annotation marks as such

State those as proposals with the exact call, and wait.

**Watch for a read that needs a write scope.** The NGSIEM search above required
`NGSIEM:write` to perform a read. Do not escalate to a write scope to satisfy a
read — report the blocker and let the operator decide.

### Why this is not the same as "uncertainty escalates"

Both rules are in force and they are not in conflict:

- **Uncertainty escalates** governs the *verdict*. Thin evidence still returns
  need-more-data rather than a confident guess.
- **Close the gaps** governs the *effort before* the verdict. Escalating a
  question you could have answered in one query is not caution; it is passing
  work to a human who has less tooling than you do.

Escalate what you cannot resolve. Resolve what you can.

---

## Query the entity as a DESTINATION before reading its detections

**The victim never records who attacked it. Only the attacker's entity does.**

This is not a data gap — it is how entity-scoped detection works. A detection
describes behaviour *by* an entity, so a host that was compromised holds no
record of the compromise. Investigated alone, it looks like an independent
intrusion that began with its own command channel.

Observed on `Deacon-desktop` (107159) on 2026-09-02: all eight detections had it
as the **source**. No inbound remote execution, no admin-share access against
it, no service creation on it, `account_access_history` empty. The earliest
evidence on the entity was its own C2. The host had in fact been compromised
over SMB by another host three minutes earlier.

### The query

Run this **before** forming a verdict on any host:

```sql
SELECT timestamp, id.orig_h AS source_ip, orig_hostname.name AS source_host, id.resp_p AS dest_port, orig_ip_bytes AS bytes_sent, resp_ip_bytes AS bytes_received FROM network.isession._all WHERE dt > date_add('day', -14, now()) AND timestamp BETWEEN date_add('day', -14, now()) AND now() AND id.resp_h = '<THE HOST IP>' AND id.resp_p IN (445, 4444, 135, 139, 3389, 5985) ORDER BY timestamp LIMIT 60
```

One query. On Deacon it returned the ingress immediately — source host, port,
timestamp, and a byte count that matched the upstream host's own stage-loader
detection exactly.

### Why it changes the verdict rather than decorating it

Without it, the verdict names the host as the **origin** of an intrusion it was
a **victim** of. That is wrong in a way that matters:

- Containment scope is wrong — the upstream host keeps operating
- The attribution is wrong — you brief a chain that started somewhere else
- And the same error repeats at every hop downstream

### Apply it at every hop, not just the first

Each host reached by lateral movement has the same blindness. In this
environment:

```
jump-station5   -> 10.232.100.30
Piper-desktop   -> Deacon-desktop
Deacon-desktop  -> dc2-aws-us-west-01
Deacon-desktop  -> eu-db5-aws.demo.corp
```

Every host on the right of an arrow will, investigated alone, appear to be
patient zero. **When an investigation hands you a downstream host, the first
question is not "what did it do" but "who reached it".**

### Ports to include

`445` and `139` (SMB), `4444` (common reverse-shell listener), `135` (RPC
endpoint mapper), `3389` (RDP), `5985` (WinRM). Widen if the environment uses
others; a zero result across all of them is itself a finding worth stating —
it means the ingress was not lateral, and the host was reached some other way.

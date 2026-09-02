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
| **NO DATA** | The query worked and returned nothing. **Prove it with a control query** — see *Prove every empty result with a control query* below. An empty result you cannot distinguish from a broken feed is not a finding. |
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

## Prove every empty result with a control query

**A query that returns nothing has told you nothing until you have proved the
table would have answered.** Zero rows has two causes that look identical in the
output: the activity did not happen, or you cannot see it. Only one of them is a
finding.

Observed on `O365:virginia-choi-02` on 2026-09-02: a query for SharePoint file
downloads in the compromise window returned zero rows. Written up as-is, that
becomes "no files were exfiltrated" — the sentence the operator most wants to
read, and it would have been false. The control query showed
`office365.sharepoint` holds **two rows for the entire tenant across all
time**. The table is barely populated. The correct finding was not "nothing was
taken" but "we have no visibility into what was taken", and it changed the
recommended action from *monitor* to *rotate credentials and assume access*.

### The control

Re-run the same query against the same table with the entity predicate and the
time window removed, and no filter but a `LIMIT`:

```sql
SELECT count(*) AS rows_all_time FROM office365.sharepoint._all WHERE dt > date_add('day', -90, now()) LIMIT 1
```

Then read the result against three cases:

| Control returns | What your zero means | How to write it |
|---|---|---|
| Substantial rows, and rows in your window for **other** entities | The activity did not happen | State it as a **negative finding** — it is evidence, and it is worth having |
| Substantial rows, but none anywhere near your window | The feed has a gap in time | **NO DATA**, and name the window that is missing |
| Few or no rows at all | The table is not meaningfully populated for this tenant | **NO DATA** — and say the table is empty, not that the activity is absent |

### The rule

Never write "no evidence of X" from an empty result alone. Either the control
supports it — in which case say so and cite the control — or the outcome is
**NO DATA** and the gap goes in the report.

**This applies hardest to the queries whose zero is reassuring.** Exfiltration,
data access, credential use, downloads. An empty result on a question the
operator is afraid of is exactly where a silent visibility gap does the most
damage, because nobody challenges good news.

### It costs one query

The control is cheaper than every other step in this workflow — one aggregate,
no window, no join. There is no case where the evidence was too expensive to
check.

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

---

## An identifier means nothing without its tenant

**Every entity ID and detection ID is scoped to one tenant.** The same
identifier exists in other tenants and points at something else entirely — so
a stale ID does not produce an error. It produces a confident answer about the
wrong thing.

Measured across two tenants on 2026-09-02:

| Entity | Tenant A (`209437179984.uw2`) | Tenant B (`109796245472.ew1`) |
|---|---|---|
| `virginia-choi-02.northstar@…` | account **3511** | account **3553** |
| `adam_admin@fictotech.com` | account **3529** | account **3575** |

The ranges **overlap**. `3553` is a real account in tenant A as well — a
different person. An analyst carrying "investigate account 3553" over from
yesterday's notes gets a complete, plausible investigation of the wrong
identity, and nothing in the output says so.

### Within one tenant, IDs are stable — so this is not a reason to distrust them

Checked deliberately, because the opposite assumption leads to re-deriving
everything on every turn. In the same tenant five days after an investigation:

- detection `19813` was still Hidden HTTPS Tunnel on `jump-station5` (107073),
  same 117 sessions to `40.121.154.127`, same byte counts, same 5 / 5 scores
- account `3553` was still `O365:virginia-choi-02.northstar@…`

An ID obtained **in this conversation, from this tenant** is trustworthy. The
risk is entirely about identifiers that arrive from somewhere else.

### The rule

1. **Before acting on any identifier you did not obtain in this conversation,
   confirm the tenant.** Call `get_active_profile` when it is available; it
   reports the profile name, tenant URL and API client id and cannot change
   them. In a multi-tenant deployment, the tool name prefix carries the tenant
   instead.
2. **Resolve by name, then use the ID it returns.**
   `lookup_entity_info_by_name` costs one call and removes the whole class of
   error. This is why the pipeline in this workflow starts with a lookup rather
   than accepting an ID.
3. **Never carry an ID between tenants**, including from a report, a ticket, a
   note, or an earlier conversation. Re-resolve the name.
4. **Write the tenant into anything you leave behind.** A note or verdict
   citing "account 3553" is ambiguous the moment a second tenant exists; the
   tenant URL or profile name makes it durable.

### Names are safer, but they are not identical either

The same user is `O365:virginia-choi-02.northstar@…` in one tenant and
`virginia-choi-02.northstar@…` in the other — the prefix differs because the
account types differ (`o365` versus `o365` + `entra_principal`). So a name
lookup can also miss across tenants. Use partial matching, and check what came
back rather than assuming the first hit is the entity you meant.

### Detections accumulate; they do not update

A recurring behaviour produces **new detection IDs**, it does not renumber the
old one. `Piper-desktop` carried detections up to `19794` during an
investigation and `19866` / `19867` five days later, with the earlier ones
unchanged. So "the Kerberoasting detection, 19794" names one past occurrence,
not the current state of that behaviour — which is the same reason recurrence
is read from `last_timestamp` rather than by hunting for a second detection.

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

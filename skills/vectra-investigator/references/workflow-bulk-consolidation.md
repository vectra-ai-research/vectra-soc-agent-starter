# Workflow 8 — Bulk Detection Consolidation

**Goal:** a batch of detections looks similar (same category, same
detection type, or just "a lot of low-urgency noise") and the ask is
whether they can be handled — and authorized — together, rather than
one entity at a time. The output is a **recommended triage rule or
group addition**, not a per-entity verdict.

> Read this in conjunction with
> [`verdict-framework.md`](verdict-framework.md) §"Triage rules are
> scalpels" (the scoping discipline this workflow exists to apply at
> batch scale) and
> [`workflow-queue-triage.md`](workflow-queue-triage.md) (the
> entity-first alternative — use that instead when the queue is a
> handful of serious entities rather than a large cluster of
> look-alike noise).

---

## Why this is a separate workflow

Grouping detections by a shared **label** — "these are all PUP", "these
are all Suspicious HTTP" — is not a common denominator. A triage rule
or an authorized-entities group has to be scoped to a concrete,
literal value: a destination IP or domain, a destination port, a
target service, a source subnet. Two detections sharing a category
with two *different* destinations are not the same behavior for
authorization purposes, even if they look identical in a queue list.

This workflow's job is to find that literal shared value — if one
actually exists — before recommending anything. If it doesn't exist,
say so plainly and hand back to entity-by-entity triage (Workflow 1 or
3). Forcing a batch recommendation onto a cluster that only shares a
label is exactly the "blanket rule" mistake
[`verdict-framework.md`](verdict-framework.md) already warns against —
this workflow exists to keep that discipline intact at batch scale,
not to relax it.

---

## Pipeline

```
┌─ 1. Pull the candidate set (lightweight) ────────────────────────────┐
│ list_detection_ids or list_detections_with_basic_info                │
│ Coarse cluster by (detection_category, name) only — a starting       │
│ hypothesis, not a conclusion                                         │
└────────────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─ 2. Pull detail for each cluster candidate only ─────────────────────┐
│ get_detection_details / get_detection_summary per ID in the cluster  │
│ (never list_detections_with_details on the whole unfiltered batch)  │
│ Extract scoping-candidate fields: destination IP/domain, port,       │
│ target service, target host, source subnet                          │
└────────────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─ 3. Test for a real common denominator ──────────────────────────────┐
│ Group by (detection_type, <candidate field>) — keep only groups      │
│ where the value is IDENTICAL across ≥3 detections. Nothing           │
│ survives? → no batch recommendation, route back to Workflow 1 / 3.   │
└────────────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─ 4. Check for an existing authorization path ────────────────────────┐
│ list_triage_rules + list_groups — does a rule/group already cover    │
│ this detection_type and just need the new value added?               │
└────────────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─ 5. Recommend — draft only, human-in-the-loop ───────────────────────┐
│ Existing group match → propose add_member_to_group                   │
│ No match → propose a new narrowly-scoped triage rule                 │
│ Never call either without explicit approval (AGENTS.md guardrail 1)  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Step 1 — Pull the candidate set

Start light:

```
list_detections_with_basic_info(state="active", limit=100)
```

(or `list_detection_ids` if you just need volume-by-category first).
Group the results by `(detection_category, name)` — this is a
**hypothesis**, not a finding. A cluster of 15 detections all named
"PUP" is 15 detections that *might* share a cause; it does not yet
tell you whether they actually do.

Drop any cluster smaller than ~3 — a one-off doesn't need batch
handling, route it through Workflow 1 (Queue Triage) or Workflow 3
(Single-Detection Pivot) instead.

If this workflow was reached from a "lowest urgency" pull, remember
`is_prioritized` is unrelated to urgency and should stay unset for a
general sweep — see [`best-practices.md`](best-practices.md).

---

## Step 2 — Pull detail for each cluster candidate only

For each cluster worth checking, pull full detail **only for that
cluster's IDs** — never call `list_detections_with_details` against
the whole unfiltered batch (see
[`best-practices.md`](best-practices.md) Common Pitfalls — the same
"tool result too large" mistake progressive disclosure exists to
prevent).

```
get_detection_details(detection_id=<id>)   # or get_detection_summary for the short form
```

Read off whichever of these fields the detection type actually
carries — not every detection has every field:

- Destination IP / domain / port (network C2, botnet, exfiltration)
- Target host / share (lateral movement, SMB)
- Target service / resource (cloud, identity)
- Source subnet (recon, scanning noise)

---

## Step 3 — Test for a real common denominator

Re-group the cluster by `(detection_type, <candidate field>)`. A group
only counts as a common denominator if the field value is **exactly
identical**, not merely similar, across multiple detections:

> 12 detections, all "Hidden HTTP/S Tunnel", all resolving to
> `cdn.vendorapp.com` → **real common denominator.** One shared
> destination, many hosts.

versus:

> 12 detections, all "PUP", 12 different destinations, 9 different
> hosts → **no common denominator.** Same label, different behavior
> each time. Do not force a batch recommendation — hand these back to
> Workflow 1, one entity at a time.

If the cluster splits (8 share one destination, 4 share nothing),
report both halves separately: batch recommendation for the 8,
individual triage for the 4. Never let the batch conclusion silently
absorb the entities that don't actually fit it.

---

## Step 4 — Check for an existing authorization path

Before drafting anything new, check whether the platform already has
a mechanism this value could slot into:

```
list_triage_rules()
list_groups(group_type="ip")   # or "domain" / "host" / "account", matching the shared field
```

If a rule already covers this `detection_type` and references a group
of the matching type, adding the new value to that group is
**strictly preferred** over writing a new rule — see
[`../../../AGENTS.md`](../../../AGENTS.md) and the `add_member_to_group`
tool's own description ("the safe/preferred way to authorize
behavior… rather than editing the rule directly").

---

## Step 5 — Recommend, as a draft

Every recommendation from this workflow is a **draft for approval**,
never an executed action (guardrail 1 in `AGENTS.md` — propose, don't
execute). State the finding, the evidence, and the exact proposed
call.

**Existing group found:**

```markdown
**Common denominator:** 12 × "Hidden HTTP/S Tunnel" across 9 hosts,
all to `cdn.vendorapp.com` (same domain, same dst port 443, last 24h).

**Existing coverage:** Triage rule #<id> ("Approved SaaS tunnels")
already scopes this detection type to group #<id> ("approved-domains",
type=domain).

**Recommendation:** add `cdn.vendorapp.com` to group #<id>.
Proposed call: `add_member_to_group(group_id=<id>, group_type="domain",
member_value="cdn.vendorapp.com")`

**Pending your approval — this has not been executed.**
```

**No existing coverage:**

```markdown
**Common denominator:** <as above>

**Existing coverage:** none found — no rule currently scopes this
detection type to a group.

**Recommendation:** new triage rule scoped to (detection_type =
"Hidden HTTP/S Tunnel", destination = cdn.vendorapp.com) only — not
detection-type-wide. Consider whether a reusable group is worth
creating now if this destination is likely to recur.

**Pending your approval — this has not been executed.**
```

**No common denominator found:**

```markdown
No shared destination / service / subnet across these 12 "PUP"
detections beyond the shared label. Recommend routing back to
Workflow 1 (Queue Triage) — handle per-entity.
```

---

## Cross-references

- [`verdict-framework.md`](verdict-framework.md) — "Triage rules are
  scalpels" scoping discipline; this workflow applies that same
  discipline when the scope spans many entities instead of one.
- [`workflow-queue-triage.md`](workflow-queue-triage.md) — the
  entity-first alternative when there's no real cross-entity common
  denominator, or the queue is a handful of serious entities rather
  than a large look-alike cluster.
- [`best-practices.md`](best-practices.md) — the progressive-disclosure
  rule (Step 2 exists because of it) and the `is_prioritized` /
  `urgency_score` distinction if this workflow was reached via a
  "lowest urgency" pull.

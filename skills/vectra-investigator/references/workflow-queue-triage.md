# Workflow 1 — Queue Triage

**Goal:** start of shift, no specific entity in mind. Walk the queue,
pick the top-N entities, render verdicts.

> Read this in conjunction with
> [`mental-model.md`](mental-model.md) (entity-first, kill-chain
> composition, multi-tenancy) and
> [`verdict-framework.md`](verdict-framework.md) (the rubric and
> write-up template).

---

## Pipeline

```
┌─ 1. Pull the queue ────────────────────────────────────────────────┐
│ list_entities or list_detections_with_basic_info, filter open,     │
│ sort by score                                                      │
└────────────────────────────────────────────────────────────────────┘
              │
              ▼
┌─ 2. For each top-N entity ─────────────────────────────────┐
│ get_host_details / get_account_details                     │
│ Read ALL its open detections (don't pick one in isolation) │
│ Note: any existing assignment? note? triage rule?          │
└────────────────────────────────────────────────────────────┘
              │
              ▼
┌─ 3. Build the kill-chain story ────────────────────────────┐
│ Group detections by category (C2 / LM / Exfil / Recon)     │
│ Does it look like a chain, or one-off behavior?            │
└────────────────────────────────────────────────────────────┘
              │
              ▼
┌─ 4. Pivot for evidence (per category) ─────────────────────┐
│ For each detection: open the matching playbook in          │
│ references/playbook-<category>.md                          │
│ Run the prescribed pivot recipes via vectra-hunt           │
└────────────────────────────────────────────────────────────┘
              │
              ▼
┌─ 5. Verdict & disposition ─────────────────────────────────┐
│ BTP / TP-Low / TP-High / Need-more-data                    │
│ See references/verdict-framework.md                        │
└────────────────────────────────────────────────────────────┘
```

---

## Step 1 — Pull the queue

```
list_entities(state="active", ordering="-priority", page_size=25)
```

Or if the user prefers detection-centric:

```
list_detections_with_basic_info(state="active", ordering="-threat", page_size=25)
```

Always filter for **active / unresolved** state. Triaged-but-still-firing
detections are surfaced via the entity score, not by re-walking the
detection list.

In a multi-tenant deployment, run this per tenant — see
[`mental-model.md`](mental-model.md) §4.

---

## Step 2 — Open one entity

```
get_host_details(host_id=<id>)
# or
get_account_details(account_id=<id>)
```

What to read off the response:

- `name`, `last_source` IP, `tags`, `groups` — identity / segment.
- `urgency_score` / `priority_score` — current rollup.
- `threat`, `certainty` — current detection-driven signal.
- `is_key_asset` — was this entity flagged as crown-jewel?
- `assignment` — already owned by another analyst?
- `detection_set` / `detection_summaries` — every open detection on
  this entity.

If `assignment` exists and is not the user, **do not double-triage**.
Note it and move to the next entity unless the user explicitly wants
to take it over.

---

## Step 3 — Build the kill-chain story

Group the entity's open detections by category. A useful summary line:

> Host `WIN-FILESVR-03` (priority 87, key asset): 1 × C&C (Hidden
> HTTP/S Tunnel, T:75/C:90), 2 × Recon (Port Sweep + RPC Recon, both
> T:35), 1 × LM (Suspicious Admin, T:80/C:60). Pattern: external
> implant + internal mapping + admin pivot. **Likely active
> intrusion**.

Versus:

> Host `BACKUP-AGENT-04` (priority 65): 1 × Exfil (Smash and Grab,
> T:65/C:80). No other categories. Tag `backup-server`. **Likely
> BTP — verify backup window**.

Pattern recognition is the actual skill — combinations are diagnostic.

---

## Step 4 — Pivot for evidence

For each detection in the entity's set, open the matching
detection-category playbook (sibling reference in this folder — see
[`playbooks-overview.md`](playbooks-overview.md) for the catalogue):

1. Pick the playbook by category — e.g. Exfiltration →
   [`playbook-exfiltration.md`](playbook-exfiltration.md).
2. Match the specific detection type in the playbook's "Detection
   types in scope" table.
3. Run the playbook's "Pivot pipeline" — each step names a recipe in
   [`vectra-hunt/references/`](../../vectra-hunt/references/) to
   execute.
4. Apply the playbook's "Verdict rubric" (which is a per-detection
   refinement of the global rubric in
   [`verdict-framework.md`](verdict-framework.md)).

When pulling supporting telemetry, use the detection's
`first_timestamp` / `last_timestamp` window — not "last 24h". Narrow
windows surface the actual evidence; wide windows drown it.

---

## Step 5 — Verdict & disposition

Apply the four-outcome rubric in
[`verdict-framework.md`](verdict-framework.md) (TP-High / TP-Low /
BTP / Need-more-data) and use its write-up template. Key reminders:

- Always name the benign source on a BTP.
- Triage rules must be scoped narrowly (per host / per service / per
  dst — never blanket).
- Time-box at ~15 minutes per entity. NMD → tier 2 is a valid
  outcome.
- Containment / suppression actions are human-in-the-loop — propose,
  don't execute (`AGENTS.md` §7).

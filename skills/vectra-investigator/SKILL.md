---
name: vectra-investigator
description: Primary Vectra AI tier-1 SOC analyst orchestrator. Routes requests to the right workflow (queue triage, entity deep-dive, single-detection pivot, TI hunt, ad-hoc investigation, canned report, PCAP triage, bulk detection consolidation), runs detection-category playbooks (Exfiltration, Lateral Movement, etc.), and lands a four-outcome verdict (BTP / TP-Low / TP-High / Need-more-data) or a batch triage-rule/group recommendation. Delegates to vectra-hunt for SQL recipes, vectra-reports or vectra-reports-mcp for dashboards, vectra-pcap for packet captures, and virustotal for IOC reputation. Use when the user says triage the queue, investigate an entity, detection, or alert, asks if a detection or alert is real, wants help understanding an alert they received, requests priorities or shift start, asks whether a batch of similar detections can be authorized together, or any open-ended SOC workflow starting inside Vectra.
---

# Vectra Investigator — Tier 1 SOC Workflow Orchestrator

This is the **main orchestration skill** for operating Vectra AI (RUX)
as a tier-1 SOC analyst. It owns the full triage layer — which
workflow fits the ask, how to run the matching detection-category
playbook, how to scope across tenants, how to land a verdict. The
detail for each piece lives in [`references/`](references/); load only
what the current context calls for — see
[`references/MANIFEST.md`](references/MANIFEST.md) for the required
per-workflow load set (progressive load is **mandatory**).

| Sub-area | Reference file |
|----------|----------------|
| The Vectra mental model + multi-tenancy | [`references/mental-model.md`](references/mental-model.md) |
| Verdict rubric (BTP / TP-Low / TP-High / NMD) and write-up template | [`references/verdict-framework.md`](references/verdict-framework.md) |
| Detection-category playbook overview (structure + how-to-use + index) | [`references/playbooks-overview.md`](references/playbooks-overview.md) |
| Playbook — Exfiltration (Smash and Grab, Hidden Tunnels, Cloud Storage, M365 Download / Mail Forwarding) | [`references/playbook-exfiltration.md`](references/playbook-exfiltration.md) |
| Playbook — Lateral Movement (Suspicious Admin, Kerberoasting, Brute-Force, RPC Recon, LDAP, RDP, Ransomware, Privilege Anomaly) | [`references/playbook-lateral-movement.md`](references/playbook-lateral-movement.md) |
| Workflow 1 — Queue Triage | [`references/workflow-queue-triage.md`](references/workflow-queue-triage.md) |
| Workflow 2 — Entity Deep-Dive | [`references/workflow-entity-deep-dive.md`](references/workflow-entity-deep-dive.md) |
| Workflow 3 — Single-Detection Pivot | [`references/workflow-detection-pivot.md`](references/workflow-detection-pivot.md) |
| Workflow 4 — TI-Driven Hunt | [`references/workflow-ti-hunt.md`](references/workflow-ti-hunt.md) |
| Workflow 5 — Ad-Hoc Investigation Query | [`references/workflow-ad-hoc-query.md`](references/workflow-ad-hoc-query.md) |
| Workflow 6 — Canned Report | [`references/workflow-canned-report.md`](references/workflow-canned-report.md) |
| Workflow 7 — Network PCAP Triage | [`references/workflow-pcap-triage.md`](references/workflow-pcap-triage.md) |
| Workflow 8 — Bulk Detection Consolidation | [`references/workflow-bulk-consolidation.md`](references/workflow-bulk-consolidation.md) |
| Best practices + common pitfalls | [`references/best-practices.md`](references/best-practices.md) |

The data and SQL detail is delegated to other skills:

- **Direct entity / detection lookups** → Vectra MCP REST tools (see
  [Direct Vectra MCP lookups](#direct-vectra-mcp-lookups) below).
- **Ad-hoc SQL recipes + TI-driven hunts** →
  [`vectra-hunt`](../vectra-hunt/SKILL.md).
- **Canned dashboards / KPI reports** →
  [`vectra-reports`](../vectra-reports/SKILL.md) (Python) or
  [`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md) (MCP).
- **Network detection PCAPs** →
  [`vectra-pcap`](../vectra-pcap/SKILL.md). Cloud / log-based
  detections (M365, Entra / Azure AD, AWS CloudTrail, …) have **no
  PCAP** — those stay on metadata pivots.
- **External IOC reputation** →
  [`virustotal`](../virustotal/SKILL.md) (corroboration only,
  never overrides the behavioural verdict).

> **Universal SOC rules** (read-only by default, human-in-the-loop
> for mutations, scope discipline, evidence preservation, output
> expectations) live in [`../../AGENTS.md`](../../AGENTS.md) and apply
> to everything below. This file adds the **Vectra-specific** layer
> on top.

---

## When to use this skill

Trigger this skill when the user request is **workflow-shaped** or
**detection-shaped**, or open-ended enough that you need to pick the
right reference first:

- "Triage the Vectra queue" / "run tier-1 on the last shift"
- "Walk me through the top 5 critical entities right now"
- "Investigate host `<name>` / account `<UPN>` end-to-end"
- "I have detection ID `<n>` — what do I do?"
- "Is this Smash and Grab / Suspicious Admin / Hidden DNS Tunnel /
  Kerberoasting real, or BTP?"
- "Sweep this advisory across our tenant"
- "Summarize the security posture from Vectra over the last 24h"
- *Anything where the user names "Vectra" but doesn't name a specific
  channel.*

If the user names the channel ("run the C2 beacon report", "show me
NXDOMAIN spikes for host X"), skip this skill and go straight to the
named sub-skill.

---

## Prerequisites

The **Vectra MCP server** must be connected. Required tools:

| Tool | Purpose |
|------|---------|
| `list_entities` | Pull prioritized entities (hosts + accounts unified view) |
| `list_detections_with_basic_info` / `list_detections_with_details` | Pull the detection queue, filter by state / category / score |
| `list_entity_detections` | Pull every detection on a specific host / account / entity |
| `lookup_entity_info_by_name` / `lookup_host_by_ip` | Resolve an entity ID from a name or IP |
| `list_assignments` / `list_assignments_for_user` / `get_assignment_for_entity` | See which entities are already assigned / under investigation |
| `get_detection_details` / `get_detection_summary` | Drill into a single detection |
| `get_host_details` / `get_account_details` | Drill into entity context |
| `list_triage_rules` / `list_groups` | See what triage rules and authorized-entity groups already exist (Bulk Detection Consolidation) |
| `add_member_to_group` | Propose adding a shared value (IP/domain/host/account) to an existing group — draft only, human-in-the-loop |
| `close_detection` | Propose closing a detection with a reason — draft only, human-in-the-loop |
| `run_investigation` | Execute Investigation Query SQL pivots (used via `vectra-hunt`) |
| `get_investigation_results` | Page through SQL results |
| `get_investigation_schema` / `get_investigation_sql_reference` | Inspect tables / SQL grammar before authoring queries |

If MCP is not connected, point the user at `install/<HOST>.md` before
proceeding.

---

## Vectra-side operating principles

Vectra-specific "always do X / never do Y" rules — they sit on top of
the universal SOC principles in
[`../../AGENTS.md`](../../AGENTS.md) and apply whenever you are
operating Vectra.

1. **Entity-first triage.** Sort by entity urgency / priority, open
   the entity, read **all** its open detections before deciding. A
   detection in isolation is rarely actionable — composition is the
   signal. (Detail: [`references/mental-model.md`](references/mental-model.md).)
2. **Behavior over reputation.** Vectra is behavioral AI; a
   detection on a non-blocklisted IP is still a detection. Validate
   against environment context (tags, groups, change windows,
   key-asset flags), not against IP / domain reputation.
3. **Verdict, not narration.** Every triage output is a verdict
   (TP-High / TP-Low / BTP / Need-more-data) plus reasoning and
   disposition — not a wall of telemetry. (Rubric:
   [`references/verdict-framework.md`](references/verdict-framework.md).)
4. **Never invent Investigation Query SQL.** Use a recipe from
   [`vectra-hunt/references/`](../vectra-hunt/references/), or call
   the Investigation MCP tool with its associated resources. Every
   query needs a time filter and should be timestamp-narrow when
   pivoting from a detection.
5. **One Vectra channel per task.** Don't mix
   [`vectra-reports`](../vectra-reports/SKILL.md) and
   [`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md) mid-run —
   pick one per workflow and stick with it. Same for ad-hoc
   investigation: don't re-run the same recipe via REST and via MCP
   in the same triage.
6. **Reports are dashboards, not investigations.** The
   [`vectra-reports`](../vectra-reports/SKILL.md) /
   [`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md) skills only
   apply when the user **explicitly names a canned report** from the
   catalogue (e.g. *"run the C2 beacon report"*, *"render the
   top-talkers dashboard"*). Every other Vectra log / metadata
   question — *"check CloudTrail to understand what's going on"*,
   *"what did this credential do?"*, *"who's behind this IP?"*,
   *"investigate this entity"*, *"pivot from this detection"* — goes
   to [`vectra-hunt`](../vectra-hunt/SKILL.md) (ad-hoc Investigation
   Query SQL via the Vectra MCP server, using the recipe library and
   query-construction rules). If a routing call is ambiguous, default
   to `vectra-hunt`.
7. **Never hand-roll REST against the Investigation Query API.** Every
   SQL pivot goes through the Vectra MCP tools
   `run_investigation` / `get_investigation_results` (used
   internally by `vectra-hunt` and `vectra-reports-mcp`) — they
   already encapsulate Basic-auth OAuth2, the request-id polling
   lifecycle, and the documented rate-limit. DIY `httpx` /
   `curl` against `/oauth2/token` and `/investigation/results` is a
   known cascade of failures (auth body vs Basic, polling shape,
   endpoint URL).
8. **Know Vectra's blind spots — and call them out.** Vectra metadata
   does **not** include file hashes, mutexes, registry keys, process
   command lines (outside of detection evidence), in-memory artifacts,
   or anything the sensor can't see. When a verdict needs that kind
   of evidence, recommend an EDR / SIEM / endpoint-side pivot.
9. **Multi-tenancy is data isolation, not data merging.** Discover
   tenants, scope explicitly, correlate per-tenant rather than
   blending rows. (Detail:
   [`references/mental-model.md`](references/mental-model.md) §4.)

---

## The Vectra mental model — at a glance

Internalize these four concepts before triaging — full detail in
[`references/mental-model.md`](references/mental-model.md):

1. **Attack Signal Intelligence — behavior, not signatures.** A
   detection means the platform observed an entity *behaving* like an
   attacker pattern. Don't dismiss because the IOC isn't "known
   bad"; do correlate with environment context.
2. **Entities are the unit of work, not detections.** Vectra
   prioritizes hosts and accounts via Urgency Score (rollup of all
   open detections + passive context). Triage flow is entity-first:
   sort, open, read the *full* open detection set, verdict the entity.
3. **Kill-chain categories.** Detections carry an Attack category
   (Command & Control, Reconnaissance, Lateral Movement, Exfiltration,
   Botnet, Initial Access / Privilege Escalation / Persistence, Info).
   The category drives the playbook (`playbook-<category>.md` in
   [`references/`](references/)) and the recipe file in
   [`vectra-hunt`](../vectra-hunt/SKILL.md). See
   [`references/playbooks-overview.md`](references/playbooks-overview.md)
   for the playbook catalogue and how-to-use guidance.
4. **Multi-tenancy.** Each wired tenant is independent. Discover,
   scope explicitly, correlate per-tenant, surface gaps.

---

## Pick your workflow

Match the user's ask to one of these workflows. **Read the matching
reference file before running anything** — each is a numbered
checklist that names the right sub-skill or MCP tool at every step.

| User asks for… | Workflow | Reference |
|----------------|----------|-----------|
| "Triage the queue" / "run tier 1" / start of shift | Queue Triage | [`references/workflow-queue-triage.md`](references/workflow-queue-triage.md) |
| "Investigate host / account `<X>` end-to-end" | Entity Deep-Dive | [`references/workflow-entity-deep-dive.md`](references/workflow-entity-deep-dive.md) |
| "I have detection ID `<n>` — what do I do?" / "is this Smash and Grab / Suspicious Admin / Kerberoasting real?" | Single-Detection Pivot (loads matching `playbook-<category>.md`) | [`references/workflow-detection-pivot.md`](references/workflow-detection-pivot.md) |
| "Sweep this CISA advisory / TI report / IOC list" | TI-Driven Hunt | [`references/workflow-ti-hunt.md`](references/workflow-ti-hunt.md) |
| "Did host X talk to evil.com last night?" / "check CloudTrail" / any narrow ad-hoc log / metadata question | Ad-Hoc Investigation Query | [`references/workflow-ad-hoc-query.md`](references/workflow-ad-hoc-query.md) |
| **User explicitly names a canned report** ("run the C2 beacon report", "render the top-talkers dashboard") — *no name = ask, never infer* | Canned Report | [`references/workflow-canned-report.md`](references/workflow-canned-report.md) |
| "Pull the PCAP for detection `<id>`" / "show me the raw packets" | Network PCAP Triage | [`references/workflow-pcap-triage.md`](references/workflow-pcap-triage.md) |
| "Do any of these share a pattern worth handling together?" / "can we bulk-authorize this instead of one at a time?" / a large cluster of similar low-urgency detections | Bulk Detection Consolidation | [`references/workflow-bulk-consolidation.md`](references/workflow-bulk-consolidation.md) |

Every workflow ends in a verdict — apply the rubric and write-up
template in
[`references/verdict-framework.md`](references/verdict-framework.md).

---

## Quick commands

Tier-1 shifts start with the same handful of asks ("what are the
priorities today?", "deep-dive this host", "drill into this
detection"). To save the analyst from re-typing the same prompt every
time, this skill recognises a small set of **canonical opening
phrases**. When the analyst's first message matches one of them
(case-insensitive, alone or followed by arguments), **skip clarifying
questions and jump straight to the named workflow** with the listed
default scope. If the analyst supplies arguments, override the
corresponding default.

Every command works with or without the `vectra` prefix (`vectra
priorities` and `priorities` route identically). Use the prefix when a
bare phrase could collide with other tooling or read as ordinary
conversation.

| Phrase | Workflow | Default scope |
|--------|----------|---------------|
| `vectra priorities` / `shift start` / `queue` / `triage` | [Queue Triage](references/workflow-queue-triage.md) | Top 5 active entities by urgency, all wired tenants, last 24 h |
| `vectra entity <name-or-id>` | [Entity Deep-Dive](references/workflow-entity-deep-dive.md) | Named host or account, all open detections, last 7 d |
| `vectra detection <id>` | [Single-Detection Pivot](references/workflow-detection-pivot.md) | Named detection + its entity context + matching `playbook-<category>.md`, detection's own time window |
| `vectra hunt <url-or-ioc-or-actor>` | [TI-Driven Hunt](references/workflow-ti-hunt.md) | Last 14 d for network metadata (Vectra retention ceiling — see `vectra-hunt` Limitations), up to 30 d for cloud tables, all wired tenants. State the effective window in the hunt report. |
| `vectra report <name>` | [Canned Report](references/workflow-canned-report.md) | Last 24 h, MCP channel unless `vectra-reports` Python venv is wired. **`report` with no name → list the catalogue and ask the analyst to pick — do not default to a generic report.** |
| `vectra pcap <detection-id>` | [Network PCAP Triage](references/workflow-pcap-triage.md) | Named network detection, full capture window, structured `tshark` pass |

Examples: `vectra priorities` → top 5 entities; `vectra priorities 10` → top 10;
`vectra priorities tenant-eu` → top 5 scoped to one tenant; `entity
WIN-FILESVR-03`; `detection 12345`; `hunt
https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-...`;
`report c2-beacons`; `vectra report` (no name) → list the catalogue and ask;
`vectra pcap 12345` (refuses for cloud / log-based detections — no PCAP).

Quick commands inherit the safety guardrails in `AGENTS.md` — they
are **read-only by default**, must respect the multi-tenancy scoping
rules in [`references/mental-model.md`](references/mental-model.md),
and never auto-close, dismiss, or mutate detections. If a quick
command's default scope would silently broaden the investigation
(e.g. fan out across many tenants, or bump a detection-window pivot
up to "last 30 d"), **confirm with the analyst before running**.

Ad-hoc natural-language asks ("did host X talk to rare domains last
night?") don't need a canonical prefix — they route through the
[Decision guide in `AGENTS.md`](../../AGENTS.md#decision-guide)
into the right workflow on their own. Quick commands are for the
high-frequency, repeated openers, not a replacement for free-form
analyst language.

---

## Direct Vectra MCP lookups

Some asks don't need a workflow at all. When the user just wants the
**raw record** for a detection / host / account / entity — no
correlation, no rendering, no kill-chain story — call the Vectra MCP
REST tools directly without loading a sub-skill:

| User asks for… | Tool |
|----------------|------|
| Detection record by ID | `get_detection_details` (or `get_detection_summary` for the short form) |
| Host record by ID / name | `get_host_details` (use `lookup_entity_info_by_name` or `lookup_host_by_ip` to find the ID) |
| Account record by ID / UPN | `get_account_details` (use `lookup_entity_info_by_name` to find the ID) |
| Prioritized entity list | `list_entities` |
| Detection queue | `list_detections_with_basic_info` (or `list_detections_with_details` for the full record) |
| Detections on a single entity | `list_entity_detections` |
| Just the IDs / counts (lightweight pre-pivot) | `list_detection_ids` / `get_detection_count` |
| Current assignments | `list_assignments` (or `list_assignments_for_user` / `get_assignment_for_entity` / `get_assignment_detail_by_id`) |
| Locked-down entities | `list_lockdown_entities` |
| Platform users | `list_platform_users` |

If the user follows up with "now what?", "is this real?", or "pull
related telemetry", that's the trigger to drop into the matching
workflow above (typically Workflow 2 or 3).

---

## Cross-skill orchestration

| If you need… | Use… |
|--------------|------|
| Top-N entities or open detections (the queue) | MCP REST: `list_entities` / `list_detections_with_basic_info` |
| Detail on one detection / host / account | MCP REST: `get_detection_details` / `get_host_details` / `get_account_details` |
| The triage playbook for a detection's category (Exfiltration / Lateral Movement / …) | In-skill: [`references/playbooks-overview.md`](references/playbooks-overview.md) → matching `playbook-<category>.md` |
| **Any log / metadata pivot from an entity, detection, or IOC** ("check CloudTrail", "what did this account do", "who's behind this IP", "blast-radius for this domain") | [`vectra-hunt`](../vectra-hunt/SKILL.md) — ad-hoc query mode (MCP) |
| A SQL recipe / pivot for an investigation | [`vectra-hunt`](../vectra-hunt/SKILL.md) — ad-hoc query mode |
| A multi-IOC sweep against a TI report | [`vectra-hunt`](../vectra-hunt/SKILL.md) — TI hunt mode |
| A canned analytic dashboard **and the analyst named the report** ("run the C2 beacon report", "render the top-talkers dashboard") | [`vectra-reports`](../vectra-reports/SKILL.md) (Python 3.11+) or [`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md) (MCP). Never reach for these for an investigation pivot — that's `vectra-hunt`. |
| The PCAP behind a network detection (TLS / JA3 / JA4 / HTTP auth / SMB / RPC / DNS …) | [`vectra-pcap`](../vectra-pcap/SKILL.md) — cloud / log-based detections have no PCAP |
| External reputation on an IOC pulled from a Vectra finding | [`virustotal`](../virustotal/SKILL.md) — corroboration only, never overrides behaviour |

---

The full index of context-specific reference files (mental model,
verdict framework, detection-category playbooks, per-workflow
pipelines, best practices) is at the top of this file. Load only
what the current task needs.

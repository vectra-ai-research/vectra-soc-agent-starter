# Best Practices & Common Pitfalls

These are the durable, cross-workflow habits that separate a good
tier-1 Vectra triage from a noisy one. Read after the workflow you're
running, before you ship a verdict.

---

## Best practices

### Always entity-first

A detection in isolation is rarely actionable. Open the **entity**
view first, read the *whole* detection set, then drill in. Tier-1
analysts who pick detections off the top of the list without entity
context churn through duplicates and miss the kill-chain pattern.
(Background: [`mental-model.md`](mental-model.md) §2.)

### Trust the model, validate the context

If a behavioral detection is high-certainty, the *behavior* is real.
The question is **environment context** — does this host
legitimately do this? Check tags (`backup`, `vuln-scanner`,
`ad-server`), groups, and recent change windows before declaring
BTP.

### Pivot timestamp-narrow

When pulling supporting telemetry, use the detection's
`first_timestamp` / `last_timestamp` window — not "last 24h". Narrow
windows surface the actual evidence; wide windows drown it.

### Triage rules are scalpels

When you BTP something, the right scope for a suppression rule is
the **narrowest combination** that still covers the benign source:
per `(host, detection_type, destination)` or per `(account,
detection_type, target service)`. Never write a rule that suppresses
a detection type globally — that blinds the platform to real future
TPs of the same shape. (Detail in
[`verdict-framework.md`](verdict-framework.md).)

### Document the BTP baseline

Every BTP should leave behind a one-liner the next analyst can read
in 10 s:

> BTP — Veeam backup agent (`BACKUP-AGENT-04`) writing to
> `\\fileserver\C$` nightly between 02:00–03:00 UTC. Suppression
> scope: this host + SMB Files destination = fileserver only.

### Don't forget the account side

Hybrid attacks pivot from network → identity early. If a host
detection lands, also check the matching account(s) for the same
user / session / source IP — resolve account IDs via
`lookup_entity_info_by_name` (or `list_entities` filtered to account
type), pull `get_account_details`, and run
`list_entity_detections(entity_id=<account_id>, state="active")` —
then look for Entra / M365 / AWS detections in the same window.
Cloud recipes live in
[`vectra-hunt/references/cloud_investigations.md`](../../vectra-hunt/references/cloud_investigations.md).

### Time-box each entity

Tier-1 should not spend more than ~15 minutes per entity. If you
can't reach a verdict in that time, the verdict is **"need more
data, escalate to tier 2"** — that's a valid outcome, not a failure.

### Stay scope-honest across tenants

In a multi-tenant deployment, name the tenant(s) you actually queried
and the tenant(s) you skipped or that errored. "No hits" across N-1
tenants is not the same as "no hits". See
[`mental-model.md`](mental-model.md) §4.

### Read-only by default

Containment, suppression, dismissal, mute, isolation, account
disable, triage-rule writes — all human-in-the-loop per
[`../../../AGENTS.md`](../../../AGENTS.md) §7. The agent **proposes**
the action and the exact tool call; the analyst **executes**.

---

## Common pitfalls

| Pitfall | Why it's wrong | Fix |
|---------|----------------|-----|
| Closing a detection because the destination IP "isn't on a blocklist" | Vectra is behavioral; reputation is not the signal | Pivot into the actual behavior (timing, payload, JA4) before deciding |
| Triaging detections in isolation, skipping the entity view | Misses the kill-chain composition | Always open the entity first, read its full detection set |
| Running 7-day pivots on every detection | Drowns the analyst in noise; misses the actual evidence window | Use `first_timestamp` / `last_timestamp` from the detection |
| Writing global suppression rules ("suppress all RPC Recon") | Blinds the platform to future TPs | Scope by `(host, type, dst)` or `(account, type, target)` |
| Treating Threat and Certainty as one number | Loses the prioritization signal | Always read both; high-T low-C still goes early in the queue |
| Running the same canned report repeatedly instead of pivoting | Reports are dashboards, not investigations | Use `vectra-hunt` for investigation pivots |
| Reaching for `vectra-reports` / `vectra-reports-mcp` to investigate a specific entity / detection / IOC ("check CloudTrail", "what did this account do", "who's behind this IP") | Reports are canned dashboards, not investigation tools; the trigger is an *explicitly-named* report from the catalogue, not a data-domain | Use `vectra-hunt` (ad-hoc Investigation Query SQL via the Vectra MCP server) for any "check / what / who / how" question. Reports run only when the analyst names a specific report. |
| Hand-rolling Python / `httpx` / `curl` against the Investigation Query API to dodge a Python venv issue | Easy to get wrong (Basic-auth OAuth2 vs body params, polling endpoint shape, request-id lifecycle); cascades into 10-minute debugging loops | Always go through MCP `run_investigation` / `get_investigation_results` via `vectra-hunt` (or `vectra-reports-mcp` for canned reports). If the Python channel of `vectra-reports` is broken, switch to `vectra-reports-mcp` — never DIY REST. |
| BTP without naming the benign source | Unauditable; the next analyst will redo the same work | Always name the tool / user / service that explains the behavior |
| Using `vectra-reports` and `vectra-reports-mcp` in the same run | Inconsistent output / mixed contexts | Pick one channel per workflow and stick to it |
| Calling `get_detection_pcap` on a cloud / log-based detection | Returns 406 — those have no PCAP | Check `category` / `source` first; stay on metadata pivots and load the matching cloud `playbook-<category>.md` |
| Auto-closing or dismissing detections | Destroys evidence and breaks chain of custody | Read-only by default; closures are human-in-the-loop |
| Silently fanning out across all tenants when the user named one | Breaks scope discipline; may breach data-sharing constraints | Confirm tenant scope before broadening; surface gaps when partial |
| Setting `list_entities`'s `is_prioritized` filter for a general urgency sweep | `is_prioritized` flags entities already manually/platform-flagged — it's unrelated to `urgency_score`, and setting it silently drops every non-flagged entity, breaking a "lowest urgency" or "walk the queue" ask | Leave `is_prioritized` unset for a general sweep; only set it when the user explicitly wants pre-flagged entities. Sort by `urgency_score` / `-urgency_score` instead |
| Setting `entity_type` on `list_entities` during a queue sweep | The filter is optional; omitting it returns hosts **and** accounts in one call. Restricting to one halves the queue, and kill chains routinely span both — a compromised account driving a compromised host | Leave `entity_type` unset for a sweep; set it only to deliberately scope to one type |
| Defaulting to `list_detections_with_details` for a broad or exploratory pull | Returns per-detection detail — the wrong shape for a sweep, even though the two heaviest fields are now excluded by default | Start with `list_detection_ids` or `list_detections_with_basic_info`; use `list_detections_with_details` once narrowed to a specific set of IDs, and pass `exclude_fields=None` only when you genuinely need `process_context_data` or `grouped_details` |
| Answering "has this detection fired before?" from narrative memory | `grouped_details` carries one entry per occurrence, with per-occurrence timestamps and byte counts | Detect recurrence from `last_timestamp` > `first_timestamp` (always present, free); enumerate the occurrences from `grouped_details` via `get_detection_details`. Never from prior conversation |
| Counting detection objects to answer "has this behaviour happened before?" | **A recurring behaviour is ONE detection whose `last_timestamp` moves forward — not a second detection.** Grouping detections by `first_timestamp` therefore shows a single cluster no matter how many times the behaviour repeated, and the honest-looking conclusion is "no prior occurrence" | Compare `first_timestamp` with `last_timestamp` per detection. For the entity-level question, answer from **metadata** (`aws.cloudtrail._all`, `network.*`) which records every occurrence as its own row |
| Treating an absent `grouped_details` as evidence of no recurrence | It is excluded by default on `list_detections_with_details` (see row above). Absent because unrequested looks identical to absent because empty | Request it explicitly (`exclude_fields=None`) before concluding anything about recurrence, or fall back to the timestamp comparison |

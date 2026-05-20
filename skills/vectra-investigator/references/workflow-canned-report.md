# Workflow 6 — Canned Report

**Goal:** the user **explicitly names** a pre-built report ("C2 beacons
last 24h", "top talkers", "DNS error rate", "TLS posture",
"zone-to-zone data transfer").

This workflow is owned by either
[`vectra-reports`](../../vectra-reports/SKILL.md) (Python 3.11+) or
[`vectra-reports-mcp`](../../vectra-reports-mcp/SKILL.md) (MCP). The
orchestrator's job is **pick the channel, hand off, and pivot if the
report rows raise questions.**

---

## When NOT to use this workflow (read this first)

Reports are **canned dashboards**. They render the *shape* of the
environment over a time window — they do not produce a verdict on a
specific entity, detection, IOC, or open-ended question. If the user's
ask is investigative rather than dashboard-shaped, route elsewhere:

| User says… | Right workflow |
|------------|----------------|
| "Check CloudTrail to understand what's going on" | [Ad-hoc Investigation Query](workflow-ad-hoc-query.md) → `vectra-hunt` cloud recipes |
| "What did this credential / account / host do?" | [Ad-hoc Investigation Query](workflow-ad-hoc-query.md) → `vectra-hunt` |
| "Who's behind this IP / domain / SNI?" | [Ad-hoc Investigation Query](workflow-ad-hoc-query.md) → `vectra-hunt` |
| "Investigate / triage this entity" | [Entity Deep-Dive](workflow-entity-deep-dive.md) → `vectra-hunt` |
| "Pivot from detection `<id>`" / "is detection `<id>` real?" | [Single-Detection Pivot](workflow-detection-pivot.md) → matching `playbook-<category>.md` → `vectra-hunt` |
| "Did host X talk to evil.com?" | [Ad-hoc Investigation Query](workflow-ad-hoc-query.md) |
| "Sweep this CISA advisory across our tenant" | [TI-Driven Hunt](workflow-ti-hunt.md) |
| "Triage the queue" | [Queue Triage](workflow-queue-triage.md) |
| "Look at / check / investigate / understand X" (no report named) | [Ad-hoc Investigation Query](workflow-ad-hoc-query.md) — default to `vectra-hunt` whenever the request is investigative |

If the user names neither a specific report nor a clear investigation
question, **list the catalogue** (e.g. `python scripts/list_reports.py`
or read `skills/vectra-reports-mcp/definitions/*.yaml`) and ask the
analyst which report they want — **never silently default** to a
generic "summary" report.

---

## Pipeline (only after the report is named)

1. **Confirm the report exists in the catalogue.** If the named
   report doesn't exist, list the catalogue and ask the analyst to
   pick.
2. **Pick the channel — and stick with it.**
   - If a Python 3.11+ venv with
     [`vectra-reports`](../../vectra-reports/SKILL.md) is wired up,
     use it.
   - Otherwise use
     [`vectra-reports-mcp`](../../vectra-reports-mcp/SKILL.md).
   - **Do not mix** the two channels mid-run — output formats and
     parameters differ.
   - **Never hand-roll REST calls** against the Investigation Query
     API as a workaround if the Python channel fails — switch to the
     MCP channel.
3. **Confirm scope.** Time window (default last 24 h), tenant(s),
   any report-specific filters (zone, host group, severity).
   Multi-tenancy rules: see [`mental-model.md`](mental-model.md) §4.
4. **Hand off to the chosen sub-skill.** It owns the report
   catalogue, the SQL definitions, and the rendering.
5. **If a row in the rendered report raises a question, pivot
   into a different workflow.** A row in a report is a starting
   point for investigation, not a verdict:
   - Row corresponds to an existing detection → [Single-Detection
     Pivot](workflow-detection-pivot.md).
   - Row is just an entity / IP / domain you want to dig into →
     [Ad-hoc Investigation Query](workflow-ad-hoc-query.md) →
     `vectra-hunt`.

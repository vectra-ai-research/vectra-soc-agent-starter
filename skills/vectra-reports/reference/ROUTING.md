# Reports vs Hunt — Shared Routing Rules

This file is the **single source of truth** for when the two report
channels (`vectra-reports`, `vectra-reports-mcp`) are the right tool and
when the request belongs in `vectra-hunt` instead. Both report `SKILL.md`
bodies link here; update **this file**, not the inline summaries.

Reports are **canned, named dashboards**. They render the *shape* of the
environment over a time window — they do **not** produce a verdict on a
specific entity, detection, IOC, or open-ended question. The trigger is
always the **report name**, not the data domain.

---

## Use a report channel only when…

The user **explicitly names** a report from the catalogue. Examples:

- "Run the C2 beacon report for the last 24 h"
- "Render the top-talkers dashboard as HTML"
- "Show me the DNS error rate report, last hour"
- "Generate the zone-to-zone data transfer report"
- "Give me the TLS posture report as Markdown"
- "Daily threat summary"

If the user names neither a specific report nor a clear investigation
question, **list the available reports** and ask them to pick — **do
not** silently default to a generic "summary" report.

---

## Route to `vectra-hunt` (or `vectra-investigator`) when…

| User says… | Right skill |
|------------|-------------|
| "Check CloudTrail / Entra / M365 to understand what's going on" | [`vectra-hunt`](../../vectra-hunt/SKILL.md) (cloud recipes) |
| "What did this credential / account / host do?" | [`vectra-hunt`](../../vectra-hunt/SKILL.md) |
| "Who's behind this IP / domain / SNI?" | [`vectra-hunt`](../../vectra-hunt/SKILL.md) |
| "Investigate / triage / pivot from detection `<id>`" | [`vectra-investigator`](../../vectra-investigator/SKILL.md) → matching `playbook-<category>.md` → `vectra-hunt` |
| "Investigate entity `<name>`" | [`vectra-investigator`](../../vectra-investigator/SKILL.md) (entity deep-dive) → `vectra-hunt` |
| "Find Kerberoasting / DGA / unusual logons in the last N days" | [`vectra-hunt`](../../vectra-hunt/SKILL.md) |
| "Sweep this CISA advisory / IOC list across the tenant" | [`vectra-hunt`](../../vectra-hunt/SKILL.md) (TI hunt mode) |
| "I don't know which report I want, just look at X" | [`vectra-hunt`](../../vectra-hunt/SKILL.md) |
| "Did host X talk to evil.com?" | [`vectra-hunt`](../../vectra-hunt/SKILL.md) |

**Key principle:** the moment the question is "what is going on with X"
rather than "render dashboard Y", switch channels. Both
`vectra-reports-mcp` and `vectra-hunt` go through the same MCP
`run_investigation` tool — the difference is the **library and
intent** (canned dashboard SQL vs investigation recipe library +
verdict workflow).

---

## Channel selection — Python vs MCP

When the user **has** named a report, pick exactly **one** of the two
report channels for the whole run:

- [`vectra-reports`](../SKILL.md) — Python channel. HTML rendering with
  charts. Requires a Python 3.11+ venv synced via `uv sync` in
  `skills/vectra-reports/`.
- [`vectra-reports-mcp`](../../vectra-reports-mcp/SKILL.md) — MCP
  channel. Markdown only. No Python required.

Do not mix mid-run; do not hand-roll REST calls against the
Investigation Query API as a workaround. If the Python venv is not
available, switch to the MCP channel.

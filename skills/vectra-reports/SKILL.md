---
name: vectra-reports
description: Renders canned Vectra AI dashboard reports via the Python channel. The user must explicitly name a report from the catalog — active connections, C2 beacon report, DNS error rate, flow records, HTTP status codes, NPM active TCP/UDP connections, protocol distribution, remote access sessions, RPC latency, SaaS reachability, TLS session duration / posture, top listeners by IP, top talkers / senders by IP, VLAN utilisation, zone-to-zone data transfers, cert expiration, daily threat summary. Each report is a YAML definition bundling Investigation Query SQL statements plus a rendering spec (KPIs, tables, charts), executed via the REST API by a Python engine. Not for investigation, detection pivots, entity deep-dives, or open-ended questions — those go to vectra-hunt. Reports are dashboards, not investigation tools. Refuses and routes to vectra-hunt if the request does not name a specific report.
---

# Vectra AI Reports (Python channel)

Render **canned, named, repeatable dashboards** against a Vectra AI tenant.
Each report is a YAML definition under `definitions/` that bundles one or more
SQL queries against the Investigation Query API plus a rendering spec (summary
KPIs, tables, pie charts, Sankey diagrams). Queries inside a single report run
**in parallel**, gated only by the documented 5 req/min token bucket.

## When to use this skill

Use **only** when the user **explicitly names a canned report** from the
catalog (run `python scripts/list_reports.py` to see it). Examples:

- "Run the C2 beacon report for the last 24 h"
- "Render the top-talkers dashboard as HTML"
- "Show me the DNS error rate report, last hour"
- "Generate the zone-to-zone data transfer report"
- "Give me the TLS posture report as Markdown"

The trigger is the **report name**, not the data domain. A report
can be named by its exact ID (`protocol_distribution`) or by its
catalog label phrased as a question ("what's the protocol
distribution across the network?", "show me active connections
right now"). Both count as a named trigger.

## When NOT to use this skill

**Reports are dashboards, not investigation tools.** If the request is
investigative ("check CloudTrail", "what did this account do", "who's
behind this IP", "pivot from detection `<id>`", "investigate entity
`<name>`", "find Kerberoasting last 7 d", "sweep this CISA advisory"),
route to [`vectra-hunt`](../vectra-hunt/SKILL.md) instead.

Full routing table lives in
[**`reference/ROUTING.md`**](./reference/ROUTING.md) — shared with
`vectra-reports-mcp`, so update it there.

If the user names neither a specific report nor a clear investigation
question, **list the available reports** (`python scripts/list_reports.py`)
and ask them to pick one — do not silently default to a generic report.

## Channel selection — Python vs MCP

This skill (`vectra-reports`) is the **Python channel**. The same report
catalogue is also runnable via the **MCP channel**
([`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md)) which needs no
Python venv. Pick one channel per task and stick with it; do not mix
mid-run. If the Python venv (3.11+) isn't available, switch to the MCP
channel — **do not hand-roll REST calls** against the Investigation
Query API. The MCP server handles auth, polling, rate limits, and
response shape; bypassing it is a known source of cascading failures
(OAuth body vs Basic, polling endpoint shape, request-id lifecycle).
See [`reference/ROUTING.md`](./reference/ROUTING.md) for the channel
selection rules.

## Prerequisites

| Requirement | Why | How to check |
|-------------|-----|--------------|
| **Python 3.11+** | Pinned by `pyproject.toml` (`requires-python = ">=3.11"`). The engine also uses PEP 604 union syntax in module-level expressions; macOS / RHEL system Python is often 3.9 and will fail at import time with `TypeError: unsupported operand type(s) for \|: 'ModelMetaclass' and 'ModelMetaclass'`. **Always run from the synced venv** (`uv sync` or `python -m venv .venv && pip install -e .`), never via the system `python3`. | `.venv/bin/python --version` (must report `3.11.x` or higher) |
| **Skill venv synced** | Pinned dependency set installed in `skills/vectra-reports/.venv/`. | `cd skills/vectra-reports && uv sync` (or `pip install -e .`) |
| **Vectra credentials** | `VECTRA_BASE_URL`, `VECTRA_CLIENT_ID`, `VECTRA_CLIENT_SECRET` in the current environment or the repo-root `.env`. | Check repo-root `.env` for the variable names without printing values. |

If Python 3.11+ is **not** available, **stop and switch to
[`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md)** — same reports, same
YAML definitions, executed through the Vectra MCP server with no Python
required. Do **not** try to hand-roll REST calls; the MCP server already
encapsulates auth (Basic-auth OAuth2), polling, the request-id lifecycle, and
rate-limiting.

## Workflow

```
1. Confirm   → user has explicitly named a report from the catalog
               (otherwise list and ask them to pick — do not default)
2. Discover  → python scripts/list_reports.py
3. Inspect   → python scripts/show_report.py <id>
4. Run       → python scripts/run_report.py <id> [--<param> <value>] [--format html|markdown|json]
5. Save      → redirect stdout to a file the user can open
```

Always read the report definition with `show_report.py` before running it — the
parameters and time-window defaults vary per report.

## Available scripts

| Script | Purpose | Reads | Writes |
|--------|---------|-------|--------|
| `scripts/list_reports.py` | List all reports grouped by category | `definitions/*.yaml` | stdout |
| `scripts/show_report.py <id>` | Print parameters, SQL, sections for one report | one YAML | stdout |
| `scripts/run_report.py <id> [...]` | Execute a report (parallel queries) and render | YAML + Vectra API | stdout (HTML / Markdown / JSON) |
| `scripts/validate.py` | Validate every YAML loads cleanly | all YAML | stdout |

Each script supports `--help`. `run_report.py` builds its argparse parser
dynamically from the report's `parameters:` list, so flags vary per report.

## Output formats

| `--format` | When to use |
|------------|-------------|
| `html` (default for most) | Self-contained HTML with inline CSS + SVG charts. Save and open in a browser. |
| `markdown` | Inline conversation, IDE preview, or pasting into a document. Pie charts fall back to Mermaid. |
| `json` | Programmatic post-processing or piping into another tool. |

## Available reports (17)

Run `python scripts/list_reports.py` to see the canonical list with
descriptions and parameters. Categories:

- **Network** — `active_connections`, `c2_beacon_report`, `dns_error_rate`,
  `flow_records`, `http_status_codes`, `npm_active_tcp_udp_connections`,
  `protocol_distribution`, `remote_access_sessions`, `rpc_latency`,
  `saas_reachability`, `tls_session_duration`, `top_listeners_by_ip`,
  `top_talkers_senders_by_ip`, `vlan_utilization`, `zone_segment_data_transfers`
- **Operations** — `cert_expiration`
- **Identity / Cloud** — `daily_threat_summary`

## Examples

### Example 1 — Top talkers in the last 6 hours, save HTML

```bash
python scripts/run_report.py top_talkers_senders_by_ip --hours 6 > talkers.html
```

### Example 2 — C2 beacons in the last 24 hours as Markdown for the chat

```bash
python scripts/run_report.py c2_beacon_report --hours 24 --limit 50 --format markdown
```

### Example 3 — Discover then run

The user says: "Show me what reports you have, then run the DNS error one for the last hour."

```bash
python scripts/list_reports.py
python scripts/show_report.py dns_error_rate
python scripts/run_report.py dns_error_rate --hours 1 > dns_errors.html
```

### Example 4 — Programmatic JSON for post-processing

```bash
python scripts/run_report.py active_connections --hours 1 --format json > conn.json
jq '.data_sources.proto_ds[] | {protocol, session_count}' conn.json
```

## Parallelism (why this skill is fast)

A report with N investigation queries no longer takes `N × 12s` of pure
rate-gating. The token bucket inside `engine/client.py` allows bursts up to
5 in-flight requests, and `engine/executor.py` runs every data source
concurrently. Wall-clock time is now bounded by the slowest single query plus
one polling cycle, not by the sum of all queries.

If you suspect a query is slow, check the `Report Metadata` footer in the
output — it lists per-source `request_id`, `row_count`, and `duration_ms`.

## Configuration

Credentials are loaded from environment variables, optionally bootstrapped
from the centralized repo-root `.env` file. Do not create or use a
skill-local `.env`, and do not fall back to `~/.vectra/credentials.env`.
Existing exported environment variables still win over values loaded from
repo-root `.env`.

Required:

- `VECTRA_BASE_URL` (e.g. `https://acme.cc1.portal.vectra.ai/api/v3.4`)
- `VECTRA_CLIENT_ID`
- `VECTRA_CLIENT_SECRET`

Optional:

- `VECTRA_OAUTH_TOKEN_URL` (defaults to `<base host>/oauth2/token`)
- `VECTRA_RATE_LIMIT_REQUESTS` (default `5`)
- `VECTRA_RATE_LIMIT_PERIOD_SEC` (default `60`)

If the user reports `RuntimeError: Missing Vectra credentials`, check whether
the required variable names are present in the repo-root `.env` without
printing values, then point them at [INSTALL.md](./INSTALL.md) step 3.

## Adding new reports

Drop a YAML file into `definitions/` following the schema in
[reference/AUTHORING.md](./reference/AUTHORING.md). The next invocation of
`list_reports.py` / `run_report.py` will pick it up — no code changes needed.

> **This directory is the authoritative source.** `vectra-reports-mcp/`
> symlinks its `definitions/` and `reference/` into this skill, so adding
> a YAML here automatically lights up the MCP channel too. See
> [`../PACKAGING.md`](../PACKAGING.md) for shipping guidance (when to
> dereference the symlinks).

After adding a YAML file, always:

```bash
python scripts/validate.py
```

If any file is broken, validate prints which one and exits non-zero.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `TypeError: unsupported operand type(s) for \|: 'ModelMetaclass' and 'ModelMetaclass'` (or similar in `engine/loader.py`) | Running with system `python3` (typically 3.9 on macOS) instead of the skill venv | Activate / use the synced `.venv` (`uv sync` first), or switch to [`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md). Do not hand-roll REST calls against the Investigation Query API. |
| `ModuleNotFoundError: No module named 'engine'` | Skill venv not synced, or PYTHONPATH wrong | `cd skills/vectra-reports && uv sync`, then run scripts from the skill root |
| `RuntimeError: Missing Vectra credentials` | Required variables are not exported and are not present in the repo-root `.env` | Configure per [INSTALL.md](./INSTALL.md) |
| `HTTP 400` on a query | SQL uses flat field name (`orig_h`) where dot-notation is required (`id.orig_h`) | Fix the YAML; see [reference/SQL_GUIDE.md](./reference/SQL_GUIDE.md) |
| `HTTP 401` from `/oauth2/token` | Trying to send `client_id`/`client_secret` in the body — Vectra's OAuth2 endpoint expects HTTP Basic auth | Don't bypass `engine/client.py`; if you must DIY, use Basic auth with the `client_credentials` grant |
| Report runs but a section is empty | `value_field` / `label_field` doesn't match the SQL alias | Check `show_report.py <id>` and ensure aliases match |
| `QueryTimeoutError` | Vectra job hasn't finished within 2 min | Reduce time window, simplify SQL, or rerun |
| Report extremely slow | Many large pages requested | Set `pagination.enabled: false` for aggregate queries |

## Reference

- [reference/AUTHORING.md](./reference/AUTHORING.md) — full YAML schema + cookbook
- [reference/SQL_GUIDE.md](./reference/SQL_GUIDE.md) — Vectra Investigation Query SQL rules
- [INSTALL.md](./INSTALL.md) — install/registration in Cursor / Claude Code / Codex

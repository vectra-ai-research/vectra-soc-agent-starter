---
name: vectra-reports-mcp
description: Renders canned Vectra AI dashboard reports via the MCP channel (no Python venv required). The user must explicitly name a report from the catalog — active connections, C2 beacon report, DNS error rate, flow records, HTTP status codes, NPM active TCP/UDP connections, protocol distribution, remote access sessions, RPC latency, SaaS reachability, TLS session duration / posture, top listeners by IP, top talkers / senders by IP, VLAN utilisation, zone-to-zone data transfers, cert expiration, daily threat summary. Each report is a YAML definition bundling Investigation Query SQL statements plus a rendering spec (KPIs, tables, charts), executed through the Vectra MCP server. Not for investigation, detection pivots, entity deep-dives, or open-ended questions — those go to vectra-hunt. Reports are dashboards, not investigation tools. Refuses and routes to vectra-hunt if the request does not name a specific report.
---

# Vectra AI Reports (MCP channel)

Render **canned, named, repeatable dashboards** against a Vectra AI tenant
using the **Vectra MCP server** for all API calls. Each report is a YAML file
in `definitions/` that bundles one or more SQL queries plus rendering
instructions (summary KPIs, tables, charts). You read the YAML, substitute
parameters into the SQL templates, call the MCP tools, and format the results.

No Python scripts, no venv, no pip install. The MCP server handles
authentication, rate limiting, and query execution.

## When to use this skill

Use **only** when the user **explicitly names a canned report** from the
catalogue below. Examples:

- "Run the C2 beacon report for the last 24 h"
- "Render the top-talkers dashboard"
- "Show me the DNS error rate report, last 7 d"
- "Generate the zone-to-zone data transfer report"
- "Give me the daily threat summary"

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
route to [`vectra-hunt`](../vectra-hunt/SKILL.md) instead. Both
`vectra-reports-mcp` and `vectra-hunt` go through the same MCP
`run_investigation` tool — the difference is the **library and
intent** (canned dashboard SQL vs investigation recipe library +
verdict workflow).

Full routing table lives in
[**`reference/ROUTING.md`**](reference/ROUTING.md) — shared with
`vectra-reports`, so update it there.

If the user names neither a specific report nor a clear investigation
question, **list the available reports** (from the catalogue below) and
ask them to pick one — do not silently default to a generic report.

## Channel selection — MCP vs Python

This skill (`vectra-reports-mcp`) is the **MCP channel** — no local
Python required. The same report catalogue is also runnable via the
**Python channel** ([`vectra-reports`](../vectra-reports/SKILL.md)) for
HTML rendering with charts, but that requires Python 3.11+ and a synced
venv. Pick one channel per task and stick with it; do not mix mid-run.
See [`reference/ROUTING.md`](reference/ROUTING.md) for the channel
selection rules.

## Prerequisites

The **Vectra MCP server** must be connected and authenticated. It provides
these tools:

| MCP tool | Purpose |
|----------|---------|
| `run_investigation` | Submit an async SQL job, returns a `request_id` |
| `get_investigation_results` | Poll / fetch results for a `request_id` |
| `list_detections_with_basic_info` / `list_detections_with_details` | List detections (with filters) |
| `list_entity_detections` | List detections scoped to a single host / account / entity |
| `list_entities` | List entities (host + account unified) |
| `list_assignments` | List analyst assignments |

YAML report definitions are shared with the Python channel and use
Python REST method names in their `client_method:` fields. The
**channel-to-MCP-tool mapping** when executing those YAMLs through MCP:

| YAML `client_method` | MCP tool to call |
|----------------------|------------------|
| `submit_investigation_query` | `run_investigation` |
| `get_investigation_results` | `get_investigation_results` |
| `get_detections` | `list_detections_with_basic_info` (or `list_entity_detections` when filtered to one entity) |
| `get_entities` | `list_entities` |
| `get_assignments` | `list_assignments` |
| `get_hosts` / `get_accounts` | `list_entities` (filter by entity type), or `lookup_entity_info_by_name` / `lookup_host_by_ip` when resolving a single record |

If the MCP server is not connected, tell the user to configure it before
proceeding.

## Workflow

```
1. Discover   → Read definitions/ directory listing to find available reports
2. Inspect    → Read the YAML file for the requested report
3. Template   → Substitute parameter values into SQL templates (Jinja2 syntax)
4. Execute    → Call MCP tools for each data source
5. Format     → Render results as Markdown tables, summaries, and analysis
```

## Step-by-step execution

### Step 1 — Find the report

List `definitions/*.yaml` to see available reports. Each filename (without
`.yaml`) is the report ID.

### Step 2 — Read and parse the YAML

Read the full YAML file. Key sections:

- **`parameters`** — user-configurable inputs with defaults (hours, days, limit, etc.)
- **`data_sources`** — one or more queries to execute
- **`sections`** — how to render results (summary, table, chart)

### Step 3 — Substitute parameters into SQL

Each `data_source` of type `investigation_query` has a `query` field with
Jinja2 templates. Replace `{{ param_name | int }}` with the actual value.

Example — given `hours=24`:
```
# Template
WHERE timestamp BETWEEN date_add('hour', -{{ hours | int }}, now()) AND now()

# Rendered
WHERE timestamp BETWEEN date_add('hour', -24, now()) AND now()
```

### Step 4 — Execute data sources via MCP

For each data source in the YAML:

**If `type: investigation_query`:**
1. Call `run_investigation` with the rendered SQL
2. Receive a `request_id`
3. Call `get_investigation_results` with that `request_id` to poll for results
4. If status is not `SUCCESS`, wait and retry `get_investigation_results`
5. Extract the `data` array from the response

**If `type: vectra_rest`:**
1. Look at `client_method` (e.g. `get_detections`) — that's the
   Python REST method baked into the shared YAML
2. Translate it to the matching MCP tool via the mapping table in
   the **Prerequisites** section above (`get_detections` →
   `list_detections_with_basic_info`, `get_entities` →
   `list_entities`, `get_assignments` → `list_assignments`, etc.)
3. Call the MCP tool with the rendered `arguments`
4. Extract the `results` array from the response

### Step 5 — Render results

Use the `sections` definitions to format output:

- **`summary`** sections: compute aggregations (sum, count, min, max) over
  the specified `value_field` and display as bold KPI lines
- **`table`** sections: render a Markdown table using the `columns` list
  (field → label mapping, with format hints: `ip`, `bytes`, `number`,
  `timestamp`, `text`, `percent`, `duration`, `hash`)
- **`chart`** sections: describe the distribution in text or a Mermaid diagram

Format hints for values:
- `bytes` → human-readable (KB, MB, GB)
- `number` → comma-separated
- `timestamp` → ISO 8601 or relative
- `duration` → human-readable (ms, s, min, h)
- `percent` → with % suffix
- `ip` → as-is

## Available reports (17)

### Network
| ID | Name | Default params |
|----|------|----------------|
| `active_connections` | Active Connection Count | hours=1 |
| `c2_beacon_report` | C2 Beacon Indicators | hours=24, limit=100 |
| `cert_expiration` | Certificate Expiration | days=7, expiry_window=90 |
| `dns_error_rate` | DNS Error Rate | days=7 |
| `flow_records` | Flow Records (NetFlow Equivalent) | hours=24 |
| `http_status_codes` | HTTP Status Code Distribution | days=7 |
| `npm_active_tcp_udp_connections` | NPM - Active TCP/UDP Connections | days=14 |
| `protocol_distribution` | Protocol Distribution | days=7 |
| `remote_access_sessions` | Remote Access Sessions | days=14 |
| `rpc_latency` | RPC / SMB Latency | days=7 |
| `saas_reachability` | SaaS Reachability | days=7 |
| `tls_session_duration` | TLS Session Duration | days=7 |
| `top_listeners_by_ip` | Top Listeners (Receivers) by IP | days=7 |
| `top_talkers_senders_by_ip` | Top Talkers (Senders) by IP | days=7 |
| `vlan_utilization` | VLAN Utilization | days=7 |
| `zone_segment_data_transfers` | Zone / Segment Data Transfers | hours=24 |

### Operations
| ID | Name | Default params |
|----|------|----------------|
| `cert_expiration` | Certificate Expiration | days=7 |

### Identity / Cloud
| ID | Name | Default params |
|----|------|----------------|
| `daily_threat_summary` | Daily Threat Summary | hours=24, page_size=25 |

## Examples

### Example 1 — User says "run top talkers for last 3 days"

1. Read `definitions/top_talkers_senders_by_ip.yaml`
2. Set `days=3`
3. Render SQL: replace `{{ days | int }}` → `3`
4. Call `run_investigation` with the rendered SQL
5. Poll `get_investigation_results` until SUCCESS
6. Format the `sections`: Overview (Total Bytes Sent, Total Sessions), then
   the Top Senders table with columns: Source IP, Hostname, Sessions, Bytes Sent, Bytes Received

### Example 2 — User says "daily threat summary"

1. Read `definitions/daily_threat_summary.yaml`
2. Use defaults: `hours=24`, `page_size=25`
3. Execute 3 data sources:
   - `sessions_agg` → `run_investigation` (session count SQL)
   - `top_talkers` → `run_investigation` (top flow pairs SQL)
   - `open_detections` → YAML says `client_method: get_detections`,
     translate to the `list_detections_with_basic_info` MCP tool
     (`page=1`, `page_size=25`)
4. Render: Overview KPI, Top flow pairs table, Active detections table

## Vectra Investigation Query SQL rules

- Use **dot-notation** for nested fields: `id.orig_h`, `id.resp_h`, `orig_hostname.name`
- Always alias dot-notation fields: `id.orig_h AS src_ip`
- The `timestamp` field is always available for time filtering
- Use `date_add('hour', -N, now())` or `date_add('day', -N, now())` for time windows
- Use `dt > date_add(...)` alongside `timestamp BETWEEN ...` for partition pruning
- See [reference/SQL_GUIDE.md](reference/SQL_GUIDE.md) for the full SQL reference

## Adding new reports

Drop a YAML file into `definitions/` following the schema in
[reference/AUTHORING.md](reference/AUTHORING.md). No code changes needed.

> **Catalog parity:** `definitions/` and `reference/` are symlinks to the
> authoritative copy in [`../vectra-reports/`](../vectra-reports/) — edit
> the YAML or markdown there once and both channels stay in sync. See
> [`../PACKAGING.md`](../PACKAGING.md) for how to ship a MCP-only bundle
> (the symlinks must be dereferenced).

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| MCP server not connected | Vectra MCP not configured | User must add the Vectra MCP server |
| `HTTP 400` on a query | SQL uses flat field name instead of dot-notation | Fix the YAML; see SQL_GUIDE.md |
| Query returns no data | Wrong time window or table name | Check the SQL and try a wider window |
| Empty section | `value_field` doesn't match the SQL alias | Compare section config with SQL aliases |

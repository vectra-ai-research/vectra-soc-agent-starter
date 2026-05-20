# Authoring Reports — YAML Schema & Cookbook

Add a new report by dropping one YAML file into `definitions/`. No Python edits
required. The next invocation of `scripts/list_reports.py` /
`scripts/run_report.py` discovers and validates it.

For Vectra-specific SQL syntax (table names, dot-notation, time windows), see
[SQL_GUIDE.md](./SQL_GUIDE.md).

---

## Quick start

```bash
# 1. Copy the closest existing report
cp definitions/c2_beacon_report.yaml definitions/my_report.yaml

# 2. Edit id, name, queries, sections
$EDITOR definitions/my_report.yaml

# 3. Validate
python scripts/validate.py

# 4. Run
python scripts/run_report.py my_report --hours 1
```

---

## Full YAML schema

```yaml
# ─── Identity ────────────────────────────────────────────────────────────────
id: my_report_id            # snake_case only: ^[a-z0-9_]+$
name: Human Readable Title  # Shown in `list_reports.py`
description: >-             # One paragraph; first line shows in listings
  What this report does and when to use it.
category: Network           # Free-form: Network | Identity | Cloud | Operations
version: "1.0"

# ─── Parameters ─────────────────────────────────────────────────────────────
parameters:
  - name: hours             # Must match ^[a-z][a-z0-9_]*$
    type: int               # int | str | bool
    description: Hours of history (1–168).
    default: 24             # Used when caller omits the flag
    required: false         # true = no default; must be passed

# ─── Data sources ───────────────────────────────────────────────────────────
data_sources:
  - id: my_ds               # Unique within this report; referenced by sections
    type: investigation_query
    query: |
      SELECT ...
      WHERE timestamp BETWEEN date_add('hour', -{{ hours | int }}, now()) AND now()
    parameters: {}          # Extra Jinja vars (rare)
    pagination:
      enabled: false        # true ONLY for raw event row dumps
      max_pages: 1
      page_size: 500        # max 10,000

# ─── Sections ───────────────────────────────────────────────────────────────
sections:
  - id: overview
    title: Overview
    type: summary           # summary | table | chart
    data_source: my_ds      # Must match a data_sources[].id

    metrics:                # for type: summary
      - label: Total events
        value_field: event_count   # SQL alias from the query
        aggregation: sum           # count | sum | max | min
        format: number             # number | bytes | duration

    columns:                # for type: table
      - field: timestamp    # SQL alias (dot-notation supported for nested rows)
        label: Time
        format: timestamp   # text | bytes | timestamp | ip | number | hash | percent | duration
    row_limit: 100
    empty_message: No data in this window.

    chart_type: pie         # for type: chart — pie | sankey
    label_field: protocol   # pie+sankey: source/slice label
    value_field: cnt        # pie+sankey: numeric magnitude
    dst_field: dst_subnet   # sankey only: destination node

# ─── Output ─────────────────────────────────────────────────────────────────
output:
  default_format: html      # html | markdown | json
  title_template: "{{ name }} — last {{ hours }}h"
  include_metadata: true
```

---

## Validation rules

| Rule | Failure mode |
|------|--------------|
| `id` matches `^[a-z0-9_]+$` | Validate fails |
| `data_sources[].id` unique within report | Validate fails |
| Every `section.data_source` matches a `data_sources[].id` | Validate fails |
| `summary` has at least one `metric` | Validate fails |
| `table` has at least one `column` | Validate fails |
| `chart` has `chart_type`, `label_field`, `value_field` | Validate fails |
| `chart_type` ∈ `{pie, sankey}` (`bar` and `line` not implemented) | Validate fails |
| `parameter.name` matches `^[a-z][a-z0-9_]*$` | Skipped at runtime |

Run `python scripts/validate.py` to see exact line numbers.

---

## Data source types

### `investigation_query` (most common)

Submits SQL to the Vectra Data API, polls for completion, returns rows.

```yaml
data_sources:
  - id: dns_agg
    type: investigation_query
    query: |
      SELECT query AS domain, COUNT(*) AS lookups
      FROM network.dns._all
      WHERE timestamp BETWEEN date_add('hour', -{{ hours | int }}, now()) AND now()
      GROUP BY query ORDER BY lookups DESC LIMIT 50
    parameters: {}
    pagination:
      enabled: false   # true only when fetching > page_size raw event rows
      max_pages: 3
      page_size: 500
```

**Parallelism:** every investigation query in a report runs concurrently. The
token bucket inside `engine/client.py` enforces the documented 5 req/min rate
limit on the submit endpoint and shares it with polling, so wall-clock time
collapses to roughly the slowest single query.

### `vectra_rest`

Calls a `VectraClient` `get_*` / `search_*` method directly.

```yaml
data_sources:
  - id: open_detections
    type: vectra_rest
    client_method: get_detections
    arguments:
      page: "1"
      page_size: "{{ page_size }}"   # Jinja in arg values
      state: "active"
```

Allowlist: only methods starting with `get_` or `search_`. The investigation
endpoints (`submit_investigation_query`, `get_investigation_results`) are
blocked from YAML — the executor handles them internally.

---

## Section types

### `summary` — KPI tiles

```yaml
- id: kpis
  title: Summary
  type: summary
  data_source: my_ds
  metrics:
    - label: Total sessions
      value_field: session_count    # SQL alias
      aggregation: sum              # count | sum | max | min
      format: number                # number | bytes | duration
    - label: Unique hosts
      value_field: orig_h
      aggregation: count            # counts non-null values
      format: number
    - label: Largest transfer
      value_field: bytes_out
      aggregation: max
      format: bytes
```

### `table` — sortable data table

```yaml
- id: detail
  title: Recent events
  type: table
  data_source: my_ds
  columns:
    - field: timestamp
      label: Time
      format: timestamp
    - field: orig_h
      label: Source IP
      format: ip
    - field: bytes_out
      label: Bytes
      format: bytes
  row_limit: 100
  empty_message: No events in this window.
```

Format types render as: `text` (sans, truncate at 80), `ip`/`hash` (mono),
`number` (locale-grouped), `bytes` (`1.2 MB`), `duration` (`2h 14m`),
`timestamp` (`2026-03-06 14:32 UTC`), `percent` (`42.3%`).

### `chart` — pie or sankey (HTML only)

```yaml
# Pie
- id: proto_pie
  title: Sessions by protocol
  type: chart
  chart_type: pie
  data_source: my_ds
  label_field: protocol     # SQL alias for slice label
  value_field: session_count
  empty_message: No data in this window.

# Sankey (zone-to-zone, src→dst flows)
- id: flow
  title: Subnet to subnet
  type: chart
  chart_type: sankey
  data_source: flow_ds
  label_field: src_subnet
  dst_field: dst_subnet
  value_field: total_bytes
  empty_message: No internal-to-internal sessions in this window.
```

In `--format markdown`, pie charts fall back to a Mermaid `pie` block plus a
bullet list. Sankey charts fall back to a top-20 flows table.

---

## Parameters and Jinja

Parameters are Jinja2 variables in any `query` field and in `output.title_template`.

```yaml
parameters:
  - name: hours
    type: int
    default: 24
  - name: src_ip
    type: str
    default: ""
```

In SQL, **always cast int parameters explicitly** to prevent injection:

```sql
WHERE timestamp BETWEEN date_add('hour', -{{ hours | int }}, now()) AND now()
{% if src_ip %}AND id.orig_h = '{{ src_ip }}'{% endif %}
```

The Jinja environment is sandboxed (`SandboxedEnvironment`) — no file access,
no class traversal. Standard filters (`| int`, `| string`, `| default`,
`| lower`) are available.

`output.title_template` receives all report parameters plus `name`, `id`,
`category`, and `now` (a `datetime`).

---

## Cookbook

### Pattern A — single aggregate query (most common)

See `definitions/c2_beacon_report.yaml`.

### Pattern B — pie chart over the same query

See `definitions/active_connections.yaml` (`proto_pie` section).

### Pattern C — multiple parallel queries

See `definitions/daily_threat_summary.yaml`. All queries fire at once.

### Pattern D — REST + investigation combined

See [examples in CONTRIBUTING.md of the original MCP repo].

```yaml
data_sources:
  - id: detections
    type: vectra_rest
    client_method: get_detections
    arguments: { page: "1", page_size: "50", state: "active" }
  - id: sessions
    type: investigation_query
    query: |
      SELECT COUNT(*) AS sessions FROM network.isession._all
      WHERE timestamp BETWEEN date_add('hour', -1, now()) AND now()
```

### Pattern E — optional filter

```yaml
parameters:
  - name: src_ip
    type: str
    default: ""

data_sources:
  - id: events
    type: investigation_query
    query: |
      SELECT timestamp, id.orig_h AS src, COUNT(*) AS cnt
      FROM network.isession._all
      WHERE timestamp BETWEEN date_add('hour', -1, now()) AND now()
        {% if src_ip %}AND id.orig_h = '{{ src_ip }}'{% endif %}
      GROUP BY timestamp, id.orig_h
```

---

## Pull request checklist

- [ ] `id` is unique snake_case across all files in `definitions/`
- [ ] `python scripts/validate.py` exits zero
- [ ] SQL uses `timestamp` (not `ts`) and `._all` table suffixes
- [ ] WHERE/ORDER BY use dot-notation for 5-tuple fields (`id.orig_h`)
- [ ] `pagination.enabled: false` for aggregate queries
- [ ] Each `summary` has at least one `metric`; each `table` has at least one `column`
- [ ] `empty_message` set on `table` and `chart` sections
- [ ] Description is one paragraph: what + when
- [ ] Tested live (even `--hours 1`) to confirm no 400 errors

# Vectra Investigation Query SQL — Field Guide

Hard-won rules from running queries against the live Vectra Data API.
Violations cause silent wrong results or `400 Bad Request`.

For full table column listings, consult the schema docs in your tenant's
documentation (or the `resources/schemas/` folder of the original MCP repo).

---

## Tables — always use the `._all` suffix

```sql
network.isession._all      network.beacon._all      network.dns._all
network.http._all          network.ssl._all         network.x509._all
network.kerberos._all      network.ldap._all        network.ntlm._all
network.smb_files._all     network.smb_mapping._all network.rdp._all
network.ssh._all           network.smtp._all        network.dhcp._all
network.dce_rpc._all       network.match._all       network.radius._all

entra.signins._all         entra.directoryaudits._all
m365.general._all          m365.exchange._all       m365.sharepoint._all
m365.active_directory._all
aws.cloudtrail._all        azurecp.operations._all
```

Omitting `._all` returns 400.

---

## 5-tuple field naming — CRITICAL

In `WHERE` and `ORDER BY`, the session 5-tuple **must** use dot-notation.
Flat names return 400.

```sql
-- CORRECT
WHERE id.orig_h = '10.1.2.3'
WHERE id.resp_h = '8.8.8.8' AND id.resp_p = 443
ORDER BY id.orig_h

-- WRONG — returns 400 Bad Request
WHERE orig_h = '10.1.2.3'
WHERE resp_h = '8.8.8.8'
```

Output columns come back **flat** (`orig_h`, `resp_h`) regardless of the WHERE
notation. So in the YAML `field:` of a table/chart section, use the **flat**
alias name (or use `AS` to rename in the SELECT).

---

## Timestamp field

The API uses `timestamp` (not `ts`, despite some Vectra docs):

```sql
-- CORRECT
WHERE timestamp BETWEEN date_add('hour', -24, now()) AND now()

-- WRONG
WHERE ts BETWEEN ...
```

---

## Time windows

```sql
-- Hours
WHERE timestamp BETWEEN date_add('hour', -{{ hours | int }}, now()) AND now()

-- Days
WHERE timestamp BETWEEN date_add('day', -{{ days | int }}, now()) AND now()

-- Fixed range
WHERE timestamp BETWEEN TIMESTAMP '2026-01-01' AND TIMESTAMP '2026-01-31'
```

For tables that have a partition column `dt`, **always** add a `dt` predicate
alongside `timestamp`. Without it the engine scans the full retention window:

```sql
WHERE dt > date_add('hour', -{{ hours | int }}, now())
  AND timestamp BETWEEN date_add('hour', -{{ hours | int }}, now()) AND now()
```

---

## Aggregation patterns

```sql
-- Count by group
SELECT proto_name, COUNT(*) AS cnt
FROM network.isession._all
WHERE timestamp BETWEEN date_add('day', -7, now()) AND now()
GROUP BY proto_name
ORDER BY cnt DESC

-- Top N pairs
SELECT id.orig_h AS src, id.resp_h AS dst, COUNT(*) AS flows
FROM network.isession._all
WHERE timestamp BETWEEN date_add('day', -1, now()) AND now()
GROUP BY id.orig_h, id.resp_h
ORDER BY flows DESC
LIMIT 50

-- UNION ALL (supported)
SELECT 'Client' AS role, COUNT(*) AS cnt
FROM network.isession._all
WHERE id.orig_h = '{{ host_ip }}'
  AND timestamp BETWEEN date_add('day', -1, now()) AND now()
UNION ALL
SELECT 'Server' AS role, COUNT(*) AS cnt
FROM network.isession._all
WHERE id.resp_h = '{{ host_ip }}'
  AND timestamp BETWEEN date_add('day', -1, now()) AND now()
```

---

## Pagination

For aggregate queries (GROUP BY / COUNT / SUM), one page is always enough —
set `pagination.enabled: false`. Only enable pagination when fetching raw
event rows that may exceed `page_size`.

When pagination is enabled, the executor fetches pages 2..N **in parallel**
once page 1 reports the total row count.

---

## Rate limit

The Investigation Query submit endpoint is documented at 5 req/min. The
skill's `_TokenBucket` enforces this with bursts allowed. With multiple
queries in one report:

| Sources | Old MCP server (sequential, strict 12s gate) | This skill (parallel + bucket) |
|---------|---------------------------------------------|--------------------------------|
| 1 | ~12 s gate + query time | ~1 s gate + query time |
| 3 | ~36 s gate + sum of query times | ~12 s burst + max query time |
| 5 | ~60 s gate + sum of query times | ~12 s burst + max query time |

The bucket then re-fills at 5 tokens / 60s, so very large reports still
respect the per-minute ceiling.

---

## Common mistakes that cost hours

1. **Flat field name in WHERE** — `WHERE orig_h = '...'` returns 400; must be `id.orig_h`.
2. **`ts` instead of `timestamp`** — silently returns nothing in some tables.
3. **Missing `._all` suffix** — `FROM network.dns` is invalid; use `FROM network.dns._all`.
4. **No `dt` predicate** — query scans full retention; can take minutes.
5. **`pagination.enabled: true` on a `GROUP BY`** — wastes API calls; aggregates fit in one page.
6. **Output column name mismatch** — section's `field:` must match the SQL alias exactly (e.g. `COUNT(*) AS cnt` → `field: cnt`).

# Query Construction Rules

Use these rules whenever you author Investigation Query SQL — both
in [`mode-ad-hoc.md`](mode-ad-hoc.md) (when no recipe matches) and
in [`mode-ti-hunt.md`](mode-ti-hunt.md) (when a TI artifact has no
direct recipe).

> Read [`table-gotchas.md`](table-gotchas.md) for per-table quirks
> *before* substituting the rules below into a real query.

---

## Time filtering (REQUIRED on every query)

**Hourly lookback (most tables):**
```sql
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
```

**Detection window (precise time range):**
```sql
WHERE dt >= DATE(FROM_ISO8601_TIMESTAMP('{start_time}'))
  AND timestamp BETWEEN FROM_ISO8601_TIMESTAMP('{start_time}')
                     AND FROM_ISO8601_TIMESTAMP('{end_time}')
```

**Day-level partitioning (Azure CP only):**
```sql
WHERE dt > date_add('day', -{days_back}, current_date)
```

---

## Host and entity filtering

- **By Vectra host entity ID (preferred):** `AND orig_hostname.id = {host_id}`
- **By source IP:** `AND id.orig_h = '{src_ip}'`
- **By destination IP:** `AND id.resp_h = '{dest_ip}'`
- **By destination port:** `AND id.resp_p = {port}`

---

## String matching

- **Substring (case-insensitive):** `AND CONTAINS(LOWER(field), LOWER('{value}'))`
- **Exact match:** `AND field = '{value}'`
- **Array search:** `AND ANY_MATCH(array_field, x -> CONTAINS(x, '{value}'))`

---

## Field notation rules

- 5-tuple fields MUST use dot notation in WHERE / ORDER BY:
  `id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`.
- Struct fields use dot notation: `certificate.subject`,
  `status.error_code`, `alert.severity`.
- Table names MUST use `._all` suffix: `network.dns._all`.
- Timestamp field is `timestamp`, NOT `ts` (with table-specific
  exceptions — see [`table-gotchas.md`](table-gotchas.md)).

---

## Result-size defaults

| Scenario | LIMIT |
|----------|-------|
| Targeted host query | 100–200 |
| Hunting sweep | 500 |
| Maximum allowed | 10000 |
| Max lookback | 336 hours (14 days) |

---

## Supported SQL functions

- **Aggregates:** COUNT, MAX, MIN, SUM, AVG, STDDEV, STDDEV_SAMP,
  STDDEV_POP
- **String:** LOWER, UPPER, LENGTH, ABS, CONCAT, CONTAINS, COALESCE
- **Time:** DATE, NOW, DATE_ADD, DATE_DIFF,
  FROM_ISO8601_TIMESTAMP, FROM_UNIXTIME, TO_UNIXTIME
- **Regex:** REGEXP_COUNT, REGEXP_EXTRACT_ALL, REGEXP_EXTRACT,
  REGEXP_LIKE, REGEXP_POSITION, REGEXP_REPLACE, REGEXP_SPLIT
- **Casting:** TRY_CAST, CAST
- **Arrays:** ANY_MATCH, ALL_MATCH, DISTINCT, ARRAY_AGG, CARDINALITY
- **Multi-table:** UNION ALL supported. JOIN is NOT supported.

---

## When no recipe matches

If you've scanned the relevant `references/<recipe-library>.md` and
nothing answers the user's question, **do not stop** — author the
query yourself:

1. Read the schema for the target table at
   `vectra://resources/schemas/<domain>/<table>.md`.
2. Pick the closest existing recipe as a structural template (it
   already has the correct table name, time filter, and field
   notation).
3. Adjust the `SELECT` columns, `WHERE` clauses, `GROUP BY`, and
   `ORDER BY` to fit the question, following the rules above.
4. Cross-check [`table-gotchas.md`](table-gotchas.md) for the table
   you're targeting — several tables have non-obvious quirks
   (timestamp field name, epoch-millisecond fields, missing
   `id`/`local_*` structs, JSON-string columns) that will silently
   produce empty results if you assume the standard shape.
5. Run via `run_investigation` and iterate if the result set
   is too narrow / too noisy.

The recipes are seeds, not a fence — Vectra Investigation Query SQL
supports much more than what's enumerated here.

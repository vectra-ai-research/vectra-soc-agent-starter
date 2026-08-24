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

- **Substring (case-insensitive):** `AND LOWER(field) LIKE LOWER('%{value}%')`
- **Exact match:** `AND field = '{value}'`
- **Array membership:** `AND CONTAINS(array_field, '{value}')`
- **Array, case-insensitive:** `AND ANY_MATCH(array_field, a -> UPPER(a) = UPPER('{value}'))`
- **Array, substring:** `AND ANY_MATCH(array_field, a -> LOWER(a) LIKE LOWER('%{value}%'))`

> **`CONTAINS` is an array function, not a string function.** Its only valid
> forms are `CONTAINS(array, element)` and `CONTAINS('<cidr>', TRY_CAST(ip AS
> IPADDRESS))`. There is no two-string signature, so
> `CONTAINS(LOWER(field), LOWER('x'))` fails with `FUNCTION_NOT_FOUND` — and
> because `LOWER`/`UPPER`/`TRIM` return varchar, wrapping an array in one of
> them breaks the array form too. Use `LIKE`, `STRPOS(...) > 0`, or
> `REGEXP_LIKE(field, '(?i)value')` for text; `ANY_MATCH` for arrays.
>
> This file previously documented the two-string form, and 45 recipe call sites
> copied it. `skills/scripts/validate_recipes.py` now catches it.

---

## Field notation rules

- 5-tuple fields MUST use dot notation in WHERE / ORDER BY:
  `id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p`.
- Struct fields use dot notation: `certificate.subject`,
  `status.error_code`, `alert.severity`.
- Table names: `._all` suffix is optional — bare names (`network.dns`)
  and `._all`-suffixed names (`network.dns._all`) are equivalent
  (confirmed live). The recipes below keep the `._all` suffix for
  clarity, but you don't need to add it when writing new queries.
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

## Rate limit (REQUIRED reading before batching queries)

**Hard limit: 5 `run_investigation` submissions per minute.** This
is an API-enforced ceiling, not a soft guideline — submitting more
than 5 in a parallel batch will trip `429 Too Many Requests` on the
excess calls. When a hunt needs more than ~4 queries, submit them
sequentially with a short pause between batches rather than firing
them all in parallel.

---

## Supported SQL functions

- **Aggregates:** COUNT, MAX, MIN, SUM, AVG, STDDEV, STDDEV_SAMP,
  STDDEV_POP
- **String:** LOWER, UPPER, LENGTH, ABS, CONCAT, COALESCE,
  SUBSTR, REPLACE, REVERSE, SPLIT, SPLIT_PART, STRPOS, NULLIF, TRIM
  — **not** CONTAINS; see String matching above
- **Time:** DATE, NOW, DATE_ADD, DATE_DIFF,
  FROM_ISO8601_TIMESTAMP, FROM_UNIXTIME, TO_UNIXTIME
- **Regex:** REGEXP_COUNT, REGEXP_EXTRACT_ALL, REGEXP_EXTRACT,
  REGEXP_LIKE, REGEXP_POSITION, REGEXP_REPLACE, REGEXP_SPLIT
- **Casting:** TRY_CAST, CAST
- **Conditional:** CASE WHEN
- **Arrays:** CONTAINS, ANY_MATCH, ALL_MATCH, DISTINCT, ARRAY_AGG, CARDINALITY
- **Aggregation extras:** COUNT(DISTINCT ...), APPROX_DISTINCT,
  APPROX_PERCENTILE (use with GROUP BY / HAVING as needed)
- **JSON:** JSON_PARSE, JSON_ARRAY_LENGTH, JSON_ARRAY_CONTAINS
  (confirmed live). JSON_EXTRACT, JSON_EXTRACT_SCALAR, JSON_FORMAT,
  JSON_SIZE are documented as expected to work but not independently
  confirmed — verify with a small test query before relying on them
  in a hunt.
- **Multi-table:** `UNION` and `UNION ALL` supported across any
  tables (confirmed live, not just same-table pairs). Subqueries
  (`WHERE x IN (SELECT ...)`) are supported (confirmed live). `JOIN`
  is NOT supported — use `UNION`/subqueries instead.

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

# Table-specific Gotchas

Per-table quirks that will silently produce empty results — or wrong
results — if you assume the standard shape from
[`query-construction.md`](query-construction.md). Cross-check this
file before authoring SQL against any of these tables.

---

## Network tables

| Table | Gotcha |
|-------|--------|
| `network.beacon._all` | Uses `first_event_time`, **not** `timestamp`. `resp_domains` is ARRAY (use `ANY_MATCH`). `duration` is in **milliseconds**. |
| `network.x509._all` | `certificate.not_valid_after` is epoch **milliseconds**. `key_length` is STRING (cast before numeric compare). |
| `network.kerberos._all` | Uses `protocol` field, **not** `proto`. |
| `network.dhcp._all` | No `id` struct. `orig_hostname` is plain STRING. No `local_orig` / `local_resp`. |
| `network.match._all` | No `uid`. `alert.severity`: `1` = Critical, `2` = Major, `3` = Minor. |
| `network.radius._all` | `result` is STRING (e.g. `'Access-Accept'`). Schema unvalidated against live data — confirm field shapes before relying on them. |
| `network.smtp._all` | Schema unvalidated against live data — confirm field shapes before relying on them. |
| `network.ssh._all` | No `auth_success` / `auth_attempts` fields — infer from session shape instead. |

---

## Cloud / identity tables

| Table | Gotcha |
|-------|--------|
| `azurecp.operations._all` | Day-level `dt` only — use the day-level partitioning recipe in [`query-construction.md`](query-construction.md). `identity` / `properties` are JSON blobs. |
| `entra.*` | `_flat`-suffix fields are JSON strings — use `CONTAINS` rather than struct dot-notation. |
| `m365.*` | `user_id` = UPN. `_flat`-suffix fields are JSON strings — use `CONTAINS`. |
| `aws.cloudtrail._all` | `user_identity` is a struct. `vectra.entity.resolved_identity` is plain VARCHAR (use this when you want a single-string identity column). |

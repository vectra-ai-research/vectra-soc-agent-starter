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
| `network.smtp` | **Does not exist.** Confirmed live (`TABLE_NOT_FOUND`) — not in the current platform's `network.*` table list. Do not query it; use `m365.exchange` for email-based hunts instead. |
| `network.ssh._all` | No `auth_success` / `auth_attempts` fields — infer from session shape instead. |

---

## Cloud / identity tables

| Table | Gotcha |
|-------|--------|
| `azurecp.operations._all` | Day-level `dt` only — use the day-level partitioning recipe in [`query-construction.md`](query-construction.md). `identity` / `properties` are JSON blobs. |
| `entra.signins` | Has `status_flat`, `device_detail_flat`, `location_flat` — JSON strings, use `CONTAINS` rather than struct dot-notation on these. Field is `risk_level_during_sign_in` (with the underscore), not `risk_level_during_signin`. |
| `entra.directoryaudits` | Has `initiated_by_flat` only. **No** `target_resources_flat` — `target_resources` is an ARRAY of structs with no flat companion; use `ANY_MATCH`/dot-notation on a resolved element, not a `_flat` field (it doesn't exist and returns `COLUMN_NOT_FOUND`). |
| `m365.*` | `user_id` = UPN. Individual tables have their own `_flat`-suffix companion fields (e.g. `m365.exchange.item_flat`, `.parameters_flat`) — don't assume every struct field has one; check the schema reference per table before relying on `_flat`. |
| `aws.cloudtrail._all` | `user_identity` is a struct. `vectra.entity.resolved_identity` is **also a struct** — reference a leaf (`.user_name`, `.arn`, `.account_id`, …); `LOWER()` on the bare struct is `FUNCTION_NOT_FOUND`. Prefer `.user_name`, since `.arn` is often null on assumed-role events. Selecting the same leaf name from two structs (`user_identity.arn` and `…resolved_identity.arn`) collapses to one field in the result — alias both. |

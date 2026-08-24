# Cloud Investigation Recipes
Covers: AWS CloudTrail, Entra ID (Sign-ins + Directory Audits), M365, Azure CP

## AWS CloudTrail — `aws.cloudtrail._all`

**Key:** user_identity is a struct (.arn, .type, .account_id). `vectra.entity.resolved_identity` is **also a struct**, not a VARCHAR — leaves are `.arn`, `.user_name`, `.account_id`, `.principal_id`, `.identity_type`, `.canonical_name`, `.invoked_by`, `.aws_region`. `LOWER()` on the bare struct is a `FUNCTION_NOT_FOUND` (probed live 2026-08-24). Prefer `.user_name`: on assumed-role events `.arn` is frequently null while `.user_name` carries the human identity.

Two structs can share a leaf name, and **the result serialisation keys by leaf, so a duplicate silently overwrites**. `SELECT user_identity.arn, vectra.entity.resolved_identity.arn` returns one `arn` field, not two — the populated value can vanish behind the null. Alias both: `user_identity.arn AS user_arn, vectra.entity.resolved_identity.arn AS resolved_arn`. Aliases must be bare identifiers with no quotes.

error_code non-null = failed. `read_only` is stored as a lowercase **string** (`'true'`/`'false'`), not a boolean — always quote the value.

### 1. Principal CloudTrail Events
**When to use:** What did a compromised credential do?
```sql
SELECT timestamp, event_name, event_source,
       user_identity.arn AS user_arn, user_identity.type, user_identity.account_id,
       vectra.entity.resolved_identity.user_name AS resolved_user,
       source_ip_address, error_code, read_only, management_event, aws_region
FROM aws.cloudtrail._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (LOWER(user_identity.arn) LIKE LOWER('%{identity}%')
       OR LOWER(vectra.entity.resolved_identity.user_name) LIKE LOWER('%{identity}%'))
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Access Denied — Permission enumeration
**When to use:** error_code values: AccessDenied, UnauthorizedAccess, NoCredentialsError.
```sql
SELECT timestamp, event_name, event_source,
       user_identity.arn, user_identity.type,
       source_ip_address, error_code, management_event, aws_region
FROM aws.cloudtrail._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND error_code IS NOT NULL
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND LOWER(user_identity.arn) LIKE LOWER('%{identity}%')`
- `AND source_ip_address = '{src_ip}'`

### 3. Hunt by Event Name
**High-value:** GetSecretValue, CreateUser, CreateAccessKey, PutRolePolicy, AttachRolePolicy, AssumeRole, GetObject.
```sql
SELECT timestamp, event_name, event_source,
       user_identity.arn, user_identity.type, user_identity.account_id,
       source_ip_address, error_code, read_only, management_event, aws_region
FROM aws.cloudtrail._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(event_name) LIKE LOWER('%{event_name}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. Hunt from IP
```sql
SELECT timestamp, event_name, event_source,
       user_identity.arn, user_identity.type, user_identity.account_id,
       source_ip_address, error_code, read_only, management_event, aws_region
FROM aws.cloudtrail._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND source_ip_address = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 5. IAM Changes — Persistence/privilege escalation (default 168h)
```sql
SELECT timestamp, event_name, event_source,
       user_identity.arn, user_identity.type, user_identity.account_id,
       source_ip_address, error_code, aws_region
FROM aws.cloudtrail._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND event_source = 'iam.amazonaws.com' AND read_only = 'false'
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND LOWER(user_identity.arn) LIKE LOWER('%{identity}%')`

---

## Entra ID Sign-ins — `entra.signins._all`

**Key:** ip_address (not client_ip). status.error_code (0=success). risk_level_aggregated: none/low/medium/high. location: .city/.state/.country_or_region.

### 1. User Sign-ins (default 168h)
```sql
SELECT timestamp, user_principal_name, ip_address,
       app_display_name, client_app_used,
       status.error_code, status.failure_reason,
       location.city, location.state, location.country_or_region,
       risk_level_aggregated, risk_level_during_sign_in,
       device_detail.is_compliant, device_detail.is_managed,
       conditional_access_status
FROM entra.signins._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(user_principal_name) LIKE LOWER('%{upn}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Failed Sign-ins — Password spraying/brute force
```sql
SELECT timestamp, user_principal_name, ip_address,
       app_display_name, client_app_used,
       status.error_code, status.failure_reason,
       location.city, location.country_or_region
FROM entra.signins._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND status.error_code != 0
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND LOWER(user_principal_name) LIKE LOWER('%{upn}%')`
- `AND ip_address = '{src_ip}'`

### 3. Risky Sign-ins — Identity Protection anomalies
```sql
SELECT timestamp, user_principal_name, ip_address,
       app_display_name, client_app_used,
       status.error_code, status.failure_reason,
       location.city, location.country_or_region,
       risk_level_aggregated, risk_level_during_sign_in,
       conditional_access_status
FROM entra.signins._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (risk_level_aggregated = 'high' OR risk_level_aggregated = 'medium')
ORDER BY risk_level_aggregated DESC, timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND LOWER(user_principal_name) LIKE LOWER('%{upn}%')`

### 4. Sign-ins from Country
```sql
SELECT timestamp, user_principal_name, ip_address,
       app_display_name, client_app_used,
       status.error_code, status.failure_reason,
       location.city, location.state, location.country_or_region,
       risk_level_aggregated, conditional_access_status
FROM entra.signins._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND UPPER(location.country_or_region) LIKE UPPER('%{country}%')
ORDER BY timestamp DESC LIMIT {limit}
```

---

## Entra ID Directory Audits — `entra.directoryaudits._all`

**Key:** initiated_by.user.user_principal_name, initiated_by.app.display_name. `initiated_by_flat` is a JSON-string companion field. `target_resources` has **no** flat companion — it's an ARRAY of structs; use `ANY_MATCH`/dot-notation on a resolved element, not a `_flat` field (that field doesn't exist and will fail with `COLUMN_NOT_FOUND`).

### 1. User Directory Activity (default 168h)
```sql
SELECT timestamp, activity_display_name, category, operation_type,
       initiated_by.user.user_principal_name,
       initiated_by.app.display_name,
       target_resources, result
FROM entra.directoryaudits._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(initiated_by.user.user_principal_name) LIKE LOWER('%{upn}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Privileged Role Changes
```sql
SELECT timestamp, activity_display_name, category, operation_type,
       initiated_by.user.user_principal_name,
       initiated_by.app.display_name,
       target_resources, result
FROM entra.directoryaudits._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (category = 'RoleManagement'
       OR UPPER(activity_display_name) LIKE '%ROLE%'
       OR UPPER(activity_display_name) LIKE '%ADMIN%')
ORDER BY timestamp DESC LIMIT {limit}
```

---

## M365 SharePoint — `m365.sharepoint._all`

### 1. User SharePoint Activity (default 168h)
```sql
SELECT timestamp, user_id, operation, workload,
       source_file_name, site_url, sharing_type, target_user_or_group_type
FROM m365.sharepoint._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(user_id) LIKE LOWER('%{user_id}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Bulk File Downloads (operation = 'FileDownloaded')
```sql
SELECT timestamp, user_id, operation, workload, source_file_name, site_url
FROM m365.sharepoint._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND operation = 'FileDownloaded'
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND LOWER(user_id) LIKE LOWER('%{user_id}%')`

### 3. External Sharing
```sql
SELECT timestamp, user_id, operation, workload,
       source_file_name, site_url, sharing_type, target_user_or_group_type
FROM m365.sharepoint._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (operation = 'SharingInvitationCreated' OR operation = 'AnonymousLinkCreated'
       OR operation = 'AddedToSecureLink' OR CONTAINS(operation, 'Sharing'))
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND LOWER(user_id) LIKE LOWER('%{user_id}%')`

## M365 Exchange — `m365.exchange._all`

### 1. User Exchange Activity (default 168h)
```sql
SELECT timestamp, user_id, mailbox_owner_upn, operation,
       logon_type, external_access, item_flat, parameters_flat
FROM m365.exchange._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (LOWER(user_id) LIKE LOWER('%{user_id}%')
       OR LOWER(mailbox_owner_upn) LIKE LOWER('%{user_id}%'))
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Mailbox Forwarding Rules — Email exfiltration
```sql
SELECT timestamp, user_id, mailbox_owner_upn, operation,
       logon_type, external_access, parameters_flat
FROM m365.exchange._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (operation = 'New-InboxRule' OR operation = 'Set-InboxRule'
       OR operation = 'UpdateInboxRules'
       OR UPPER(parameters_flat) LIKE '%FORWARDTO%'
       OR UPPER(parameters_flat) LIKE '%REDIRECTTO%')
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND LOWER(user_id) LIKE LOWER('%{user_id}%')`

## M365 General — `m365.general._all`

### 1. User General M365 Activity — Teams, Power Automate, Copilot (default 168h)
```sql
SELECT timestamp, user_id, operation, workload,
       team_name, flow_connector_names, copilot_event_data
FROM m365.general._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(user_id) LIKE LOWER('%{user_id}%')
ORDER BY timestamp DESC LIMIT {limit}
```

## M365 Active Directory — `m365.active_directory._all`

### 1. User AAD Activity — Auth, MFA, device registration (default 168h)
```sql
SELECT timestamp, user_id, operation, actor_ip_address,
       error_number, logon_error, device_properties_flat
FROM m365.active_directory._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(user_id) LIKE LOWER('%{user_id}%')
ORDER BY timestamp DESC LIMIT {limit}
```

---

## Azure Control Plane — `azurecp.operations._all`

**Important:** Day-level dt (use date_add('day', -N, current_date)). identity/properties are JSON blobs. resulttype: Success/Failure/Start (not "Failed").

### 1. Actor Azure Operations
```sql
SELECT timestamp, operationname, actor.name, actor.objectid,
       resulttype, calleripaddress, resourceid,
       rolename, rolescope, applicationname
FROM azurecp.operations._all
WHERE dt > date_add('day', -{days_back}, current_date)
  AND (LOWER(actor.name) LIKE LOWER('%{actor}%')
       OR LOWER(actor.objectid) LIKE LOWER('%{actor}%'))
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Failed Azure Operations
```sql
SELECT timestamp, operationname, actor.name, actor.objectid,
       resulttype, calleripaddress, resourceid, applicationname
FROM azurecp.operations._all
WHERE dt > date_add('day', -{days_back}, current_date)
  AND resulttype = 'Failed'
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND LOWER(actor.name) LIKE LOWER('%{actor}%')`
- `AND calleripaddress = '{src_ip}'`

### 3. Hunt by Operation
**High-value:** roleAssignments/write, roleAssignments/delete, virtualMachines/delete, storageAccounts/write, vaults/secrets/get, networkSecurityGroups/write.
```sql
SELECT timestamp, operationname, actor.name, actor.objectid,
       resulttype, calleripaddress, resourceid,
       rolename, rolescope, applicationname
FROM azurecp.operations._all
WHERE dt > date_add('day', -{days_back}, current_date)
  AND LOWER(operationname) LIKE LOWER('%{operation}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. Hunt from IP
```sql
SELECT timestamp, operationname, actor.name, actor.objectid,
       resulttype, calleripaddress, resourceid,
       rolename, rolescope, applicationname
FROM azurecp.operations._all
WHERE dt > date_add('day', -{days_back}, current_date)
  AND calleripaddress = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 5. Role Assignment Changes — Azure RBAC persistence
```sql
SELECT timestamp, operationname, actor.name, actor.objectid,
       resulttype, calleripaddress, resourceid,
       rolename, rolescope, applicationname
FROM azurecp.operations._all
WHERE dt > date_add('day', -{days_back}, current_date)
  AND (LOWER(operationname) LIKE '%roleassignments/write%'
       OR LOWER(operationname) LIKE '%roleassignments/delete%')
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND LOWER(actor.name) LIKE LOWER('%{actor}%')`

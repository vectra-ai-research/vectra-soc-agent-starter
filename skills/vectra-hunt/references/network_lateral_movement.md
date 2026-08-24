# Lateral Movement Investigation Recipes
Covers: SMB, Kerberos, NTLM, LDAP, RDP, DCE-RPC

### 1. Host Share Connections
**When to use:** What file shares is this host accessing?
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       username, path, service, version, uid
FROM network.smb_mapping._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Admin Share Access — Lateral movement via PsExec/WMI
**When to use:** ADMIN$, C$, IPC$ = PsExec, WMI, service execution, relay attacks.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       username, path, service, version, uid
FROM network.smb_mapping._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (path LIKE '%ADMIN$%' OR path LIKE '%C$%' OR path LIKE '%IPC$%'
       OR UPPER(path) LIKE '%\\ADMIN$%' OR UPPER(path) LIKE '%\\C$%')
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

## SMB Files — `network.smb_files._all`
Schema: `vectra://resources/schemas/network/network.smb_files._all.md`

### 3. Host File Operations
**When to use:** See exactly which files an attacker accessed/modified.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       action, path, name, prev_name, delete_on_close, uid
FROM network.smb_files._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. File Writes/Deletes/Renames — Ransomware and payloads
**When to use:** Ransomware, payload drops, track covering. Actions: `SMB::WRITE`, `SMB::FILE_DELETE`, `SMB::FILE_RENAME`.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       action, path, name, prev_name, delete_on_close, uid
FROM network.smb_files._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (action = 'SMB::WRITE' OR action = 'SMB::FILE_DELETE' OR action = 'SMB::FILE_RENAME')
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

---

## Kerberos — `network.kerberos._all`

**Note:** Uses `protocol` field (not `proto`) for L4.

### 1. Host Kerberos Activity
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       request_type, client, service, success,
       rep_cipher, ticket_cipher, account_privilege, uid
FROM network.kerberos._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Kerberoasting — TGS with weak RC4 encryption
**When to use:** RC4/DES ticket ciphers = offline crackable service ticket hashes.
```sql
SELECT timestamp, id.orig_h, id.resp_h,
       request_type, client, service, success,
       rep_cipher, ticket_cipher, account_privilege, uid
FROM network.kerberos._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND request_type = 'TGS'
  AND (LOWER(ticket_cipher) LIKE '%rc4%' OR LOWER(ticket_cipher) LIKE '%des%')
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

### 3. Failed Kerberos — Brute force / password spraying
```sql
SELECT timestamp, id.orig_h, id.resp_h,
       request_type, client, service, success, rep_cipher, ticket_cipher, uid
FROM network.kerberos._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND success = false
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

### 4. Kerberos for User
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       request_type, client, service, success,
       rep_cipher, ticket_cipher, account_privilege, uid
FROM network.kerberos._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(client) LIKE LOWER('%{username}%')
ORDER BY timestamp DESC LIMIT {limit}
```

---

## NTLM — `network.ntlm._all`

### 1. Host NTLM Auth
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       username, hostname, domain, success, status, uid
FROM network.ntlm._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. NTLM Failures — Password spraying
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       username, hostname, domain, success, status, uid
FROM network.ntlm._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND success = false
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

### 3. NTLM for User — Track user authentication
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       username, hostname, domain, success, status, uid
FROM network.ntlm._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(username) LIKE LOWER('%{username}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. Pass-the-Hash Indicators — Successful NTLM for review
**When to use:** Hostname mismatch or rapid auths to multiple targets from one source.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       username, hostname, domain, success, status,
       orig_hostname.id AS src_host_id, uid
FROM network.ntlm._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND success = true
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

---

## LDAP — `network.ldap._all`

### 1. Host LDAP Queries
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       base_object, query_scope, query, result_count,
       bind_error_count, response_bytes, attributes, uid
FROM network.ldap._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. LDAP Reconnaissance — Large result sets (default min: 100)
```sql
SELECT timestamp, id.orig_h, id.resp_h,
       base_object, query_scope, query, result_count,
       response_bytes, attributes, uid
FROM network.ldap._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND result_count >= {min_result_count}
ORDER BY result_count DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

### 3. Hunt by Base Object — Specific OU queries
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       base_object, query_scope, query, result_count,
       response_bytes, attributes, uid
FROM network.ldap._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND UPPER(base_object) LIKE UPPER('%{base_object}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. Sensitive Attribute Requests — LAPS, SPN, passwords
**When to use:** Attackers request: ms-Mcs-AdmPwd, ServicePrincipalName, userPassword, unicodePwd, ntPwdHistory.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       base_object, query_scope, query, result_count,
       response_bytes, attributes, uid
FROM network.ldap._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND ANY_MATCH(attributes, a -> UPPER(a) IN (
        'MS-MCS-ADMPWD', 'SERVICEPRINCIPALNAME', 'USERPASSWORD',
        'UNICODEPWD', 'NTPWDHISTORY'))
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

---

## RDP — `network.rdp._all`

### 1. Host RDP Sessions
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       cookie, client_name, client_build, result, keyboard_layout, uid
FROM network.rdp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Internal RDP Lateral Movement (local_orig=true AND local_resp=true)
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       cookie, client_name, client_build, result, keyboard_layout,
       orig_hostname.id AS src_host_id, resp_hostname.id AS dst_host_id, uid
FROM network.rdp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND local_orig = true AND local_resp = true
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

### 3. Hunt by Client Name
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       cookie, client_name, client_build, result, keyboard_layout, uid
FROM network.rdp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND UPPER(client_name) LIKE UPPER('%{client_name}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. Unencrypted RDP — result != 'encrypted'
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       cookie, client_name, client_build, result, keyboard_layout, uid
FROM network.rdp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (result IS NULL OR result = '' OR result != 'encrypted')
ORDER BY timestamp DESC LIMIT {limit}
```

---

## DCE-RPC — `network.dce_rpc._all`

### 1. Host DCE-RPC Activity
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       endpoint, operation, username, rtt, uid
FROM network.dce_rpc._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Hunt by Endpoint
**Key endpoints:** svcctl (PsExec), drsuapi (DCSync), samr (enumeration), atsvc (scheduled tasks), wkssvc/srvsvc (recon), winreg (registry).
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       endpoint, operation, username, rtt, uid
FROM network.dce_rpc._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(endpoint) LIKE LOWER('%{endpoint}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 3. Hunt by Operation
**Key operations:** DsGetNCChanges (DCSync), CreateService/StartService, SamrLookupNamesInDomain, SchRpcRegisterTask, OpenSCManager.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       endpoint, operation, username, rtt, uid
FROM network.dce_rpc._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND LOWER(operation) LIKE LOWER('%{operation}%')
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. Lateral Movement RPC — svcctl + drsuapi + atsvc
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       endpoint, operation, username, rtt, uid
FROM network.dce_rpc._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (LOWER(endpoint) LIKE '%svcctl%'
       OR LOWER(endpoint) LIKE '%drsuapi%'
       OR LOWER(endpoint) LIKE '%atsvc%')
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

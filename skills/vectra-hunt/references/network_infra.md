# Network Infrastructure Investigation Recipes
Covers: SSH, SMTP, DHCP, RADIUS, Beacon, IDS Match

## SSH — `network.ssh._all`

**Note:** No auth_success or auth_attempts fields.

### 1. Host SSH Sessions
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       client, server, cipher_alg, mac_alg, kex_alg,
       hassh, hassh_server, host_key, uid
FROM network.ssh._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Inbound SSH — External to internal (local_resp=true, local_orig=false)
**When to use:** Internet-facing server targeted, backdoor, VPN bypass.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       client, server, cipher_alg, kex_alg,
       hassh, hassh_server, host_key, uid
FROM network.ssh._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND local_resp = true AND local_orig = false
  -- Optional: AND id.resp_h = '{dst_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 3. Hunt by HASSH — Known-bad SSH client (e.g. Impacket)
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       client, server, cipher_alg, kex_alg,
       hassh, hassh_server, host_key, uid
FROM network.ssh._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND hassh = '{hassh}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. Hunt by Cipher — Weak/unusual SSH ciphers (arcfour, 3des-cbc)
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       client, server, cipher_alg, mac_alg, kex_alg,
       hassh, hassh_server, uid
FROM network.ssh._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(LOWER(cipher_alg), LOWER('{cipher}'))
ORDER BY timestamp DESC LIMIT {limit}
```

---

## SMTP — `network.smtp._all`

**Warning:** Schema from PDF only, unvalidated.

### 1. Host SMTP Activity
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       mailfrom, rcptto, subject, helo, tls, fuids, uid
FROM network.smtp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Hunt by Sender
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       mailfrom, rcptto, subject, helo, tls, uid
FROM network.smtp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(LOWER(mailfrom), LOWER('{sender}'))
ORDER BY timestamp DESC LIMIT {limit}
```

### 3. Hunt by Recipient — Data exfiltration via email
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       mailfrom, rcptto, subject, helo, tls, uid
FROM network.smtp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(LOWER(rcptto), LOWER('{recipient}'))
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. Unencrypted SMTP (tls = false)
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       mailfrom, rcptto, subject, helo, tls, uid
FROM network.smtp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND tls = false
  -- Optional: AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

---

## DHCP — `network.dhcp._all`

**Important:** No id struct. orig_hostname is plain STRING. No local_orig/local_resp.

### 1. DHCP by Hostname — IP assignment history
```sql
SELECT timestamp, orig_hostname, assigned_ip, mac, server_addr, lease_time, uid
FROM network.dhcp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(UPPER(orig_hostname), UPPER('{hostname}'))
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. DHCP by IP — Who held this IP?
```sql
SELECT timestamp, orig_hostname, assigned_ip, mac, server_addr, lease_time, uid
FROM network.dhcp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND assigned_ip = '{ip_address}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 3. DHCP by MAC — Track physical device
```sql
SELECT timestamp, orig_hostname, assigned_ip, mac, server_addr, lease_time, uid
FROM network.dhcp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(LOWER(mac), LOWER('{mac_address}'))
ORDER BY timestamp DESC LIMIT {limit}
```

### 4. DHCP by Server — Audit/rogue DHCP
```sql
SELECT timestamp, orig_hostname, assigned_ip, mac, server_addr, lease_time, uid
FROM network.dhcp._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND server_addr = '{server_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

---

## RADIUS — `network.radius._all`

**Warning:** Schema from PDF only. result is STRING ('Access-Accept', 'Access-Reject').

### 1. Host RADIUS Auth
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       username, result, framed_ip_address,
       account_session_time, account_output_octets, account_input_octets, uid
FROM network.radius._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. RADIUS Failures (result = 'Access-Reject')
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       username, result, framed_ip_address, uid
FROM network.radius._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND result = 'Access-Reject'
  -- Optional: AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 3. RADIUS for User
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       username, result, framed_ip_address,
       account_session_time, account_output_octets, account_input_octets, uid
FROM network.radius._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(LOWER(username), LOWER('{username}'))
ORDER BY timestamp DESC LIMIT {limit}
```

---

## Beacon — `network.beacon._all`

**Important:** External destinations only. resp_domains is ARRAY. duration in MS. Uses first_event_time.

### 1. Host Beacons
```sql
SELECT first_event_time, last_event_time, id.orig_h, id.resp_h, id.resp_p,
       orig_hostname.id AS host_id, resp_domains,
       session_count, duration, ja3, beacon_uid
FROM network.beacon._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND first_event_time BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND orig_hostname.id = {host_id}
ORDER BY session_count DESC LIMIT {limit}
```

### 2. Hunt by Domain — Uses ANY_MATCH on array
```sql
SELECT first_event_time, last_event_time, id.orig_h, id.resp_h, id.resp_p,
       orig_hostname.id AS host_id, resp_domains,
       session_count, duration, ja3, beacon_uid
FROM network.beacon._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND first_event_time BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND ANY_MATCH(resp_domains, d -> CONTAINS(d, '{domain}'))
ORDER BY session_count DESC LIMIT {limit}
```

### 3. High-Frequency Beacons (default min: 50 sessions)
```sql
SELECT first_event_time, last_event_time, id.orig_h, id.resp_h, id.resp_p,
       orig_hostname.id AS host_id, resp_domains,
       session_count, duration, ja3, beacon_uid
FROM network.beacon._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND first_event_time BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND session_count >= {min_session_count}
ORDER BY session_count DESC LIMIT {limit}
```

### 4. Hunt by Destination IP
```sql
SELECT first_event_time, last_event_time, id.orig_h, id.resp_h, id.resp_p,
       orig_hostname.id AS host_id, resp_domains,
       session_count, duration, ja3, beacon_uid
FROM network.beacon._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND first_event_time BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.resp_h = '{dest_ip}'
ORDER BY session_count DESC LIMIT {limit}
```

---

## IDS Alerts (Match) — `network.match._all`

**Important:** No uid. alert.severity: 1=Critical, 2=Major, 3=Minor.

### 1. Host IDS Alerts
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       alert.signature, alert.signature_id, alert.severity,
       alert.category, app_proto
FROM network.match._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY alert.severity ASC, timestamp DESC LIMIT {limit}
```

### 2. Critical Alerts (severity <= 2)
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       alert.signature, alert.signature_id, alert.severity,
       alert.category, app_proto
FROM network.match._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND alert.severity <= 2
  -- Optional: AND id.orig_h = '{src_ip}'
ORDER BY alert.severity ASC, timestamp DESC LIMIT {limit}
```

### 3. Hunt by Signature (ET MALWARE, Cobalt Strike, etc.)
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       alert.signature, alert.signature_id, alert.severity,
       alert.category, app_proto
FROM network.match._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(UPPER(alert.signature), UPPER('{signature}'))
ORDER BY alert.severity ASC, timestamp DESC LIMIT {limit}
```

### 4. Hunt by Category
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       alert.signature, alert.signature_id, alert.severity,
       alert.category, app_proto
FROM network.match._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(UPPER(alert.category), UPPER('{category}'))
ORDER BY alert.severity ASC, timestamp DESC LIMIT {limit}
```

# SSL/TLS & X.509 Certificate Investigation Recipes

## SSL/TLS — `network.ssl._all`

Schema: `vectra://resources/schemas/network/network.ssl._all.md`

### 1. Host TLS Sessions — Encrypted channels for a host
**When to use:** Spot anomalous TLS clients via JA3/JA4.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       server_name, version, established, cipher,
       subject, issuer, ja3, ja4, uid
FROM network.ssl._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND orig_hostname.id = {host_id}
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Hunt by Server Name (SNI) — Who connected to a domain over TLS?
**When to use:** Find all hosts that connected to a suspicious domain.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       server_name, version, established, cipher,
       subject, issuer, orig_hostname.id AS host_id, ja3, ja4, uid
FROM network.ssl._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(server_name, '{server_name}')
ORDER BY timestamp DESC LIMIT {limit}
```

### 3. Hunt Weak TLS — Deprecated protocol versions
**When to use:** TLSv1.0/1.1 (POODLE, BEAST, DROWN). version_num: TLSv1.0=769, TLSv1.1=770, TLSv1.2=771, TLSv1.3=772.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       server_name, version, version_num, cipher,
       subject, issuer, orig_hostname.id AS host_id, uid
FROM network.ssl._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND version_num <= 770
  -- Optional: AND orig_hostname.id = {host_id}
ORDER BY version_num ASC, timestamp DESC LIMIT {limit}
```

### 4. Hunt by JA3 Fingerprint — Known-bad TLS client
**When to use:** JA3 identifies malware families. Hunt known-bad tooling.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       server_name, version, established, cipher,
       subject, issuer, orig_hostname.id AS host_id, ja3, ja4, uid
FROM network.ssl._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND ja3 = '{ja3_hash}'
ORDER BY timestamp DESC LIMIT {limit}
```

---

## X.509 Certificates — `network.x509._all`

Schema: `vectra://resources/schemas/network/network.x509._all.md`

**Important:** `certificate.not_valid_after` is epoch MILLISECONDS. `certificate.key_length` is STRING.

### 1. Host Certificates — Certs observed for a host's connections
**When to use:** Investigate certs seen on connections from a suspect host.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       certificate.subject, certificate.issuer,
       certificate.not_valid_before, certificate.not_valid_after,
       certificate.key_type, certificate.key_length,
       san.dns, basic_constraints.ca, ja4x, uid
FROM network.x509._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Self-Signed Certificates — C2 infrastructure indicator
**When to use:** Self-signed certs (subject=issuer) used by Cobalt Strike, Metasploit, malware C2.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       certificate.subject, certificate.issuer,
       certificate.not_valid_before, certificate.not_valid_after,
       certificate.key_type, san.dns, ja4x, uid
FROM network.x509._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND certificate.subject = certificate.issuer
  -- Optional: AND id.orig_h = '{src_ip}'
ORDER BY timestamp DESC LIMIT {limit}
```

### 3. Expiring Certificates — Certificate hygiene
**When to use:** Find certs expiring within N days. Expired certs included.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       certificate.subject, certificate.issuer,
       certificate.not_valid_before, certificate.not_valid_after,
       certificate.key_type, san.dns, ja4x, uid
FROM network.x509._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND certificate.not_valid_after <= (TO_UNIXTIME(now()) * 1000 + {days} * 86400000)
  AND certificate.not_valid_after IS NOT NULL
ORDER BY certificate.not_valid_after ASC LIMIT {limit}
```

### 4. Hunt by Certificate Subject — Suspicious CAs or subjects
**When to use:** Hunt certs with specific subject strings, country codes, known malware subjects.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       certificate.subject, certificate.issuer,
       certificate.not_valid_before, certificate.not_valid_after,
       certificate.key_type, certificate.key_length,
       san.dns, basic_constraints.ca, ja4x, uid
FROM network.x509._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND CONTAINS(UPPER(certificate.subject), UPPER('{subject}'))
ORDER BY timestamp DESC LIMIT {limit}
```

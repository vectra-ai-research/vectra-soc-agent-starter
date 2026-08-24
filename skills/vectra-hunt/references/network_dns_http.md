# DNS & HTTP Investigation Recipes

## DNS — `network.dns._all`

### 1. Host DNS Queries — What domains is this host resolving?
**When to use:** Pivot from detection, spot DGA domains or C2 beaconing.
```sql
SELECT timestamp, id.orig_h, query, qtype_name, rcode_name,
       answers, ttls, orig_hostname.id AS host_id, uid
FROM network.dns._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND orig_hostname.id = {host_id}
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Hunt by Domain — Blast radius for a malicious domain
**When to use:** Malicious domain identified. Find which hosts resolved it.
```sql
SELECT timestamp, id.orig_h, orig_hostname.id AS host_id,
       query, qtype_name, rcode_name, answers, ttls, uid
FROM network.dns._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND query LIKE '%{domain}%'
ORDER BY timestamp DESC LIMIT {limit}
```

### 3. NXDOMAIN Hunting — DGA malware indicator
**When to use:** High NXDOMAIN volumes = DGA malware probing for C2.
```sql
SELECT timestamp, id.orig_h, orig_hostname.id AS host_id,
       query, qtype_name, rcode_name, uid
FROM network.dns._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND rcode_name = 'NXDOMAIN'
ORDER BY timestamp DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND orig_hostname.id = {host_id}`

### 4. DNS Tunneling Indicators — Covert data channels
**When to use:** Long subdomain labels (data encoding) or TXT queries (tunneling channel). Default min_query_length: 50.
```sql
SELECT timestamp, id.orig_h, orig_hostname.id AS host_id,
       query, qtype_name, rcode_name, answers, uid
FROM network.dns._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND (LENGTH(query) >= {min_query_length} OR qtype_name = 'TXT')
ORDER BY LENGTH(query) DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND orig_hostname.id = {host_id}`

---

## HTTP — `network.http._all`

### 1. Host HTTP Activity — Web traffic for a host
**When to use:** Understand web resources a host is accessing.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       method, host, uri, status_code, user_agent,
       request_body_len, response_body_len, ja4h, uid
FROM network.http._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND orig_hostname.id = {host_id}
ORDER BY timestamp DESC LIMIT {limit}
```

### 2. Hunt by Host Header — Who accessed a specific web server?
**When to use:** Malicious web server identified. Find all internal hosts that connected.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       method, host, uri, status_code, user_agent,
       request_body_len, response_body_len,
       orig_hostname.id AS host_id, ja4h, uid
FROM network.http._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND host LIKE '%{http_host}%'
ORDER BY timestamp DESC LIMIT {limit}
```

### 3. Hunt POST Requests — Data exfiltration over HTTP
**When to use:** Large POST requests to external IPs = data exfiltration.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       method, host, uri, status_code, user_agent,
       request_body_len, response_body_len,
       orig_hostname.id AS host_id, ja4h, uid
FROM network.http._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND method = 'POST' AND request_body_len >= {min_body_bytes}
ORDER BY request_body_len DESC LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND orig_hostname.id = {host_id}`

### 4. Hunt by User-Agent — Suspicious HTTP clients
**When to use:** Hunt curl, PowerShell, Python, Cobalt Strike, Metasploit, wget.
```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       method, host, uri, status_code, user_agent,
       request_body_len, response_body_len,
       orig_hostname.id AS host_id, ja4h, uid
FROM network.http._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND user_agent LIKE '%{user_agent}%'
ORDER BY timestamp DESC LIMIT {limit}
```

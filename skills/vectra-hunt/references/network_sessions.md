# Network Sessions — `network.isession._all`

## 1. Host Sessions — What is this host doing?

**When to use:** Primary pivot from a detection. Understand a host's recent network activity.

```sql
SELECT timestamp, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
       proto_name, service, conn_state, duration,
       orig_ip_bytes, resp_ip_bytes, orig_pkts, resp_pkts,
       local_resp, resp_domain, application, ja4t, ja4ts, uid
FROM network.isession._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND orig_hostname.id = {host_id}
ORDER BY timestamp DESC
LIMIT {limit}
```

## 2. Traffic Summary — Top outbound flows by volume

**When to use:** Spot large uploads, unexpected cloud sync, exfiltration. Ordered by `orig_ip_bytes` DESC.

```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       proto_name, service, conn_state,
       orig_ip_bytes, resp_ip_bytes, orig_pkts, resp_pkts,
       local_resp, resp_domain, resp_hostname.name, application, uid
FROM network.isession._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND orig_hostname.id = {host_id}
ORDER BY orig_ip_bytes DESC
LIMIT {limit}
```

## 3. Large Outbound Transfers — Exfiltration hunting

**When to use:** Environment-wide exfiltration sweep. Internal hosts sending large volumes to external IPs. Default `min_bytes`: 10000000 (10 MB).

```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       proto_name, service, conn_state,
       orig_ip_bytes, resp_ip_bytes, resp_domain, application,
       orig_hostname.id, orig_hostname.name, uid
FROM network.isession._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND local_orig = true AND local_resp = false
  AND orig_ip_bytes > {min_bytes}
ORDER BY orig_ip_bytes DESC
LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND id.orig_h = '{src_ip}'`

## 4. Failed Connections — Scanning and C2 indicators

**When to use:** Port scanning, lateral movement probing, C2 beaconing to unreachable infra.
- **S0** = SYN sent, no response. High volume to many dests = horizontal scan.
- **REJ** = RST received. High volume to single host = vertical port scan.

```sql
SELECT timestamp, id.orig_h, id.resp_h, id.resp_p,
       proto_name, service, conn_state,
       orig_hostname.id, orig_hostname.name, uid
FROM network.isession._all
WHERE dt > date_add('hour', -{hours_back}, now())
  AND timestamp BETWEEN date_add('hour', -{hours_back}, now()) AND now()
  AND local_orig = true
  AND conn_state IN ('S0', 'REJ')
ORDER BY timestamp DESC
LIMIT {limit}
```

**Optional filters** — add inside the `WHERE` clause as needed:

- `AND orig_hostname.id = {host_id}`
- `AND id.orig_h = '{src_ip}'`

## 5. Detection Window Sessions — Bridge detection to network evidence

**When to use:** Highest-value pivot. After get_detection_details (first_timestamp, last_timestamp, host entity ID), retrieve all sessions in that exact window.

```sql
SELECT timestamp, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
       proto_name, service, conn_state, duration,
       orig_ip_bytes, resp_ip_bytes, orig_pkts, resp_pkts,
       local_resp, resp_domain, application,
       ja4t, ja4ts, ja4lc, ja4ls,
       first_orig_resp_data_pkt, first_resp_orig_data_pkt, uid
FROM network.isession._all
WHERE dt >= DATE(FROM_ISO8601_TIMESTAMP('{start_time}'))
  AND timestamp BETWEEN FROM_ISO8601_TIMESTAMP('{start_time}')
                     AND FROM_ISO8601_TIMESTAMP('{end_time}')
  AND orig_hostname.id = {host_id}
ORDER BY timestamp ASC
LIMIT {limit}
```
JA4 fingerprints and first-packet payloads (base64-encoded) support C2 fingerprinting.

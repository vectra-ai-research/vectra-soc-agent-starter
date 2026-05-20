# tshark Query Corpus — Vectra Detection PCAPs

Practical `tshark` filters and commands grouped by ATT&CK-aligned
investigation goals, suited to the *narrow* per-detection PCAPs that
Vectra hands out (typically 5-tuple-scoped to the alert window). Use
this file as a copy/paste corpus during triage, in tandem with the
single-pass `scripts/pcap-context.sh` helper.

For broader narrative on filters, recovery, and field-name variance,
see [`tshark-usage.md`](tshark-usage.md).

## Preflight and field validation

1. Validate `tshark` version and build info.

```bash
tshark -v
```

Confirm dissector behavior for your installed version before running
the deeper filters below.

2. Preserve evidence fingerprint before analysis.

```bash
sha256sum capture.pcap   # or:  shasum -a 256 capture.pcap
```

(`scripts/fetch-detection-pcap.sh` already prints this when it decodes
the MCP payload.)

3. Validate key DNS / SMB / RDP / HTTP fields.

```bash
tshark -G fields | grep -E "(dns\\.qry\\.name|smb2\\.cmd|tds|tpkt|http\\.request\\.uri)"
```

4. Validate identity / lateral-movement fields.

```bash
tshark -G fields | grep -E "(kerberos\\.|ldap\\.|dcerpc\\.|ntlmssp\\.|http\\.request\\.uri)"
```

5. Fast capture sanity check before deeper filtering.

```bash
tshark -r capture.pcap -q -z io,phs
```

Identifies the protocol mix and helps pick the right ATT&CK workflow
to start with.

## Command and control (TA0011) and beaconing detection

6. Count TLS Client Hello events per source host.

```bash
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.src | sort | uniq -c | sort -rn
```

Repeated periodic TLS initiation patterns from a single endpoint are
the textbook beacon signature.

7. Summarize repetitive destination pairs for potential beaconing.

```bash
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn | head -30
```

8. Inspect destination fan-out by suspect host.

```bash
tshark -r capture.pcap -Y "ip.src==10.10.10.25 && tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn
```

Distinguish broad scan behavior (high fan-out) from low-and-slow
beaconing (single repeating destination).

9. Identify long-lived conversations (possible C2 channels).

```bash
tshark -r capture.pcap -q -z conv,tcp
```

10. Extract TLS SNI values from client-hello traffic.

```bash
tshark -r capture.pcap -Y "tls.handshake.type == 1 && tls.handshake.extensions_server_name" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
```

11. Server certificate subjects / SANs (when handshake is captured).

```bash
tshark -r capture.pcap -Y "tls.handshake.type == 11" \
  -T fields -e ip.src -e ip.dst -e x509ce.subject -e x509ce.subjectAltName_element
```

## Discovery and suspicious DNS behavior (TA0007)

12. List DNS queries with response code.

```bash
tshark -r capture.pcap -Y "dns" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e dns.flags.response -e dns.qry.name -e dns.flags.rcode
```

13. Count queried domains by frequency.

```bash
tshark -r capture.pcap -Y "dns.flags.response == 0" \
  -T fields -e dns.qry.name | tr '[:upper:]' '[:lower:]' | sort | uniq -c | sort -rn | head -50
```

14. Flag high-entropy or long DNS labels (possible tunneling).

```bash
tshark -r capture.pcap -Y "dns.flags.response == 0 && dns.qry.name matches \"[A-Za-z0-9]{25,}\"" \
  -T fields -e frame.time -e ip.src -e dns.qry.name
```

15. Find TXT record lookups that may carry payload data.

```bash
tshark -r capture.pcap -Y "dns.flags.response == 0 && dns.qry.type == 16" \
  -T fields -e frame.time -e ip.src -e dns.qry.name
```

16. Track a single endpoint's DNS query spread.

```bash
tshark -r capture.pcap -Y "dns.flags.response == 0 && ip.src==10.10.10.25" \
  -T fields -e dns.qry.name | sort | uniq -c | sort -rn
```

## Lateral movement over SMB / RDP (TA0008)

17. Enumerate SMB2 command activity between hosts.

```bash
tshark -r capture.pcap -Y "smb2" \
  -T fields -e frame.time -e ip.src -e ip.dst -e smb2.cmd -e smb2.tree -e smb2.share_name
```

Watch for admin-share access (`ADMIN$`, `C$`, `IPC$`), file operations,
or remote service control.

18. Count SMB sessions by source and destination.

```bash
tshark -r capture.pcap -Y "tcp.port==445" \
  -T fields -e ip.src -e ip.dst | sort | uniq -c | sort -rn
```

19. Detect failed SMB authentication indicators.

```bash
tshark -r capture.pcap -Y "smb2 && smb2.nt_status" \
  -T fields -e frame.time -e ip.src -e ip.dst -e smb2.nt_status
```

20. Baseline probable RDP transport flows (TCP/3389).

```bash
tshark -r capture.pcap -Y "tcp.port==3389" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport
```

21. Detect long-lived RDP conversations.

```bash
tshark -r capture.pcap -q -z conv,tcp | grep 3389
```

## Credential access and domain control plane (TA0006)

22. Inspect Kerberos ticket operations.

```bash
tshark -r capture.pcap -Y "kerberos.msg_type" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e kerberos.msg_type -e kerberos.CNameString -e kerberos.SNameString
```

23. Count Kerberos failures (pre-auth and ticket issues).

```bash
tshark -r capture.pcap -Y "kerberos.error_code" \
  -T fields -e ip.src -e kerberos.error_code | sort | uniq -c | sort -rn
```

Spikes here can indicate password spraying, AS-REP roasting, or service
account misuse against the KDC.

24. Inspect LDAP bind and search behavior.

```bash
tshark -r capture.pcap -Y "ldap" \
  -T fields -e frame.time -e ip.src -e ip.dst -e ldap.messageID -e ldap.protocolOp
```

25. Baseline WinRM traffic for remote-admin abuse.

```bash
tshark -r capture.pcap -Y "tcp.port==5985 || tcp.port==5986" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport
```

26. Scope traffic touching domain controllers / identity tier.

```bash
tshark -r capture.pcap -Y "ip.addr==10.0.0.10 || ip.addr==10.0.0.11" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport
```

Keep the IP list scoped to what's already on the detection — don't
silently broaden.

## Collection and exfiltration over HTTP (TA0010 / TA0011)

27. Extract HTTP methods, host, URI, user agent.

```bash
tshark -r capture.pcap -Y "http.request.method" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e http.host -e http.request.method -e http.request.uri -e http.user_agent
```

28. Hunt large HTTP POST requests.

```bash
tshark -r capture.pcap -Y "http.request.method == \"POST\" && http.content_length > 500000" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e http.host -e http.request.uri -e http.content_length
```

29. List suspicious upload-like URI patterns.

```bash
tshark -r capture.pcap -Y "http.request.uri matches \"(upload|gate|submit|api/v[0-9]+/sync)\"" \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```

30. Count HTTP destinations contacted by one endpoint.

```bash
tshark -r capture.pcap -Y "http.request.method && ip.src==10.10.10.25" \
  -T fields -e http.host | tr '[:upper:]' '[:lower:]' | sort | uniq -c | sort -rn
```

31. Identify uncommon HTTP user agents.

```bash
tshark -r capture.pcap -Y "http.user_agent" \
  -T fields -e http.user_agent | sort | uniq -c | sort -rn | head -50
```

## Reconnaissance and brute-force indicators

32. Detect SYN-only patterns suggesting scanning.

```bash
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn
```

33. Count denied HTTP responses (401/403) by source.

```bash
tshark -r capture.pcap -Y "http.response.code == 401 || http.response.code == 403" \
  -T fields -e ip.src -e ip.dst -e http.response.code | sort | uniq -c | sort -rn
```

## Recovery

- **Missing dissector / field** — run the field-validation commands at
  the top of this corpus, then swap to available fields or port-based
  fallbacks (`tcp.port==445`, `tcp.port==3389`, `http.request.method`).
- **Malformed or unreadable capture** — confirm file type
  (`file capture.pcap`), parse with `capinfos`, and re-fetch through
  MCP if the original was truncated.
- **Empty results** — widen filters stepwise, validate traffic exists
  with `-z io,phs` and `-z conv,tcp`. Remember Vectra-attached PCAPs
  are scoped tightly to the alert; missing context may simply mean
  it's outside the capture window.
- **Missing Kerberos / LDAP fields** — fall back to port pivots
  (`tcp/udp 88`, `389`, `636`, `3268`, `3269`) and corroborate in
  EDR / IdP / SIEM.

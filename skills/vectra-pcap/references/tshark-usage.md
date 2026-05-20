# tshark Usage for Vectra Detection PCAPs

`tshark` (the Wireshark CLI) is the analysis side of this skill — once
the PCAP is on disk (via `scripts/fetch-detection-pcap.sh` or a manual
download), you read it locally with display filters and field exports.
This page is the cheat sheet of filters most often useful when working
a Vectra detection's capture; the structured one-shot triage lives in
`scripts/pcap-context.sh`.

## Prerequisites

- **`tshark`** — `apt install tshark` (Debian/Ubuntu) or
  `brew install wireshark` (macOS, ships the CLI).
- **`capinfos`** *(optional)* — useful to confirm the file isn't
  truncated (`capinfos capture.pcap`).
- **Evidence handling** — sha256 the capture before triage and keep the
  hash in case notes:

```bash
sha256sum capture.pcap
# or on macOS
shasum -a 256 capture.pcap
```

`scripts/fetch-detection-pcap.sh` already prints the hash when it
decodes the MCP payload — just paste it into the case note.

## Sanity preflight

Always run these first, before any deeper filter — they confirm the
file is parseable and tell you which protocols are even present in the
capture window.

```bash
tshark -v                                    # version + build info
tshark -r capture.pcap -q -z io,phs          # protocol hierarchy
tshark -r capture.pcap -c 5                  # first 5 frames — sanity check
tshark -G fields | grep -E "(dns\\.qry\\.name|smb2\\.cmd|http\\.request\\.uri|tls\\.handshake|kerberos\\.|ldap\\.|ntlmssp\\.|ssh\\.)"
```

If `io,phs` shows only TCP/UDP and no application-layer dissectors, the
capture is encrypted-only or the dissectors aren't loaded — you'll be
limited to 5-tuple and TLS fingerprint pivots.

## TLS pivots

TLS is the most common signal in modern detection captures.

```bash
# All TLS Client Hellos with full tuple + SNI + ALPN + cipher
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -E header=y \
  -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport \
  -e tls.handshake.version -e tls.handshake.ciphersuite \
  -e tls.handshake.extensions_server_name -e tls.handshake.extensions_alpn_str

# SNI distribution (top destinations a host is contacting over TLS)
tshark -r capture.pcap -Y "tls.handshake.type == 1 && tls.handshake.extensions_server_name" \
  -T fields -e tls.handshake.extensions_server_name | sort | uniq -c | sort -rn

# JA3 client fingerprints (always available — older fingerprint format)
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.src -e ip.dst -e tls.handshake.ja3 | sort | uniq -c | sort -rn

# Server certificates seen during the conversation
tshark -r capture.pcap -Y "tls.handshake.type == 11" \
  -T fields -e ip.src -e ip.dst -e x509ce.subject -e x509ce.subjectAltName_element
```

## Beaconing / C2 candidates

```bash
# Repeated TLS Client Hellos by source — periodic check-ins?
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.src | sort | uniq -c | sort -rn

# Repeated outbound SYNs to the same destination — heartbeat candidate
tshark -r capture.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn | head -30

# Long-lived TCP conversations — sustained C2 channel?
tshark -r capture.pcap -q -z conv,tcp
```

## DNS

```bash
# Queries with response codes
tshark -r capture.pcap -Y "dns" \
  -T fields -e frame.time -e ip.src -e ip.dst -e dns.flags.response \
  -e dns.qry.name -e dns.qry.type -e dns.flags.rcode

# Possible DNS tunneling — long, high-entropy labels
tshark -r capture.pcap -Y "dns.flags.response == 0 && dns.qry.name matches \"[A-Za-z0-9]{25,}\"" \
  -T fields -e frame.time -e ip.src -e dns.qry.name

# TXT lookups (common payload-carrying record type)
tshark -r capture.pcap -Y "dns.flags.response == 0 && dns.qry.type == 16" \
  -T fields -e frame.time -e ip.src -e dns.qry.name
```

## Lateral movement (SMB / RDP / WinRM)

```bash
# SMB2 commands — admin share / file ops / DCERPC over named-pipe
tshark -r capture.pcap -Y "smb2" \
  -T fields -e frame.time -e ip.src -e ip.dst -e smb2.cmd -e smb2.tree -e smb2.share_name

# SMB authentication failures (status codes)
tshark -r capture.pcap -Y "smb2 && smb2.nt_status" \
  -T fields -e frame.time -e ip.src -e ip.dst -e smb2.nt_status

# RDP transport baseline (TCP/3389)
tshark -r capture.pcap -Y "tcp.port==3389" \
  -T fields -e frame.time -e ip.src -e ip.dst

# WinRM (HTTP-based remote management)
tshark -r capture.pcap -Y "tcp.port==5985 || tcp.port==5986" \
  -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport
```

## Credential access (Kerberos / LDAP / NTLM)

```bash
# Kerberos — TGT / TGS / S4U flows, principal and service name
tshark -r capture.pcap -Y "kerberos.msg_type" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e kerberos.msg_type -e kerberos.CNameString -e kerberos.SNameString -e kerberos.realm

# Kerberos errors (KRB5KDC_ERR_*)
tshark -r capture.pcap -Y "kerberos.error_code" \
  -T fields -e ip.src -e kerberos.error_code | sort | uniq -c | sort -rn

# LDAP bind / search activity
tshark -r capture.pcap -Y "ldap" \
  -T fields -e frame.time -e ip.src -e ip.dst -e ldap.protocolOp

# NTLM auth (account, workstation, target)
tshark -r capture.pcap -Y "ntlmssp" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e ntlmssp.auth.username -e ntlmssp.auth.domain \
  -e ntlmssp.negotiate.callingworkstation -e ntlmssp.challenge.target_name
```

## HTTP exfiltration / staging indicators

```bash
# Large outbound POSTs
tshark -r capture.pcap -Y "http.request.method == \"POST\" && http.content_length > 500000" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e http.host -e http.request.uri -e http.content_length

# Suspicious URI patterns
tshark -r capture.pcap -Y "http.request.uri matches \"(upload|gate|submit|api/v[0-9]+/sync)\"" \
  -T fields -e frame.time -e ip.src -e http.host -e http.request.uri

# HTTP user-agent distribution (scripted clients tend to stand out)
tshark -r capture.pcap -Y "http.user_agent" \
  -T fields -e http.user_agent | sort | uniq -c | sort -rn | head -50

# HTTP basic / bearer auth (Authorization header present)
tshark -r capture.pcap -Y "http.authorization || http.authbasic" \
  -T fields -e frame.time -e ip.src -e ip.dst \
  -e http.host -e http.request.method -e http.request.uri -e http.user_agent
```

## Reconnaissance / brute force

```bash
# SYN scans — single source touching many destinations / ports
tshark -r capture.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -rn

# HTTP 401/403 waves
tshark -r capture.pcap -Y "http.response.code == 401 || http.response.code == 403" \
  -T fields -e ip.src -e ip.dst -e http.response.code | sort | uniq -c | sort -rn
```

## Field validation by version / plugin

`tshark` field names drift across versions. Run a preflight before
trusting a filter:

```bash
tshark -G fields | grep -E "(dns\\.qry\\.name|smb2\\.cmd|smb2\\.nt_status|http\\.request\\.uri|tls\\.handshake|kerberos\\.|ldap\\.|ntlmssp\\.|ssh\\.|dcerpc\\.)"
```

If a field is missing, fall back to:

- **SMB fields missing** — pivot via `tcp.port==445` conversations.
- **HTTP-specific fields missing** — pivot via `tcp.port==80` /
  `tcp.port==443` conversations.
- **Kerberos / LDAP fields missing** — pivot via UDP/TCP `88`,
  `389`, `636`, `3268`, `3269` and corroborate against EDR / IdP logs.

## JA4 (optional)

If a JA4 / JA4+ Wireshark plugin is installed, tshark may expose `ja4`
or `tls.ja4` as fields. The structured `pcap-context.sh` triage pulls
them automatically when present. Quick check:

```bash
tshark -G fields | grep -i ja4
tshark -r capture.pcap -Y "tls.handshake.type == 1" \
  -T fields -e frame.number -e ip.src -e ip.dst -e tls.ja4 -e ja4
```

JA4 is **not** required for this skill — the TLS section still emits
tuples, SNI, ALPN, JA3, and ciphers without the plugin.

## Recovery

- **Empty output** — confirm protocol presence with `-z io,phs`, then
  remove restrictive predicates one at a time.
- **Malformed capture** — `file capture.pcap` and `capinfos
  capture.pcap` will tell you whether the file is truncated; if so,
  re-fetch from Vectra (the original may have been replaced by a
  follow-up PCAP).
- **Missing dissector field** — see "Field validation" above; swap to
  port-based or 5-tuple pivots.
- **TLS 1.3 with no plaintext SNI** — Encrypted Client Hello (ECH) /
  ESNI hides the SNI; you're left with tuple, JA3, and ALPN as the
  fingerprint surface.

## References

- [tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Wireshark display filters](https://www.wireshark.org/docs/dfref/)
- [`query-corpus.md`](query-corpus.md) — ATT&CK-aligned filter library
- [`tshark-examples.json`](tshark-examples.json) — same content, machine-readable

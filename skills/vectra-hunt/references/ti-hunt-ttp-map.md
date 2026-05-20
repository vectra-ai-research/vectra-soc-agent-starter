# TTP & Tool → Recipe Map

Translate MITRE ATT&CK techniques and named tools / malware families
into the right recipe(s) in this skill's recipe library. Combine
recipes when a technique has multiple expressions in the network /
identity telemetry.

> Used by both modes:
> - **TI hunt** ([`mode-ti-hunt.md`](mode-ti-hunt.md)) — Phase 3
>   when mapping a report's TTPs and named tools to queries.
> - **Ad-hoc** ([`mode-ad-hoc.md`](mode-ad-hoc.md)) — when the user
>   names a single TTP or tool ("look for T1558.003", "are we seeing
>   Cobalt Strike?").

---

## MITRE ATT&CK technique → recipe

| Tactic / Technique | Recipe in `references/` |
|--------------------|-------------------------|
| `T1071.001` Application Layer Protocol — Web | [`network_dns_http.md`](network_dns_http.md) (HTTP host hunt), [`network_tls_certs.md`](network_tls_certs.md) (SNI hunt) |
| `T1071.004` Application Layer Protocol — DNS | [`network_dns_http.md`](network_dns_http.md) (DNS tunneling, NXDOMAIN/DGA) |
| `T1572` Protocol Tunneling | [`network_dns_http.md`](network_dns_http.md) (DNS tunneling) |
| `T1568.002` DGA | [`network_dns_http.md`](network_dns_http.md) (NXDOMAIN/DGA hunt) |
| `T1573` Encrypted Channel | [`network_tls_certs.md`](network_tls_certs.md) (weak TLS, JA3 hunt, self-signed certs) |
| `T1090` Proxy / `T1102` Web Service | [`network_dns_http.md`](network_dns_http.md), [`network_tls_certs.md`](network_tls_certs.md) (SNI / cert hunts) |
| `T1021.002` SMB / Admin Shares | [`network_lateral_movement.md`](network_lateral_movement.md) (admin share access) |
| `T1021.001` RDP | [`network_lateral_movement.md`](network_lateral_movement.md) (internal lateral movement RDP) |
| `T1021.004` SSH | [`network_infra.md`](network_infra.md) (HASSH / cipher hunt) |
| `T1558.003` Kerberoasting | [`network_lateral_movement.md`](network_lateral_movement.md) (RC4 TGS) |
| `T1110.003` Password Spraying | [`network_lateral_movement.md`](network_lateral_movement.md) (NTLM failures) |
| `T1550.002` Pass-the-Hash | [`network_lateral_movement.md`](network_lateral_movement.md) (NTLM Pass-the-Hash) |
| `T1087` Account Discovery / `T1018` Remote System Discovery | [`network_lateral_movement.md`](network_lateral_movement.md) (LDAP recon, DCE-RPC samr) |
| `T1003` OS Credential Dumping | [`network_lateral_movement.md`](network_lateral_movement.md) (DCE-RPC drsuapi / LSARPC) |
| `T1486` Data Encrypted for Impact (ransomware) | [`network_lateral_movement.md`](network_lateral_movement.md) (SMB writes/deletes/renames) |
| `T1567` Exfiltration Over Web Service | [`network_dns_http.md`](network_dns_http.md) (HTTP POST exfil), [`network_sessions.md`](network_sessions.md) (large transfers) |
| `T1071.002` File Transfer Protocols / SMTP | [`network_infra.md`](network_infra.md) (sender / unencrypted SMTP) |
| `T1078.004` Cloud Accounts | [`cloud_investigations.md`](cloud_investigations.md) (Entra signins, AWS CloudTrail, Azure ops) |
| `T1098.001` Additional Cloud Credentials | [`cloud_investigations.md`](cloud_investigations.md) (IAM changes, role assignments) |
| `T1114.003` Email Forwarding Rules | [`cloud_investigations.md`](cloud_investigations.md) (M365 Exchange forwarding) |

---

## Tools / malware → behaviors

| Tool / family | Hunt recipes |
|---------------|--------------|
| Cobalt Strike | JA3 hunt, default Beacon profile DNS / HTTP, named-pipe lateral movement (DCE-RPC) |
| Sliver | JA3 hunt, mTLS / WireGuard / DNS C2 |
| Mimikatz / DCSync | DCE-RPC drsuapi recipe |
| BloodHound / SharpHound | LDAP recon (large results, sensitive attrs) |
| Impacket (psexec, secretsdump, wmiexec) | SMB admin share + DCE-RPC svcctl / samr |
| AnyDesk / TeamViewer / ScreenConnect | HTTP user-agent + SNI hunt |
| Rclone / MEGAcmd | Large outbound transfers + HTTP host hunt |

---

## Coverage gaps (call these out in the report)

The map above is **best-effort** — a recipe miss does not prove the
technique is absent, only that the network / identity telemetry
Vectra collects shows no evidence. Common gaps to surface in the
final TI Hunt Report:

- **Host-side artifacts** (mutexes, registry keys, services,
  scheduled tasks, in-memory artifacts) — Vectra has no visibility;
  hand off to EDR.
- **File hashes** (MD5 / SHA1 / SHA256) — not stored; hand off to
  EDR / sandbox / TIP.
- **Process command lines** — only what surfaces in detection
  evidence; otherwise EDR.
- **Encrypted east-west traffic without a sensor on path** — no
  visibility regardless of the recipe.

# Progressive-Load Manifest — `vectra-hunt/references/`

This skill's `references/` tree is ~12 files / ~1.8K lines (mostly the
recipe libraries). **Hosts must not bundle / load all of them
up-front.** Use the table below to load only the references the
current task needs.

## Always loaded (when this skill activates)

The SKILL.md body and these two short files:

- `query-construction.md` — SQL rules the agent must follow when
  authoring or adapting any query (dot-notation, time filters,
  partition pruning, …).
- `table-gotchas.md` — per-table quirks (short).

## Per-mode load

| Mode | Required reference |
|------|--------------------|
| Mode 1 — Ad-hoc | `mode-ad-hoc.md` |
| Mode 2 — TI-driven hunt | `mode-ti-hunt.md`, `ti-hunt-ttp-map.md`, `ti-hunt-report-template.md` |

## Per-recipe-library load

Recipe libraries are large (90–330 lines each). Load **only the one**
matching the data domain the analyst is hunting in. Multiple libraries
in one task are allowed when the question genuinely spans domains
(e.g. DNS + TLS for a beacon hunt), but loading "all of them" is never
required.

| Hunting domain | Recipe library |
|----------------|----------------|
| Network sessions (flow shape, large transfers, failed connects) | `network_sessions.md` |
| DNS / HTTP | `network_dns_http.md` |
| TLS / X.509 certs | `network_tls_certs.md` |
| Lateral movement (SMB, Kerberos, NTLM, LDAP, RDP, DCE-RPC) | `network_lateral_movement.md` |
| Other network infra (SSH, SMTP, DHCP, RADIUS, beacons, IDS matches) | `network_infra.md` |
| Cloud + identity (AWS CloudTrail, Entra, M365, Azure CP) | `cloud_investigations.md` |

## Hosts: implementation note

If your agent host bundles every `references/*.md` file into one
context window when this skill activates, you are spending ~10× the
tokens this skill needs for any single hunt. The progressive-load
contract is **mandatory** — hosts that can't honor it should not ship
the full `references/` tree (ship only the recipe libraries the target
deployment needs).

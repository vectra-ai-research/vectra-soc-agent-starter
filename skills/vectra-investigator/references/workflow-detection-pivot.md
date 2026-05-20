# Workflow 3 — Single-Detection Pivot

**Goal:** the user has one detection ID and wants to know what to do.

> Read alongside [`mental-model.md`](mental-model.md) (kill-chain
> composition, multi-tenancy) and
> [`verdict-framework.md`](verdict-framework.md) (the rubric and
> write-up template).

> **Routing rule.** Every log / metadata pivot from this detection —
> sessions, DNS, HTTP, TLS, SMB, Kerberos, NTLM, LDAP, RDP, DCE-RPC,
> Entra sign-ins, M365 audit, AWS CloudTrail, Azure CP — goes through
> [`vectra-hunt`](../../vectra-hunt/SKILL.md) (ad-hoc Investigation
> Query SQL via the Vectra MCP server). Do **not** reach for
> [`vectra-reports`](../../vectra-reports/SKILL.md) /
> [`vectra-reports-mcp`](../../vectra-reports-mcp/SKILL.md) for
> detection pivots — those are dashboards, not investigation tools.

---

## Pipeline

1. **Drill in.** `get_detection_details(detection_id=<id>)` — capture
   `category`, `detection_type`, `host_id` / `account_id`,
   `first_timestamp`, `last_timestamp`, narrative summary, evidence
   blob.
2. **Get entity context.** `get_host_details` /
   `get_account_details` for the resolved entity. *Do not stop at one
   detection* — pull all open detections on that entity
   (`list_entity_detections(entity_id=<id>, state="active")`) so the
   verdict reflects the kill-chain, not just one data point.
3. **Open the matching playbook.** Use the category to pick the
   sibling `playbook-<category>.md` in this folder (catalogue:
   [`playbooks-overview.md`](playbooks-overview.md)). If no playbook
   exists yet for this category (C&C, Botnet, Cloud Initial Access),
   fall back to running detection-window pivots from
   [`vectra-hunt`](../../vectra-hunt/SKILL.md) (the
   `network_sessions.md` "Detection Window Sessions" recipe is a good
   starting point regardless of category).
4. **Pivot timestamp-narrow.** Use `first_timestamp` /
   `last_timestamp`, not "last 24h". Narrow windows surface evidence;
   wide windows drown it.

   ```sql
   WHERE timestamp BETWEEN FROM_ISO8601_TIMESTAMP('{first_timestamp}')
                       AND FROM_ISO8601_TIMESTAMP('{last_timestamp}')
     AND orig_hostname.id = {host_id}
   ```

5. **Verdict per detection, then roll up to per-entity** if the
   entity has other open detections. The per-entity verdict is what
   ships — see [`verdict-framework.md`](verdict-framework.md).

---

## When to fan out from a single detection

A single detection rarely tells the whole story. Fan out when **any**
of these are true:

- The entity has other open detections in the same or adjacent
  categories (Recon → LM, C&C → Exfil) → escalate into
  [`workflow-entity-deep-dive.md`](workflow-entity-deep-dive.md).
- The detection has a **network** category and you need the raw
  packets (TLS / SNI / JA3 / JA4, HTTP body, NTLM / Kerberos, SMB
  shares, DCE-RPC) → run
  [`workflow-pcap-triage.md`](workflow-pcap-triage.md).
- The detection surfaces an external observable (IP, domain, URL,
  hash) and you want reputation context →
  [`virustotal`](../../virustotal/SKILL.md). Reputation never
  overrides the behavioural verdict.
- The detection is identity-side (Suspicious Sign-On, Mail
  Forwarding, M365 Suspicious Download) → also pull the host(s) the
  identity touched in-window.

---

## Common pitfalls

- **Closing on the detection alone** — composition is the signal;
  pull the entity's full open set first.
- **Wide-window pivots** — use `first_timestamp` / `last_timestamp`,
  not "last 24h" or "last 7d".
- **Skipping the playbook** — if a sibling `playbook-<category>.md`
  matches the detection, use it; the per-detection verdict rubric in
  the playbook is more specific than the global rubric.

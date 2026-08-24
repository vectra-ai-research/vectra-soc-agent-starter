# Workflow 7 — Network PCAP Triage

**Goal:** the user has a Vectra **network** detection ID and wants
the underlying packets — TLS / SNI / JA3 / JA4, HTTP auth, NTLM /
Kerberos, SMB shares, DCE/RPC bindings, DNS, SSH,
`ProcessCommandLine`.

This workflow is owned end-to-end by
[`vectra-pcap`](../../vectra-pcap/SKILL.md). The orchestrator's job
is **confirm a PCAP exists, hand off, and feed the evidence back into
the verdict.**

---

## Pipeline

1. **Confirm the detection has a PCAP.** Cloud / log-based detections
   (M365, Entra / Azure AD, AWS CloudTrail, identity-only signals) do
   **not** carry a PCAP — route those back to
   [`workflow-detection-pivot.md`](workflow-detection-pivot.md) (which
   loads the matching cloud `playbook-<category>.md`). Use
   `get_detection_details` to check `category` / `detection_type` /
   `source` before pulling. The MCP `get_detection_pcap` tool returns
   406 for cloud / log-based detections.
2. **Hand off to `vectra-pcap`** — pull the capture via the MCP
   `get_detection_pcap` tool, which writes it to disk and returns the
   path (nothing to decode; never read the file into context), then run
   the structured
   `tshark` triage pass (TLS Client Hello tuples — SNI / JA3 /
   cipher / ALPN, JA4 when the plugin is available; HTTP auth;
   NTLM / Kerberos; SMB shares; RPC bindings; DNS history; SSH; any
   `ProcessCommandLine` strings).
3. **Feed evidence back into the verdict.** Treat PCAP findings (TLS
   tuples, JA3 / JA4, observed protocols, `ProcessCommandLine`) as
   **behavioral** evidence — the same rubric in
   [`verdict-framework.md`](verdict-framework.md) (BTP / TP-Low /
   TP-High / Need-more-data) applies. PCAP confirms or refutes the
   hypothesis the metadata started; it does not produce its own
   verdict.
4. **Optional pivots.**
   - Hand observable IOCs (TLS SNI, contacted IP, extracted file
     hash) to [`virustotal`](../../virustotal/SKILL.md) for
     reputation context — never let VT reputation override the
     behavioural verdict.
   - Use [`vectra-hunt`](../../vectra-hunt/SKILL.md) for east-west
     history beyond the alert window when the PCAP raises follow-up
     questions ("did the same SNI appear from other hosts?", "did
     this JA3 fingerprint show up earlier?").

---

## When NOT to use this workflow

- The detection is **cloud / log-based** (M365, Entra / Azure AD,
  AWS CloudTrail) — no PCAP exists. Route to
  [`workflow-detection-pivot.md`](workflow-detection-pivot.md) (which
  will load the matching cloud `playbook-<category>.md`) and pull
  cloud-side context via
  [`vectra-hunt/references/cloud_investigations.md`](../../vectra-hunt/references/cloud_investigations.md).
- The user just wants the **detection record** — that's a direct MCP
  lookup (`get_detection_details`), not a PCAP triage.
- The user wants east-west history without packet detail — that's an
  ad-hoc query, see
  [`workflow-ad-hoc-query.md`](workflow-ad-hoc-query.md).

---

## Common pitfalls

- **Forgetting the cloud-detection check** — calling
  `get_detection_pcap` on a cloud detection returns 406. Always
  confirm `category` / `source` first.
- **Treating PCAP findings as the only verdict input** — PCAP is
  *one* evidence source. Combine with detection metadata, entity
  context, and the kill-chain composition (see
  [`mental-model.md`](mental-model.md) §2) before landing a verdict.
- **Mistaking external IP reputation for verdict** — VT / threat
  intel corroborates, never overrides, behavioural evidence.

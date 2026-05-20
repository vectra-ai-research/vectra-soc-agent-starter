# Detection-category Playbooks — Overview

This file is the **decision-document layer** between a Vectra detection
and a verdict. It tells you: *given this detection / detection set on
this entity, what exactly is Vectra seeing, what benign baselines
explain it, what malicious indicators confirm it, and what verdict do I
land?*

> Read alongside [`verdict-framework.md`](verdict-framework.md) (the
> per-entity rubric every playbook rolls up to) and
> [`mental-model.md`](mental-model.md) §2 (entity-first triage,
> kill-chain composition).

The playbooks themselves live as `playbook-<category>.md` files
sibling to this one — this file is the index, the structural
template, and the how-to-use guidance.

---

## Available playbooks

| Playbook | Categories covered | Open when… |
|----------|--------------------|------------|
| [`playbook-exfiltration.md`](playbook-exfiltration.md) | Exfiltration, Exfil-adjacent C&C tunnels | Detection is "Smash and Grab" / "Data Smuggler" / "Hidden DNS Tunnel" / "Hidden HTTP/S Tunnel" / "Suspicious Cloud Storage Activity" / "M365 Suspicious Download" / "Mail Forwarding" / large outbound transfers |
| [`playbook-lateral-movement.md`](playbook-lateral-movement.md) | Lateral Movement, related Reconnaissance | Detection is "Suspicious Admin" / "Suspicious Remote Execution" / "Suspicious Remote Desktop" / "Kerberoasting" / "Brute-Force (Kerberos / NTLM / SMB / RDP)" / "Automated Replication" / "Ransomware File Activity" / "Privilege Anomaly" / "RPC Recon" / "Suspicious LDAP Query" / "SMB Account Scan" |

Coming next (placeholders — same six-section shape):

- `playbook-command-and-control.md` — C&C / beaconing / external
  remote access / threat-intel-match / suspect domain activity.
- `playbook-recon.md` — port-scan / port-sweep /
  internal-darknet-scan / file-share enumeration when they fire
  **without** a paired LM detection.
- `playbook-cloud-initial-access.md` — Suspicious Sign-On, Disabled
  Auditing, Unusual Permission Grant, identity-side kill-chain
  entry.
- `playbook-botnet.md` — Cryptocurrency Mining, Outbound Brute
  Force, Abnormal Ad Activity.

If a detection's category has **no playbook yet**, fall back to the
generic kill-chain framing in [`mental-model.md`](mental-model.md) and
use [`vectra-hunt`](../../vectra-hunt/SKILL.md) recipes directly for
evidence (the `network_sessions.md` "Detection Window Sessions"
recipe is a good starting point regardless of category).

---

## Playbook structure (every `playbook-*.md` follows this shape)

The same six-section template across every category file so the
analyst always knows where to look:

1. **What Vectra is detecting** — the behavioral signal and the
   questions the analyst must actually answer.
2. **Detection types in scope** — names you'll see in the queue,
   plus tightly-related categories (e.g. Recon detections that chain
   into Lateral Movement).
3. **Benign baselines** — what to rule out before calling TP, with
   how-to-confirm guidance. Every BTP must name one of these.
4. **Malicious indicators** — what flips the verdict to TP,
   stack-rankable so the analyst can combine signals.
5. **Pivot pipeline** — exact SQL recipes to run, in order, with the
   `vectra-hunt/references/<file>.md` recipe path. Per detection
   type.
6. **Verdict rubric** — per-detection-type matrix (BTP / TP-Low /
   TP-High / Need-more-data) plus a write-up template that rolls up
   to the global rubric in
   [`verdict-framework.md`](verdict-framework.md).

The playbooks are **decision documents, not narratives** — read
top-down, short-circuit at the first matching benign baseline or
malicious-indicator combo.

---

## How to use a playbook

1. **Identify the detection's category and type.** From
   `get_detection_details`, read `category` and `detection_type`.
2. **Open the matching `playbook-<category>.md`.** Match by detection
   type in its "Detection types in scope" table.
3. **Read top-down** — the six-section structure is the decision
   flow.
4. **Don't skip the benign-baseline check.** Most exfil / LM
   detections in a real enterprise are benign-true-positive; ruling
   out the named baselines is the actual triage work.
5. **Pivot via `vectra-hunt`** — every `Pivot pipeline` step names a
   recipe file and recipe number in
   [`vectra-hunt/references/`](../../vectra-hunt/references/). Copy
   the SQL, substitute `host_id` / `first_timestamp` /
   `last_timestamp` from the detection, and run it through the MCP
   server.
6. **(Optional, network detections only) Pull the PCAP via
   [`vectra-pcap`](../../vectra-pcap/SKILL.md).** When a metadata
   pivot leaves a question unanswered — was the SNI really
   `evil.tld`? what was in the HTTP body? did NTLM auth succeed? —
   fetch the per-detection capture with `get_detection_pcap` (MCP),
   decode it locally, and run the structured `tshark` triage.
   **Skip for cloud / log-based detections** (M365, Azure AD, AWS,
   Entra) — those have no underlying PCAP and the MCP tool returns
   406.
7. **Land a verdict** using the playbook's per-detection-type rubric,
   then roll up to the per-entity verdict using
   [`verdict-framework.md`](verdict-framework.md). Always:
   - Name the behavior + the pivot evidence.
   - Cite the kill-chain or benign-baseline match.
   - Record the disposition (assignment / triage rule / escalation).

---

## Key principle — entity rolls up, detection rolls in

Each playbook produces a **per-detection** verdict, but tier-1
dispositions are **per-entity**. A single Hidden HTTP/S Tunnel without
surrounding detections is a different verdict than the same tunnel
paired with Suspicious Admin and Kerberoasting on the same host. Read
the entity's **full open-detection set**
(`list_entity_detections(entity_id=<id>, state="active")`) before
finalizing — kill-chain composition is the actual signal.

The playbooks tell you how to triage one detection.
[`workflow-queue-triage.md`](workflow-queue-triage.md) and
[`workflow-entity-deep-dive.md`](workflow-entity-deep-dive.md) tell
you how to roll those into an entity verdict.

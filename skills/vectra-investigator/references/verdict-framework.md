# Verdict Framework

Every workflow under [`vectra-investigator/SKILL.md`](../SKILL.md) ends in
a **verdict**, not a narration. This file is the rubric and the
write-up template — load it whenever you're closing out a triage step,
an entity deep-dive, a single-detection pivot, or a TI-hunt hit.

---

## The four outcomes

A tier-1 verdict has exactly four outcomes — pick one and name it
explicitly:

| Verdict | Means | Action |
|---------|-------|--------|
| **TP-High** (true positive, escalate) | Real malicious behavior, kill-chain visible, sensitive entity | Escalate to tier 2 / IR; assign; suggest containment (isolate host, disable account); preserve evidence |
| **TP-Low** (true positive, contain locally) | Real but limited — single low-threat detection, low-value asset, no chain | Document; assign owner; monitor; don't escalate |
| **BTP** (benign true positive) | Detection fired correctly on a real event that is **not malicious** in this environment (admin tool, scanner, backup) | Document the baseline; recommend a **triage rule** to scope future suppressions narrowly (per host / per service / per dst — never blanket) |
| **Need more data** (NMD) | Insufficient signal, evidence is ambiguous | Run additional pivots; defer; do not close |

> **Reminder.** Every actual containment / suppression action
> (isolate, disable, dismiss, mute, write the triage rule) is
> human-in-the-loop per [`../../../AGENTS.md`](../../../AGENTS.md) §7.
> The agent **proposes**, the analyst **executes**.

---

## What every verdict must include

Always write the verdict with three things:

1. **The behavior observed** — what Vectra saw + your pivot evidence
   (cite the recipe / MCP call / time window / key fields).
2. **The reasoning** — benign-baseline match? kill-chain match?
   entity context (tags, groups, key-asset)?
3. **The disposition** — assignment, recommended triage rule,
   escalation note.

Never close as "BTP" without **naming the benign baseline** (which
tool, scanner, backup agent, user, change window). "Looked benign" is
not a verdict.

---

## Composition matters — verdict the entity, not each detection

A tier-1 verdict is most useful at the **entity** level, even when
each detection has its own per-detection rubric in
[`playbook-<category>.md`](playbooks-overview.md) (sibling reference).

Example contrast:

> Host `WIN-FILESVR-03` (priority 87, key asset): 1 × C&C (Hidden
> HTTP/S Tunnel, T:75/C:90), 2 × Recon (Port Sweep + RPC Recon, both
> T:35), 1 × LM (Suspicious Admin, T:80/C:60). Pattern: external
> implant + internal mapping + admin pivot. **TP-High — likely
> active intrusion. Escalate to IR. Recommend isolating host pending
> tier-2 review.**

versus:

> Host `BACKUP-AGENT-04` (priority 65): 1 × Exfil (Smash and Grab,
> T:65/C:80). No other categories. Tag `backup-server`. **BTP —
> Veeam backup agent writing to `\\fileserver\C$` nightly between
> 02:00–03:00 UTC. Recommend triage rule scoped to (host =
> BACKUP-AGENT-04, type = Smash and Grab, dst = fileserver) only.**

Same data shape, different verdicts — composition is the signal.

---

## Triage rules are scalpels

When you BTP something, the right scope for a suppression rule is the
**narrowest combination** that still covers the benign source:

- per `(host, detection_type, destination)` for network detections.
- per `(account, detection_type, target service)` for identity / cloud
  detections.

Never recommend a rule that suppresses a detection type globally —
that blinds the platform to real future TPs of the same shape.

---

## BTP baseline one-liner (for the next analyst)

Every BTP should leave behind a one-liner the next analyst can read in
10 s:

> BTP — Veeam backup agent (`BACKUP-AGENT-04`) writing to
> `\\fileserver\C$` nightly between 02:00–03:00 UTC. Suppression
> scope: this host + SMB Files destination = fileserver only.

---

## Need-more-data is a valid outcome

If you can't reach a TP / BTP verdict in ~15 minutes per entity, the
verdict is **NMD — escalate to tier 2** (or "pull EDR / SIEM
evidence"). NMD is *not* a failure mode — it's the correct call when
the loaded tooling can't see the next pivot. Always:

1. Name the **specific gap** (e.g. "no file-hash visibility in
   Vectra", "no EDR pivot wired", "user / asset owner not reachable
   on shift").
2. Name the **next pivot** (EDR query, SIEM lookup, identity-side
   sign-on history, ticket the asset owner).
3. **Preserve the evidence** — never auto-close, dismiss, or mute.

---

## Verdict write-up template

```markdown
**Entity:** `<host or account name>` (id `<n>`, tenant `<tenant>`)
**Urgency / Priority:** <score>  •  **Key asset:** <yes/no>  •
**Existing assignment:** <none / analyst>

**Open detections (active only):**
- <category> — <type> (T:<n> / C:<n>) — <one-line summary>
- <category> — <type> (T:<n> / C:<n>) — <one-line summary>

**Behavior observed:** <what Vectra saw + pivot evidence; cite recipe
files / MCP calls / time windows / key fields>.

**Reasoning:** <benign-baseline match OR kill-chain composition;
entity context (tags / groups / key-asset / change windows)>.

**Verdict:** TP-High / TP-Low / BTP / Need-more-data

**Disposition:**
- Assignment: <propose to assign to <analyst> / leave open>
- Triage rule (BTP only): scope = (<host>, <detection_type>, <dst /
  service>)
- Escalation (TP-High only): <to whom, with what summary>
- Next pivots (NMD only): <EDR / SIEM / identity / ticketing>

**Gaps Vectra cannot answer:** <e.g. file hashes, registry keys,
process command lines, agent-less hosts, encrypted east-west without a
sensor>.
```

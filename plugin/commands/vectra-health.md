---
description: Vectra posture snapshot — platform health, daily threat summary, and the current priority queue.
argument-hint: "[hours]"
---

Give the analyst a **posture / health snapshot** of the Vectra environment.
Optional argument overrides the lookback window in hours (default **24**):
`$ARGUMENTS`

Run three things and present them together as one snapshot:

1. **Platform health** — call `get_platform_health` for each category:
   overall platform, EDR, external connectors, and network brain. This answers
   *can the platform see anything*, which the other two sections assume. A
   sensor outage or a disconnected connector makes a quiet queue meaningless,
   so lead with anything degraded.
2. **Daily Threat Summary** — use the **vectra-reports-mcp** skill to render
   the `daily_threat_summary` report (session volume, top flow pairs, active
   detections) for the window.
3. **Priority queue** — use the **vectra-investigator** skill's Queue Triage
   view to list the top active entities by urgency across all wired tenants
   for the same window (headline verdicts only, not a full per-entity
   deep-dive).

Close with a two-line posture read: is anything trending that warrants a
deeper look, and what would you triage first. **Name coverage gaps explicitly**
— an entity with no EDR agent, a connector that is down, a sensor reporting
stale — because "no hits" from a blind sensor is not the same as "no activity",
and that distinction is the point of this command.

Stay **read-only** — this is a dashboard, not an investigation. For any entity
worth a deep-dive, tell the analyst to run `/vectra-investigate <entity>`.

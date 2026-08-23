---
description: Vectra environment posture snapshot — daily threat summary plus the current priority queue.
argument-hint: "[hours]"
---

Give the analyst a **posture / health snapshot** of the Vectra environment.
Optional argument overrides the lookback window in hours (default **24**):
`$ARGUMENTS`

Run two things and present them together as one snapshot:

1. **Daily Threat Summary** — use the **vectra-reports-mcp** skill to render
   the `daily_threat_summary` report (session volume, top flow pairs, active
   detections) for the window.
2. **Priority queue** — use the **vectra-investigator** skill's Queue Triage
   view to list the top active entities by urgency across all wired tenants
   for the same window (headline verdicts only, not a full per-entity
   deep-dive).

Close with a two-line posture read: is anything trending that warrants a
deeper look, and what would you triage first. Stay **read-only** — this is a
dashboard, not an investigation. For any entity worth a deep-dive, tell the
analyst to run `/investigate <entity>`.

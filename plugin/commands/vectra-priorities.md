---
description: Start-of-shift Vectra queue triage — top entities by urgency across all wired tenants.
argument-hint: "[N] [tenant]"
---

Use the **vectra-investigator** skill and run its **Queue Triage** workflow
(`references/workflow-queue-triage.md`).

This is the canonical "shift start / priorities" opener. Default scope:
**top 5 active entities by urgency, all wired tenants, last 24 h.**

Arguments (optional): `$ARGUMENTS`
- A bare number overrides the entity count (e.g. `10` → top 10).
- A tenant name scopes to one tenant (e.g. `tenant-eu`).
- Both may be combined.

Land a verdict per entity using the verdict framework. Stay **read-only** —
never dismiss, close, or mutate detections; propose any state change for
approval. If the default scope would fan out across many tenants, confirm
before running.

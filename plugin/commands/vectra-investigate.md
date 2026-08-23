---
description: End-to-end Vectra deep-dive on one host or account entity.
argument-hint: "<entity-name-or-id>"
---

Use the **vectra-investigator** skill and run its **Entity Deep-Dive**
workflow (`references/workflow-entity-deep-dive.md`) on:

**`$ARGUMENTS`**

Resolve the entity (name, UPN, IP, or ID) via the Vectra MCP lookup tools,
read **all** its open detections, run the matching detection-category
playbook(s), and land a four-outcome verdict (BTP / TP-Low / TP-High /
Need-more-data) with reasoning and disposition.

Default scope: named host or account, all open detections, last 7 d. Stay
**read-only** — propose any state change for approval, never mutate.

If no entity was supplied, ask the analyst which host or account to
investigate before running.

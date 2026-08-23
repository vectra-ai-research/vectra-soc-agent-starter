---
description: Pivot on a single Vectra detection ID and decide if it is real.
argument-hint: "<detection-id>"
---

Use the **vectra-investigator** skill and run its **Single-Detection Pivot**
workflow (`references/workflow-detection-pivot.md`) on detection:

**`$ARGUMENTS`**

Pull the detection record, load the matching `playbook-<category>.md`, pivot
into the entity context and supporting metadata (delegating SQL pivots to the
**vectra-hunt** skill as needed), and land a verdict (BTP / TP-Low / TP-High /
Need-more-data) with reasoning and disposition.

Default scope: the detection + its entity context, the detection's own time
window. Stay **read-only** — propose any state change for approval.

If no detection ID was supplied, ask for one before running.

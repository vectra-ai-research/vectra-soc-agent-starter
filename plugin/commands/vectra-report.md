---
description: Render a named canned Vectra dashboard report (e.g. c2-beacons, top-talkers, daily-threat-summary).
argument-hint: "[report-name] [param=value ...]"
---

Use the **vectra-reports-mcp** skill to render the canned report:

**`$ARGUMENTS`**

The trigger is an explicit report name (ID like `c2_beacon_report` or a
catalog label like "top talkers"). Optional trailing `param=value` pairs
override defaults (e.g. `days=3`, `hours=24`, `limit=100`).

**If no report name was supplied, do NOT default to a generic report** —
list the report catalogue (Network / Operations / Identity-Cloud) and ask
the analyst to pick one.

Reports are dashboards, not investigations. If the ask is investigative
(pivot, entity, IOC, "what did this account do"), route to the
**vectra-hunt** skill instead. Stay **read-only**.

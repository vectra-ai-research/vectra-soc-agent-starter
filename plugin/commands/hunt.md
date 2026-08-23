---
description: Threat-intel hunt or ad-hoc metadata sweep over Vectra — TI report, IOC, actor, CVE, or a direct question.
argument-hint: "<url | ioc | actor | cve | question>"
---

Use the **vectra-hunt** skill on:

**`$ARGUMENTS`**

Pick the mode from the input:
- A TI report URL, advisory, IOC list, named APT / ransomware family, or CVE
  → **Mode 2 (TI-driven hunt)**: structured multi-query sweep +
  consolidated hunt report (IOC hits, TTP coverage, gaps, recommendations).
- A single narrow question ("did host X talk to evil.com last night?",
  "find RC4 TGS requests", "show POST exfil traffic") → **Mode 1 (ad-hoc
  query)**: one recipe, summarized in chat.

Default scope: last 14 d for network metadata (Vectra retention ceiling), up
to 30 d for cloud tables, all wired tenants — state the effective window in
the output. Stay **read-only**. Be honest about coverage gaps: "no hits" ≠
"not affected".

If nothing was supplied, ask what to hunt (report URL, IOC, actor, or a
specific question).

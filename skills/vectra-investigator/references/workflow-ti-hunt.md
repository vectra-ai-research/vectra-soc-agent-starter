# Workflow 4 — TI-Driven Hunt

**Goal:** the user supplies a TI report / advisory / IOC list / named
APT-malware-campaign and asks "are we affected?"

This workflow is owned end-to-end by
[`vectra-hunt`](../../vectra-hunt/SKILL.md) (TI hunt mode). The
orchestrator's job is **scope, hand off, and bring back the hits.**

---

## Pipeline

1. **Confirm the input** — URL to a vendor blog / advisory, local
   file (PDF / HTML / MD / TXT), pasted text, bare IOC list (CSV /
   newline / STIX), or a named actor / malware / campaign / CVE.
2. **Confirm the scope** — which tenant(s) and what lookback. Default
   is all wired tenants and 14 d (Vectra retention floor for most
   tables) unless the report's observation window is shorter or the
   user says otherwise. See [`mental-model.md`](mental-model.md) §4
   for the multi-tenancy rules.
3. **Hand off to `vectra-hunt`** — open its `SKILL.md`, follow the
   six-phase methodology (Ingest → Extract → Map → Run → Triage →
   Report). The hunt produces a consolidated TI Hunt Report with the
   structure documented in `vectra-hunt/SKILL.md` (executive summary,
   IOC hits, TTP coverage matrix, affected entities, gaps,
   recommendations, query appendix).
4. **Bring back the hits** — for each affected host / account, decide
   whether to escalate into
   [`workflow-entity-deep-dive.md`](workflow-entity-deep-dive.md) on
   those entities. A confirmed TI hit on a host typically warrants a
   full entity deep-dive plus EDR correlation.
5. **Always include the gap list** — Vectra cannot hunt file hashes,
   mutexes, registry keys, or process command lines. Recommend EDR /
   SIEM sweeps for those, and call out any tenant that errored / was
   unreachable during the hunt.

---

## Verdict expectations

A TI hunt produces **per-IOC** and **per-entity** results. Wrap up:

- **Per IOC** — confirmed (artifact + behavior + matching Vectra
  detection) > partial (artifact only) > weak (common IOC, low
  confidence).
- **Per entity** — when an entity has any confirmed or partial hit,
  apply the global rubric in
  [`verdict-framework.md`](verdict-framework.md): TP-High /
  TP-Low / BTP / NMD. A TI match alone is *not* automatically
  TP-High — environment context still matters (the IOC could be a
  known false-positive in this network, or hit a sinkhole / scanner).

---

## Cross-skill follow-ups

| If the hunt surfaces… | Follow-up |
|-----------------------|-----------|
| A host with multiple confirmed hits | [`workflow-entity-deep-dive.md`](workflow-entity-deep-dive.md) on that host |
| A network-detection-grade hit and you need packets | [`workflow-pcap-triage.md`](workflow-pcap-triage.md) on the matching detection |
| External IOCs you want enriched | [`virustotal`](../../virustotal/SKILL.md) — corroboration only |
| Gaps Vectra cannot hunt (hashes, registry, mutexes) | Recommend EDR / SIEM / TIP follow-up; do not silently drop |

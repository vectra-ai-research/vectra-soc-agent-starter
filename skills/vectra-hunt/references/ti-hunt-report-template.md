# TI Hunt Report — Output Template

Render the final hunt report exactly in this structure at Phase 6 of
[`mode-ti-hunt.md`](mode-ti-hunt.md). A complete worked example
lives in [`../examples.md`](../examples.md).

---

## Template

```markdown
# TI Hunt Report — <Threat Name>

## Source
- **Report:** <title>
- **Vendor / Author:** <vendor>
- **Published:** <date>
- **Hunt window:** <last N days> (`<start> → <end>` UTC)
- **Tenant:** <vectra tenant / scope>

## Executive summary
- <2–4 bullets: was anything found? severity? scope?>

## Artifacts ingested
| Type | Count | Examples |
|------|-------|----------|
| Domains | N | … |
| IPs | N | … |
| Hashes | N | (no Vectra coverage) |
| User-agents | N | … |
| TTPs | N | T1071.001, T1558.003, … |

## Hits
| Severity | Artifact | Type | First seen | Last seen | Hosts / identities | Vectra evidence |
|----------|----------|------|------------|-----------|--------------------|-----------------|
| 🔴 / 🟡 / 🟢 | evil.com | domain | … | … | host-123, host-456 | DNS query in `network.dns._all`; 47 sessions |

## TTP coverage matrix
| MITRE | Technique | Hunted via | Result |
|-------|-----------|------------|--------|
| T1558.003 | Kerberoasting | `network.kerberos._all` RC4 TGS recipe | 0 hits |
| T1071.004 | DNS C2 | `network.dns._all` NXDOMAIN/DGA + tunneling recipes | 3 hits — host-123 |

## Affected hosts / identities
| Entity | Type | Hits | Active detections | Notes |
|--------|------|------|-------------------|-------|

## Gaps (artifacts not hunted)
| Artifact | Reason | Recommended action |
|----------|--------|--------------------|
| SHA256 hashes | No file-hash coverage in Vectra | Sweep via EDR / SIEM |
| Mutex names | Not collected | Sweep via EDR |

## Recommendations
1. <Specific, actionable next step>
2. <…>

## Appendix — Queries run
<For each: query name, target table, time window, IOC batch size, request_id, hit count.>
```

---

## Section-by-section guidance

- **Source.** Cite the exact URL / file / paste the report came
  from, plus tenant scope (multi-tenancy rules:
  [`../../vectra-investigator/references/mental-model.md`](../../vectra-investigator/references/mental-model.md)
  §4).
- **Executive summary.** Lead with the verdict shape — *anything
  found?*, *which entities?*, *what severity?* — not a recap of the
  hunt's mechanics.
- **Hits.** Sort by severity descending. Confirmed match
  (artifact + behavior + Vectra detection) → 🔴; partial (artifact
  only) → 🟡; weak (common IOC, low confidence) → 🟢.
- **TTP coverage matrix.** Include every technique you tried to hunt
  — both 0-hit and N-hit rows. The matrix is what proves you
  *covered* the report, not just the hits you found.
- **Gaps.** Mandatory section — list every artifact type that Vectra
  could not hunt (hashes, mutexes, registry keys, process command
  lines, host-side artifacts) and the recommended out-of-band
  follow-up (EDR / SIEM / TIP). "No hits" without a gap section is
  not a defensible answer.
- **Appendix — Queries run.** One row per `request_id` so the hunt
  is reproducible. Include query name, target table, time window,
  IOC batch size, hit count.

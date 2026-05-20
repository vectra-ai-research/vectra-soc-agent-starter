# Progressive-Load Manifest — `vectra-investigator/references/`

This skill's `references/` tree is ~13 files / ~2K lines. **Hosts must
not bundle / load all of them up-front.** Use the table below to load
only the references the current workflow needs; everything else stays
on disk until something references it.

## Always loaded (when this skill activates)

The SKILL.md body and these three short files:

- `mental-model.md` — Vectra entity-first triage, kill-chain
  categories, multi-tenancy rules.
- `verdict-framework.md` — BTP / TP-Low / TP-High / NMD rubric.
- `best-practices.md` — common pitfalls (kept short on purpose).

## Per-workflow load

When the orchestrator picks a workflow, load the matching row's files
**lazily** (only if/when execution reaches them):

| Workflow | Required references |
|----------|--------------------|
| Queue Triage | `workflow-queue-triage.md` |
| Entity Deep-Dive | `workflow-entity-deep-dive.md` |
| Single-Detection Pivot | `workflow-detection-pivot.md`, `playbooks-overview.md`, **plus** the matching `playbook-<category>.md` (Exfiltration → `playbook-exfiltration.md`; LM/Recon → `playbook-lateral-movement.md`; others land in `playbooks-overview.md`) |
| TI-Driven Hunt | `workflow-ti-hunt.md` (then routes into `vectra-hunt` references) |
| Ad-Hoc Investigation Query | `workflow-ad-hoc-query.md` (then routes into `vectra-hunt` references) |
| Canned Report | `workflow-canned-report.md` (then routes into `vectra-reports*` skills) |
| Network PCAP Triage | `workflow-pcap-triage.md` (then routes into `vectra-pcap`) |

## Playbook load (within Single-Detection Pivot or Entity Deep-Dive)

`playbook-<category>.md` files are large (300–400 lines each). Load
**only the one** matching the detection's category. Never load both
playbooks "for safety" — the orchestrator already knows the category
from the detection record.

| Detection category | Playbook file |
|--------------------|---------------|
| Exfiltration | `playbook-exfiltration.md` |
| Lateral Movement / Recon | `playbook-lateral-movement.md` |
| C&C / Botnet / Initial Access | not yet shipped — see `playbooks-overview.md` for the routing fallback |

## Hosts: implementation note

If your agent host bundles every `references/*.md` file into one
context window when this skill activates, you are spending ~10× the
tokens this skill needs for any single workflow. The progressive-load
contract is **mandatory** — hosts that can't honor it should not ship
the full `references/` tree (drop the unused playbooks and
workflow-`*` files from the deployment instead).

---
name: investigation-report
description: Renders a completed Vectra entity investigation as one self-contained HTML report — a one-sentence answer, a relationship diagram, a graded timeline, what the sweep found, what is not established, open gaps with their outcomes, and an evidence table where every claim carries the detection ID or tool call it rests on. Use after an entity deep-dive when the user asks for the report, the assessment, the write-up, the full output, or something to hand to someone else. Not for a single detection pivot, not for dashboards, and not a substitute for the investigation itself — this skill formats findings that already exist.
---

# Investigation Report

Turns a finished investigation into one HTML file a human can absorb in
sixty seconds and act on.

The skill is **only the format**. It does not investigate. Run the entity
deep-dive first — [`vectra-investigator`](../vectra-investigator/SKILL.md),
`references/workflow-entity-deep-dive.md` — and come here with the findings.
A report rendered from a thin investigation is a well-presented thin
investigation.

## The two steps

**1. Write a case file.** One JSON document holding the findings. The
contract is [`references/case-schema.md`](references/case-schema.md); the
worked example is [`examples/piper-desktop.json`](examples/piper-desktop.json).

**2. Render it.**

```bash
python3 scripts/render_report.py case.json
python3 scripts/render_report.py case.json --check      # validate, write nothing
python3 scripts/render_report.py case.json -o out.html
```

Standard library only — no virtualenv, no install. Run `--check` first: it
validates the case, lays out the diagram, and reports geometry problems
without producing a file.

## Non-negotiables

**Record the tenant.** `tenant.label` is required and the renderer refuses
without it. Entity and detection IDs are scoped to one tenant and the ID
ranges overlap between tenants, so an ID quoted with no tenant recorded
resolves to a *different real entity* elsewhere rather than erroring. This is
the single most likely way a report becomes actively misleading.

**Every claim carries its provenance.** A detection ID, or the tool call it
came from. Without that this format is prettier prose with the same trust
problem — a reader cannot check it, so they either believe all of it or none.

**No raw HTML in the case file.** Strings are escaped, then a three-token
markup is applied: `` `code` ``, `**bold**`, `_italic_`. Anything else is
displayed literally. Do not try to smuggle a `<div>` in; it will appear as
text and look broken.

**Do not invent structure.** If you did not establish something, leave the
field out. An empty section is omitted; a fabricated one is a lie in a
document designed to look authoritative.

## What goes where, and why

The section order is the format's whole argument, and each part answers a
comprehension failure observed in real use:

| Section | Field | Exists because |
|---|---|---|
| One-sentence answer | `answer` | A reader who does not know what they are looking for finds nothing |
| Recommended action | `next_action` | The report is read to decide something |
| Headline figures | `headline` | Three numbers survive a skim; paragraphs do not |
| Relationship diagram | `diagram` | Prose describing a graph is the hardest thing to read; the shape goes **above** the narrative so the reader confirms it rather than assembling it |
| Composition | `composition` | Individually low-scoring detections compose into a critical entity; the sequence is the signal |
| Sequence | `timeline` | Graded, so the reader has permission not to read all of it |
| What is established | `established` | Collapsed by default — progressive disclosure for a human, not just for a model |
| What the sweep found | `sweep` | On six investigations, looking beyond the detections changed the answer **six times** |
| Considered and not established | `ruled_out` | A report that only lists what it confirmed reads as more certain than it is |
| Open questions | `gaps` | Each with an outcome, so a gap is a worked task rather than a shrug |
| What would settle the rest | `next_steps` | Hands the next analyst a starting point |
| Evidence | `evidence` | The audit trail for every claim above |

## Grading

Every timeline and evidence row takes a `grade`. Grading is what makes the
report skimmable, so use it honestly:

- `decisive` — remove it and the verdict changes
- `supporting` — consistent with the verdict, not load-bearing
- `context` — background a reader may want and can skip
- `ambiguous` — suggestive, not established. Say so here rather than in prose

If everything is `decisive`, nothing is. Expect a handful per report.

## Gap outcomes

From the gap-closing rule in the deep-dive workflow. A gap you have named is a
task, not a caveat — attempt it before reporting it:

- `CLOSED` — you got the answer. Fold it in, and re-check whether it changes
  the verdict or the recommended action
- `NO DATA` — the query worked and returned nothing. **Prove it with a control
  query** before writing it up as an absence
- `BLOCKED` — permission or scope error. Quote the scope verbatim
- `OUT OF REACH` — no connected telemetry could answer it. Name what would

## The diagram

Give nodes and edges. **Do not try to choose a layout** — the renderer lays
out columns by longest path, so the shape emerges from the evidence. Six
shapes appeared naturally across six investigations (fan, chain, identity,
loop, middle-of-chain, ladder) without anyone selecting one.

Node `role` sets the colour, and one node should be `subject` — the entity the
report is about. Roles: `subject`, `attacker`, `victim`, `external`,
`identity`, `infra`.

Edges may set `kind: "dashed"` for an inferred or unproven relationship, and
`back: true` for a return path such as a reverse shell, which is routed below
the diagram so it never crosses a box. Cycles are handled; a real
investigation contains them.

## Before you hand it over

Run `--check` and read the warnings. Then confirm three things a validator
cannot:

1. **The one-sentence answer answers the question that was asked.** Not the
   question the evidence happened to answer.
2. **The recommended action is still correct given the closed gaps.** On the
   first investigation in this format, gap-closing invalidated the containment
   advice — the report told the operator to revoke an AWS key the intruder had
   already deleted. The gaps were worked; the action was not revisited.
3. **The verdict is one of four, and BTP is a real option.** If the format can
   only say "this is bad", it is half a format. See
   [`examples/minimal-btp.json`](examples/minimal-btp.json).

## Output

`Investigation-Report-<entity>.html` in the working directory unless `-o` says
otherwise. One file, no external references, no JavaScript, works offline,
prints, and respects dark mode. Safe to attach to a ticket or email.

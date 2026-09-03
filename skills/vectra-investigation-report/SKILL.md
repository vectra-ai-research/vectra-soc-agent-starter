---
name: vectra-investigation-report
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

**2. Render it** by calling the MCP tool:

```
render_investigation_report(case=<the case JSON as text>)
```

It returns the path to a written HTML file, plus its size, a sha256, and any
warnings. **Give the operator that path** — the report is 25–30 KB of markup
and re-emitting it through the conversation costs more than the investigation
did.

Nothing is installed, no script is run, and no filesystem access is needed on
your side: the server renders it. That is why this is a tool. Earlier versions
shipped `render_report.py` inside this skill, which could never work — a plugin
carrying a fourth file under any `skills/*/scripts/` directory silently fails
to install, and an MCP client cannot execute Python in any case.

**A rejected case file comes back as a value, not an error.** Expect
`rendered: false` with the offending field named. That is normal traffic: fix
the field and call again. Getting there in two attempts is fine; guessing is
not.

**Never write the HTML yourself.** If the tool is unavailable, say so and hand
the operator the case JSON. A hand-built substitute looks like the real format
and silently lacks its checks — no diagram geometry validation, no escaping
guarantees, no gap-outcome vocabulary — which is worse than no report, because
it is indistinguishable from one that was checked.

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
| Persistence | `persistence` | Sits **directly under the action**, because it is the reason the action is what it is. "Reset the password" was insufficient or wrong in most of the six investigations behind this format |
| Headline figures | `headline` | Three numbers survive a skim; paragraphs do not |
| Relationship diagram | `diagram` | Prose describing a graph is the hardest thing to read; the shape goes **above** the narrative so the reader confirms it rather than assembling it |
| Identities involved | `identities` | The credential is usually what the incident is *about*. One account on four control planes is a table row; as a sentence it gets skimmed |
| Composition | `composition` | Individually low-scoring detections compose into a critical entity; the sequence is the signal |
| Sequence | `timeline` | Graded, so the reader has permission not to read all of it |
| What is established | `established` | Collapsed by default — progressive disclosure for a human, not just for a model |
| What the sweep found | `sweep` | On six investigations, looking beyond the detections changed the answer **six times** |
| Considered and not established | `ruled_out` | A report that only lists what it confirmed reads as more certain than it is |
| Open questions | `gaps` | Each with an outcome, so a gap is a worked task rather than a shrug |
| What would settle the rest | `next_steps` | Hands the next analyst a starting point |
| Evidence | `evidence` | The audit trail for every claim above |

## Identity is a subject, not an attribute

Fill `identities` on **every** report, not only when the entity is an account.
The platform models hosts and accounts; an attack is usually one credential
moving across surfaces. A report titled after a host describes the room the
attack passed through.

Per identity, record what the deep-dive workflow's identity-set step told you
to read: the surface list from `account_type`, the privilege from
`privilege_level` / `privilege_category`, the home from `probable_home`, and a
role — `compromised`, `used`, `targeted` or `owner`.

Then fill `persistence` with anything a credential reset would not remove, and
say what each item survives. That block is what makes the recommended action
correct rather than plausible.

`also_seen_as` is for the case where one event was recorded twice — a host
detection and an account detection sharing a timestamp are one observation from
both sides, and worth more than two rows that look like agreement.

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

The tool writes the file and returns its path. **Quote that path verbatim in
your reply** — a report the operator is told about but cannot find is not a
deliverable. Do not paraphrase it or reconstruct it from the entity name.

One file, no external references, no JavaScript, light-only on the Vectra
palette. It opens offline, prints, and can be attached to a ticket as-is.

If the server runs in a container the path is inside the container. Say so
rather than leaving the operator hunting for a file that is not on their disk.

**Also give the operator the case JSON**, or tell them where you saved it if
you could. It is the investigation in structured form: cheaper to re-render
than to re-derive, and the thing to correct and re-run when a finding turns
out to be wrong.

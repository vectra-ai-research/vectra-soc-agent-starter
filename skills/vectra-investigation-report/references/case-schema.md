# The case file

One JSON document, passed to the `render_investigation_report` MCP tool as
text. The tool validates it and refuses anything it cannot render faithfully —
a report that renders wrong is worse than one that does not render, because
nobody notices.

A rejection comes back as `rendered: false` with the offending field named,
not as an error. Fix that field and call again.

Only five fields are required. Everything else is omitted from the output when
absent, so a thin investigation produces a short report rather than a padded
one.

## Required

| Field | Type | Notes |
|---|---|---|
| `schema` | int | Must be `1` |
| `entity.name` | string | The entity the report is about |
| `tenant.label` | string | e.g. `109796245472.ew1`. **Refused if missing** — see below |
| `verdict.code` | string | `TP-High`, `TP-Low`, `BTP`, `Need-more-data` (`NMD` accepted) |
| `answer` | string | One sentence. Warns above ~90 words |
| `next_action` | string | What to do now |

`tenant.label` is required rather than optional because entity and detection
IDs are tenant-scoped, and the ID ranges overlap between tenants. A report
citing `account 3553` with no tenant recorded does not fail when read against
the wrong tenant — it resolves to a different real account and reads as
correct. That is the one failure mode worth blocking at the schema level.

## Expected: `decisions` — the reviewable tree

Not in the required list only because case files predate it, and omitting it
warns rather than refuses. **Write it on every report.** It is the difference
between a conclusion and an argument.

The problem it solves: an analyst reading a report can reject the verdict, and
nothing else. There is nowhere to say *"I disagree with the third step."*
Node IDs give disagreement an address that survives into a ticket.

```jsonc
"decisions": [
  {
    "id": "D1",                          // unique; how a reviewer cites it
    "question": "Is the Hidden HTTPS Tunnel real C2, or a sanctioned tunnel?",
    "concluded": "Real C2",
    "confidence": "high",                // high | moderate | low
    "load_bearing": true,                // remove it and the verdict changes

    "because": ["121 sessions to one external IP inside 2.5 hours",
                "653 KB in against 29 KB out — asymmetry consistent with tasking"],
    "rests_on": ["19768", "get_detection_history"],

    "considered": [
      { "alternative": "Sanctioned VPN or update service",
        "rejected_because": "the domain has no corporate association and the destination is in no known vendor range" }
    ],

    "would_change_if": "The destination resolves into a sanctioned SaaS or CDN range, or IT confirms an approved tunnel",

    "depends_on": [],                    // parent IDs — makes it a tree
    "satisfies": ["R2"]                  // workflow rule IDs, for coverage
  }
]
```

**`would_change_if` is required on every node and refused if absent or blank.**
A judgement whose author cannot name what would overturn it was not a
judgement, it was an assumption. It is also what turns "I disagree" into "go
and check this specific thing" — and it is the field an agent under time
pressure drops first, which is exactly why it is enforced.

| Refused | Warned |
|---|---|
| a node with no `id`, `question`, `concluded` or `would_change_if` | no node marked `load_bearing` — the report doesn't say what the verdict rests on |
| a duplicate `id` — two judgements cannot answer to one name | more than four `load_bearing` — if most of the tree is load-bearing the grading says nothing |
| `confidence` outside `high`/`moderate`/`low` | a `load_bearing` node at `low` confidence — the verdict rests on something soft, and that belongs in front of the reader |
| `depends_on` naming an unknown node, or itself | a node with an empty `rests_on` — a judgement a reader cannot trace is an opinion |
| a dependency **cycle** — a reviewer following `depends_on` must reach a start | no `decisions` block at all |
| a `considered` entry with no `rejected_because` | |
| `satisfies` naming something outside `R1`–`R7` | |
| `because` / `rests_on` / `depends_on` / `satisfies` given as anything but a list | |

Confidence is three values rather than a percentage on purpose: a model asked
for a number will produce one, and it will mean nothing. The useful question a
reviewer asks is *"should I spend my attention here"*, which has three answers.

## Expected: `coverage` — which workflow rules ran

The seven numbered rules in
[`workflow-entity-deep-dive.md`](../../vectra-investigator/references/workflow-entity-deep-dive.md)
are the ones that separate a thorough investigation from a shallow one. The
report accounts for **every one**, because *"I followed the workflow"* is
unverifiable and *"R3 not run"* is a fact a reviewing analyst can act on.

The table is **derived**, not written twice: tag decision nodes with
`satisfies`, and use `coverage` only for rules that produced no node — which
is how a rule you deliberately skipped gets to say so.

```jsonc
"coverage": {
  "R3": { "status": "done",    "detail": "1 of 1 negative findings has a control query" },
  "R4": { "status": "partial", "detail": "3 gaps attempted, 0 closed" },
  "R2": "not run"                        // a bare string is accepted
}
```

`status` is `done`, `partial`, `not run` or `n/a`. A rule with neither a
`satisfies` tag nor a `coverage` entry renders as **Not reported** — a visible
row rather than an absence nobody notices. That distinction is the entire
reason the table exists: silence is otherwise indistinguishable from a rule
that ran and found nothing.

**A rule you did not run is reported, not omitted.** A report saying
*"R2 — not run"* is more trustworthy than a better-researched one that stays
quiet about what it skipped.

## Optional

```jsonc
{
  "entity": {
    "kind": "host",              // host | account
    "id": 107074,                // tenant-scoped, hence tenant.label above
    "ip": "192.168.150.100",
    "note": "10 detections"      // free text for the subtitle line
  },
  "tenant": { "url": "https://109796245472.ew1.portal.vectra.ai" },
  "generated": "2026-09-02T18:00Z",

  "headline": [                  // three works well; more crowds
    { "value": "4", "label": "hosts in the chain",
      "detail": "two found only by sweeping" }
  ],

  "composition": "Prose. Why the detections together mean more than separately.",

  "diagram": {
    "nodes": [
      { "id": "piper",           // unique; referenced by edges
        "label": "Piper-desktop",
        "sublabel": "192.168.150.100",
        "role": "subject",       // subject|attacker|victim|external|identity|infra
        "column": 1 }            // optional override; normally omit
    ],
    "edges": [
      { "from": "piper", "to": "deacon",
        "label": "SMB stage 16:01",
        "kind": "dashed",        // dashed = inferred or unproven
        "back": true }           // return path; routed below the diagram
    ]
  },

  "identities": [
    { "name": "adam_admin@fictotech.com",
      "id": 3575,
      "surfaces": ["kerberos", "o365", "entra_principal", "aws"],
      "privilege": "Low (2)",    // free text; quote the level and category
      "home": "fictotech.com",   // probable_home, or the forest/tenant
      "role": "compromised",     // compromised|used|targeted|owner
      "note": "One credential, four control planes." }
  ],

  "persistence": [
    { "mechanism": "OAuth application grant",
      "surface": "entra_principal",
      "provenance": "19839",
      "survives": ["password reset", "session revocation"],
      "removal": "Revoke the application grant in Entra ID." }
  ],

  "timeline": [
    { "time": "28 Aug 16:05",    // any string; displayed as given
      "title": "Reverse shell back from Deacon-desktop",
      "lane": "Lateral movement",
      "provenance": "19794",     // detection id or tool name
      "detail": "Longer explanation.",
      "grade": "decisive",       // decisive|supporting|context|ambiguous
      "also_seen_as": "detection 19834 on account 3575" }
  ],

  "established":  [ { "claim": "...", "evidence": "..." } ],
  "sweep":        [ { "claim": "...", "evidence": "..." } ],
  "ruled_out":    [ { "claim": "...", "evidence": "..." } ],

  "gaps": [
    { "question": "Is Deacon-desktop compromised, or only targeted?",
      "outcome": "CLOSED",       // CLOSED|NO DATA|BLOCKED|OUT OF REACH
      "detail": "One entity lookup. Urgency 100, eight detections." }
  ],

  "next_steps": [ { "title": "Deep-dive dc2-aws-us-west-01", "why": "..." } ],

  "evidence": [
    { "id": "19794", "what": "4444 session direction Deacon to Piper",
      "source": "get_detection_details", "grade": "decisive" }
  ]
}
```

Any key beginning `_` is ignored, so `_comment` is a safe place for a note to
the next reader of the case file.

## Text

Every string is HTML-escaped, then three markup tokens are applied:

| Write | Renders as |
|---|---|
| `` `text` `` | inline code |
| `**text**` | bold |
| `_text_` | italic |

Nothing else. A `<div>` in a case file appears as the literal characters
`<div>`. This is deliberate: an agent emitting raw HTML will eventually emit
something unbalanced, and the page will render wrong in a way that survives
review.

Backslashes follow JSON rules, so a Windows path needs doubling twice —
`\\\\host\\share` in the JSON source produces `\\host\share` on the page.

## What is refused, and what only warns

**Refused** (exit 1, nothing written):

- `schema` other than `1`
- missing `entity.name`, `tenant.label`, `verdict`, `answer`, `next_action`
- a `verdict.code` outside the four
- a `grade` or gap `outcome` outside its set — a typo silently downgrading an
  item to "context" would quietly change what a reader reads first
- duplicate diagram node ids, or an edge naming a node that does not exist
- a `role` outside the six
- any two diagram nodes whose boxes overlap. The layout is computed, but an
  earlier hand-drawn report shipped with an identity banner sitting on top of a
  DCSync box, so the geometry is asserted rather than assumed

- an identity `role` outside `compromised`, `used`, `targeted`, `owner`
- `surfaces` or `survives` given as anything but a list. `surfaces` being a
  list is the entire point of the field: one credential holding four control
  planes is what makes an incident an identity incident

**Warns** (renders, prints to stderr, and shows the warnings in the report
itself so they cannot be missed):

- empty `timeline` or `evidence`
- an `answer` longer than about 90 words
- no diagram node with `role: "subject"` — the reader cannot tell which entity
  the report is about
- a `persistence` entry that does not say what it `survives` — that field is
  what makes the section change the operator's action
- an `entity.kind` of `account` with no `identities` block, which is almost
  always an oversight: the subject of the report is a credential

## Notes on the identity fields

`identities` renders **above the narrative**, for the same reason the diagram
does. "One account, four control planes" is a table row; as a sentence in a
findings list it gets skimmed. The renderer shows the *count* of surfaces
before listing them, because the count is usually the finding.

`persistence` renders **immediately after the recommended action**, because it
is the reason the action is what it is. Across the six investigations that
produced this format, "reset the password" was insufficient or actively wrong
most of the time — an OAuth grant, an access key minted for a different
principal, and a set of Kerberoasted service principals all survive it. A
column headed *Survives* cannot be skimmed past the way a sentence can.

`also_seen_as` on a timeline row is for one event recorded twice. A host
detection and an account detection sharing a timestamp and a description are a
single observation seen from both sides — which is stronger evidence than two
rows that merely look like corroboration, and only if the report says so.

## Verified behaviour

The renderer is exercised against degenerate cases on purpose: a single node,
no diagram at all, a nine-host chain, a twelve-leaf fan, a three-node cycle, a
pure cycle with no source node, hostnames long enough to wrap, non-Latin and
right-to-left entity names, and an entity name containing
`<script>alert(1)</script>` — which appears as visible text, with no script
element and no event-handler attribute in the parsed output.

# The case file

One JSON document. `render_report.py` validates it and refuses anything it
cannot render faithfully — a report that renders wrong is worse than one that
does not render, because nobody notices.

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

  "timeline": [
    { "time": "28 Aug 16:05",    // any string; displayed as given
      "title": "Reverse shell back from Deacon-desktop",
      "lane": "Lateral movement",
      "provenance": "19794",     // detection id or tool name
      "detail": "Longer explanation.",
      "grade": "decisive" }      // decisive|supporting|context|ambiguous
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

**Warns** (renders, prints to stderr, and shows the warnings in the report
itself so they cannot be missed):

- empty `timeline` or `evidence`
- an `answer` longer than about 90 words
- no diagram node with `role: "subject"` — the reader cannot tell which entity
  the report is about

## Verified behaviour

The renderer is exercised against degenerate cases on purpose: a single node,
no diagram at all, a nine-host chain, a twelve-leaf fan, a three-node cycle, a
pure cycle with no source node, hostnames long enough to wrap, non-Latin and
right-to-left entity names, and an entity name containing
`<script>alert(1)</script>` — which appears as visible text, with no script
element and no event-handler attribute in the parsed output.

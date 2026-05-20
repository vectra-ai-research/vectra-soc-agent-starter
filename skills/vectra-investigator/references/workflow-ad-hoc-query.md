# Workflow 5 — Ad-Hoc Investigation Query

**Goal:** narrow, specific question ("did host X talk to rare domains
last night?", "find Kerberoasting in the last 7 days", "show me POST
exfil traffic to `evil.com`").

This workflow is owned by [`vectra-hunt`](../../vectra-hunt/SKILL.md)
(ad-hoc query mode). The orchestrator's job is **scope, hand off, and
escalate if the result is interesting.**

---

## Pipeline

1. **Confirm the scope.** What entity (host / account / IP /
   domain)? What time window? Which tenant(s)? Default to the
   minimum scope that answers the question — wider scopes drown the
   signal. Multi-tenancy rules: see
   [`mental-model.md`](mental-model.md) §4.
2. **Hand off to `vectra-hunt`** — pick the right recipe in
   `references/*.md` (or author SQL using its query-construction
   rules if no recipe matches). Don't invent SQL outside that recipe
   library / those rules.
3. **Run via the MCP** — `run_investigation` →
   `get_investigation_results`. Page through results.
4. **Summarize the rows in chat** — what's there, what's missing,
   what's interesting.
5. **If results suggest an entity is compromised** — escalate into
   [`workflow-entity-deep-dive.md`](workflow-entity-deep-dive.md) on
   the implicated host(s) / account(s), or
   [`workflow-detection-pivot.md`](workflow-detection-pivot.md) if
   the rows correspond to a specific Vectra detection.

---

## Verdict expectations

An ad-hoc query is a **data pull**, not always a verdict. When the
rows do warrant a verdict (the user asked "is this real?", or the
data is unmistakably benign / malicious), apply the global rubric in
[`verdict-framework.md`](verdict-framework.md). When the rows are
just data ("here are the destinations host X talked to"), summarize
and offer the next pivot — don't manufacture a verdict.

---

## Common pitfalls

- **Wide-window pivots that drown the signal** — start with the
  narrowest reasonable window, expand only on miss.
- **Inventing SQL outside the recipe library** — recipes are
  pre-validated against the platform; off-recipe SQL needs the
  schema resource (`vectra://resources/schemas/<domain>/<table>.md`)
  and the query-construction rules in `vectra-hunt/SKILL.md`.
- **Mixing channels mid-task** — don't re-run the same recipe via
  REST and via MCP in the same investigation.
- **Reaching for `vectra-reports*` to answer an investigation
  question** — Reports are canned dashboards, not investigation
  tools. "Check CloudTrail", "what did account X do", "who's behind
  this IP" all belong here (ad-hoc query → `vectra-hunt`), not in
  the canned-report workflow.
- **Hand-rolling Python / `httpx` / `curl` against the Investigation
  Query API** — auth (Basic-auth OAuth2), polling shape, and
  endpoint paths are easy to get wrong. Always go through the MCP
  tools `run_investigation` / `get_investigation_results` via
  `vectra-hunt`.

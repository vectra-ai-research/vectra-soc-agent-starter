# Skills Catalog

This folder holds the **agent skills** the Vectra SOC assistant loads on
demand. Each skill is a self-contained directory with a `SKILL.md`
(YAML frontmatter + markdown body) plus optional `references/`,
`examples.md`, and `scripts/`.

> **Router lives in [`../AGENTS.md`](../AGENTS.md).** That file is the
> single source of truth for *which skill fires when*. This README is the
> author/maintainer view: layout, packaging, and how to add a new skill.
> Per-skill details (prerequisites, workflows, troubleshooting) live in
> each `SKILL.md` — do not re-document them here.

See [`../install/README.md`](../install/README.md) for how each agent
host discovers these skills (native folder, `AGENTS.md`-only, or
hint-file alias) and [`PACKAGING.md`](PACKAGING.md) for shipping
guidance (Python-vs-MCP, symlink dereferencing, lockfile policy).

---

## Skill layout

```
skills/
├── vectra-investigator/     # MAIN orchestrator + detection-category playbooks (Exfil, LM, …)
├── vectra-hunt/             # Metadata search — ad-hoc SQL recipes + TI-driven hunts
├── vectra-reports/          # Canned analytic reports — Python / REST API (authoritative defs)
├── vectra-reports-mcp/      # Same canned reports, executed via MCP (definitions/ + reference/ symlink into vectra-reports/)
├── vectra-pcap/             # Detection PCAP retrieval (MCP) + local tshark triage
└── virustotal/              # VirusTotal IOC enrichment (Bash adapter)
```

Each `SKILL.md` starts with YAML frontmatter (`name`, `description`); the
description is what an agent host shows in its skill picker — keep it
sharp.

---

## Skill index

The trigger-shaped "Use when…" catalog lives **only** in
[`../AGENTS.md` → Skills catalog](../AGENTS.md#skills-catalog) — it is
the single source of truth for routing and is not repeated here (a
second copy would drift). The layout tree above tells you what each
directory *is*; each `SKILL.md` frontmatter tells the agent *when* to
fire it.

---

## Authoring a new skill

```
skills/<your-skill-name>/
├── SKILL.md          # YAML frontmatter (name, description) + markdown body
├── references/       # optional — deep-dive content the skill body links to
├── examples.md       # optional — fully-worked example
└── scripts/          # optional — anything the skill invokes
```

Rules of thumb:

1. **Keep `SKILL.md` short.** The agent loads the body when relevant;
   long bodies waste context. Push detail into `references/`.
2. **Frontmatter `description` is what the host shows in its skill
   picker.** Be specific about *when* to use the skill; vague
   descriptions don't get picked up.
3. **Cross-link to other skills with relative paths**
   (`../<skill>/SKILL.md`).
4. **Single source of truth.** Do not duplicate prose between
   `SKILL.md`, `references/`, this README, and `AGENTS.md`. If two
   skills share routing/auth/SQL rules, extract to a single file and
   link from both.
5. **After creating a skill, register it in three places:**
   - This `README.md` (skill index table only — one row).
   - [`../AGENTS.md`](../AGENTS.md) (router catalog).
   - [`../README.md`](../README.md) (top-level pitch / skill table).

See Anthropic's [agent-skills guide](https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills)
for skill-structure conventions.

---

## Maintenance checklist

Before shipping a release or a customer bundle, run the bundled
pre-ship check (Python version, catalogue parity, credential hygiene,
Bash sanity):

```bash
bash skills/scripts/check.sh
```

Suitable for CI; exits non-zero on the first failure. See
[`PACKAGING.md`](PACKAGING.md) for shipping-mode details (MCP-only vs
Python+MCP) and what to dereference.

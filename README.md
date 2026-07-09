# Vectra SOC Agent Starter

A **starter pack** for building your own AI agent / assistant on top of the
Vectra AI platform (RUX). It's the companion repository to the Vectra
conference talk *"Get started building an AI agent for the SOC"*, and is meant
as a **GO-TO place to clone, fork, and grow** into your own internal
SOC-assistant project.

It is intentionally small. Read it, run it, then extend it.

---

## What this repo gives you

A working bundle of the four pillars an agent needs to operate the Vectra
platform — wired together end-to-end:

| Pillar | What it is | Where it lives |
|--------|------------|----------------|
| **1. LLM** | The reasoning engine (Claude, GPT, Gemini, …). You bring your own. | Provided by your agent host (Claude Code, Codex, Goose, …) |
| **2. MCP server** | A bridge that exposes the Vectra REST + Investigation Query APIs as **tools** the LLM can call. | External — installed from [`vectra-ai-research/vectra-ai-mcp-server`](https://github.com/vectra-ai-research/vectra-ai-mcp-server) via `uvx` |
| **3. Agent SKILLS** | Domain-specific playbooks the agent loads on demand: SOC workflows, SQL recipes, report definitions, threat-hunt orchestration. | [`skills/`](skills/) in this repo |
| **4. `AGENTS.md`** | The top-level instruction set that tells the agent *who it is*, *which skills exist*, and *when to use which*. | [`AGENTS.md`](AGENTS.md) at the repo root |

Drop this repo into any agent host that understands `AGENTS.md` and `SKILL.md`,
point the host at the Vectra MCP server, and you have a tier-1 SOC assistant
that can triage detections, run investigation queries, generate reports, and
hunt against threat-intel — all in plain English.

---

## Skills included

Each skill is a self-contained directory under `skills/` with its own
`SKILL.md`. The agent reads `AGENTS.md` first, then loads only the skills it
needs for the current task.

| Skill | Purpose |
|-------|---------|
| [`vectra-investigator`](skills/vectra-investigator/SKILL.md) | **Main orchestrator.** Picks the right tier-1 workflow (queue triage, entity deep-dive, single-detection pivot, TI hunt, ad-hoc query, canned report, PCAP triage), runs the matching detection-category **playbook** (Exfiltration, Lateral Movement, …) — benign baselines, malicious indicators, pivot pipeline, verdict rubric — and routes to the sub-skills. |
| [`vectra-hunt`](skills/vectra-hunt/SKILL.md) | Metadata search & threat-intel hunting. **Two modes:** ad-hoc Investigation Query SQL recipes (for narrow questions / pivots) + 6-phase TI-driven hunt campaigns (for advisories / IOC lists / named APTs). |
| [`vectra-reports`](skills/vectra-reports/SKILL.md) | Pre-defined security reports that run against the Vectra **REST API** (Python). HTML / Markdown / JSON output. |
| [`vectra-reports-mcp`](skills/vectra-reports-mcp/SKILL.md) | Same report definitions, but executed entirely through the **MCP server** (no Python venv needed). |
| [`vectra-pcap`](skills/vectra-pcap/SKILL.md) | Pull the PCAP attached to a **network** Vectra detection via the MCP `get_detection_pcap` tool, decode it to disk, and run a single-pass `tshark` triage (TLS / SNI / JA3 / HTTP auth / NTLM / Kerberos / SMB shares / RPC / DNS / ProcessCommandLine). Cloud / log-based detections have no PCAP. |
| [`virustotal`](skills/virustotal/SKILL.md) | VirusTotal IOC enrichment (hashes / IPs / domains / URLs) via a Bash adapter (`scripts/virustotal.sh`) sourced into a host IOC-enrichment workflow. Returns a compact `malicious` / `suspicious` / `reputation` / `country` / `asn` summary plus the full v3 response. |

For per-skill detail, the catalog and decision guide live in
[`skills/README.md`](skills/README.md).

These are **examples**. Keep what you need, delete what you don't, and add
your own. See [Make it yours](#make-it-yours) below.

---

## Install

Start with **[`install/README.md`](install/README.md)** — it covers the
prerequisites, the Vectra MCP server, and the three patterns by which agent
hosts load skills (native folder / `AGENTS.md`-only / hint-file alias).

Then pick your agent host:

- **[Claude Code](install/CLAUDE_CODE.md)** — Anthropic's CLI coding agent.
- **[Codex CLI](install/CODEX.md)** — OpenAI's `codex` CLI.
- **[Goose](install/GOOSE.md)** — Block's open-source agent.

Adding another host (Cursor, VS Code, your own tooling, …)? See
[`install/README.md` → Adding a new client](install/README.md#adding-a-new-client)
— the three patterns cover almost everything, so a new host file is usually
30 lines.

Every per-host guide follows the same three sections:

1. **Register the MCP server** — the only truly host-specific snippet
   (different config file per host).
2. **Make the skills discoverable** — usually one symlink, or nothing at
   all.
3. **Launch and sanity-check** — one prompt to confirm it works.

---

## Try it

Once installed, try one of these prompts inside your agent:

```text
Triage the Vectra queue and walk me through the top 3 entities.

Did host WIN-FILESVR-03 talk to any rare external domains in the last 24h?

Run the C2 beacon report for the last 7 days.

Here's a CISA advisory: https://www.cisa.gov/.../alert.html
Hunt for everything in it across our tenant.
```

The agent will read `AGENTS.md`, pick the right skill, call the MCP tools,
and reply.

---

## Make it yours

This is a **starter pack**, not a product. Recommended path to internalize it:

1. **Fork it** into your own org's repo.
2. **Trim** the skills you don't need
   (e.g. drop `vectra-reports` if you never want a Python venv on analyst
   laptops, or drop the `vectra-hunt` TI-mode sections if you don't do
   TI-driven hunts).
3. **Add your own SOC playbooks** as new skills under `skills/`.
   The convention is dead simple:
   ```
   skills/<your-skill-name>/
     SKILL.md          # YAML frontmatter (name, description) + markdown body
     references/       # optional — recipe / playbook files
     scripts/          # optional — anything the skill needs to invoke
   ```
4. **Edit `AGENTS.md`** to teach the agent your team's vocabulary, escalation
   policy, and shift handoff format.
5. **Pin your MCP server version** in the host config
   (`uvx vectra-ai-mcp-server@<version>`) so analysts get a reproducible
   environment.

Everything in this repo is plain Markdown and tiny scripts. No build step, no
runtime — your customers' SOC team can read every line and feel safe.

---

## Repo layout

```
vectra-soc-agent-starter/
├── README.md            # This file
├── AGENTS.md            # Agent instruction set (read this second)
├── SECURITY.md          # Security policy
├── install/
│   ├── README.md        # Concepts, prerequisites, the 3 skill-discovery patterns
│   ├── CLAUDE_CODE.md   # Per-host install guides (Pattern A)
│   ├── CODEX.md         # Pattern B
│   └── GOOSE.md         # Pattern C
├── skills/
│   ├── README.md             # Author/maintainer view: layout, packaging, adding skills
│   ├── PACKAGING.md          # Shipping guidance (Python-vs-MCP, symlinks, lockfiles)
│   ├── scripts/check.sh      # Pre-ship checks (run in CI)
│   ├── vectra-investigator/  # Main orchestrator + detection-category playbooks
│   ├── vectra-hunt/          # Ad-hoc SQL + TI-driven hunts
│   ├── vectra-reports/       # Canned reports (Python)
│   ├── vectra-reports-mcp/   # Canned reports (MCP)
│   ├── vectra-pcap/          # Detection PCAP retrieval (MCP) + tshark triage
│   └── virustotal/           # VirusTotal IOC enrichment (Bash adapter)
├── scripts/
│   └── bundle_desktop.py     # Zip each skill for Claude Desktop upload
├── reports/             # Demo artifacts — sample incident reports the agent produced
├── .github/workflows/   # CI — runs skills/scripts/check.sh
└── .env.template        # Credentials template (copy to .env, never commit)
```

---

## Further reading

- **Vectra AI MCP Server:** <https://github.com/vectra-ai-research/vectra-ai-mcp-server>
- **Anthropic — Agent Skills:** <https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills>
- **Anthropic — `AGENTS.md` spec:** <https://agents.md/>
- **MCP spec:** <https://modelcontextprotocol.io/>

---

## License

MIT. Use it, fork it, share it.

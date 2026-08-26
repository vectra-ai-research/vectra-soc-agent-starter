# Install — Concepts & Shared Steps

This folder explains **how** to wire this repo into an agent host, plus per-host
recipes for the most common ones. Read this file once for the model, then jump
to the file matching your client:

- [Claude Code](CLAUDE_CODE.md)
- [Codex CLI](CODEX.md)
- [Goose](GOOSE.md)

Adding a new host? Skip to [Adding a new client](#adding-a-new-client).

---

## What you're setting up

An agent that can operate the Vectra AI platform needs four moving parts:

| | What it is | Lives where |
|---|------------|-------------|
| **LLM** | Reasoning engine. You bring it. | Configured by your agent host. |
| **Vectra MCP server** | Translates natural-language tool calls into Vectra REST + Investigation Query API requests. | External — installed via `uvx` from [`vectra-ai-research/vectra-ai-mcp-server`](https://github.com/vectra-ai-research/vectra-ai-mcp-server). |
| **Agent skills** | Domain playbooks the agent loads on demand. | [`skills/`](../skills/) in this repo. |
| **`AGENTS.md`** | Top-level instruction set — orchestrates the three above. | [`AGENTS.md`](../AGENTS.md) at the repo root. |

The **only** things that genuinely vary per client are:

1. **Where the MCP server is registered** — each host has its own config file.
2. **How skills are surfaced** — three patterns, see below.

`AGENTS.md` itself is universal.

---

## Prerequisites (all clients)

- A **Vectra AI tenant** with API credentials (Client ID / Client Secret).
  Generate them from your tenant's *API Clients* page.
- **`uv` / `uvx`** installed:
  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  ```
  (Windows: `powershell -c "irm https://astral.sh/uv/install.ps1 | iex"`)
- **Python 3.12+** is fetched automatically by `uvx` if missing.
- **Python 3.11+** *only if* you plan to run the
  [`vectra-reports`](../skills/vectra-reports/SKILL.md) skill locally.
  The MCP-only skills don't need it.
- This repo cloned somewhere on disk:
  ```bash
  git clone https://github.com/vectra-ai-research/vectra-soc-agent-starter.git
  cd vectra-soc-agent-starter
  ```
- **Windows only:** the repo uses symlinks
  (`skills/vectra-reports-mcp/{definitions,reference}` point into
  `vectra-reports/`). Enable symlink support *before* cloning —
  turn on Windows Developer Mode, then
  `git clone -c core.symlinks=true …` — otherwise the
  `vectra-reports-mcp` skill checks out as broken text files.

---

## The Vectra MCP server

The server is a **separate project** maintained by Vectra at
<https://github.com/vectra-ai-research/vectra-ai-mcp-server>. We never embed
it here — we just register it in each agent host's config so the host can
launch it on demand.

### Minimum server version — **0.4.0**

> The version number below assumes 0.4.0 is the next server release. If it ships
> under a different number, correct this section — the requirement is real
> regardless of what it ends up being called.

The skills in this repo call tools that older servers do not have. Five of them
arrived after 0.3.2:

| Tool | Used by |
|---|---|
| `close_detections` | verdict framework, bulk detection consolidation |
| `reopen_detections` | verdict framework |
| `get_detection_history` | detection pivot workflow |
| `set_detection_workflow_state` | ticket correlation |
| `add_member_to_group` | scoped triage rules |

**What it looks like on an older server:** the agent finds the skill, follows
the playbook, and then a tool call fails with an unknown-tool error partway
through an investigation. Nothing announces a version mismatch. If you see an
agent confidently start work and then fail on `close_detections`, this is why —
upgrade the server rather than debugging the skill.

The recommended install method is `uvx`, which fetches the published package
into an isolated environment with no clone, no venv, and no Docker:

```bash
uvx vectra-ai-mcp-server --help
```

If the package isn't on PyPI yet for your environment, use the Git form:

```bash
uvx --from git+https://github.com/vectra-ai-research/vectra-ai-mcp-server vectra-ai-mcp-server
```

**Pin a version in production**, appending `@<version>`:

```bash
uvx vectra-ai-mcp-server@0.4.0
```

Pin at or above the minimum above. Pinning lower gets you a stable server and
skills that reference tools it does not expose.

The credentials are passed in via the host's `env` block, **not** a `.env`
file (`uvx` doesn't load `.env`). The three required values are:

| Variable | Example |
|----------|---------|
| `VECTRA_BASE_URL` | `https://<tenant>.portal.vectra.ai` (no `/api/v3.4` — the server appends it) |
| `VECTRA_CLIENT_ID` | `<from your tenant's API Clients page>` |
| `VECTRA_CLIENT_SECRET` | `<same>` |

For multi-tenant setups, see the upstream [`tenants.yaml`
docs](https://github.com/vectra-ai-research/vectra-ai-mcp-server#mcp-client-configuration-multi-tenant).

The per-client files in this folder show the exact config-file snippet for
each host.

---

## How skills are loaded — three patterns

This is the only place this repo cares which client you're on. Every host
falls into one of three patterns:

### Pattern A — Native skill folder

> *Used by:* Claude Code, Claude Desktop, Cursor

The host **auto-discovers** skills from a known directory (e.g.
`.claude/skills/` or `~/.cursor/skills/`). It reads each `SKILL.md`'s YAML
frontmatter (`name`, `description`) up front and only loads the body of the
skill when the model decides it's relevant — *progressive disclosure*.

To wire this repo in: symlink (preferred) or copy each skill into the host's
canonical directory. Example for Claude Code:

```bash
mkdir -p .claude/skills
for skill in skills/*/; do
  ln -sf "$PWD/$skill" ".claude/skills/$(basename $skill)"
done
```

### Pattern B — `AGENTS.md`-only

> *Used by:* Codex CLI, generic MCP clients

The host reads `AGENTS.md` from the current working directory. `AGENTS.md`
references each skill by relative path (`skills/<name>/SKILL.md`), and the
agent reads them on demand. **No skill-installation step needed** — just
launch the agent from the repo root.

### Pattern C — Hint-file alias

> *Used by:* Goose (`.goosehints`), some others

The host reads project-level instructions from a specific filename. Symlink
`AGENTS.md` to that filename and the rest behaves like Pattern B.

```bash
ln -s AGENTS.md .goosehints       # Goose
```

---

## (Optional) `vectra-reports` Python deps

Skip this section if you only plan to use the MCP-based skills
(`vectra-reports-mcp`, `vectra-investigator`, `vectra-hunt`).

```bash
cd skills/vectra-reports
uv sync
cp .env.example .env
$EDITOR .env       # fill in VECTRA_BASE_URL / CLIENT_ID / CLIENT_SECRET
```

This is host-agnostic — the Python scripts run from your shell, not from the
agent host's process.

---

## Sanity check

Whatever your host, once you've registered the MCP server and made `AGENTS.md`
available, ask the agent:

```text
Read AGENTS.md, list the available skills, and list the Vectra MCP tools you can call.
```

You should see all skills under `skills/` enumerated and a list of
`vectra-ai-mcp` tools (`get_detections`, `get_entities`,
`run_investigation_query`, …).

Then try a real workflow:

```text
Triage the Vectra queue — top 3 entities by urgency. Walk me through your reasoning.
```

---

## Troubleshooting

Most issues are MCP-related and apply across all hosts:

- **`uvx` not found** — make sure `~/.local/bin` is on your `PATH`.
  Re-open your shell after installing `uv`.
- **MCP server fails to start** — run `uvx vectra-ai-mcp-server --help`
  directly to confirm the package resolves. Each host has its own command
  to list registered MCP servers — check the per-client file.
- **Auth errors (`401 Unauthorized`)** — double-check the credentials in the
  `env` block. `VECTRA_BASE_URL` should be the tenant URL **without**
  `/api/v3.4` (the MCP server appends the API path itself).
- **`AGENTS.md` not picked up** — confirm you launched the host from the
  repo root (`pwd` should end in `vectra-soc-agent-starter`).
- **Skills not picked up (Pattern A hosts)** — check that the symlinks
  resolve (`ls -la .claude/skills/` etc.) and that the `SKILL.md`
  frontmatter parses (must start with `---` on the first line).

---

## Adding a new client

When a new host appears (Cursor, VS Code, your own tooling, …):

1. **Find its MCP config** — every host has somewhere to declare an MCP
   server with `command`, `args`, `env`. Copy the credential block from the
   examples in this folder.
2. **Identify its skill-loading pattern** — does it auto-discover skills
   from a folder (A), read `AGENTS.md` (B), or expect a custom hint file
   (C)? The host's docs will tell you.
3. **Copy the closest existing per-client file** (`CLAUDE_CODE.md` for
   Pattern A, `CODEX.md` for Pattern B, `GOOSE.md` for Pattern C) and swap
   the host-specific commands.

Each per-client file follows the same three-section template:

```markdown
# Install — <Client>

## 1. Register the MCP server
<host-specific config snippet>

## 2. Make the skills discoverable
This client follows **Pattern <A|B|C>**.
<concrete command(s) — usually one symlink, or "nothing to do">

## 3. Launch and sanity-check
<one prompt to verify, link back to the shared sanity check>
```

Send a PR. New hosts almost never need to invent a fourth pattern — keep
the file short.

# Installation — vectra-reports

This skill is a self-contained directory with a `SKILL.md` file, scripts, and
report definitions. Any agent that can read markdown and run shell commands can
use it.

## Prerequisites

- **Python 3.11 or newer** — pinned in `pyproject.toml` (`requires-python = ">=3.11"`).
  System Python on macOS / RHEL is often 3.9, which will fail with
  `TypeError: unsupported operand type(s) for |: 'ModelMetaclass' and 'ModelMetaclass'`
  at import time. Always run from the synced venv, never via `python3` directly.
- `uv` (recommended) or `pip` for dependency management
- A Vectra AI tenant + API client (Client ID / Client Secret)

> **If Python 3.11+ isn't available**, do not work around it by hand-rolling
> REST calls against the Vectra Investigation Query API — switch channels
> instead. Use [`vectra-reports-mcp`](../vectra-reports-mcp/SKILL.md) (same
> reports, executed through the MCP server, no Python required) or, for
> investigation pivots that aren't canned reports at all, use
> [`vectra-hunt`](../vectra-hunt/SKILL.md).

## Step 1 — Clone the repo

```bash
git clone https://github.com/vectra-ai-research/vectra-soc-agent-starter.git ~/code/vectra-soc-agent-starter
```

## Step 2 — Install dependencies

From the skill directory:

```bash
cd ~/code/vectra-soc-agent-starter/skills/vectra-reports
```

With `uv` (fastest):

```bash
uv sync
```

Or with pip:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Step 3 — Configure credentials

Use the repo-root `.env` as the central source for credentials. From the repo
root:

```bash
$EDITOR .env
```

Required:
- `VECTRA_BASE_URL` — e.g. `https://acme.cc1.portal.vectra.ai/api/v3.4`
- `VECTRA_CLIENT_ID`
- `VECTRA_CLIENT_SECRET`

The scripts auto-load only the repo-root `.env`. Do not create a
`skills/vectra-reports/.env` file or use `~/.vectra/credentials.env` for this
repo.

## Step 4 — Point your agent at the skill

The skill just needs to be readable by your agent. Options:

**Option A — Symlink the skill directory** (works with agents that scan a skills folder):

```bash
# Example paths — adjust for your agent
ln -s ~/code/vectra-soc-agent-starter/skills/vectra-reports ~/.cursor/skills/vectra-reports
ln -s ~/code/vectra-soc-agent-starter/skills/vectra-reports ~/.claude/skills/vectra-reports
```

**Option B — Point at SKILL.md directly** (works with any agent):

Tell your agent to read `~/code/vectra-soc-agent-starter/skills/vectra-reports/SKILL.md`.
The frontmatter (`name`, `description`) tells the agent when to activate.

**Option C — Point at the whole repo**:

If your agent reads `AGENTS.md` at the repo root, it will discover all skills
automatically.

## Step 5 — Verify

```bash
cd ~/code/vectra-soc-agent-starter/skills/vectra-reports
python scripts/validate.py
python scripts/list_reports.py
```

You should see 17 reports listed.

## Updating

```bash
cd ~/code/vectra-soc-agent-starter
git pull
cd skills/vectra-reports
uv sync   # or: pip install -e .
```

Your repo-root `.env` is gitignored and will not be touched.

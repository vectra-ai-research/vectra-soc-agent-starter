# Install — Claude Code

> Read [`install/README.md`](README.md) first for prerequisites, the MCP
> server overview, and the three skill-discovery patterns.

[Claude Code](https://docs.claude.com/en/docs/claude-code/overview) is
Anthropic's CLI coding agent. It uses **Pattern A** (native skill folder) and
auto-discovers skills from `.claude/skills/`.

---

## 1. Register the MCP server

Either user-level (recommended for a single analyst laptop):

```bash
claude mcp add vectra-ai-mcp \
  --scope user \
  --env VECTRA_BASE_URL=https://<your-tenant>.portal.vectra.ai \
  --env VECTRA_CLIENT_ID=<your-client-id> \
  --env VECTRA_CLIENT_SECRET=<your-client-secret> \
  --uvx vectra-ai-mcp-server
```

Or project-level by checking in `.mcp.json` at the repo root:

```json
{
  "mcpServers": {
    "vectra-ai-mcp": {
      "command": "uvx",
      "args": ["vectra-ai-mcp-server"],
      "env": {
        "VECTRA_BASE_URL": "https://<your-tenant>.portal.vectra.ai",
        "VECTRA_CLIENT_ID": "<your-client-id>",
        "VECTRA_CLIENT_SECRET": "<your-client-secret>"
      }
    }
  }
}
```

> **Don't commit secrets.** Either keep the user-level config, or check in a
> `.mcp.json.example` and `.gitignore` the real `.mcp.json`.

Verify with `claude mcp list`.

---

## 2. Make the skills discoverable

Pattern A — symlink each skill into Claude Code's discovery folder:

```bash
mkdir -p .claude/skills
for skill in skills/*/; do
  ln -sf "$PWD/$skill" ".claude/skills/$(basename $skill)"
done
```

Claude Code will read each `SKILL.md`'s frontmatter on startup and load the
body only when a skill is needed (progressive disclosure).

`AGENTS.md` at the repo root is also picked up automatically — no extra
step.

---

## 3. Launch and sanity-check

```bash
claude
```

Then run the sanity-check prompts from
[`install/README.md` → Sanity check](README.md#sanity-check). Inside Claude
Code, you can also run `/skills` to list the loaded skills.

---

## Client-specific troubleshooting/

- **`claude mcp list` shows no server** — confirm you ran `claude mcp add`
  with the right `--scope` (`user` vs `project`). Project-scope only loads
  when you're inside that project.
- **`/skills` shows nothing** — check the symlinks resolve
  (`ls -la .claude/skills/`) and that you started `claude` from the repo
  root.

For everything else, see
[`install/README.md` → Troubleshooting](README.md#troubleshooting).

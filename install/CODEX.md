# Install — Codex CLI

> Read [`install/README.md`](README.md) first for prerequisites, the MCP
> server overview, and the three skill-discovery patterns.

[Codex CLI](https://github.com/openai/codex) is OpenAI's terminal-based
coding agent. It uses **Pattern B** (`AGENTS.md`-only) — no skill-folder
registration needed; the agent reads `AGENTS.md` from the repo root and
follows the relative paths to each `SKILL.md` on demand.

---

## 1. Register the MCP server

Codex stores its config in `~/.codex/config.toml`. Add an entry under
`[mcp_servers]`:

```toml
[mcp_servers.vectra-ai-mcp]
command = "uvx"
args    = ["vectra-ai-mcp-server"]
env     = {
  VECTRA_BASE_URL      = "https://<your-tenant>.portal.vectra.ai",
  VECTRA_CLIENT_ID     = "<your-client-id>",
  VECTRA_CLIENT_SECRET = "<your-client-secret>"
}
```

Verify with `codex mcp list`.

(Optional) Add this at the end of the config file to automatically allow running Vectra's MCP tools:

```toml
default_tools_approval_mode = "approve"
```

---

## 2. Make the skills discoverable

Pattern B — **nothing to do**. `AGENTS.md` is already at the repo root, and
it references each skill by relative path (`skills/<name>/SKILL.md`). Codex
reads them on demand the first time the agent needs them.

---

## 3. Launch and sanity-check

```bash
cd vectra-soc-agent-starter
codex
```

Then run the sanity-check prompts from
[`install/README.md` → Sanity check](README.md#sanity-check).

---

## Client-specific troubleshooting

- **`codex mcp list` shows no server** — re-check the TOML syntax in
  `~/.codex/config.toml` (a single missing comma will silently drop the
  block). Run `uvx vectra-ai-mcp-server --help` to confirm the package
  resolves.
- **Codex doesn't seem to read `AGENTS.md`** — confirm you launched `codex`
  from the repo root (`pwd` should end in `vectra-soc-agent-starter`).

For everything else, see
[`install/README.md` → Troubleshooting](README.md#troubleshooting).

# Install — Goose

> Read [`install/README.md`](README.md) first for prerequisites, the MCP
> server overview, and the three skill-discovery patterns.

[Goose](https://block.github.io/goose/) is Block's open-source agent. It
uses **Pattern C** (hint-file alias) — it reads project-level instructions
from `.goosehints`, so we symlink `AGENTS.md` to that filename.

---

## 1. Register the MCP server

Goose calls MCP servers "extensions". Either run `goose configure` →
*Add Extension* → *Command-line Extension*, or edit
`~/.config/goose/config.yaml` directly:

```yaml
extensions:
  vectra-ai-mcp:
    type: stdio
    enabled: true
    name: vectra-ai-mcp
    cmd: uvx
    args:
      - vectra-ai-mcp-server
    envs:
      VECTRA_BASE_URL: https://<your-tenant>.portal.vectra.ai
      VECTRA_CLIENT_ID: <your-client-id>
      VECTRA_CLIENT_SECRET: <your-client-secret>
    timeout: 300
```

Verify with `goose info`.

---

## 2. Make the skills discoverable

Pattern C — symlink `AGENTS.md` to the filename Goose reads project hints
from:

```bash
ln -s AGENTS.md .goosehints
```

From there, Goose follows the relative paths in `AGENTS.md`
(`skills/<name>/SKILL.md`) on demand — same as Pattern B.

---

## 3. Launch and sanity-check

```bash
cd vectra-soc-agent-starter
goose session
```

Then run the sanity-check prompts from
[`install/README.md` → Sanity check](README.md#sanity-check).

---

## Client-specific troubleshooting

- **`goose info` doesn't list the extension** — confirm `enabled: true` in
  `~/.config/goose/config.yaml` and re-run `goose configure` to validate
  the YAML.
- **Goose ignores `AGENTS.md`** — confirm `.goosehints` exists at the repo
  root (`ls -la .goosehints`) and that you started the session from the
  repo root.

For everything else, see
[`install/README.md` → Troubleshooting](README.md#troubleshooting).

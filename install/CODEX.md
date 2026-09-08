# Install — Codex CLI

> Read [`install/README.md`](README.md) first for prerequisites, the MCP
> server overview, and the three skill-discovery patterns.

[Codex CLI](https://github.com/openai/codex) is OpenAI's terminal-based
agent. It uses **Pattern B** (`AGENTS.md`-only) — no skill-folder
registration needed; the agent reads `AGENTS.md` from the repo root and
follows the relative paths to each `SKILL.md` on demand.

The ChatGPT desktop app and the Codex IDE extension **share this same
configuration** on the same host, so configuring it once covers all three.

---

## 1. Sign in

```bash
codex login          # opens a browser; SSO happens there
codex login status
```

There is no separate SSO mode — the browser flow lands on normal ChatGPT
sign-in and your IdP takes over. If your account belongs to several ChatGPT
workspaces, pick the right one: Codex inherits that workspace's RBAC and
data-handling policy.

Behind a corporate TLS proxy, set `CODEX_CA_CERTIFICATE` to your PEM bundle
before logging in. If the localhost callback is blocked, use
`codex login --device-auth` (a workspace admin must enable device-code login).

## 2. Install the server

Internal users install from the `internal` channel — a persistent install, so
startup needs no network and the config below never changes again:

```bash
uv tool install --force \
  --from git+https://github.com/vectra-ai-research/vectra-ai-mcp-server@internal \
  vectra-ai-mcp-server
```

This puts both `vectra-ai-mcp-server` (the server) and `vectra-mcp` (the
profile CLI) on `PATH`. External users install the published package instead:
`uv tool install vectra-ai-mcp-server`.

Update later with `uv tool upgrade vectra-ai-mcp-server` — it re-resolves the
branch even when the version number hasn't changed.

## 3. Store your Vectra credentials

**Not in `config.toml`.** Credentials live in your OS keychain, via a
profile:

```bash
vectra-mcp profile add prod_a
```

The secret is typed without echo and never touches a config file. See
[`docs/profiles.md`](https://github.com/vectra-ai-research/vectra-ai-mcp-server/blob/main/docs/profiles.md)
in the server repo for the full profile CLI.

> On macOS, run this from a terminal **before** starting Codex and answer the
> Keychain dialog with **Always Allow**. From a Codex-launched process you may
> not see that dialog, and the server will appear to hang.

## 4. Register the MCP server

```bash
codex mcp add vectra-ai-mcp -- vectra-ai-mcp-server
```

No `--env` and no credentials — the server resolves the active profile from
the keychain.

Then add two settings to the entry in `~/.codex/config.toml`:

```toml
[mcp_servers.vectra-ai-mcp]
command = "vectra-ai-mcp-server"

# Prompt only for tools that change tenant state. Uses each tool's read-only
# annotation, so the 33 read-only tools run uninterrupted and the 8 mutating
# ones ask first. Do NOT use "approve" — that auto-approves close_detections
# and mark_detection_fixed along with everything else.
default_tools_approval_mode = "writes"

# The default is 60s; investigation queries submit-then-poll and PCAP pulls
# are slower than that.
tool_timeout_sec = 180
```

Verify with `codex mcp list`, and `/mcp` inside the TUI.

`startup_timeout_sec` is not needed with a `uv tool install` server — it starts
immediately. Only raise it if you run the server via `uvx`, which fetches at
launch.

### Optional — deny the mutating tools outright

```toml
disabled_tools = [
  "close_detections", "reopen_detections", "mark_detection_fixed",
  "set_detection_workflow_state", "create_assignment", "delete_assignment",
  "create_entity_note", "add_member_to_group",
]
```

Triage, hunting, investigation and reporting all still work.

---

## 5. Make the skills discoverable

Pattern B — **nothing to do for prose invocation**. `AGENTS.md` is already at
the repo root and references each skill by relative path
(`skills/<name>/SKILL.md`). Codex reads them on demand, so describing a task
in prose reaches the right workflow.

**There are no `/vectra-…` slash commands in Codex.** Those come from
`plugin/commands/*.md`, which is a Claude Code convention; Codex does not read
that directory and returns *"Unrecognized command"*. Codex's own `/` list is
its built-ins plus installed skills and custom prompts.

For `$`-mention invocation — Codex's equivalent of ChatGPT's `@`, and the
nearest thing to the Claude slash commands — install the skills into the Codex
skills directory:

```bash
python3 scripts/bundle_openai_skills.py --install
```

That regenerates `dist/openai-skills/` from the current tree and copies each
skill into `~/.agents/skills/`. Restart Codex and `$vectra-investigator`,
`$vectra-hunt` and the rest resolve by name, and appear in the `/` list.
Re-run it after a `git pull`, since it is a copy rather than a link.

## 6. Launch and sanity-check

```bash
cd vectra-soc-agent-starter
codex
```

**Launch from the repo root**, or the agent has tools but no workflow. Then
ask it to call `get_active_profile` — it should report your profile name,
tenant URL and client ID. Follow with the sanity-check prompts in
[`install/README.md` → Sanity check](README.md#sanity-check).

---

## Client-specific troubleshooting

- **`codex mcp list` shows no server** — re-check the TOML syntax in
  `~/.codex/config.toml` (a single missing comma will silently drop the
  block). Confirm the package resolves with
  `command -v vectra-ai-mcp-server && vectra-mcp --version`.
- **`command not found: vectra-ai-mcp-server`** — uv's executable directory
  isn't on `PATH`. Run `uv tool update-shell`, then open a new terminal.
- **The server hangs on first use** — almost always the keychain prompt you
  couldn't see. Quit Codex, run `vectra-mcp profile test` from a terminal,
  answer **Always Allow**, restart.
- **"No credentials"** — check an active profile is set with
  `vectra-mcp profile list`; the active one is marked `*`.
- **Timeouts on hunts** — raise `tool_timeout_sec`. Note also the API's hard
  ceiling of 5 investigation submissions per minute.
- **Wrong results after switching tenants** — profile switches apply at server
  start, so restart Codex. And confirm the tenant before working from an ID:
  entity and detection IDs are tenant-scoped with overlapping ranges.
- **Codex doesn't seem to read `AGENTS.md`** — confirm you launched `codex`
  from the repo root (`pwd` should end in `vectra-soc-agent-starter`).

For everything else, see
[`install/README.md` → Troubleshooting](README.md#troubleshooting).

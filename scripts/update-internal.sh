#!/bin/sh
# Update both halves of the internal channel: the MCP server and the skills.
#
# Why this script exists rather than a one-line instruction
# ---------------------------------------------------------
# `uv tool upgrade vectra-ai-mcp-server` is NOT sufficient. uv caches the
# resolution of a git ref, so an https:// branch that has moved still reports
# "Nothing to upgrade" -- and so does `uv tool upgrade --reinstall`, despite
# that flag implying --refresh. Verified against this channel on 2026-09-08:
# only the full `uv tool install --force --refresh --from git+...@BRANCH` form
# re-resolves the branch head.
#
# That command is too long to hand anyone as a weekly ritual, and a mistyped
# ref silently installs the wrong thing, so it lives here instead. The
# instruction stays short and stable; the URL is version-controlled.
#
# Usage:  sh scripts/update-internal.sh
# Then restart your MCP client (Codex, or Cmd-Q and reopen Claude Desktop).

set -eu

BRANCH="${VECTRA_CHANNEL:-internal}"
SERVER_REPO="https://github.com/vectra-ai-research/vectra-ai-mcp-server"

# Resolve the repo root from this script's own location, so the script works
# from any working directory.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

if ! command -v uv >/dev/null 2>&1; then
    echo "uv not found on PATH. Install it:" >&2
    echo "  curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
    exit 1
fi

echo "channel: $BRANCH"
echo

before=$(vectra-mcp --version 2>/dev/null || echo "not installed")
echo "server before: $before"

# --force     replace the existing install rather than refusing
# --refresh   invalidate cached data, including the resolved git commit. This
#             is the flag that actually matters; without it a moved branch is
#             a no-op and the update silently does nothing.
uv tool install --force --refresh \
    --from "git+${SERVER_REPO}@${BRANCH}" \
    vectra-ai-mcp-server

after=$(vectra-mcp --version 2>/dev/null || echo "FAILED")
echo "server after:  $after"
echo

# The skills half. --ff-only so a dirty working tree fails loudly instead of
# producing a merge commit in someone's clone.
if [ -d "$REPO_ROOT/.git" ]; then
    echo "skills: $REPO_ROOT"
    git -C "$REPO_ROOT" fetch origin "$BRANCH"
    if ! git -C "$REPO_ROOT" merge --ff-only "origin/$BRANCH"; then
        echo >&2
        echo "Could not fast-forward the skills repo. You have local commits" >&2
        echo "or uncommitted changes. Resolve them, then re-run." >&2
        exit 1
    fi
    echo "skills now at: $(git -C "$REPO_ROOT" log --oneline -1)"
else
    echo "skills: $REPO_ROOT is not a git clone, skipping"
fi

echo
echo "Done. Restart your MCP client:"
echo "  Codex          - exit and relaunch"
echo "  Claude Desktop - Cmd-Q completely, then reopen"
echo
echo "The version string may be unchanged even when the code moved: an"
echo "internal release does not bump the version. Trust the commit, not the"
echo "version -- 'uv tool install' printed the resolved commit above."

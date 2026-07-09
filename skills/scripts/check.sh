#!/usr/bin/env bash
# check.sh — pre-ship checks for the skills/ tree.
#
# Run from the repo root. Exits non-zero on the first failure so this
# script is safe to plug into CI:
#
#     bash skills/scripts/check.sh
#
# What it checks:
#   1. Python version pin is consistent (>=3.11 everywhere, no stale 3.10).
#   2. Report catalogue parity — definitions/ and reference/ are identical
#      between vectra-reports and vectra-reports-mcp (symlinks resolve).
#   3. No real-looking credentials in .env templates.
#   4. No real-looking credentials inside tracked *.zip bundles
#      (a leak in dist/ is invisible to a plain text grep).
#   5. Every bash script parses cleanly (bash -n).
#
# Portability: bash 3.2+, POSIX `grep`/`find`/`diff` only — no ripgrep,
# no `mapfile`, so this works on macOS, slim CI images, alpine, etc.
#
# Adjust this script when the parity contract changes (new report skill,
# new shared dir, new credential env var).

set -eu

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"

failures=0
section() { printf '\n=== %s ===\n' "$1"; }
fail()    { printf 'FAIL: %s\n' "$1"; failures=$((failures + 1)); }
ok()      { printf 'ok:   %s\n' "$1"; }

# ----------------------------------------------------------------------
section "1. Python version consistency"

# Only scan first-party docs and our own code — skip vendored site-packages
# (.venv/) and build artifacts (*.egg-info, .uv-cache).
hits=$(
  grep -RIn \
    --include='*.md' --include='*.py' --include='*.toml' \
    --exclude-dir='.venv' --exclude-dir='*.egg-info' \
    --exclude-dir='.uv-cache' --exclude-dir='node_modules' --exclude-dir='.git' \
    -E '[Pp]ython ?3\.10|python_requires.*3\.10|requires-python.*3\.10|>=[[:space:]]*3\.10[^.0-9]' \
    skills/ install/ 2>/dev/null || true
)
if [ -n "$hits" ]; then
  fail "stale 'Python 3.10' references found:"
  printf '%s\n' "$hits"
else
  ok "no first-party '3.10' references under skills/ or install/"
fi

if ! grep -q 'requires-python = ">=3\.11"' skills/vectra-reports/pyproject.toml; then
  fail "skills/vectra-reports/pyproject.toml not pinned to >=3.11"
else
  ok "pyproject.toml pins >=3.11"
fi

# ----------------------------------------------------------------------
section "2. Report catalogue parity"

if [ ! -L skills/vectra-reports-mcp/definitions ]; then
  fail "skills/vectra-reports-mcp/definitions is not a symlink"
elif ! diff -rq skills/vectra-reports/definitions skills/vectra-reports-mcp/definitions >/dev/null; then
  fail "definitions/ differ between the two report skills"
  diff -rq skills/vectra-reports/definitions skills/vectra-reports-mcp/definitions || true
else
  ok "definitions/ symlink resolves identically"
fi

if [ ! -L skills/vectra-reports-mcp/reference ]; then
  fail "skills/vectra-reports-mcp/reference is not a symlink"
elif ! diff -rq skills/vectra-reports/reference skills/vectra-reports-mcp/reference >/dev/null; then
  fail "reference/ differ between the two report skills"
  diff -rq skills/vectra-reports/reference skills/vectra-reports-mcp/reference || true
else
  ok "reference/ symlink resolves identically"
fi

# ----------------------------------------------------------------------
section "3. .env templates contain no real values"

# Any .env.template or .env.example file under skills/ or at the repo
# root must only have empty assignments (`KEY=`) or commented examples.
leaked=0
env_paths=""
[ -f .env.template ] && env_paths=".env.template"
env_paths="$env_paths $(find skills -name '.env.example' -type f 2>/dev/null || true)"

for f in $env_paths; do
  [ -f "$f" ] || continue
  if grep -E '^(VECTRA_CLIENT_(ID|SECRET)|VECTRA_BASE_URL|VT_API_KEY)=[A-Za-z0-9_./:-]+' "$f" >/dev/null 2>&1; then
    fail "$f appears to contain a real value:"
    grep -nE '^(VECTRA_CLIENT_(ID|SECRET)|VECTRA_BASE_URL|VT_API_KEY)=' "$f" || true
    leaked=$((leaked + 1))
  fi
done
[ "$leaked" = "0" ] && ok "no populated credential lines in env templates"

# ----------------------------------------------------------------------
section "4. No credentials inside tracked zip bundles"

# A leak inside dist/*.zip (or any other tracked zip) is invisible to
# the plaintext scans above. unzip -p extracts to stdout without
# touching the filesystem.
zip_leaked=0
zip_count=0
if command -v unzip >/dev/null 2>&1; then
  while IFS= read -r z; do
    [ -f "$z" ] || continue
    zip_count=$((zip_count + 1))
    # Pull every file out of the archive in one shot, look for
    # populated credential lines.
    if unzip -p "$z" 2>/dev/null | \
       grep -E '^(VECTRA_CLIENT_(ID|SECRET)|VECTRA_BASE_URL|VT_API_KEY)=[A-Za-z0-9_./:-]+' >/dev/null 2>&1; then
      fail "$z contains a populated credential line"
      unzip -p "$z" 2>/dev/null | \
        grep -nE '^(VECTRA_CLIENT_(ID|SECRET)|VECTRA_BASE_URL|VT_API_KEY)=' || true
      zip_leaked=$((zip_leaked + 1))
    fi
  done < <(find . -name '*.zip' -type f -not -path './.git/*' 2>/dev/null)
  if [ "$zip_count" = "0" ]; then
    ok "no zip bundles tracked"
  elif [ "$zip_leaked" = "0" ]; then
    ok "$zip_count zip bundle(s) scanned, none leak credentials"
  fi
else
  printf 'warn: unzip not available — skipping zip credential scan\n'
fi

# ----------------------------------------------------------------------
section "5. Bash scripts parse"

# Collect all bash -n errors in one pass; a fixed /tmp path would collide
# between concurrent CI runs, so use mktemp.
bash_errs="$(mktemp)"
find skills -name '*.sh' -type f -exec bash -n {} \; 2>"$bash_errs"
if [ -s "$bash_errs" ]; then
  fail "one or more *.sh under skills/ failed bash -n"
  cat "$bash_errs"
else
  ok "all *.sh under skills/ pass bash -n"
fi
rm -f "$bash_errs"

# ----------------------------------------------------------------------
printf '\n'
if [ "$failures" -gt 0 ]; then
  printf '%d check(s) failed\n' "$failures" >&2
  exit 1
fi
printf 'all checks passed\n'

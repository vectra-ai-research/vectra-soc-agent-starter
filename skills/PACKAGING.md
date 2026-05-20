# Packaging the Skills

This document is for **maintainers and packagers** who bundle the skills
in `skills/` into a customer deliverable (a tarball, a vendored
sub-folder of another product, an internal pip-installable archive,
etc.). End users just read each skill's `SKILL.md` and `INSTALL.md`.

> **TL;DR**
> - If the host can run Python 3.11+, ship **everything** under `skills/`.
> - If the host is MCP-only (no Python), ship `skills/vectra-reports-mcp/`
>   with `rsync -aL` so the `definitions/` and `reference/` symlinks
>   are dereferenced — **drop** `skills/vectra-reports/` from the
>   bundle.
> - Never ship two copies of the report YAML side by side; the
>   `vectra-reports-mcp/{definitions,reference}` paths are symlinks
>   into `vectra-reports/`, which is the single source of truth.

---

## Two supported deployment modes

### 1. Python + MCP (recommended)

The full-fat install. Use this when the analyst host can run a
Python 3.11+ venv.

What to ship:

```
skills/
├── vectra-investigator/    # text-only
├── vectra-hunt/            # text-only
├── vectra-reports/         # text + Python engine + YAML defs + uv.lock
├── vectra-reports-mcp/     # text + symlinks into ../vectra-reports/
├── vectra-pcap/            # text + bash scripts
└── virustotal/             # text + bash scripts
```

Packaging command (rsync preserves symlinks as symlinks):

```bash
rsync -a --delete skills/ <bundle-root>/skills/
```

Both report channels work. The agent picks `vectra-reports` (Python)
when `uv sync` has been run; otherwise it falls back to
`vectra-reports-mcp` (MCP).

### 2. MCP-only (no Python on host)

Use this when the analyst host **cannot** run Python (locked-down
runtime, IDE-embedded agent, etc.). Customer expects to drive
everything through the Vectra MCP server.

What to ship:

```
skills/
├── vectra-investigator/    # text-only
├── vectra-hunt/            # text-only
├── vectra-reports-mcp/     # YAML defs + reference docs (de-symlinked)
├── vectra-pcap/            # text + bash scripts
└── virustotal/             # text + bash scripts
```

Packaging command (`-L` dereferences symlinks, so the YAML and
reference markdown become real files inside `vectra-reports-mcp/`):

```bash
rsync -aL --exclude='vectra-reports' skills/ <bundle-root>/skills/
```

**Do not** include `skills/vectra-reports/` — it would silently duplicate
the YAML now that the MCP folder is fully self-contained. The
authoritative location moves to `vectra-reports-mcp/definitions/`
for this bundle.

After dereferencing, edit either bundle to add reports by dropping new
YAML into `vectra-reports-mcp/definitions/` (no symlink to maintain).

---

## Why the symlinks?

`skills/vectra-reports-mcp/definitions` and
`skills/vectra-reports-mcp/reference` are **symlinks** into
`skills/vectra-reports/`. That keeps the YAML catalogue and SQL /
authoring documentation in a single authoritative location while still
letting both skills work transparently in their `SKILL.md` flow.

Verify the symlinks resolve:

```bash
ls -la skills/vectra-reports-mcp/
# definitions -> ../vectra-reports/definitions
# reference   -> ../vectra-reports/reference

diff -rq skills/vectra-reports/definitions skills/vectra-reports-mcp/definitions
# (no output — identical)
```

If `diff -rq` ever produces output, the symlink is broken — investigate
before shipping.

---

## Lockfile policy (`vectra-reports/uv.lock`)

`uv.lock` is **required** for Python-channel deployments — it pins
exact dependency versions so the engine is reproducible across analyst
hosts. Keep it in any **Python + MCP** bundle.

For **MCP-only** bundles, `uv.lock` is dead weight and may confuse
customers who think the bundle depends on Python. Strip it as part of
the packaging step:

```bash
rm <bundle-root>/skills/vectra-reports/uv.lock          # python+mcp: optional cleanup
# In MCP-only bundles, the whole vectra-reports/ folder is already gone.
```

(The `pyproject.toml` is still authoritative for Python builds. Do not
delete it from a Python+MCP bundle.)

---

## Pre-ship checklist

Run [`scripts/check.sh`](scripts/check.sh) from the repo root before
producing any bundle:

```bash
bash skills/scripts/check.sh
```

It exits non-zero on the first failure and bundles four checks:

1. **Python version pin** — no stale `3.10` first-party references;
   `pyproject.toml` pins `>=3.11`.
2. **Report catalogue parity** — `vectra-reports-mcp/{definitions,reference}`
   are symlinks that resolve identically to the authoritative copy in
   `vectra-reports/`.
3. **Credential hygiene** — no populated values in any `.env.template`
   or `.env.example`.
4. **Bash sanity** — every `*.sh` under `skills/` passes `bash -n`.

For Python+MCP bundles, also confirm the engine still imports cleanly
(this needs network and is not in the script):

```bash
cd skills/vectra-reports && uv sync && uv run python -c "import engine"
```

If `check.sh` passes plus (for Python bundles) the engine import works,
the bundle is shippable.

---

## When to update this doc

- A new report YAML category is added (e.g. a third `skills/` folder
  shares the catalogue).
- A new channel is introduced.
- The symlink convention changes.
- A new prerequisite is added to any skill.

Otherwise leave it alone — short docs that age slowly are better than
long docs that drift.

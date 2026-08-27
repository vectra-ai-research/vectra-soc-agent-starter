#!/usr/bin/env python3
"""Assemble the `vectra-soc` Claude plugin from this repo.

The repo keeps plugin *source* under `plugin/`; this script produces the
*archive shape* a plugin install expects:

    .claude-plugin/plugin.json     from plugin/plugin.json
    .mcp.json                      from plugin/mcp.json.template  (release only)
    commands/                      from plugin/commands/
    skills/                        selected skills, symlinks dereferenced
    AGENTS.md                      repo root -- see "Why AGENTS.md" below

Profiles
--------
    dev       No `mcpServers` block. You supply the MCP server yourself via a
              hand-configured connector, so you can point it at a local
              checkout and switch branches freely. This is the profile for
              iterating: it also avoids two known plugin bugs (see below).

    beta      Includes `mcpServers`, pinned to a **Git ref** of the server
              repo and fetched by uvx. This is the profile for handing one
              .zip to a beta tester: nothing to clone, no JSON to hand-edit,
              and the host prompts for their own tenant credentials. Requires
              --server-git-ref. Use when the server capability a tester needs
              is on a branch and not yet on PyPI.

    release   Includes `mcpServers`, pinned to an exact published version.
              Requires --server-version, which MUST already be on PyPI --
              shipping skills that call tools the pinned server lacks is the
              failure this flag exists to prevent.

    --server-path /abs/path may be given with dev to point `mcpServers` at a
    local source checkout. It bakes in an absolute path, so it produces a
    bundle that only works on the machine that built it -- never send one.

Why beta exists
---------------
The three older options each fail the "send a tester one file" case:
dev makes them hand-configure a connector (and get the --from argument right);
release refuses anything not on PyPI, which is the whole point of a beta; and
--server-path embeds a path that will not exist on their disk. beta pairs the
branch skills with the branch server inside a single artifact, which is also
the pairing the tester is most likely to get wrong by hand.

Why AGENTS.md is copied into the bundle
---------------------------------------
`skills/vectra-investigator/SKILL.md` refers to `../../AGENTS.md` four times,
including for the six non-negotiable safety guardrails. From
`skills/<name>/SKILL.md` that path resolves to the bundle root, so copying
AGENTS.md there makes every reference resolve. Without it the skill points at
a file that isn't in the bundle and the guardrails silently vanish -- the
agent keeps operating, just without the rules.

Known plugin bugs the dev profile sidesteps
-------------------------------------------
* An MCP server whose `env` block references `${user_config.*}` can silently
  fail to spawn (anthropics/claude-code#51573).
* A plugin-declared MCP server silently overrides a same-named user-configured
  one (anthropics/claude-code#66474).

Usage
-----
    python scripts/bundle_plugin.py                       # dev bundle
    python scripts/bundle_plugin.py --server-path "$PWD/../vectra-ai-mcp-server"
    python scripts/bundle_plugin.py --profile beta --server-git-ref test/integration
    python scripts/bundle_plugin.py --profile beta --server-git-ref f2ce531   # reproducible
    python scripts/bundle_plugin.py --profile release --server-version 0.4.0
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PLUGIN_SRC = REPO_ROOT / "plugin"
SKILLS_DIR = REPO_ROOT / "skills"
DIST_DIR = REPO_ROOT / "dist"

SERVER_REPO = "https://github.com/vectra-ai-research/vectra-ai-mcp-server"
STARTER_REPO = "https://github.com/vectra-ai-research/vectra-soc-agent-starter"

# A 40-char hex string is a full commit SHA; anything else (branch, tag, short
# SHA) is a name that can move or be ambiguous. Used only to decide whether to
# warn -- uvx accepts all of these.
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

CRED_ENV = {
    "VECTRA_BASE_URL": "${user_config.vectra_base_url}",
    "VECTRA_CLIENT_ID": "${user_config.vectra_client_id}",
    "VECTRA_CLIENT_SECRET": "${user_config.vectra_client_secret}",
}

# PACKAGING.md "MCP-only" mode: everything that needs no local Python venv.
# vectra-reports is excluded (Python engine); vectra-reports-mcp is its
# MCP-channel equivalent and ships instead.
DEFAULT_SKILLS = [
    "vectra-investigator",
    "vectra-hunt",
    "vectra-reports-mcp",
    "vectra-pcap",
    "virustotal",
]

EXCLUDE = {
    "__pycache__", ".venv", "venv", ".env", ".env.local", ".DS_Store",
    ".pytest_cache", "build", "dist", "out", "uv.lock", "tests",
    "pyproject.toml",
}

CRED_RE = re.compile(
    r"^(VECTRA_CLIENT_ID|VECTRA_CLIENT_SECRET|VECTRA_BASE_URL|VT_API_KEY)="
    r"[A-Za-z0-9_./:\-]+",
    re.MULTILINE,
)


def fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def excluded(path: Path, root: Path) -> bool:
    rel = path.relative_to(root)
    return any(part in EXCLUDE for part in rel.parts)


def copy_skill(src: Path, dst: Path) -> None:
    """Copy a skill, dereferencing symlinks.

    vectra-reports-mcp/{definitions,reference} are symlinks into
    vectra-reports/. The MCP-only bundle does not ship vectra-reports, so those
    targets must be materialised or the skill ships with empty directories.

    NOTE: use copytree(symlinks=False), not rglob. Path.rglob does not descend
    into symlinked directories -- it yields the link itself, which is_dir()
    reports as a directory, so a naive walk creates the directory and copies
    nothing. That failure is silent and produces a skill whose report
    definitions are all missing.
    """
    shutil.copytree(
        src, dst,
        symlinks=False,                       # dereference
        ignore=shutil.ignore_patterns(*EXCLUDE),
        dirs_exist_ok=True,
    )


def check_conflict_markers(staged: Path) -> list[str]:
    """Refuse to ship an unresolved merge.

    A committed conflict marker inside a SKILL.md is invisible to every other
    check here and to the agent's own loader -- it just reads as broken prose
    in the middle of, in the worst case, the tool table.
    """
    hits = []
    for f in staged.rglob("*"):
        if not f.is_file() or f.suffix not in {".md", ".yaml", ".yml", ".json"}:
            continue
        text = f.read_text(errors="ignore")
        for n, line in enumerate(text.splitlines(), 1):
            if line.startswith(("<<<<<<< ", ">>>>>>> ")) or line.rstrip() == "=======":
                hits.append(f"{f.relative_to(staged)}:{n}")
    return hits


def install_agents_md(staged: Path, agents: Path, skills: list[str]) -> None:
    """Put AGENTS.md where a skill can actually reach it.

    Copying it only to the bundle root is not enough. Hosts extract plugin
    skills into a skills-only location, so `../../AGENTS.md` from
    skills/<name>/SKILL.md resolves outside anything that got installed and the
    six safety guardrails silently disappear. Observed in a clean-chat test on
    2026-08-23: the agent reported the file did not exist and fell back to the
    host's generic rules, losing "preserve evidence", "escalate don't act" and
    "uncertainty escalates".

    So: copy AGENTS.md into every shipped skill, and rewrite each reference to
    it by the referring file's depth. Root copy stays for hosts that do
    preserve the bundle layout.
    """
    shutil.copyfile(agents, staged / "AGENTS.md")
    for name in skills:
        skill_root = staged / "skills" / name
        shutil.copyfile(agents, skill_root / "AGENTS.md")
        for md in skill_root.rglob("*.md"):
            depth = len(md.relative_to(skill_root).parts) - 1
            text = md.read_text()
            # skills/<name>/x.md needs "AGENTS.md";
            # skills/<name>/references/x.md needs "../AGENTS.md"; etc.
            replacement = ("../" * depth) + "AGENTS.md"
            new = re.sub(r"(?:\.\./)+AGENTS\.md", replacement, text)
            if new != text:
                md.write_text(new)


def rewrite_excluded_skill_links(staged: Path, shipped: list[str]) -> int:
    """Point links at skills this bundle omits to the repo instead.

    Every shipped skill references `../vectra-reports/SKILL.md` -- it's offered
    as the Python-engine alternative to vectra-reports-mcp. The MCP-only bundle
    deliberately excludes vectra-reports (it needs a local venv), so those
    relative paths resolve to nothing once installed.

    Left alone this is worse than a broken hyperlink: the agent is told a
    sibling skill exists, tries to read it, and gets a missing file with no
    explanation. Rewriting to an absolute URL keeps the cross-reference
    honest -- the skill is real, it just isn't here. Each of these references
    names vectra-reports-mcp in the same breath, which *is* in the bundle, so
    the agent still has a working path.

    Returns the number of files changed.
    """
    changed = 0
    for md in (staged / "skills").rglob("*.md"):
        text = md.read_text()

        def _sub(m: re.Match) -> str:
            name = m.group(2)
            if name in shipped:
                return m.group(0)
            return f"{STARTER_REPO}/blob/main/skills/{name}/SKILL.md"

        new = re.sub(r"((?:\.\./)+)([a-z0-9-]+)/SKILL\.md", _sub, text)
        if new != text:
            md.write_text(new)
            changed += 1
    return changed


def check_dangling_links(staged: Path, shipped: list[str]) -> list[str]:
    """Report cross-skill links pointing at skills not in this bundle."""
    warnings = []
    for md in (staged / "skills").rglob("*.md"):
        for match in re.finditer(r"\.\./([a-z0-9-]+)/SKILL\.md", md.read_text()):
            if match.group(1) not in shipped:
                rel = md.relative_to(staged)
                warnings.append(f"{rel} -> {match.group(1)} (not in bundle)")
    return sorted(set(warnings))


def scan_for_credentials(staged: Path) -> list[str]:
    hits = []
    for f in staged.rglob("*"):
        if f.is_file() and f.suffix in {".md", ".json", ".yaml", ".yml", ".sh", ".example", ".template"}:
            try:
                if CRED_RE.search(f.read_text(errors="ignore")):
                    hits.append(str(f.relative_to(staged)))
            except OSError:
                pass
    return hits


def build_mcp_json(args) -> dict | None:
    if args.server_path:
        server_path = Path(args.server_path).expanduser().resolve()
        if not (server_path / "pyproject.toml").is_file():
            fail(f"--server-path has no pyproject.toml: {server_path}")
        return {
            "mcpServers": {
                "vectra-ai-mcp": {
                    "type": "stdio",
                    "command": "uv",
                    "args": ["--directory", str(server_path), "run",
                             "vectra-ai-mcp-server"],
                    "env": dict(CRED_ENV),
                }
            }
        }

    if args.server_git_ref:
        return {
            "mcpServers": {
                "vectra-ai-mcp": {
                    "type": "stdio",
                    "command": "uvx",
                    "args": ["--from", f"git+{SERVER_REPO}@{args.server_git_ref}",
                             "vectra-ai-mcp-server"],
                    "env": dict(CRED_ENV),
                }
            }
        }

    if args.profile == "dev":
        return None

    template = (PLUGIN_SRC / "mcp.json.template").read_text()
    return json.loads(template.replace("__SERVER_VERSION__", args.server_version))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", choices=["dev", "beta", "release"], default="dev")
    p.add_argument("--server-version",
                   help="exact published vectra-ai-mcp-server version to pin "
                        "(required for --profile release)")
    p.add_argument("--server-git-ref",
                   help="branch, tag or commit SHA of the vectra-ai-mcp-server "
                        "repo; mcpServers fetches it with uvx --from git+... "
                        "(required for --profile beta). Prefer a full commit "
                        "SHA for a reproducible bundle")
    p.add_argument("--server-path",
                   help="absolute path to a local vectra-ai-mcp-server checkout; "
                        "points mcpServers at it instead of a published package. "
                        "Machine-specific -- do not send the result to anyone")
    p.add_argument("--plugin-version",
                   help="override the version in plugin/plugin.json")
    p.add_argument("--skills", nargs="+", default=DEFAULT_SKILLS,
                   help=f"skills to include (default: {' '.join(DEFAULT_SKILLS)})")
    p.add_argument("--output", type=Path, default=DIST_DIR)
    p.add_argument("--allow-dangling", action="store_true",
                   help="downgrade dangling cross-skill links to a warning")
    args = p.parse_args()

    if args.server_git_ref and args.server_path:
        fail("--server-git-ref and --server-path both define mcpServers; pick one")

    if args.profile == "release":
        if args.server_git_ref:
            fail("--profile release means a published package. A Git ref is not "
                 "a release -- use --profile beta, or publish the version first "
                 "and pass --server-version.")
        if not args.server_version and not args.server_path:
            fail("--profile release requires --server-version (an exact version "
                 "that is already published to PyPI). Shipping skills against an "
                 "unreleased server pairs new tool calls with an old server.")
        if args.server_path:
            fail("--server-path produces a machine-specific bundle and cannot be "
                 "combined with --profile release")

    if args.profile == "beta":
        if not args.server_git_ref:
            fail("--profile beta requires --server-git-ref, e.g.\n"
                 "         --server-git-ref test/integration\n"
                 "       The point of a beta bundle is that the skills and the "
                 "server come from the same branch.")
        if args.server_version:
            fail("--server-version pins a PyPI release; --profile beta pins a "
                 "Git ref. Passing both is ambiguous.")

    manifest = json.loads((PLUGIN_SRC / "plugin.json").read_text())
    version = args.plugin_version or manifest["version"]
    if args.profile == "dev":
        # Stamp dev builds so two are distinguishable. Without this every dev
        # bundle reads 0.2.0-dev, an installer treats a same-version upload as
        # already-installed, and you end up testing the previous build while
        # reading the new source. That cost two full test cycles on 2026-08-23.
        version = f"{version}-dev.{datetime.now(timezone.utc):%Y%m%d%H%M}"
    elif args.profile == "beta":
        # Same reasoning as the dev stamp, and it matters more here: a branch
        # ref moves, so two beta bundles cut a day apart are different software
        # under an identical version string. Semver prerelease identifiers
        # allow only [0-9A-Za-z-], so the ref is slugified.
        slug = re.sub(r"[^0-9A-Za-z-]+", "-", args.server_git_ref).strip("-")
        version = f"{version}-beta.{slug}.{datetime.now(timezone.utc):%Y%m%d%H%M}"
    manifest["version"] = version
    if args.profile == "dev" and not args.server_path:
        # No server declared, so userConfig would prompt for Vectra credentials
        # that nothing consumes. The user supplies them to their own connector.
        manifest.pop("mcpServers", None)
        manifest.pop("userConfig", None)

    # ---- stage -----------------------------------------------------------
    staged = args.output / "_staging"
    if staged.exists():
        shutil.rmtree(staged, ignore_errors=True)
        if staged.exists():
            fail(f"stale staging dir could not be removed: {staged}\n"
                 f"       remove it by hand and re-run")
    staged.mkdir(parents=True)

    (staged / ".claude-plugin").mkdir()
    (staged / ".claude-plugin" / "plugin.json").write_text(
        json.dumps(manifest, indent=2) + "\n")

    shutil.copytree(PLUGIN_SRC / "commands", staged / "commands")

    for name in args.skills:
        src = SKILLS_DIR / name
        if not (src / "SKILL.md").is_file():
            fail(f"skill has no SKILL.md: {src}")
        copy_skill(src, staged / "skills" / name)

    # The guardrails live here; see install_agents_md.
    agents = REPO_ROOT / "AGENTS.md"
    if not agents.is_file():
        fail("AGENTS.md missing from repo root -- the skills reference it for "
             "the safety guardrails and the bundle would ship without them")
    install_agents_md(staged, agents, args.skills)

    # Must run before check_dangling_links, which is what catches these.
    n_rewritten = rewrite_excluded_skill_links(staged, args.skills)

    mcp = build_mcp_json(args)
    if mcp is not None:
        (staged / ".mcp.json").write_text(json.dumps(mcp, indent=2) + "\n")

    # ---- validate --------------------------------------------------------
    conflicts = check_conflict_markers(staged)
    if conflicts:
        fail("unresolved merge conflict markers in the bundle:\n       "
             + "\n       ".join(conflicts))

    leaks = scan_for_credentials(staged)
    if leaks:
        fail("possible credentials in staged bundle: " + ", ".join(leaks))

    dangling = check_dangling_links(staged, args.skills)
    if dangling:
        label = "warning" if args.allow_dangling or args.profile == "dev" else "error"
        for d in dangling:
            print(f"{label}: dangling cross-skill link: {d}", file=sys.stderr)
        if label == "error":
            fail(f"dangling cross-skill links in a {args.profile} bundle "
                 "(pass --allow-dangling to override). These should have been "
                 "rewritten to repo URLs -- if you are seeing this, the link "
                 "form is one rewrite_excluded_skill_links does not match.")

    # ---- archive ---------------------------------------------------------
    if args.profile == "dev":
        suffix = "dev"
    elif args.profile == "beta":
        # Readable filename for something being handed to a person; the unique
        # timestamp lives in the manifest version, which is what an installer
        # actually compares.
        suffix = f"beta-{re.sub(r'[^0-9A-Za-z-]+', '-', args.server_git_ref).strip('-')}"
    else:
        suffix = version
    archive = args.output / f"vectra-soc-{suffix}.zip"
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(staged.rglob("*")):
            if f.is_file():
                z.write(f, f.relative_to(staged))
    shutil.rmtree(staged, ignore_errors=True)
    if staged.exists():
        print(f"note: could not remove staging dir {staged}", file=sys.stderr)

    n_files = len(zipfile.ZipFile(archive).namelist())
    try:
        shown = archive.relative_to(REPO_ROOT)
    except ValueError:
        shown = archive
    print(f"\n{shown}")
    print(f"  profile:  {args.profile}")
    print(f"  version:  {version}")
    print(f"  skills:   {', '.join(args.skills)}")
    print(f"  commands: {len(list((PLUGIN_SRC / 'commands').glob('*.md')))}")
    print(f"  mcp:      {'declared' if mcp else 'not declared (supply your own connector)'}")
    if args.server_git_ref:
        print(f"  server:   git+{SERVER_REPO}@{args.server_git_ref}")
    elif args.server_version:
        print(f"  server:   vectra-ai-mcp-server=={args.server_version} (PyPI)")
    print(f"  files:    {n_files}")
    if n_rewritten:
        print(f"  links:    {n_rewritten} file(s) had links to omitted skills "
              f"rewritten to repo URLs")

    if args.profile == "dev":
        print("\n  dev bundle -- do not publish. Install it, then point your own")
        print("  vectra-ai-mcp connector at the checkout you want to test.")

    if args.profile == "beta":
        print("\n  beta bundle -- self-contained. The tester installs this one file")
        print("  and is prompted for their own tenant URL, client ID and secret.")
        if not FULL_SHA_RE.match(args.server_git_ref):
            print(f"\n  NOTE: '{args.server_git_ref}' is a moving ref, not a full commit SHA.")
            print("  uv caches a resolved Git revision, so a tester who installed")
            print("  earlier may keep running an older commit even after you push.")
            print("  Two consequences worth knowing before you send this:")
            print("    - 'it works for me' and 'it fails for them' can both be true")
            print("      while you are looking at different code.")
            print("    - to force a refresh they need:  uv cache clean vectra-ai-mcp-server")
            print("  For a bundle you can reason about later, pin the SHA instead:")
            print("    git -C ../vectra-ai-mcp-server rev-parse test/integration")
            print("    python scripts/bundle_plugin.py --profile beta --server-git-ref <sha>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

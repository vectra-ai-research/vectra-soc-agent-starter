#!/usr/bin/env python3
"""Bundle skills for Claude Desktop.

Produces one .zip per skill with SKILL.md at the top level, as Claude Desktop
requires. All files in the skill directory are included automatically (minus
common excludes like __pycache__, .venv, .env, etc.).

Usage:

    python scripts/bundle_desktop.py                    # → dist/<skill>.zip for each skill
    python scripts/bundle_desktop.py --output /tmp/out  # custom output directory
    python scripts/bundle_desktop.py --skill vectra-reports-mcp  # bundle one skill only
"""

from __future__ import annotations

import argparse
import re
import shutil
import textwrap
import zipfile
from pathlib import Path

# Lines like `VECTRA_CLIENT_SECRET=somevalue` in a .env.example mean the
# template was filled in with a real credential. Empty (`KEY=`) and
# commented (`#KEY=`) lines are fine.
_CRED_RE = re.compile(
    r"^(VECTRA_CLIENT_ID|VECTRA_CLIENT_SECRET|VECTRA_BASE_URL|VT_API_KEY)=[A-Za-z0-9_./:\-]+",
    re.MULTILINE,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = REPO_ROOT / "skills"
DIST_DIR = REPO_ROOT / "dist"

# Patterns to exclude everywhere
EXCLUDE_PATTERNS = {
    "__pycache__",
    ".venv",
    "venv",
    ".env",
    ".env.local",
    ".DS_Store",
    "*.egg-info",
    "*.pyc",
    "*.pyo",
    ".pytest_cache",
    "build",
    "dist",
    "out",
    "uv.lock",
}


def should_exclude(path: Path, skill_root: Path) -> bool:
    """Return True if path should be excluded from the bundle."""
    rel = path.relative_to(skill_root)
    for part in rel.parts:
        if part in EXCLUDE_PATTERNS:
            return True
        for pat in EXCLUDE_PATTERNS:
            if "*" in pat and part.endswith(pat.lstrip("*")):
                return True
    return False


def find_skill_md(skill_dir: Path) -> Path | None:
    """Find the main skill markdown file in a directory.

    Checks for SKILL.md first, then falls back to any top-level .md file
    that isn't a common support file (INSTALL.md, README.md, CHANGELOG.md).
    """
    # Preferred name
    if (skill_dir / "SKILL.md").exists():
        return skill_dir / "SKILL.md"
    # Fall back to any .md that looks like a skill definition
    skip = {"INSTALL.md", "README.md", "CHANGELOG.md", "LICENSE.md", "CONTRIBUTING.md"}
    candidates = [
        f for f in sorted(skill_dir.glob("*.md"))
        if f.name not in skip
    ]
    return candidates[0] if candidates else None


def discover_skills() -> list[Path]:
    """Return a list of skill directories (those containing a skill .md file)."""
    skills = []
    if SKILLS_DIR.is_dir():
        for child in sorted(SKILLS_DIR.iterdir()):
            if child.is_dir() and find_skill_md(child) is not None:
                skills.append(child)
    return skills


def copy_skill(skill_dir: Path, dest: Path) -> None:
    """Copy all files from skill_dir into dest, excluding unwanted patterns."""
    for item in sorted(skill_dir.iterdir()):
        if should_exclude(item, skill_dir):
            continue
        dst = dest / item.name
        if item.is_dir():
            shutil.copytree(
                item,
                dst,
                ignore=shutil.ignore_patterns(*EXCLUDE_PATTERNS),
            )
        elif item.is_file():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, dst)


def needs_setup_sh(skill_dir: Path) -> bool:
    """Return True if the skill has Python dependencies that need installing."""
    return (skill_dir / "pyproject.toml").exists()


def generate_setup_sh(skill_name: str) -> str:
    """Generate a setup.sh that bootstraps one skill."""
    return textwrap.dedent(f"""\
        #!/usr/bin/env bash
        # Setup script for {skill_name} Claude Desktop skill.
        # Run once after unpacking to create a venv and install dependencies.
        set -euo pipefail

        SKILL_DIR="$(cd "$(dirname "$0")" && pwd)"

        # Find Python 3.11+
        PYTHON=""
        for candidate in python3.13 python3.12 python3.11 python3; do
            if command -v "$candidate" &>/dev/null; then
                version=$("$candidate" -c "import sys; print(sys.version_info[:2])")
                major=$(echo "$version" | grep -oE '[0-9]+' | head -1)
                minor=$(echo "$version" | grep -oE '[0-9]+' | tail -1)
                if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
                    PYTHON="$candidate"
                    break
                fi
            fi
        done

        if [ -z "$PYTHON" ]; then
            echo "ERROR: Python 3.11+ is required but not found."
            echo "Install it with:  brew install python@3.13  (macOS)"
            echo "                  sudo apt install python3.13  (Ubuntu/Debian)"
            exit 1
        fi

        echo "Using $($PYTHON --version) at $(command -v $PYTHON)"

        echo ""
        echo "==> Installing dependencies ..."
        cd "$SKILL_DIR"
        if [ -f pyproject.toml ]; then
            "$PYTHON" -m venv .venv
            .venv/bin/pip install --quiet --upgrade pip
            .venv/bin/pip install --quiet -e .
            echo "    Installed into .venv/"
        fi
        if [ -f .env.example ] && [ ! -f .env ]; then
            cp .env.example .env
            echo "    Created .env from .env.example — edit it with your credentials"
        fi

        echo ""
        echo "Setup complete. Next steps:"
        echo "  1. Edit .env with your credentials"
        echo "  2. Add this folder as a Claude Desktop skill"
        echo ""
    """)


def assert_env_examples_are_templates(skill_dir: Path) -> None:
    """Fail fast if any .env.example under the skill has populated credentials.

    Stops a bundle from shipping real secrets — the bug that produced
    the leaked dist/vectra-reports.zip in this repo's early history.
    """
    for env_example in skill_dir.rglob(".env.example"):
        text = env_example.read_text(errors="replace")
        if _CRED_RE.search(text):
            offenders = [m.group(0) for m in _CRED_RE.finditer(text)]
            raise SystemExit(
                f"ERROR: {env_example} contains populated credential lines:\n"
                + "\n".join(f"  {line}" for line in offenders)
                + "\nReplace the values with empty placeholders before bundling."
            )


def bundle_skill(skill_dir: Path, dist: Path) -> Path:
    """Bundle a single skill into a .zip with SKILL.md at the root."""
    skill_name = skill_dir.name
    staging = dist / f"_staging_{skill_name}"

    # Refuse to bundle real credentials.
    assert_env_examples_are_templates(skill_dir)

    # Clean previous staging
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)

    # Copy all skill files flat into staging
    copy_skill(skill_dir, staging)

    # Ensure SKILL.md exists at root (Claude Desktop requirement).
    # If the skill uses a different name, copy it as SKILL.md.
    if not (staging / "SKILL.md").exists():
        skill_md = find_skill_md(skill_dir)
        if skill_md:
            shutil.copy2(skill_md, staging / "SKILL.md")

    # Generate setup.sh only if the skill has Python dependencies
    if needs_setup_sh(skill_dir):
        setup_sh = staging / "setup.sh"
        setup_sh.write_text(generate_setup_sh(skill_name))
        setup_sh.chmod(0o755)

    # Create zip
    zip_path = dist / f"{skill_name}.zip"
    if zip_path.exists():
        zip_path.unlink()

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in sorted(staging.rglob("*")):
            if file.is_file():
                arcname = str(file.relative_to(staging))
                zf.write(file, arcname=arcname)

    # Clean staging
    shutil.rmtree(staging)

    return zip_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bundle skills for Claude Desktop",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=None,
        help="Output directory for .zip files (default: dist/)",
    )
    parser.add_argument(
        "--skill", "-s",
        type=str,
        default=None,
        help="Bundle a single skill by name (default: all skills)",
    )
    args = parser.parse_args()

    dist: Path = args.output or DIST_DIR
    dist.mkdir(parents=True, exist_ok=True)

    # Discover skills
    all_skills = discover_skills()
    if not all_skills:
        print("ERROR: No skills found under skills/")
        raise SystemExit(1)

    # Filter to a single skill if requested
    if args.skill:
        skills = [s for s in all_skills if s.name == args.skill]
        if not skills:
            available = ", ".join(s.name for s in all_skills)
            print(f"ERROR: Skill '{args.skill}' not found. Available: {available}")
            raise SystemExit(1)
    else:
        skills = all_skills

    print(f"Bundling {len(skills)} skill(s) for Claude Desktop ...\n")

    for skill_dir in skills:
        zip_path = bundle_skill(skill_dir, dist)
        # Show zip contents summary
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            has_skill_md = "SKILL.md" in names
        size_kb = zip_path.stat().st_size / 1024
        has_setup = "setup.sh" in names
        print(f"  {zip_path.name}  ({size_kb:.0f} KB, {len(names)} files, SKILL.md: {has_skill_md}, setup.sh: {has_setup})")

    print(f"\nOutput: {dist}")
    print()
    print("To use in Claude Desktop:")
    print("  1. Unzip the skill into a directory")
    if any(needs_setup_sh(s) for s in skills):
        print("  2. Run ./setup.sh (if present) to install dependencies")
        print("  3. Edit .env with your credentials")
    print("  4. Add the skill directory to Claude Desktop")
    print()


if __name__ == "__main__":
    main()

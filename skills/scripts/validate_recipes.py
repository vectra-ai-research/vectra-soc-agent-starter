#!/usr/bin/env python3
"""Lint the Investigation Query SQL embedded in the hunt/investigator recipes.

The recipe library is ~2,400 lines of SQL that nothing executes and nothing
checked. A single wrong idiom propagated to 59 call sites before anyone ran one
of the affected recipes: `query-construction.md` documented
`CONTAINS(LOWER(field), LOWER('value'))` as the substring filter, but Trino's
`contains()` only accepts `(array, element)` or `(cidr, ipaddress)` — so every
recipe filtering a *string* column that way returns FUNCTION_NOT_FOUND.

This catches that class of error statically, before a query reaches a tenant.

Rules come from the MCP server's own reference material, so they cannot drift
from what the API actually accepts:

    sql_reference.md    §3.3 allowed functions, §3.5 forbidden constructs,
                        §3.6 required conventions
    schema_*.md         table and column names, and crucially which columns are
                        arrays (marked `[]`) vs scalars

Usage
-----
    python skills/scripts/validate_recipes.py
    python skills/scripts/validate_recipes.py --reference-dir <path>
    python skills/scripts/validate_recipes.py --quiet     # errors only

Without the reference material the schema-aware checks are skipped and said to
be skipped — never silently passed.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_REFERENCE = (
    REPO_ROOT.parent / "vectra-ai-mcp-server" / "src" / "vectra_mcp_server" / "resources"
)
RECIPE_DIRS = [
    REPO_ROOT / "skills" / "vectra-hunt",
    REPO_ROOT / "skills" / "vectra-investigator",
]

# §3.5 — validators reject these outright.
FORBIDDEN = [
    (re.compile(r"--"), "SQL line comment (`--`) is rejected by the API"),
    (re.compile(r"/\*"), "SQL block comment is rejected by the API"),
    (re.compile(r"\bJOIN\b", re.I), "JOIN is unsupported — use UNION or a subquery"),
    (re.compile(r"\bWITH\s+\w+\s+AS\b", re.I), "CTEs / WITH are unsupported"),
    (re.compile(r"\b(INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|MERGE|TRUNCATE)\b", re.I),
     "DDL/DML is rejected — queries must be read-only SELECTs"),
    (re.compile(r'"'), "double quotes are rejected — use single quotes for literals and aliases"),
    (re.compile(r"\bnetwork\.smtp\b", re.I),
     "network.smtp does not exist (confirmed TABLE_NOT_FOUND) despite appearing in the schema docs"),
]

# Query table names do not match schema section names. The SQL reference lists
# tables as `network.dce_rpc._all`; schema_network.md documents the same table
# under its metadata-type name, `dcerpctxn`. Without this map almost no columns
# resolve and the type checks silently pass. That mismatch is itself worth
# fixing upstream — the reference material should agree with itself.
TABLE_ALIASES = {
    "network.dce_rpc": "network.dcerpctxn",
    "network.dns": "network.dnsrecordinfo",
    "network.http": "network.httpsessioninfo",
    "network.kerberos": "network.kerberostxn",
    "network.smb_files": "network.smbfilestxn",
    "network.smb_mapping": "network.smbmappingtxn",
    "network.match": "network.suricata",
    # Entra/M365 queries resolve against schema_m365.md
    "entra.signins": "m365.signins",
    "entra.directoryaudits": "m365.directoryaudits",
    "entra.auditazureactivedirectory": "m365.auditazureactivedirectory",
    "m365.auditexchange": "m365.auditexchange",
    "m365.auditsharepoint": "m365.auditsharepoint",
    "m365.auditgeneral": "m365.auditgeneral",
    # single-table schemas
    "aws.cloudtrail": "aws.cloudtrail",
    "azurecp.operations": "azure.operations",
    "azurecp.flowlogs": "azure.flowlogs",
}


def strip_literals(text: str) -> str:
    """Blank out single-quoted literals so keyword scans don't match inside them.

    Without this, `'roleassignments/delete'` trips the DDL/DML rule — `/` is a
    word boundary, so \\bDELETE\\b matches a string value.
    """
    return re.sub(r"'[^']*'", "''", text)


SUBSTRING_FIX = (
    "use  LOWER(col) LIKE '%value%'  or  STRPOS(LOWER(col), LOWER('value')) > 0  "
    "or  REGEXP_LIKE(col, '(?i)value')"
)


@dataclass
class Finding:
    path: Path
    line: int
    severity: str          # "error" | "warning"
    rule: str
    detail: str
    snippet: str = ""


@dataclass
class Reference:
    functions: set[str] = field(default_factory=set)
    #: "network.ldap" -> {"attributes": True (is_array), "timestamp": False, ...}
    columns: dict[str, dict[str, bool]] = field(default_factory=dict)
    loaded: bool = False


def load_reference(ref_dir: Path) -> Reference:
    ref = Reference()
    sql_ref = ref_dir / "sql_reference.md"
    if not sql_ref.is_file():
        return ref

    # §3.3 — every backticked identifier in the "Allowed functions" section.
    text = sql_ref.read_text()
    m = re.search(r"### 3\.3 Allowed functions(.*?)### 3\.4", text, re.S)
    if m:
        ref.functions = {f.upper() for f in re.findall(r"`([A-Z_][A-Z0-9_]*)`", m.group(1), re.I)}

    # schema_*.md — markdown tables of | `col` | `type` | description |
    for schema in sorted(ref_dir.glob("schema_*.md")):
        db = schema.stem.replace("schema_", "")
        db = {"network": "network", "m365": "m365",
              "cloudtrail": "aws", "azurecp": "azure"}.get(db, db)
        table = None
        for line in schema.read_text().splitlines():
            h = re.match(r"^## (\w+)\s*$", line)
            if h:
                table = h.group(1).lower()
                continue
            c = re.match(r"^\|\s*`([^`]+)`\s*\|\s*`([^`]+)`\s*\|", line)
            if c and table:
                col, _type = c.group(1), c.group(2)
                is_array = "[]" in col
                key = f"{db}.{table}"
                ref.columns.setdefault(key, {})[col.replace("[]", "")] = is_array

    ref.loaded = bool(ref.functions)
    return ref


def sql_blocks(path: Path):
    """Yield (start_line, sql_text) for each fenced sql block."""
    lines = path.read_text().splitlines()
    inside, start, buf = False, 0, []
    for n, line in enumerate(lines, 1):
        if re.match(r"^\s*```\s*sql\s*$", line, re.I):
            inside, start, buf = True, n, []
            continue
        if inside and re.match(r"^\s*```\s*$", line):
            yield start, "\n".join(buf)
            inside = False
            continue
        if inside:
            buf.append(line)


def check_block(path: Path, start: int, sql: str, ref: Reference) -> list[Finding]:
    out: list[Finding] = []
    lines = sql.splitlines()

    def at(pattern: str) -> int:
        for i, l in enumerate(lines):
            if re.search(pattern, l, re.I):
                return start + 1 + i
        return start

    # ---- §3.5 forbidden constructs -------------------------------------
    # Keyword scans run against literal-stripped text; the `--` and `"` rules
    # run against the raw line, since those are about the text itself.
    for rx, msg in FORBIDDEN:
        raw_rule = rx.pattern in {"--", r"/\*", '"'}
        for i, l in enumerate(lines):
            if rx.search(l if raw_rule else strip_literals(l)):
                out.append(Finding(path, start + 1 + i, "error", "forbidden", msg, l.strip()))
                break

    # A block with no FROM is a *fragment* — a WHERE-clause snippet or a
    # column list quoted for illustration. Required-clause rules don't apply,
    # but forbidden constructs and function/type checks still do.
    is_fragment = not re.search(r"\bFROM\b", sql, re.I)

    # ---- §3.6 required conventions -------------------------------------
    if not is_fragment:
        if not re.search(r"\bSELECT\b", sql, re.I):
            out.append(Finding(path, start, "error", "required", "not a SELECT"))
        if not re.search(r"\bLIMIT\b", sql, re.I):
            out.append(Finding(path, start, "warning", "required", "no LIMIT clause"))
        if not re.search(r"\btimestamp\b", sql, re.I):
            out.append(Finding(path, start, "warning", "required",
                               "no timestamp filter — every table has a timestamp column"))

    # ---- REGEXP_LIKE arity (2 args only) -------------------------------
    for i, l in enumerate(lines):
        for m in re.finditer(r"REGEXP_LIKE\s*\(([^)]*)\)", l, re.I):
            if m.group(1).count(",") >= 2:
                out.append(Finding(path, start + 1 + i, "error", "arity",
                                   "REGEXP_LIKE accepts 2 arguments only", l.strip()))

    # ---- function whitelist -------------------------------------------
    if ref.loaded:
        for i, l in enumerate(lines):
            for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", l):
                fn = m.group(1).upper()
                if fn in {"SELECT", "WHERE", "AND", "OR", "NOT", "IN", "ON", "AS",
                          "BY", "FROM", "IF", "CASE", "WHEN", "THEN", "ELSE", "END",
                          "BETWEEN", "LIKE", "OVER", "PARTITION", "INTERVAL"}:
                    continue
                if fn not in ref.functions:
                    out.append(Finding(path, start + 1 + i, "error", "unknown-function",
                                       f"{fn}() is not in the allowed function list",
                                       l.strip()))

    # ---- tables --------------------------------------------------------
    tables = {t.lower() for t in re.findall(r"FROM\s+([\w.]+)", sql, re.I)}
    tables |= {t.lower() for t in re.findall(r"JOIN\s+([\w.]+)", sql, re.I)}
    resolved = set()
    for t in tables:
        parts = t.split(".")
        if len(parts) < 2:
            out.append(Finding(path, at(re.escape(t)), "error", "table",
                               f"'{t}' is not fully qualified (expected <db>.<table>._all)"))
            continue
        logical = f"{parts[0]}.{parts[1]}"
        resolved.add(TABLE_ALIASES.get(logical, logical))

    # ---- CONTAINS on a definitely-scalar expression --------------------
    # Schema-independent and therefore the stronger rule: LOWER/UPPER/TRIM
    # return varchar, never an array, so CONTAINS(LOWER(x), ...) cannot be the
    # (array, element) form no matter what x is. This catches columns absent
    # from the schema docs — e.g. Vectra-injected fields like
    # vectra.entity.resolved_identity — which the column check below skips.
    for i, l in enumerate(lines):
        for m in re.finditer(r"CONTAINS\s*\(\s*(LOWER|UPPER|TRIM)\s*\(", l, re.I):
            out.append(Finding(
                path, start + 1 + i, "error", "contains-on-string",
                f"CONTAINS() wrapping {m.group(1).upper()}() — that returns varchar, "
                f"never an array, so contains() has no valid signature here; "
                f"{SUBSTRING_FIX}",
                l.strip()))

    # ---- CONTAINS on a column the schema says is scalar ----------------
    if ref.loaded:
        known = {}
        for key in resolved:
            known.update({c: a for c, a in ref.columns.get(key, {}).items()})
        for i, l in enumerate(lines):
            for m in re.finditer(
                r"CONTAINS\s*\(\s*(?:LOWER|UPPER|TRIM)?\s*\(?\s*([A-Za-z_][\w.]*)", l, re.I
            ):
                col = m.group(1)
                if col.startswith("'"):
                    continue
                if col in known and not known[col]:
                    out.append(Finding(
                        path, start + 1 + i, "error", "contains-on-string",
                        f"CONTAINS() on scalar column '{col}' — contains() only accepts "
                        f"(array, element) or (cidr, ipaddress); {SUBSTRING_FIX}",
                        l.strip()))

    # ---- LOWER/UPPER/TRIM on something that is not a scalar -----------
    # Same class as CONTAINS(UPPER(array)): these take varchar, so handing them
    # a struct or an array is FUNCTION_NOT_FOUND. This is how the CloudTrail
    # recipe shipped broken — LOWER(vectra.entity.resolved_identity) on a struct
    # whose eight leaves the schema documents plainly.
    if ref.loaded:
        known = {}
        for key in resolved:
            known.update(ref.columns.get(key, {}))
        # Any documented column that is a prefix of another is an interior node.
        structs = {c.rsplit(".", 1)[0] for c in known if "." in c}
        for i, l in enumerate(lines):
            for m in re.finditer(
                rf"\b(LOWER|UPPER|TRIM)\s*\(\s*([A-Za-z_][\w.]*)\s*\)", l, re.I
            ):
                fn, col = m.group(1).upper(), m.group(2)
                bad_array = col in known and known[col]
                if col in structs or bad_array:
                    kind = "an array" if bad_array else "a struct"
                    hint = sorted(c for c in known if c.startswith(col + "."))[:1]
                    out.append(Finding(
                        path, start + 1 + i, "error", "scalar-fn-on-composite",
                        f"{fn}() on '{col}', which is {kind} — {fn}() takes varchar, "
                        f"so this is FUNCTION_NOT_FOUND"
                        + (f"; reference a leaf such as {hint[0]}" if hint else "")
                        + ("" if not bad_array else "; for arrays use "
                           f"ANY_MATCH({col}, x -> {fn}(x) = ...)"),
                        l.strip()))

    # ---- quoted alias in an identifier position -----------------------
    # `AS 'x'` is a hard SYNTAX_ERROR. `ORDER BY 'x'` is accepted as an ordering
    # on a string constant and silently returns unsorted rows, so a top-N recipe
    # written that way looks fine and is not a top-N. Bare identifiers only.
    for i, l in enumerate(lines):
        for m in re.finditer(
            r"\b(AS|ORDER\s+BY|GROUP\s+BY)\s+'([A-Za-z_]\w*)'", l, re.I
        ):
            kw = " ".join(m.group(1).upper().split())
            silent = kw != "AS"
            out.append(Finding(
                path, start + 1 + i, "error", "quoted-alias",
                f"{kw} '{m.group(2)}' — aliases must be bare identifiers. "
                + ("This is accepted as an ordering on a string constant and "
                   "returns unsorted rows with no error." if silent
                   else "This is a SYNTAX_ERROR.")
                + f" Write {kw} {m.group(2)}.",
                l.strip()))

    # ---- struct used where a leaf is needed ---------------------------
    if ref.loaded:
        for key in resolved:
            cols = ref.columns.get(key, {})
            # Every interior node, not just the first segment. Taking
            # c.split('.')[0] saw only `vectra` for
            # `vectra.entity.resolved_identity.arn`, so nested structs were
            # never checked and the broken CloudTrail recipe passed clean.
            parents = {
                ".".join(c.split(".")[:n])
                for c in cols if "." in c
                for n in range(1, len(c.split(".")))
            }
            leaves = set(cols)
            for i, l in enumerate(lines):
                for name in parents:
                    if name in leaves:
                        continue
                    # Bare struct name only: not preceded by a dot or word char,
                    # and NOT followed by a dot. `certificate.subject` is a leaf
                    # reference and must not match on `certificate`. Literals are
                    # blanked first, or a `'%{actor}%'` placeholder reads as a
                    # bare reference to the `actor` struct.
                    if re.search(rf"(?<![.\w]){re.escape(name)}(?!\s*\.)\b",
                                 strip_literals(l)):
                        example = sorted(c for c in cols if c.startswith(name + "."))[:1]
                        out.append(Finding(
                            path, start + 1 + i, "warning", "struct-as-scalar",
                            f"'{name}' is a struct in {key}; reference a leaf"
                            + (f" (e.g. {example[0]})" if example else ""),
                            l.strip()))
                        break
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--reference-dir", type=Path, default=DEFAULT_REFERENCE,
                   help="MCP server resources dir holding sql_reference.md and schema_*.md")
    p.add_argument("--quiet", action="store_true", help="report errors only")
    args = p.parse_args()

    ref = load_reference(args.reference_dir)
    if not ref.loaded:
        print(f"note: reference material not found at {args.reference_dir}", file=sys.stderr)
        print("      schema-aware checks (function whitelist, CONTAINS type, columns)",
              file=sys.stderr)
        print("      are SKIPPED — not passed. Pass --reference-dir to enable them.",
              file=sys.stderr)
        print(file=sys.stderr)

    findings: list[Finding] = []
    blocks = 0
    for d in RECIPE_DIRS:
        if not d.is_dir():
            continue
        for md in sorted(d.rglob("*.md")):
            for start, sql in sql_blocks(md):
                blocks += 1
                findings.extend(check_block(md, start, sql, ref))

    errors = [f for f in findings if f.severity == "error"]
    warnings = [f for f in findings if f.severity == "warning"]
    shown = errors if args.quiet else errors + warnings

    by_file: dict[Path, list[Finding]] = {}
    for f in shown:
        by_file.setdefault(f.path, []).append(f)

    for path in sorted(by_file):
        rel = path.relative_to(REPO_ROOT)
        print(f"\n{rel}")
        for f in sorted(by_file[path], key=lambda x: x.line):
            tag = "ERROR" if f.severity == "error" else "warn "
            print(f"  {tag} {f.line:>4}  [{f.rule}] {f.detail}")
            if f.snippet:
                print(f"              {f.snippet[:110]}")

    print(f"\n{blocks} SQL blocks checked")
    print(f"  {len(errors)} error(s), {len(warnings)} warning(s)")
    if ref.loaded:
        print(f"  reference: {len(ref.functions)} allowed functions, "
              f"{len(ref.columns)} tables, "
              f"{sum(len(v) for v in ref.columns.values())} columns")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())

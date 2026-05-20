# Security Policy

## Reporting a vulnerability

If you discover a security issue in this repository — for example, a skill
that leaks credentials, a script that executes attacker-controlled input,
or a prompt-injection vector in the agent instructions — please **do not
open a public GitHub issue**.

Instead, report it privately to `security@vectra.ai`. Include:

- A short description of the issue.
- Steps to reproduce (or a minimal proof-of-concept).
- The commit hash you tested against.
- Any impact assessment you've already done.

We aim to acknowledge reports within 3 business days.

## Scope

This repository ships **agent skills, prompts, and small helper scripts** —
it does not host a production service. The Vectra MCP server itself is a
separate project; security issues in the server should be reported through
its own channel:
<https://github.com/vectra-ai-research/vectra-ai-mcp-server>.

In scope here:

- Skill prompts or `SKILL.md` content that could be coerced into unsafe
  tool calls (e.g. data exfiltration via Investigation Query SQL, evidence
  destruction).
- Shell or Python helpers under `skills/*/scripts/` and `scripts/` that
  could be exploited via crafted IOCs, detection IDs, or file paths.
- Secrets accidentally committed to the repo or its release artifacts.

Out of scope:

- Vectra tenant or API issues unrelated to this repo's code.
- Issues in third-party MCP servers or LLM hosts.

## Secret hygiene

If a credential is ever committed to this repository, treat it as
compromised:

1. Rotate it in the originating system immediately (Vectra API client,
   VirusTotal key, etc.).
2. Open a private report so we can scrub the leak from history.

`bash skills/scripts/check.sh` runs the same secret-hygiene check used in
CI — please run it locally before opening a PR that touches `.env*`,
`dist/`, or any `*.zip` bundle.

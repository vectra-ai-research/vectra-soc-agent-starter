# Mode 1 — Ad-hoc Investigation Query

Use this mode when the user asks a single, narrow question — pivot
from a detection, hunt a specific IOC, characterize a host, or any
"show me X for Y" question.

> The companion files for this mode:
> [`query-construction.md`](query-construction.md) when no recipe
> matches and you need to author SQL,
> [`table-gotchas.md`](table-gotchas.md) for per-table quirks.

---

## Workflow

1. **Identify the domain** — read the recipe-library catalog in
   [`../SKILL.md`](../SKILL.md) and pick the right
   `references/<recipe-library>.md`.
2. **Look for a matching recipe** — open that reference file and
   scan for a recipe that already answers the question (host
   activity, IOC sweep, detection-window pivot, etc.).
3. **If a recipe matches** — copy the SQL, substitute the parameters
   (host_id, time window, IP, domain, username), and run it.
4. **If no recipe matches** — read the schema resource
   (`vectra://resources/schemas/<domain>/<table>.md`) for the
   relevant table, then author SQL following
   [`query-construction.md`](query-construction.md).
5. **Execute** — call `run_investigation(query=...,
   page_size=...)` to submit.
6. **Page through results** — call
   `get_investigation_results(request_id=..., page=N)` for additional
   pages.
7. **Summarize** — interpret rows in the conversation; pivot into
   another reference file if the data points elsewhere.

---

## Investigation decision guide

### Given a Vectra detection

1. `get_detection_details(detection_id)` to get host_id, timestamps,
   type.
2. Read [`network_sessions.md`](network_sessions.md) → "Detection
   Window Sessions" recipe.
3. Based on detection type, read the relevant protocol reference
   file from the catalog in [`../SKILL.md`](../SKILL.md).

### Given a host to investigate

1. `get_host_details(host_id)` for context.
2. Start with [`network_sessions.md`](network_sessions.md) → "Host
   Sessions" + "Failed Connections".
3. Expand to DNS, HTTP, TLS, then lateral-movement protocols as
   needed.

### Given a cloud identity to investigate

1. Read [`cloud_investigations.md`](cloud_investigations.md).
2. Start with Entra sign-ins, then expand to M365 and AWS / Azure as
   relevant.

### Given an IOC (IP, domain, username, filename)

| IOC | Where to look |
|-----|---------------|
| **IP** | Sessions, TLS (SNI), HTTP (host), Beacon (dest), Entra (`ip_address`), AWS / Azure (source IP) |
| **Domain** | DNS (query), TLS (`server_name`), HTTP (host), Beacon (`resp_domains`), X.509 (subject) |
| **Username** | Kerberos (client), NTLM (username), RADIUS (username), Entra (UPN), M365 (`user_id`), AWS (identity) |
| **Filename** | SMB Files (name), SharePoint (`source_file_name`), HTTP (uri) |

### Given a single TTP / tool name

If the user names one MITRE technique or one tool / malware family
("look for T1558.003", "are we seeing Cobalt Strike?"), use
[`ti-hunt-ttp-map.md`](ti-hunt-ttp-map.md) to translate it to the
right recipe(s) — you don't need to spin up the full TI-hunt
methodology for a single artifact.

---

## When to escalate to TI-hunt mode

Switch to [`mode-ti-hunt.md`](mode-ti-hunt.md) when the user supplies
a TI report / advisory / IOC list / named APT-malware-campaign and
asks "are we affected?" — that needs the multi-query orchestration
and the consolidated hunt report, not a single ad-hoc query.

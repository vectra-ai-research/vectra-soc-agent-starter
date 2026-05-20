#!/usr/bin/env bash
# vt-lookup.sh — standalone CLI for the VirusTotal v3 API.
#
# This is the no-framework path documented in `SKILL.md` for one-off
# lookups. For framework integration (loops over many IOCs, aggregation,
# multi-source enrichment) source `virustotal.sh` from a host runner
# that provides the `adapter_*` / `workflow_ioc_*` helper contract.
#
# Dependencies: curl, jq. base64 only required for URL IOCs.
# Env:
#   VT_API_KEY        (required) — VirusTotal v3 API key.
#   TIMEOUT_OVERRIDE  (optional) — curl --max-time (default 30s).
#
# Usage:
#   vt-lookup.sh <ioc-type> <ioc>
#   vt-lookup.sh ip 1.2.3.4
#   vt-lookup.sh domain evil.com
#   vt-lookup.sh url "https://example.com/foo"
#   vt-lookup.sh hash 5e8c9...a31f         # any of md5/sha1/sha256
#
# Output: a single-line JSON object with `summary` (compact key=value
# array) and `data` (full v3 response). Non-zero exit on errors.

set -euo pipefail

usage() {
  sed -n '3,21p' "$0" | sed 's/^# //; s/^#//'
  exit 2
}

[[ $# -ge 2 ]] || usage

ioc_type="$1"
ioc="$2"

: "${VT_API_KEY:?VT_API_KEY environment variable is not set}"
command -v curl >/dev/null || { echo "vt-lookup: curl not found" >&2; exit 3; }
command -v jq   >/dev/null || { echo "vt-lookup: jq not found"   >&2; exit 3; }

case "$ioc_type" in
  ip|ipv4|ipv6)        path="ip_addresses/${ioc}" ;;
  domain|fqdn)         path="domains/${ioc}" ;;
  hash|file|md5|sha1|sha256)
                       path="files/${ioc}" ;;
  url)
    command -v base64 >/dev/null || {
      echo "vt-lookup: base64 not found (required for URL IOCs)" >&2; exit 3; }
    enc=$(printf '%s' "$ioc" | base64 | tr -d '=' | tr '/+' '_-')
    path="urls/${enc}"
    ;;
  *)
    echo "vt-lookup: unsupported IOC type '$ioc_type'" >&2
    echo "supported: ip, domain, url, hash" >&2
    exit 4
    ;;
esac

url="https://www.virustotal.com/api/v3/${path}"
http_status=0
response=$(
  curl --silent --show-error \
       --max-time "${TIMEOUT_OVERRIDE:-30}" \
       --write-out '\n%{http_code}' \
       --header "x-apikey: ${VT_API_KEY}" \
       --header "User-Agent: vectra-soc-agent-starter/vt-lookup" \
       "$url"
) || { echo "vt-lookup: curl failed for $url" >&2; exit 5; }

http_status=$(printf '%s' "$response" | tail -n1)
body=$(printf '%s' "$response" | sed '$d')

case "$http_status" in
  200) ;;
  401|403)
    echo "vt-lookup: HTTP $http_status — check VT_API_KEY" >&2; exit 6 ;;
  404)
    jq -nc --arg ioc "$ioc" --arg t "$ioc_type" \
      '{ioc:$ioc, ioc_type:$t, found:false, summary:["malicious=0","suspicious=0"]}'
    exit 0 ;;
  429)
    echo "vt-lookup: HTTP 429 — rate limited; back off and retry" >&2; exit 7 ;;
  *)
    echo "vt-lookup: HTTP $http_status from $url" >&2
    echo "$body" >&2
    exit 8 ;;
esac

echo "$body" | jq -c --arg ioc "$ioc" --arg t "$ioc_type" '
  ($ioc) as $i | ($t) as $type |
  {
    ioc: $i,
    ioc_type: $type,
    found: true,
    summary: (
      [
        "malicious=\(.data.attributes.last_analysis_stats.malicious // 0)",
        "suspicious=\(.data.attributes.last_analysis_stats.suspicious // 0)"
      ]
      + (if (.data.type // "") == "ip_address" then
          [
            (if .data.attributes.reputation != null then "reputation=\(.data.attributes.reputation)" else empty end),
            ((.data.attributes.country // "") | tostring | select(length > 0) | "country=\(.)"),
            (if .data.attributes.asn != null then "asn=\(.data.attributes.asn)" else empty end)
          ]
        else [] end)
      | map(select((tostring | length) > 0))
    ),
    data: .
  }
'

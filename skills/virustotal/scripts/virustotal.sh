#!/usr/bin/env bash
# sourced-only: relies on caller strict mode (set -euo pipefail)

virustotal_enrich() {
  local ioc="$1" ioc_type="$2" ioc_subtype="$3" ioc_private="$4"
  if ! adapter_has_key virustotal; then
    missing_key_result virustotal "$ioc" "$ioc_type" "$ioc_subtype"
    return 0
  fi
  if ! workflow_ioc_guard_standard_intel virustotal "$ioc" "$ioc_type" "$ioc_subtype" "$ioc_private"; then
    return 0
  fi

  workflow_ioc_vt_set_object_parts "$ioc" "$ioc_type"
  local vt_resolve_rc=$?
  if [[ "$vt_resolve_rc" -eq 2 ]]; then
    json_result virustotal "$ioc" "$ioc_type" "$ioc_subtype" false false "base64 utility missing" "{}" "{}"
    return 0
  fi
  if [[ "$vt_resolve_rc" -ne 0 ]]; then
    json_result virustotal "$ioc" "$ioc_type" "$ioc_subtype" false false "unsupported IOC type" "{}" "{}"
    return 0
  fi

  local url
  url=$(workflow_ioc_vt_object_base_url)
  if ! adapter_fetch_json_or_error \
    virustotal \
    "VirusTotal" \
    "$ioc" \
    "$ioc_type" \
    "$ioc_subtype" \
    "$url" \
    "VirusTotal request failed" \
    "VirusTotal returned non-JSON" \
    --header "x-apikey: ${VT_API_KEY}" \
    --header "User-Agent: codex-ioc-workflow/1.0" \
    --source "VirusTotal" \
    --max-time "${TIMEOUT_OVERRIDE:-30}"; then
    return 0
  fi
  local response="$ADAPTER_FETCH_RESPONSE"
  local summary
  summary=$(echo "$response" | jq -c '
    (
      [
        "malicious=\(.data.attributes.last_analysis_stats.malicious // 0)",
        "suspicious=\(.data.attributes.last_analysis_stats.suspicious // 0)"
      ]
      +
      (if (.data.type // "") == "ip_address" then
        [
          (if .data.attributes.reputation != null then "reputation=\(.data.attributes.reputation)" else empty end),
          ((.data.attributes.country // "") | tostring | select(length > 0) | "country=\(.)"),
          (if .data.attributes.asn != null then "asn=\(.data.attributes.asn)" else empty end)
        ]
      else
        []
      end)
    ) | map(select((tostring | length) > 0))
  ')
  adapter_emit_success_with_summary virustotal "virustotal" "$ioc" "$ioc_type" "$ioc_subtype" "$response" "$summary"
}

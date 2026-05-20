#!/usr/bin/env bash
# Single-pass tshark triage for a Vectra detection PCAP.
#
# Reads a PCAP/PCAPNG file once and emits a structured JSON document plus a
# scannable human-readable summary covering:
#
#   - TLS Client Hello tuples, SNI, ALPN, JA3/JA3S (and JA4 if a tshark
#     dissector exposes the field).
#   - HTTP requests carrying authentication headers.
#   - Windows auth (NTLM + Kerberos) merged into a single section.
#   - SSH userauth attempts.
#   - DNS queries (with NXDOMAIN counts and fast-flux candidates).
#   - SMB2 TreeConnect events (admin shares flagged).
#   - DCE/RPC interface bindings.
#   - Frames containing literal "ProcessCommandLine:" strings.
#
# Usage:
#   ./pcap-context.sh <capture.pcap>           # Human summary + JSON dump
#   ./pcap-context.sh --json <capture.pcap>    # JSON only (pipe to jq)

set -euo pipefail

usage() {
    cat <<USAGE
Usage: $(basename "$0") [--json] <pcap_file>

Options:
  -h, --help    Show this message
  -j, --json    Emit JSON only (skip the human-readable summary)
USAGE
}

JSON_ONLY=0
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -j|--json) JSON_ONLY=1; shift ;;
        *)         ARGS+=("$1"); shift ;;
    esac
done
set -- "${ARGS[@]:-}"

if [[ $# -lt 1 || -z "${1:-}" ]]; then
    usage >&2
    exit 2
fi

PCAP="$1"
[[ -f "$PCAP" ]] || { echo "Error: PCAP file not found: $PCAP" >&2; exit 2; }

require_cmd() {
    local cmd="$1" purpose="${2:-this script}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: required dependency '$cmd' is not installed (needed for $purpose)." >&2
        case "$cmd" in
            tshark)  echo "Install: brew install wireshark   (macOS) or apt install tshark (Debian/Ubuntu)" >&2 ;;
            jq)      echo "Install: brew install jq          (macOS) or apt install jq     (Debian/Ubuntu)" >&2 ;;
            python3) echo "Install: brew install python      (macOS) or apt install python3 (Debian/Ubuntu)" >&2 ;;
        esac
        exit 2
    fi
}
require_cmd tshark  "PCAP analysis"
require_cmd jq      "JSON assembly"
require_cmd python3 "tabular field parsing"

FIELD_CACHE=$(mktemp)
TEMP_FILES=("$FIELD_CACHE")
cleanup() { rm -f "${TEMP_FILES[@]}"; }
trap cleanup EXIT
tshark -G fields 2>/dev/null | awk -F '\t' 'NF >= 3 { print $3 }' > "$FIELD_CACHE" || true

field_available() { grep -Fxq "$1" "$FIELD_CACHE"; }

# ─── Core helpers ─────────────────────────────────────────────────────────────

run_tshark_fields() {
    local filter="$1"; shift
    local args=()
    for f in "$@"; do args+=("-e" "$f"); done
    [[ ${#args[@]} -eq 0 ]] && return 0
    local err; err=$(mktemp); TEMP_FILES+=("$err")
    set +e
    tshark -r "$PCAP" -Y "$filter" -T fields "${args[@]}" \
        -E separator=$'\t' -E quote=d -E occurrence=f -E header=n 2>"$err"
    local rc=$?
    set -e
    [[ $rc -ne 0 ]] && { cat "$err" >&2; echo "Error: tshark failed for filter: $filter" >&2; return $rc; }
    [[ -s "$err" ]] && cat "$err" >&2
    return 0
}

parse_tabular_records() {
    local spec_json="$1" raw_file="$2"
    [[ -s "$raw_file" ]] || { echo "[]"; return; }
    python3 - "$spec_json" "$PCAP" "$raw_file" <<'PY'
import sys, csv, json
from datetime import datetime, timezone
spec = json.loads(sys.argv[1])
pcap_file = sys.argv[2]
reader = csv.reader(open(sys.argv[3], newline='', encoding='utf-8', errors='replace'),
                    delimiter='\t', quotechar='"', escapechar='\\')
records = []
for row in reader:
    if not row or all(c == '' for c in row): continue
    rec = {"pcap_file": pcap_file}
    for idx, entry in enumerate(spec):
        key = entry["key"]
        value = row[idx] if idx < len(row) else ''
        if value == '': value = None
        rec[key] = value
        if key == 'timestamp_epoch' and value is not None:
            try: rec['timestamp'] = datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
            except ValueError: rec['timestamp'] = value
    records.append(rec)
print(json.dumps(records))
PY
}

# collect_section FILTER SPEC_ARRAY_NAME → outputs JSON array of records.
# SPEC entries are "key|tshark_field" pairs; missing fields are skipped.
collect_section() {
    local filter="$1" spec_var="$2"
    local -n specs="$spec_var"
    local -a keys=() fields=()
    for item in "${specs[@]}"; do
        local key="${item%%|*}" field="${item#*|}"
        if field_available "$field"; then keys+=("$key"); fields+=("$field"); fi
    done
    if [[ ${#fields[@]} -eq 0 ]]; then echo "[]"; return; fi

    local raw; raw=$(mktemp); TEMP_FILES+=("$raw")
    run_tshark_fields "$filter" "${fields[@]}" > "$raw" || { echo "[]"; return; }
    [[ -s "$raw" ]] || { echo "[]"; return; }

    local spec_items=()
    for idx in "${!keys[@]}"; do
        spec_items+=("{\"key\":\"${keys[$idx]}\",\"field\":\"${fields[$idx]}\"}")
    done
    local spec_json="[$(IFS=,; echo "${spec_items[*]}")]"
    parse_tabular_records "$spec_json" "$raw"
}

process_command_lines() {
    local raw
    raw=$(tshark -r "$PCAP" -Y 'frame contains "ProcessCommandLine"' -V 2>/dev/null \
        | awk '
            /^Frame/ { frame=$2; sub(/:$/, "", frame); }
            /Epoch Time:/ { time=$3; }
            /ProcessCommandLine:/ {
                cmd=$0; sub(/.*ProcessCommandLine: */, "", cmd);
                print frame "\t" time "\t" cmd;
            }
          ')
    [[ -z "$raw" ]] && { echo "[]"; return; }
    local raw_file; raw_file=$(mktemp); TEMP_FILES+=("$raw_file")
    printf '%s\n' "$raw" > "$raw_file"
    parse_tabular_records '[
      {"key":"frame_number","field":"frame_number"},
      {"key":"timestamp_epoch","field":"timestamp_epoch"},
      {"key":"command_line","field":"command_line"}
    ]' "$raw_file"
}

# ─── Protocol Section Definitions ────────────────────────────────────────────

TLS_SPECS=(
    "frame_number|frame.number" "timestamp_epoch|frame.time_epoch"
    "src_ip|ip.src" "dst_ip|ip.dst" "src_port|tcp.srcport" "dst_port|tcp.dstport"
    "tls_version|tls.handshake.version" "ciphersuite|tls.handshake.ciphersuite"
    "sni|tls.handshake.extensions_server_name" "alpn|tls.handshake.extensions_alpn_str"
    "ja3|tls.handshake.ja3" "ja3s|tls.handshake.ja3s"
    "cert_subject|x509ce.subject" "cert_san|x509ce.subjectAltName_element"
)
HTTP_SPECS=(
    "frame_number|frame.number" "timestamp_epoch|frame.time_epoch"
    "src_ip|ip.src" "dst_ip|ip.dst" "src_port|tcp.srcport" "dst_port|tcp.dstport"
    "method|http.request.method" "uri|http.request.uri" "host|http.host"
    "user_agent|http.user_agent" "authorization|http.authorization" "auth_basic|http.authbasic"
    "status_code|http.response.code" "status_phrase|http.response.phrase"
)
NTLM_SPECS=(
    "frame_number|frame.number" "timestamp_epoch|frame.time_epoch"
    "src_ip|ip.src" "dst_ip|ip.dst" "src_port|tcp.srcport" "dst_port|tcp.dstport"
    "server_name|ntlmssp.server_name" "username|ntlmssp.auth.username"
    "workstation|ntlmssp.negotiate.callingworkstation" "domain|ntlmssp.auth.domain"
    "target|ntlmssp.challenge.target_name"
)
KERB_SPECS=(
    "frame_number|frame.number" "timestamp_epoch|frame.time_epoch"
    "src_ip|ip.src" "dst_ip|ip.dst" "src_port|tcp.srcport" "dst_port|tcp.dstport"
    "principal|kerberos.cname_string" "realm|kerberos.crealm"
    "service_name|kerberos.sname_string" "kdc_host|kerberos.kdc"
)
SSH_SPECS=(
    "frame_number|frame.number" "timestamp_epoch|frame.time_epoch"
    "src_ip|ip.src" "dst_ip|ip.dst" "src_port|tcp.srcport" "dst_port|tcp.dstport"
    "username|ssh.userauth_user_name" "service|ssh.userauth_service_name"
    "method|ssh.userauth_method_name"
)
DNS_SPECS=(
    "frame_number|frame.number" "timestamp_epoch|frame.time_epoch"
    "src_ip|ip.src" "dst_ip|ip.dst" "query_name|dns.qry.name" "query_type|dns.qry.type"
    "response_addr|dns.resp.addr" "response_name|dns.resp.name" "response_type|dns.resp.type"
    "response_ttl|dns.a.ttl" "response_code|dns.flags.rcode" "answer_count|dns.count.answers"
)
SHARE_SPECS=(
    "frame_number|frame.number" "timestamp_epoch|frame.time_epoch"
    "src_ip|ip.src" "dst_ip|ip.dst" "share_name|smb2.share_name" "tree_path|smb2.tree"
    "cmd|smb2.cmd" "username|ntlmssp.auth.username"
)
RPC_SPECS=(
    "frame_number|frame.number" "timestamp_epoch|frame.time_epoch"
    "src_ip|ip.src" "dst_ip|ip.dst" "interface_uuid|dcerpc.bind.iface.uuid"
    "interface_name|dcerpc.bind.iface.name" "interface_version|dcerpc.bind.if_version"
    "endpoint|dcerpc.bind.endpoint"
)

# ─── Collect all sections ─────────────────────────────────────────────────────

NOW=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
JA4_AVAILABLE=0
field_available "ja4" && JA4_AVAILABLE=1
[[ $JA4_AVAILABLE -eq 1 ]] && TLS_SPECS+=("ja4|ja4")

TLS_FILE=$(mktemp);     TEMP_FILES+=("$TLS_FILE")
HTTP_FILE=$(mktemp);    TEMP_FILES+=("$HTTP_FILE")
NTLM_FILE=$(mktemp);    TEMP_FILES+=("$NTLM_FILE")
KERB_FILE=$(mktemp);    TEMP_FILES+=("$KERB_FILE")
WINDOWS_FILE=$(mktemp); TEMP_FILES+=("$WINDOWS_FILE")
SSH_FILE=$(mktemp);     TEMP_FILES+=("$SSH_FILE")
DNS_FILE=$(mktemp);     TEMP_FILES+=("$DNS_FILE")
SHARE_FILE=$(mktemp);   TEMP_FILES+=("$SHARE_FILE")
RPC_FILE=$(mktemp);     TEMP_FILES+=("$RPC_FILE")
PROCESS_FILE=$(mktemp); TEMP_FILES+=("$PROCESS_FILE")

collect_section 'tls.handshake.type == 1'           TLS_SPECS   > "$TLS_FILE"
collect_section 'http.authorization || http.authbasic' HTTP_SPECS > "$HTTP_FILE"
collect_section 'ntlmssp'                           NTLM_SPECS  > "$NTLM_FILE"
collect_section 'kerberos'                          KERB_SPECS  > "$KERB_FILE"
jq -s 'add // []' "$NTLM_FILE" "$KERB_FILE"                    > "$WINDOWS_FILE"
collect_section 'ssh'                               SSH_SPECS   > "$SSH_FILE"
collect_section 'dns'                               DNS_SPECS   > "$DNS_FILE"
collect_section 'smb2.cmd == 3 && smb2.tree'        SHARE_SPECS > "$SHARE_FILE"
collect_section 'dcerpc'                            RPC_SPECS   > "$RPC_FILE"
process_command_lines                                          > "$PROCESS_FILE"

# ─── Build final JSON ─────────────────────────────────────────────────────────

FINAL_FILE=$(mktemp); TEMP_FILES+=("$FINAL_FILE")
jq -n --arg pcap "$PCAP" --arg generated "$NOW" --argjson ja4 "$JA4_AVAILABLE" \
  --slurpfile tls     "$TLS_FILE" \
  --slurpfile http    "$HTTP_FILE" \
  --slurpfile windows "$WINDOWS_FILE" \
  --slurpfile ssh     "$SSH_FILE" \
  --slurpfile dns     "$DNS_FILE" \
  --slurpfile shares  "$SHARE_FILE" \
  --slurpfile rpc     "$RPC_FILE" \
  --slurpfile process "$PROCESS_FILE" \
'
def keyword_counts(field):
  map(select(.[field] != null)) | sort_by(.[field]) | group_by(.[field])
  | map({value: .[0][field], count: length}) | sort_by(-.count);

def tls_section:
  ($tls[0] // []) as $r |
  ($r | map(.tuple = ((.src_ip // "?") + ":" + (.src_port // "?") + " -> " + (.dst_ip // "?") + ":" + (.dst_port // "?")))
       | map(.confidence = (if .ja4 then "ja4" else "tuple" end))) as $e |
  {
    ja4_available: ($ja4 == 1),
    records: $e,
    tuples: ($e | sort_by(.tuple) | group_by(.tuple) | map({
      tuple: .[0].tuple, count: length, ja3: .[0].ja3, ja3s: .[0].ja3s,
      sni: .[0].sni, alpn: .[0].alpn, cipher: .[0].ciphersuite, tls_version: .[0].tls_version,
      first_seen: (map(.timestamp) | map(select(.!=null)) | if length==0 then null else min end),
      last_seen:  (map(.timestamp) | map(select(.!=null)) | if length==0 then null else max end),
      ja4_present: (map(select(.ja4!=null)) | length > 0)
    }) | .[0:12]),
    summary: {
      total_tls: ($e|length),
      unique_tuples: ($e | map(.tuple) | unique | length),
      first_seen: ($e | map(.timestamp) | map(select(.!=null)) | sort | if length==0 then null else .[0] end),
      last_seen:  ($e | map(.timestamp) | map(select(.!=null)) | sort | if length==0 then null else .[-1] end),
      top_ja3:    ($e | keyword_counts("ja3")[0:5]),
      top_ja3s:   ($e | keyword_counts("ja3s")[0:5]),
      top_sni:    ($e | keyword_counts("sni")[0:5]),
      top_alpn:   ($e | keyword_counts("alpn")[0:5]),
      top_ciphers:($e | keyword_counts("ciphersuite")[0:3])
    }
  };

def http_section:
  ($http[0] // []) as $r |
  { records: $r,
    summary: {
      total_attempts: ($r|length),
      failure_count: ($r | map(select((.status_code|tonumber? // 0) >= 400)) | length),
      top_user_agents: ($r | keyword_counts("user_agent")[0:4]),
      top_targets: ($r | map(.host // .uri // "<unknown>") | map(select(.!="<unknown>")) | sort | group_by(.) | map({value:.[0],count:length}) | sort_by(-.count) | .[0:4])
    }
  };

def windows_section:
  ($windows[0] // []) as $r |
  { records: $r,
    summary: { total_events: ($r|length),
      top_usernames: ($r | keyword_counts("username")[0:4]),
      top_servers:   ($r | keyword_counts("server_name")[0:4]),
      top_realms:    ($r | keyword_counts("realm")[0:4])
    }
  };

def ssh_section:
  ($ssh[0] // []) as $r |
  { records: $r,
    summary: { total_sessions: ($r|length),
      unique_users:  ($r | map(.username) | map(select(.!=null)) | unique | length),
      top_services:  ($r | keyword_counts("service")[0:4]),
      top_methods:   ($r | keyword_counts("method")[0:4])
    }
  };

def dns_section:
  ($dns[0] // []) as $r |
  { records: $r,
    summary: {
      total_queries: ($r|length),
      unique_domains: ($r | map(.query_name) | map(select(.!=null)) | unique | length),
      nxdomain_count: ($r | map(select((.response_code|tonumber? // 0)==3)) | length),
      top_domains: ($r | keyword_counts("query_name")[0:5]),
      fast_flux_candidates: ($r | group_by(.query_name) | map({domain:.[0].query_name, unique_ips:(map(.response_addr)|map(select(.!=null))|unique|length)}) | sort_by(-.unique_ips) | .[0:5])
    }
  };

def shares_section:
  ($shares[0] // []) as $r |
  { records: $r,
    summary: {
      total_treeconnects: ($r|length),
      admin_shares: ($r | map(select((.share_name // "") | test("(?i)(admin\\$|c\\$|ipc\\$)"))) | map(.share_name) | unique),
      sensitive_paths: ($r | map(select(.tree_path != null and (.tree_path | test("\\\\")))) | map(.tree_path) | unique)
    }
  };

def rpc_section:
  ($rpc[0] // []) as $r |
  { records: $r,
    summary: { total_bindings: ($r|length),
      unique_interfaces: ($r | map(.interface_uuid) | map(select(.!=null)) | unique | length)
    }
  };

def process_section:
  ($process[0] // []) as $r |
  { records: $r,
    summary: { total_commands: ($r|length), sample_commands: ($r | map(.command_line) | .[0:5]) }
  };

{
  pcap_file: $pcap,
  generated_at: $generated,
  tls: tls_section,
  http_auth: http_section,
  windows_auth: windows_section,
  ssh: ssh_section,
  dns: dns_section,
  shares: shares_section,
  rpc: rpc_section,
  process_command_lines: process_section
}' > "$FINAL_FILE"

# ─── Output ──────────────────────────────────────────────────────────────────

if [[ "$JSON_ONLY" -eq 1 ]]; then
    cat "$FINAL_FILE"
    exit 0
fi

# Minimal inline formatter (no external common/ helpers).
COLOR_ENABLED=0
[[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]] && [[ -z "${NO_COLOR:-}" ]] && COLOR_ENABLED=1
_b() { [[ $COLOR_ENABLED -eq 1 ]] && printf '\033[1m%s\033[0m' "$1" || printf '%s' "$1"; }
_c() { [[ $COLOR_ENABLED -eq 1 ]] && printf '\033[0;36m%s\033[0m' "$1" || printf '%s' "$1"; }

section() {
    local title="$1"; shift
    echo "=== $(_b "$title") ==="
    echo ""
    while [[ $# -gt 0 ]]; do
        local key="$1" value="${2:-}"
        printf "  %s: %s\n" "$(_c "$key")" "$value"
        shift 2 || true
    done
    echo ""
}

TLS_TOTAL=$(jq -r '.tls.summary.total_tls'                              "$FINAL_FILE")
TLS_JA4=$(jq -r '.tls.ja4_available'                                    "$FINAL_FILE")
TOP_JA3=$(jq -r '.tls.summary.top_ja3 | map(.value + " (" + (.count|tostring) + ")") | join(", ")' "$FINAL_FILE")
TOP_SNI=$(jq -r '.tls.summary.top_sni | map(.value + " (" + (.count|tostring) + ")") | join(", ")' "$FINAL_FILE")
HTTP_TOTAL=$(jq -r '.http_auth.summary.total_attempts'                  "$FINAL_FILE")
HTTP_FAILURES=$(jq -r '.http_auth.summary.failure_count'                "$FINAL_FILE")
WINDOWS_EVENTS=$(jq -r '.windows_auth.summary.total_events'             "$FINAL_FILE")
SSH_SESSIONS=$(jq -r '.ssh.summary.total_sessions'                      "$FINAL_FILE")
SHARE_ADMIN=$(jq -r '.shares.summary.admin_shares | join(", ")'         "$FINAL_FILE")
SHARE_COUNT=$(jq -r '.shares.summary.total_treeconnects'                "$FINAL_FILE")
DNS_NX=$(jq -r '.dns.summary.nxdomain_count'                            "$FINAL_FILE")
DNS_QUERIES=$(jq -r '.dns.summary.total_queries'                        "$FINAL_FILE")
RPC_BINDINGS=$(jq -r '.rpc.summary.total_bindings'                      "$FINAL_FILE")
PROCESS_COUNT=$(jq -r '.process_command_lines.summary.total_commands'   "$FINAL_FILE")

echo "========================================"
echo "  $(_b "Vectra PCAP Triage Summary")"
echo "========================================"
printf "  %-12s %s\n" "PCAP:"      "$PCAP"
printf "  %-12s %s\n" "Generated:" "$NOW"
echo "========================================"
echo ""

section "TLS" \
  "Client Hellos" "$TLS_TOTAL packets" \
  "JA4 plugin"    "$(if [[ "$TLS_JA4" == "true" ]]; then echo "available"; else echo "missing (optional — install JA4 dissector)"; fi)" \
  "Top SNI"       "${TOP_SNI:-(none)}" \
  "Top JA3"       "${TOP_JA3:-(none)}"

section "Auth & Identity" \
  "HTTP auth"     "$HTTP_TOTAL attempts ($HTTP_FAILURES failures)" \
  "Windows auth"  "$WINDOWS_EVENTS NTLM/Kerberos exchanges" \
  "SSH"           "$SSH_SESSIONS sessions"

section "Lateral Movement" \
  "SMB TreeConnect"    "$SHARE_COUNT events (admin shares: ${SHARE_ADMIN:-none})" \
  "RPC"                "$RPC_BINDINGS endpoint bindings" \
  "ProcessCommandLine" "$PROCESS_COUNT snippets"

section "DNS" \
  "Queries"   "$DNS_QUERIES total" \
  "NXDomain"  "$DNS_NX responses" \
  "Fast-flux" "$(jq -r '.dns.summary.fast_flux_candidates | length' "$FINAL_FILE") candidate domain(s)"

section "Next Steps" \
  "1" "Cross-reference TLS tuples / SNIs with the Vectra detection's expected destinations." \
  "2" "Feed observable IPs/domains/hashes through the virustotal skill for external corroboration." \
  "3" "If shares/RPC/Windows-auth indicators are unexpected, pivot to vectra-hunt for east-west history."

echo "=== $(_b "RAW DATA") ==="
echo ""
jq . "$FINAL_FILE"
echo ""

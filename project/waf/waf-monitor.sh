#!/bin/bash

# ╔══════════════════════════════════════════════════════╗
# ║           WAF Monitor - ModSecurity Audit Log        ║
# ╚══════════════════════════════════════════════════════╝

# Default log path
LOG_FILE="${1:-/var/log/modsecurity/audit/audit.log}"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# Check dependencies
for cmd in jq awk sort uniq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}[ERROR] Missing dependency: $cmd${NC}"
        exit 1
    fi
done

# Check log file
if [[ ! -f "$LOG_FILE" ]]; then
    echo -e "${RED}[ERROR] Log file not found: $LOG_FILE${NC}"
    echo -e "${DIM}Usage: $0 [path/to/audit.log]${NC}"
    exit 1
fi

# ─── Parse log ───────────────────────────────────────────────────────────────

# Read all valid JSON lines
LOGS=$(grep -v '^$' "$LOG_FILE")
TOTAL=$(echo "$LOGS" | wc -l | tr -d ' ')

# Count by HTTP status
count_by_status() {
    echo "$LOGS" | jq -r '.transaction.response.http_code' 2>/dev/null | sort | uniq -c | sort -rn
}

# WAF blocked (403 with messages)
WAF_BLOCKED=$(echo "$LOGS" | jq -r 'select(.transaction.response.http_code == 403) | select(.transaction.messages | length > 0) | .transaction.unique_id' 2>/dev/null | wc -l | tr -d ' ')

# Rate limited (429)
RATE_LIMITED=$(echo "$LOGS" | jq -r 'select(.transaction.response.http_code == 429) | .transaction.unique_id' 2>/dev/null | wc -l | tr -d ' ')

# Top attacking IPs
top_ips() {
    echo "$LOGS" | jq -r 'select(.transaction.messages | length > 0) | .transaction.client_ip' 2>/dev/null \
        | sort | uniq -c | sort -rn | head -10
}

# Top targeted URIs
top_uris() {
    echo "$LOGS" | jq -r 'select(.transaction.messages | length > 0) | .transaction.request.uri' 2>/dev/null \
        | sed 's/?.*//' \
        | sort | uniq -c | sort -rn | head -10
}

# Attack type breakdown (from rule messages)
attack_types() {
    echo "$LOGS" | jq -r '.transaction.messages[]?.message' 2>/dev/null \
        | grep -oP '(SQL Injection|XSS|SSRF|File Upload|Method is not allowed|Anomaly Score|Custom rule|Injection|Scanner|LFI|RFI|Command Injection|NoScript)' \
        | sort | uniq -c | sort -rn | head -10
}

# Triggered rule IDs
top_rules() {
    echo "$LOGS" | jq -r '.transaction.messages[]?.details.ruleId' 2>/dev/null \
        | sort | uniq -c | sort -rn | head -10
}

# Recent blocked events (last 15)
recent_events() {
    echo "$LOGS" | jq -r '
        select(.transaction.messages | length > 0) |
        select(.transaction.response.http_code == 403 or .transaction.response.http_code == 429) |
        [
            .transaction.time_stamp[4:20],
            .transaction.client_ip,
            (.transaction.response.http_code | tostring),
            .transaction.request.method,
            (.transaction.request.uri | .[0:50]),
            (.transaction.messages[0].message // "-" | .[0:45])
        ] | @tsv
    ' 2>/dev/null | tail -15
}

# ─── Display ─────────────────────────────────────────────────────────────────

clear

echo -e "${BOLD}${CYAN}"
echo "  ╔══════════════════════════════════════════════════════════╗"
echo "  ║          🛡️  WAF Monitor - ModSecurity Audit Log         ║"
echo "  ╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${DIM}  Log file : ${LOG_FILE}${NC}"
echo -e "${DIM}  Generated: $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo ""

# ── Summary stats ─────────────────────────────────────────────────
echo -e "${BOLD}${BLUE}  ── TỔNG QUAN ──────────────────────────────────────────────${NC}"
printf "  %-25s %s\n" "Tổng transactions:" "${BOLD}${TOTAL}${NC}"
printf "  %-25s %s\n" "WAF blocked (403):" "${BOLD}${RED}${WAF_BLOCKED}${NC}"
printf "  %-25s %s\n" "Rate limited (429):" "${BOLD}${YELLOW}${RATE_LIMITED}${NC}"
echo ""

# ── Status code breakdown ─────────────────────────────────────────
echo -e "${BOLD}${BLUE}  ── STATUS CODE ────────────────────────────────────────────${NC}"
while IFS= read -r line; do
    count=$(echo "$line" | awk '{print $1}')
    code=$(echo "$line" | awk '{print $2}')
    case "$code" in
        403) color=$RED ;;
        429) color=$YELLOW ;;
        5*) color=$MAGENTA ;;
        2*) color=$GREEN ;;
        *) color=$NC ;;
    esac
    bar=$(printf '█%.0s' $(seq 1 $((count > 40 ? 40 : count))))
    printf "  ${color}%-6s${NC} %-6s %s\n" "$code" "($count)" "${color}${bar}${NC}"
done < <(count_by_status)
echo ""

# ── Attack types ─────────────────────────────────────────────────
echo -e "${BOLD}${BLUE}  ── LOẠI TẤN CÔNG ──────────────────────────────────────────${NC}"
ATTACK_DATA=$(attack_types)
if [[ -z "$ATTACK_DATA" ]]; then
    echo -e "  ${DIM}Không có dữ liệu${NC}"
else
    while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        type=$(echo "$line" | awk '{$1=""; print $0}' | xargs)
        printf "  ${RED}%-8s${NC} %s\n" "[$count]" "$type"
    done <<< "$ATTACK_DATA"
fi
echo ""

# ── Top IPs ─────────────────────────────────────────────────────
echo -e "${BOLD}${BLUE}  ── TOP IP TẤN CÔNG ────────────────────────────────────────${NC}"
TOP_IP_DATA=$(top_ips)
if [[ -z "$TOP_IP_DATA" ]]; then
    echo -e "  ${DIM}Không có dữ liệu${NC}"
else
    while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        ip=$(echo "$line" | awk '{print $2}')
        printf "  ${YELLOW}%-8s${NC} %s\n" "[$count]" "$ip"
    done <<< "$TOP_IP_DATA"
fi
echo ""

# ── Top URIs ────────────────────────────────────────────────────
echo -e "${BOLD}${BLUE}  ── TOP URI BỊ TẤN CÔNG ───────────────────────────────────${NC}"
TOP_URI_DATA=$(top_uris)
if [[ -z "$TOP_URI_DATA" ]]; then
    echo -e "  ${DIM}Không có dữ liệu${NC}"
else
    while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        uri=$(echo "$line" | awk '{$1=""; print $0}' | xargs)
        printf "  ${CYAN}%-8s${NC} %s\n" "[$count]" "$uri"
    done <<< "$TOP_URI_DATA"
fi
echo ""

# ── Top Rule IDs ─────────────────────────────────────────────────
echo -e "${BOLD}${BLUE}  ── RULE BỊ KÍCH HOẠT NHIỀU NHẤT ──────────────────────────${NC}"
TOP_RULE_DATA=$(top_rules)
if [[ -z "$TOP_RULE_DATA" ]]; then
    echo -e "  ${DIM}Không có dữ liệu${NC}"
else
    while IFS= read -r line; do
        count=$(echo "$line" | awk '{print $1}')
        rule=$(echo "$line" | awk '{print $2}')
        printf "  ${MAGENTA}%-8s${NC} Rule ID: %s\n" "[$count]" "$rule"
    done <<< "$TOP_RULE_DATA"
fi
echo ""

# ── Recent blocked events ────────────────────────────────────────
echo -e "${BOLD}${BLUE}  ── 15 SỰ KIỆN BỊ CHẶN GẦN NHẤT ──────────────────────────${NC}"
printf "  ${BOLD}${DIM}%-20s %-15s %-5s %-7s %-52s %s${NC}\n" \
    "THỜI GIAN" "IP" "CODE" "METHOD" "URI" "RULE MESSAGE"
echo -e "  ${DIM}$(printf '─%.0s' {1..120})${NC}"

RECENT_DATA=$(recent_events)
if [[ -z "$RECENT_DATA" ]]; then
    echo -e "  ${DIM}Không có sự kiện bị chặn${NC}"
else
    while IFS=$'\t' read -r ts ip code method uri msg; do
        case "$code" in
            403) code_color=$RED ;;
            429) code_color=$YELLOW ;;
            *) code_color=$NC ;;
        esac
        printf "  ${DIM}%-20s${NC} ${CYAN}%-15s${NC} ${code_color}%-5s${NC} ${GREEN}%-7s${NC} %-52s ${DIM}%s${NC}\n" \
            "$ts" "$ip" "$code" "$method" "$uri" "$msg"
    done <<< "$RECENT_DATA"
fi
echo ""

# ── Watch mode ───────────────────────────────────────────────────
if [[ "$2" == "--watch" ]]; then
    echo -e "${DIM}  Nhấn Ctrl+C để thoát. Tự động refresh sau 5 giây...${NC}"
    sleep 5
    exec "$0" "$LOG_FILE" "--watch"
fi

echo -e "${DIM}  Tip: Chạy với --watch để tự động refresh: $0 $LOG_FILE --watch${NC}"
echo ""

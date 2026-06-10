#!/usr/bin/env bash
# =============================================================================
# Gregrep-Overlord — macOS Forensic Triage Engine v1.0.0
# =============================================================================
# Bash/zsh native. Requires root for full artifact access.
#
# Usage:
#   sudo bash Invoke-GregrepOverlord-macOS.sh [OPTIONS]
#
# Options:
#   -d DAYS          Timeframe in days (default: 7)
#   -u USER          Focus analysis on specific user
#   -p PROCESS       Focus on specific process name
#   -i IP            Focus network analysis on specific IP
#   -o DIR           Output directory (default: ./GregrepOverlord-Output/<host>-<date>)
#   -m MODULES       Comma-separated modules to run (default: ALL)
#   -s MODULES       Comma-separated modules to skip
#   -h               Help
#
# Example:
#   sudo bash Invoke-GregrepOverlord-macOS.sh -d 3 -u jsmith -p Terminal
# =============================================================================

# Soft error handling - dont exit on individual command failures
set -uo pipefail
IFS=$'\n\t'

# ─── DEFAULTS ─────────────────────────────────────────────────────────────────
TIMEFRAME_DAYS=7
SUSPECT_USER=""
SUSPECT_PROCESS=""
SUSPECT_IP=""
OUTPUT_DIR=""
RUN_MODULES="ALL"
SKIP_MODULES=""

# ─── PARSE ARGS ───────────────────────────────────────────────────────────────
while getopts "d:u:p:i:o:m:s:h" opt; do
    case $opt in
        d) TIMEFRAME_DAYS="$OPTARG" ;;
        u) SUSPECT_USER="$OPTARG" ;;
        p) SUSPECT_PROCESS="$OPTARG" ;;
        i) SUSPECT_IP="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        m) RUN_MODULES="$OPTARG" ;;
        s) SKIP_MODULES="$OPTARG" ;;
        h) grep '^#' "$0" | head -25; exit 0 ;;
        *) echo "Unknown option: $opt"; exit 1 ;;
    esac
done

# ─── INIT ─────────────────────────────────────────────────────────────────────
START_TIME=$(date "+%Y-%m-%d %H:%M:%S")
START_EPOCH=$(date +%s)
HOSTNAME_VAL=$(hostname)
OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "Unknown")
CURRENT_USER=$(whoami)
IS_ROOT=false
[[ "$EUID" -eq 0 ]] && IS_ROOT=true

if [[ -z "$OUTPUT_DIR" ]]; then
    STAMP=$(date "+%Y%m%d-%H%M%S")
    OUTPUT_DIR="./GregrepOverlord-Output/${HOSTNAME_VAL}-${STAMP}"
fi
CSV_DIR="${OUTPUT_DIR}/csv"
mkdir -p "$OUTPUT_DIR" "$CSV_DIR"

# Log file for all output
LOG_FILE="${OUTPUT_DIR}/triage.log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Findings accumulator (TSV: Severity|Module|Title|Detail|Indicator|Time)
FINDINGS_FILE="${CSV_DIR}/FINDINGS_SUMMARY.tsv"
echo -e "Severity\tModule\tTitle\tDetail\tIndicator\tTime" > "$FINDINGS_FILE"

CRIT_COUNT=0; HIGH_COUNT=0; MED_COUNT=0; LOW_COUNT=0; INFO_COUNT=0

# ─── HELPERS ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; GRAY='\033[0;37m'; BOLD='\033[1m'; NC='\033[0m'

log_header() {
    echo -e "\n${YELLOW}[$(date '+%H:%M:%S')] ► $1${NC} ${GRAY}— $2${NC}"
}

add_finding() {
    local sev="$1" mod="$2" title="$3" detail="$4" indicator="${5:-}"
    local now; now=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e "${sev}\t${mod}\t${title}\t${detail}\t${indicator}\t${now}" >> "$FINDINGS_FILE"
    case "$sev" in
        CRITICAL) CRIT_COUNT=$((CRIT_COUNT+1)) ;;
        HIGH)     HIGH_COUNT=$((HIGH_COUNT+1)) ;;
        MEDIUM)   MED_COUNT=$((MED_COUNT+1)) ;;
        LOW)      LOW_COUNT=$((LOW_COUNT+1)) ;;
        INFO)     INFO_COUNT=$((INFO_COUNT+1)) ;;
    esac
}

save_csv() {
    local name="$1" data="$2"
    echo "$data" > "${CSV_DIR}/${name}.csv"
}

timeframe_epoch() {
    date -v "-${TIMEFRAME_DAYS}d" +%s 2>/dev/null || \
        date -d "${TIMEFRAME_DAYS} days ago" +%s 2>/dev/null || \
        echo 0
}

is_in_timeframe() {
    local filepath="$1"
    local cutoff; cutoff=$(timeframe_epoch)
    local mtime; mtime=$(stat -f %m "$filepath" 2>/dev/null || stat -c %Y "$filepath" 2>/dev/null || echo 0)
    [[ "$mtime" -ge "$cutoff" ]]
}

should_run() {
    local mod="$1"
    [[ "$RUN_MODULES" == "ALL" || "$RUN_MODULES" == *"$mod"* ]] && \
    [[ -z "$SKIP_MODULES" || "$SKIP_MODULES" != *"$mod"* ]]
}

echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
  ██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███████╗██████╗ 
 ██╔════╝ ██╔══██╗██╔════╝██╔════╝ ██╔══██╗██╔════╝██╔══██╗
 ██║  ███╗██████╔╝█████╗  ██║  ███╗██████╔╝█████╗  ██████╔╝
 ██║   ██║██╔══██╗██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██╔═══╝ 
 ╚██████╔╝██║  ██║███████╗╚██████╔╝██║  ██║███████╗██║     
  ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝     
  Forensic Triage Orchestrator v1.0.0  |  macOS Engine
BANNER
echo -e "${NC}"

echo -e "${CYAN}[CONFIG]${NC}"
echo "  Host        : ${HOSTNAME_VAL} (macOS ${OS_VERSION})"
echo "  Run As      : ${CURRENT_USER} $(${IS_ROOT} && echo '[ROOT]' || echo '[LIMITED - some modules will be incomplete]')"
echo "  Timeframe   : Last ${TIMEFRAME_DAYS} days"
echo "  Output      : ${OUTPUT_DIR}"
[[ -n "$SUSPECT_USER" ]]    && echo "  Suspect User: ${SUSPECT_USER}"
[[ -n "$SUSPECT_PROCESS" ]] && echo "  Suspect Proc: ${SUSPECT_PROCESS}"
[[ -n "$SUSPECT_IP" ]]      && echo "  Suspect IP  : ${SUSPECT_IP}"

# ─── MODULE 1: UNIFIED LOGS ───────────────────────────────────────────────────
module_unified_logs() {
    log_header "UnifiedLogs" "Apple Unified Log — auth, sudo, SSH, process events"
    local outfile="${CSV_DIR}/UnifiedLogs.csv"
    echo "Time,EventType,Process,Message" > "$outfile"

    if ! command -v log &>/dev/null; then
        echo "  [SKIP] log command not found"; return
    fi

    local start_date; start_date=$(date -v "-${TIMEFRAME_DAYS}d" "+%Y-%m-%d" 2>/dev/null || \
                                    date -d "${TIMEFRAME_DAYS} days ago" "+%Y-%m-%d" 2>/dev/null)

    # Auth/sudo events
    log show --predicate 'eventMessage CONTAINS "sudo" OR eventMessage CONTAINS "authentication"' \
        --start "$start_date" --style syslog 2>/dev/null | \
        grep -E "sudo|auth|pam|login" | head -500 | \
        while IFS= read -r line; do
            echo "\"$(echo "$line" | cut -c1-23)\",\"Auth\",\"system\",\"$(echo "$line" | sed 's/"/\\"/g')\"" >> "$outfile"
        done

    # SSH events
    log show --predicate 'process == "sshd" OR eventMessage CONTAINS "sshd"' \
        --start "$start_date" --style syslog 2>/dev/null | head -200 | \
        while IFS= read -r line; do
            if echo "$line" | grep -qiE "accept|fail|invalid|error"; then
                local severity="HIGH"
                echo "$line" | grep -qi "fail\|invalid\|error" && severity="HIGH" || severity="INFO"
                add_finding "$severity" "UnifiedLogs" "SSH Event" "$(echo "$line" | cut -c1-200)" "SSH"
            fi
            echo "\"$(echo "$line" | cut -c1-23)\",\"SSH\",\"sshd\",\"$(echo "$line" | sed 's/"/\\"/g')\"" >> "$outfile"
        done

    # Privilege escalation / sudo failures
    log show --predicate 'eventMessage CONTAINS "sudo" AND eventMessage CONTAINS "incorrect"' \
        --start "$start_date" --style syslog 2>/dev/null | head -100 | \
        while IFS= read -r line; do
            add_finding "HIGH" "UnifiedLogs" "Sudo Failure" "$(echo "$line" | cut -c1-200)" "SudoFail"
        done

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) unified log records${NC}"
}

# ─── MODULE 2: BROWSER ARTIFACTS ─────────────────────────────────────────────
module_browser_artifacts() {
    log_header "BrowserArtifacts" "Chrome, Safari, Firefox — history, downloads, extensions"
    local outfile="${CSV_DIR}/BrowserArtifacts.csv"
    echo "User,Browser,Type,URL_or_Name,Source" > "$outfile"

    local user_homes=()
    if [[ -n "$SUSPECT_USER" ]]; then
        user_homes=("/Users/${SUSPECT_USER}")
    else
        while IFS= read -r dir; do
            [[ "$dir" =~ ^/Users/(Shared|Guest)$ ]] && continue
            user_homes+=("$dir")
        done < <(find /Users -maxdepth 1 -mindepth 1 -type d 2>/dev/null)
    fi

    for home in "${user_homes[@]}"; do
        local username; username=$(basename "$home")

        # Chrome
        local chrome_hist="${home}/Library/Application Support/Google/Chrome/Default/History"
        if [[ -f "$chrome_hist" ]]; then
            local tmp_db; tmp_db=$(mktemp /tmp/go_chrome_XXXX.db)
            cp "$chrome_hist" "$tmp_db" 2>/dev/null || true
            strings "$tmp_db" 2>/dev/null | \
                grep -oE 'https?://[^[:space:]"'"'"'<>]{10,300}' | \
                sort -u | head -1000 | \
                while IFS= read -r url; do
                    echo "\"$username\",\"Chrome\",\"History\",\"$url\",\"$chrome_hist\"" >> "$outfile"
                    if echo "$url" | grep -qiE 'pastebin|ngrok|\.onion|transfer\.sh|anonfiles|rawgit|\.ps1$|\.exe$|\.hta$'; then
                        add_finding "HIGH" "BrowserArtifacts" \
                            "Suspicious Chrome URL ($username)" "$url" "SuspURL"
                    fi
                done
            rm -f "$tmp_db"
        fi

        # Safari
        local safari_hist="${home}/Library/Safari/History.db"
        if [[ -f "$safari_hist" ]]; then
            local tmp_db; tmp_db=$(mktemp /tmp/go_safari_XXXX.db)
            cp "$safari_hist" "$tmp_db" 2>/dev/null || true
            strings "$tmp_db" 2>/dev/null | \
                grep -oE 'https?://[^[:space:]"'"'"'<>]{10,300}' | \
                sort -u | head -1000 | \
                while IFS= read -r url; do
                    echo "\"$username\",\"Safari\",\"History\",\"$url\",\"$safari_hist\"" >> "$outfile"
                done
            rm -f "$tmp_db"
        fi

        # Firefox
        local ff_base="${home}/Library/Application Support/Firefox/Profiles"
        if [[ -d "$ff_base" ]]; then
            find "$ff_base" -name "places.sqlite" 2>/dev/null | \
            while IFS= read -r db; do
                local tmp_db; tmp_db=$(mktemp /tmp/go_ff_XXXX.db)
                cp "$db" "$tmp_db" 2>/dev/null || true
                strings "$tmp_db" 2>/dev/null | \
                    grep -oE 'https?://[^[:space:]"'"'"'<>]{10,300}' | \
                    sort -u | head -500 | \
                    while IFS= read -r url; do
                        echo "\"$username\",\"Firefox\",\"History\",\"$url\",\"$db\"" >> "$outfile"
                    done
                rm -f "$tmp_db"
            done
        fi

        # Chrome Extensions
        local ext_base="${home}/Library/Application Support/Google/Chrome/Default/Extensions"
        if [[ -d "$ext_base" ]]; then
            find "$ext_base" -name "manifest.json" 2>/dev/null | \
            while IFS= read -r manifest; do
                local ext_name ext_id perms
                ext_name=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d.get('name',''))" "$manifest" 2>/dev/null || echo "Unknown")
                ext_id=$(basename "$(dirname "$(dirname "$manifest")")")
                perms=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(','.join(d.get('permissions',[])))" "$manifest" 2>/dev/null || echo "")
                echo "\"$username\",\"Chrome\",\"Extension\",\"$ext_name ($ext_id)\",\"$manifest\"" >> "$outfile"
                if echo "$perms" | grep -qiE '<all_urls>|nativeMessaging|proxy|cookies'; then
                    add_finding "MEDIUM" "BrowserArtifacts" \
                        "Chrome Extension with High Permissions ($username)" \
                        "$ext_name ($ext_id) — Permissions: $perms" "ExtPermission"
                fi
            done
        fi
    done

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) browser records${NC}"
}

# ─── MODULE 3: LAUNCH AGENTS/DAEMONS (PERSISTENCE) ───────────────────────────
module_persistence() {
    log_header "Persistence" "LaunchAgents, LaunchDaemons, LoginItems, cron, at, profiles"
    local outfile="${CSV_DIR}/Persistence.csv"
    echo "Type,User,Name,Path,ProgramArgs,Modified" > "$outfile"

    # LaunchAgents and LaunchDaemons
    local plist_dirs=(
        "/Library/LaunchDaemons"
        "/Library/LaunchAgents"
        "/System/Library/LaunchDaemons"
        "/System/Library/LaunchAgents"
    )
    # Per-user
    find /Users -maxdepth 3 -name "LaunchAgents" -type d 2>/dev/null | \
    while IFS= read -r d; do plist_dirs+=("$d"); done

    for dir in "${plist_dirs[@]}"; do
        [[ -d "$dir" ]] || continue
        find "$dir" -name "*.plist" 2>/dev/null | \
        while IFS= read -r plist; do
            local label program modified
            label=$(defaults read "$plist" Label 2>/dev/null || basename "$plist" .plist)
            program=$(defaults read "$plist" ProgramArguments 2>/dev/null | tr '\n' ' ' || \
                      defaults read "$plist" Program 2>/dev/null || "")
            modified=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$plist" 2>/dev/null || "")
            local type; [[ "$dir" == *Daemon* ]] && type="LaunchDaemon" || type="LaunchAgent"
            echo "\"$type\",\"system\",\"$label\",\"$plist\",\"$program\",\"$modified\"" >> "$outfile"

            # Flag non-Apple entries
            if ! echo "$label" | grep -qiE '^com\.apple\.|^com\.microsoft\.|^com\.adobe\.'; then
                add_finding "MEDIUM" "Persistence" \
                    "Non-Apple $type: $label" \
                    "Path: $plist | Cmd: $(echo "$program" | cut -c1-200)" "LaunchAgent"
            fi

            # Flag scripts in suspicious locations
            if echo "$program" | grep -qiE '/tmp/|/var/tmp/|curl|wget|python|perl|ruby|bash.*http'; then
                add_finding "HIGH" "Persistence" \
                    "Suspicious $type Command: $label" \
                    "$program" "SuspLaunchAgent"
            fi
        done
    done

    # Cron jobs
    crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | \
    while IFS= read -r line; do
        echo "\"Cron\",\"$(whoami)\",\"crontab\",\"crontab\",\"$line\",\"\"" >> "$outfile"
        if echo "$line" | grep -qiE 'curl|wget|python|perl|/tmp|nc '; then
            add_finding "HIGH" "Persistence" \
                "Suspicious Cron Entry" "$line" "SuspCron"
        fi
    done

    # /etc/cron.d and periodic
    for dir in /etc/cron.d /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
        [[ -d "$dir" ]] && find "$dir" -type f 2>/dev/null | \
        while IFS= read -r f; do
            echo "\"CronFile\",\"system\",\"$(basename "$f")\",\"$f\",\"\",\"\"" >> "$outfile"
        done
    done

    # at jobs
    atq 2>/dev/null | while IFS= read -r line; do
        echo "\"at\",\"$(whoami)\",\"atjob\",\"\",\"$line\",\"\"" >> "$outfile"
        add_finding "MEDIUM" "Persistence" "at Job Present" "$line" "atJob"
    done

    # Login Items
    osascript -e 'tell application "System Events" to get the path of every login item' 2>/dev/null | \
    tr ',' '\n' | tr -d ' ' | grep -v '^$' | \
    while IFS= read -r item; do
        echo "\"LoginItem\",\"$(logname 2>/dev/null || echo unknown)\",\"$(basename "$item")\",\"$item\",\"\",\"\"" >> "$outfile"
        add_finding "INFO" "Persistence" "Login Item: $(basename "$item")" "$item" "LoginItem"
    done

    # Profile configuration (MDM/enterprise)
    if command -v profiles &>/dev/null; then
        profiles -P 2>/dev/null | while IFS= read -r line; do
            echo "\"MDMProfile\",\"system\",\"profile\",\"\",\"$line\",\"\"" >> "$outfile"
        done
    fi

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) persistence entries${NC}"
}

# ─── MODULE 4: NETWORK ────────────────────────────────────────────────────────
module_network() {
    log_header "NetworkConnections" "Active connections, listening ports, DNS cache, routing"
    local outfile="${CSV_DIR}/NetworkConnections.csv"
    echo "State,Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,PID,Process" > "$outfile"

    # Active connections
    lsof -i -n -P 2>/dev/null | grep -E 'ESTABLISHED|LISTEN' | \
    while IFS= read -r line; do
        local process pid proto local_addr local_port remote_addr remote_port state
        process=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        proto=$(echo "$line" | awk '{print $8}')
        local_addr=$(echo "$line" | awk '{print $9}' | cut -d: -f1)
        local_port=$(echo "$line" | awk '{print $9}' | cut -d: -f2)
        remote_addr=$(echo "$line" | awk '{print $10}' 2>/dev/null | cut -d: -f1 || echo "")
        remote_port=$(echo "$line" | awk '{print $10}' 2>/dev/null | rev | cut -d: -f1 | rev || echo "")
        state=$(echo "$line" | awk '{print $NF}')

        echo "\"$state\",\"$proto\",\"$local_addr\",\"$local_port\",\"$remote_addr\",\"$remote_port\",\"$pid\",\"$process\"" >> "$outfile"

        # Flag suspicious ports
        if echo "$remote_port" | grep -qE '^(4444|5555|8080|8443|9001|9002|1337|31337|4899)$'; then
            add_finding "HIGH" "NetworkConnections" \
                "Connection to Suspicious Port: $remote_port" \
                "$process (PID $pid) → $remote_addr:$remote_port" "SuspPort:$remote_port"
        fi

        # Flag suspect IP
        if [[ -n "$SUSPECT_IP" ]] && echo "$remote_addr" | grep -q "$SUSPECT_IP"; then
            add_finding "CRITICAL" "NetworkConnections" \
                "Active Connection to Suspect IP" \
                "$process (PID $pid) → $remote_addr:$remote_port" "$SUSPECT_IP"
        fi
    done

    # DNS cache (macOS uses mDNSResponder)
    local dns_out="${CSV_DIR}/DNS_Cache.csv"
    echo "Entry" > "$dns_out"
    dscacheutil -cachedump -entries Host 2>/dev/null | \
    grep -E 'ipv|name' | \
    while IFS= read -r line; do
        echo "\"$line\"" >> "$dns_out"
        if echo "$line" | grep -qiE '\.onion|ngrok|duckdns|no-ip|\.tk$|\.pw$|\.xyz$'; then
            add_finding "HIGH" "NetworkConnections" "Suspicious DNS Entry" "$line" "SuspDNS"
        fi
    done

    # Firewall rules
    if [[ "$IS_ROOT" == "true" ]]; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null | \
        head -50 | while IFS= read -r line; do
            echo "\"FW: $line\"" >> "$dns_out"
        done
    fi

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) network records${NC}"
}

# ─── MODULE 5: PROCESS TREE ───────────────────────────────────────────────────
module_process_tree() {
    log_header "ProcessTree" "Running processes, suspicious paths, unusual parents"
    local outfile="${CSV_DIR}/ProcessTree.csv"
    echo "PID,PPID,User,CPU,MEM,Start,Command" > "$outfile"

    ps aux 2>/dev/null | tail -n +2 | \
    while IFS= read -r line; do
        local user pid cpu mem start cmd
        user=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        cpu=$(echo "$line" | awk '{print $3}')
        mem=$(echo "$line" | awk '{print $4}')
        start=$(echo "$line" | awk '{print $9}')
        cmd=$(echo "$line" | awk '{for(i=11;i<=NF;i++) printf $i " "; print ""}')

        echo "\"$pid\",\"\",\"$user\",\"$cpu\",\"$mem\",\"$start\",\"$(echo "$cmd" | sed 's/"/\\"/g')\"" >> "$outfile"

        # Flag suspicious commands
        if echo "$cmd" | grep -qiE '/tmp/|/var/tmp/|base64 -d|bash -i|python.*-c.*import|perl.*-e|nc.*-e|ncat|meterpreter'; then
            add_finding "HIGH" "ProcessTree" \
                "Suspicious Process: $(echo "$cmd" | cut -c1-80)" \
                "PID: $pid User: $user | $cmd" "SuspProcess"
        fi

        # Flag suspect process name
        if [[ -n "$SUSPECT_PROCESS" ]] && echo "$cmd" | grep -qi "$SUSPECT_PROCESS"; then
            add_finding "HIGH" "ProcessTree" \
                "Suspect Process Found: $SUSPECT_PROCESS" \
                "PID: $pid | $cmd" "$SUSPECT_PROCESS"
        fi
    done

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) processes analyzed${NC}"
}

# ─── MODULE 6: USER ACTIVITY ──────────────────────────────────────────────────
module_user_activity() {
    log_header "UserActivity" "Recent files, bash/zsh history, last logins, sudo history"
    local outfile="${CSV_DIR}/UserActivity.csv"
    echo "Type,User,Detail,Time" > "$outfile"

    # Last logins
    last 2>/dev/null | head -100 | \
    while IFS= read -r line; do
        echo "\"LastLogin\",\"$(echo "$line" | awk '{print $1}')\",\"$(echo "$line" | sed 's/"/\\"/g')\",\"\"" >> "$outfile"
    done

    # Failed logins
    if [[ "$IS_ROOT" == "true" ]]; then
        lastb 2>/dev/null | head -50 | \
        while IFS= read -r line; do
            echo "\"FailedLogin\",\"$(echo "$line" | awk '{print $1}')\",\"$(echo "$line" | sed 's/"/\\"/g')\",\"\"" >> "$outfile"
            add_finding "MEDIUM" "UserActivity" "Failed Login" "$line" "FailedLogin"
        done
    fi

    # Shell history (bash + zsh) per user
    find /Users -maxdepth 2 \( -name ".bash_history" -o -name ".zsh_history" -o -name ".zsh_sessions" \) 2>/dev/null | \
    while IFS= read -r hist; do
        [[ -n "$SUSPECT_USER" ]] && ! echo "$hist" | grep -q "$SUSPECT_USER" && continue
        local username; username=$(echo "$hist" | cut -d/ -f3)
        grep -v '^$' "$hist" 2>/dev/null | \
        while IFS= read -r cmd; do
            cmd=$(echo "$cmd" | sed 's/^: [0-9]*:[0-9]*;//')  # strip zsh timestamp
            echo "\"ShellHistory\",\"$username\",\"$(echo "$cmd" | sed 's/"/\\"/g')\",\"\"" >> "$outfile"

            if echo "$cmd" | grep -qiE 'curl.*|.*>\s*/tmp|base64\s+-d|openssl.*s_client|nc\s+-e|python.*-c.*socket|wget.*-O\s*/tmp|sudo.*rm.*-rf\s+/|dd.*if.*of.*dev|chmod.*777|chmod.*\+s|kextload|csrutil|spctl.*disable'; then
                add_finding "HIGH" "UserActivity" \
                    "Suspicious Shell Command ($username)" \
                    "$cmd" "SuspShellCmd"
            fi
        done
    done

    # Recent files
    find /Users -maxdepth 4 -newer "$(date -v "-${TIMEFRAME_DAYS}d" "+%Y%m%d" 2>/dev/null || echo "20000101")" \
        \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" -o -name "*.bin" -o -name "*.dylib" \) \
        -not -path "*/Library/Caches/*" \
        2>/dev/null | head -200 | \
    while IFS= read -r f; do
        [[ -n "$SUSPECT_USER" ]] && ! echo "$f" | grep -q "$SUSPECT_USER" && continue
        local username; username=$(echo "$f" | cut -d/ -f3)
        local mtime; mtime=$(stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$f" 2>/dev/null || "")
        echo "\"RecentScript\",\"$username\",\"$f\",\"$mtime\"" >> "$outfile"
        add_finding "MEDIUM" "UserActivity" \
            "Recent Script/Binary: $(basename "$f")" \
            "$f" "RecentScript"
    done

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) user activity records${NC}"
}

# ─── MODULE 7: SYSTEM INTEGRITY & SECURITY CONFIG ────────────────────────────
module_security_config() {
    log_header "SecurityConfig" "SIP, Gatekeeper, FileVault, TCC, MRT, XProtect, AMFI"
    local outfile="${CSV_DIR}/SecurityConfig.csv"
    echo "Check,Status,Detail" > "$outfile"

    # SIP (System Integrity Protection)
    local sip_status; sip_status=$(csrutil status 2>/dev/null || echo "Unknown")
    echo "\"SIP\",\"$(echo "$sip_status" | grep -c enabled > /dev/null && echo enabled || echo DISABLED)\",\"$sip_status\"" >> "$outfile"
    if echo "$sip_status" | grep -qi "disabled"; then
        add_finding "CRITICAL" "SecurityConfig" "SIP (System Integrity Protection) is DISABLED" \
            "$sip_status" "SIP_Disabled"
    fi

    # Gatekeeper
    local gk_status; gk_status=$(spctl --status 2>/dev/null || echo "Unknown")
    echo "\"Gatekeeper\",\"$gk_status\",\"\"" >> "$outfile"
    if echo "$gk_status" | grep -qi "disabled"; then
        add_finding "HIGH" "SecurityConfig" "Gatekeeper is DISABLED" "$gk_status" "GatekeeperDisabled"
    fi

    # FileVault
    local fv_status; fv_status=$(fdesetup status 2>/dev/null || echo "Unknown")
    echo "\"FileVault\",\"$fv_status\",\"\"" >> "$outfile"
    if echo "$fv_status" | grep -qi "off\|not enabled"; then
        add_finding "MEDIUM" "SecurityConfig" "FileVault Encryption is OFF" "$fv_status" "FileVaultOff"
    fi

    # AMFI (Apple Mobile File Integrity)
    if [[ -f /System/Library/Extensions/AppleMobileFileIntegrity.kext/Contents/MacOS/AppleMobileFileIntegrity ]]; then
        echo "\"AMFI\",\"Present\",\"\"" >> "$outfile"
    else
        add_finding "HIGH" "SecurityConfig" "AMFI kext not found" "" "AMFIMissing"
    fi

    # XProtect version
    if [[ -f /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist ]]; then
        local xp_ver; xp_ver=$(defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist Version 2>/dev/null || echo "Unknown")
        echo "\"XProtect\",\"$xp_ver\",\"\"" >> "$outfile"
    fi

    # Check kext-consent / custom kexts loaded
    kextstat 2>/dev/null | grep -v "^Index\|com\.apple" | \
    while IFS= read -r line; do
        echo "\"ThirdPartyKext\",\"Loaded\",\"$(echo "$line" | sed 's/"/\\"/g')\"" >> "$outfile"
        add_finding "MEDIUM" "SecurityConfig" \
            "Third-Party Kext Loaded" "$(echo "$line" | awk '{print $6}')" "ThirdPartyKext"
    done

    # TCC database (permissions)
    local tcc_db="/Library/Application Support/com.apple.TCC/TCC.db"
    if [[ -f "$tcc_db" ]] && [[ "$IS_ROOT" == "true" ]]; then
        sqlite3 "$tcc_db" "SELECT service,client,auth_value FROM access" 2>/dev/null | \
        while IFS='|' read -r service client auth; do
            if [[ "$auth" == "2" ]]; then  # allowed
                echo "\"TCC\",\"$service\",\"$client\"" >> "$outfile"
            fi
        done
    fi

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) security config checks${NC}"
}

# ─── MODULE 8: MALWARE ARTIFACTS ─────────────────────────────────────────────
module_malware_artifacts() {
    log_header "MalwareArtifacts" "Known macOS malware paths, quarantine, adware, crypto miners"
    local outfile="${CSV_DIR}/MalwareArtifacts.csv"
    echo "Type,Path,Detail" > "$outfile"

    # Quarantine database
    find /Users -name "com.apple.quarantine" -o \
        -path "*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV*" 2>/dev/null | head -5 | \
    while IFS= read -r db; do
        if [[ -f "$db" ]] && file "$db" | grep -q SQLite; then
            sqlite3 "$db" "SELECT LSQuarantineDataURLString,LSQuarantineOriginURLString,LSQuarantineTimeStamp FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 500" 2>/dev/null | \
            while IFS='|' read -r data_url origin_url timestamp; do
                echo "\"Quarantine\",\"$data_url\",\"From: $origin_url | Time: $timestamp\"" >> "$outfile"
                if echo "$data_url$origin_url" | grep -qiE '\.dmg|\.pkg|\.app|\.zip|download'; then
                    add_finding "INFO" "MalwareArtifacts" \
                        "Quarantined Download: $(basename "$data_url")" \
                        "From: $origin_url" "Quarantine"
                fi
            done
        fi
    done

    # Known bad paths used by macOS malware families
    local malware_paths=(
        "/Library/Application Support/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle"
        "/Library/LaunchDaemons/com.*.plist"
        "/private/tmp/.*.sh"
        "/private/tmp/*.py"
        "/Library/Fonts/Arial.ttf.app"
        "~/.bash_profile.d"
        "/usr/local/bin/.*update"
    )

    # Recently modified apps outside /Applications
    find /Users /private/tmp /var/tmp 2>/dev/null \
        -name "*.app" -type d \
        -newer "$(date -v "-${TIMEFRAME_DAYS}d" "+%Y%m%d" 2>/dev/null || echo "20000101")" | head -50 | \
    while IFS= read -r app; do
        echo "\"SuspApp\",\"$app\",\"App outside /Applications modified in timeframe\"" >> "$outfile"
        add_finding "HIGH" "MalwareArtifacts" \
            "App in Non-Standard Location: $(basename "$app")" \
            "$app" "SuspApp"
    done

    # Hidden files in user directories (dot-prefix executables)
    find /Users -maxdepth 4 -name ".*" -type f -perm /111 \
        -not -path "*/.git/*" \
        2>/dev/null | head -100 | \
    while IFS= read -r f; do
        [[ -n "$SUSPECT_USER" ]] && ! echo "$f" | grep -q "$SUSPECT_USER" && continue
        echo "\"HiddenExecutable\",\"$f\",\"Hidden file with execute permissions\"" >> "$outfile"
        add_finding "HIGH" "MalwareArtifacts" \
            "Hidden Executable: $(basename "$f")" "$f" "HiddenExec"
    done

    # dylib injection artifacts
    local dyld_insert; dyld_insert=$(launchctl environ DYLD_INSERT_LIBRARIES 2>/dev/null || echo "")
    if [[ -n "$dyld_insert" ]]; then
        add_finding "CRITICAL" "MalwareArtifacts" \
            "DYLD_INSERT_LIBRARIES Set (dylib injection)" \
            "$dyld_insert" "DYLDInject"
        echo "\"DYLDInject\",\"ENV\",\"$dyld_insert\"" >> "$outfile"
    fi

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) malware artifact records${NC}"
}

# ─── MODULE 9: SSH & REMOTE ACCESS ───────────────────────────────────────────
module_remote_access() {
    log_header "RemoteAccess" "SSH keys, authorized_keys, Remote Desktop, VPN artifacts"
    local outfile="${CSV_DIR}/RemoteAccess.csv"
    echo "Type,User,Detail,Path" > "$outfile"

    # SSH authorized_keys
    find /Users /root 2>/dev/null -name "authorized_keys" -maxdepth 4 | \
    while IFS= read -r f; do
        local username; username=$(echo "$f" | cut -d/ -f3)
        local key_count; key_count=$(grep -c 'ssh-' "$f" 2>/dev/null || echo 0)
        echo "\"AuthorizedKeys\",\"$username\",\"$key_count SSH keys\",\"$f\"" >> "$outfile"
        if [[ "$key_count" -gt 0 ]]; then
            add_finding "MEDIUM" "RemoteAccess" \
                "authorized_keys File — $key_count key(s) ($username)" \
                "$(cat "$f" 2>/dev/null | head -3)" "AuthorizedKeys"
        fi
    done

    # Private keys in non-standard locations
    find /Users -maxdepth 5 -name "*.pem" -o -name "id_rsa" -o -name "id_ed25519" \
        -not -path "*/.ssh/*" 2>/dev/null | head -50 | \
    while IFS= read -r f; do
        local username; username=$(echo "$f" | cut -d/ -f3)
        echo "\"StrayPrivKey\",\"$username\",\"Private key outside .ssh\",\"$f\"" >> "$outfile"
        add_finding "HIGH" "RemoteAccess" \
            "Private Key Outside .ssh: $(basename "$f")" \
            "$f" "StrayPrivKey"
    done

    # Remote Desktop / Screen Sharing enabled
    if [[ "$IS_ROOT" == "true" ]]; then
        local rdp_status; rdp_status=$(systemsetup -getremoteappleevents 2>/dev/null || echo "")
        echo "\"RemoteAppleEvents\",\"system\",\"$rdp_status\",\"\"" >> "$outfile"

        # Check /etc/ssh/sshd_config
        if [[ -f /etc/ssh/sshd_config ]]; then
            local root_login; root_login=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "")
            if echo "$root_login" | grep -qi "yes"; then
                add_finding "HIGH" "RemoteAccess" \
                    "SSH PermitRootLogin = yes" \
                    "sshd_config allows root SSH login" "SSHRootLogin"
            fi
            local pass_auth; pass_auth=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "")
            echo "\"SSHConfig\",\"system\",\"PasswordAuth=$pass_auth | RootLogin=$root_login\",\"/etc/ssh/sshd_config\"" >> "$outfile"
        fi
    fi

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) remote access records${NC}"
}

# ─── MODULE 10: NETWORK CONFIG ────────────────────────────────────────────────
module_network_config() {
    log_header "NetworkConfig" "Hosts file, DNS servers, proxy settings, ARP cache"
    local outfile="${CSV_DIR}/NetworkConfig.csv"
    echo "Type,Key,Value" > "$outfile"

    # /etc/hosts anomalies
    grep -v '^#\|^$\|^127\.\|^::1\|^fe80\|^255' /etc/hosts 2>/dev/null | \
    while IFS= read -r line; do
        echo "\"HostsFile\",\"entry\",\"$line\"" >> "$outfile"
        add_finding "HIGH" "NetworkConfig" "Non-standard /etc/hosts Entry" "$line" "HostsEntry"
    done

    # DNS servers
    scutil --dns 2>/dev/null | grep "nameserver" | sort -u | \
    while IFS= read -r line; do
        echo "\"DNS\",\"nameserver\",\"$line\"" >> "$outfile"
    done

    # Proxy settings
    scutil --proxy 2>/dev/null | grep -E "HTTPProxy|HTTPSProxy|SOCKS" | \
    while IFS= read -r line; do
        echo "\"Proxy\",\"$(echo "$line" | awk '{print $1}')\",\"$(echo "$line" | awk '{print $3}')\"" >> "$outfile"
        add_finding "MEDIUM" "NetworkConfig" "Proxy Configured" "$line" "Proxy"
    done

    # ARP cache (potential ARP poisoning indicators)
    arp -a 2>/dev/null | head -50 | \
    while IFS= read -r line; do
        echo "\"ARP\",\"entry\",\"$line\"" >> "$outfile"
    done

    # Routing table
    netstat -rn 2>/dev/null | head -30 | \
    while IFS= read -r line; do
        echo "\"Route\",\"entry\",\"$(echo "$line" | sed 's/"/\\"/g')\"" >> "$outfile"
    done

    local count; count=$(wc -l < "$outfile")
    echo -e "    ${GREEN}✓ $((count-1)) network config records${NC}"
}

# ─── HTML REPORT GENERATOR ────────────────────────────────────────────────────
generate_report() {
    log_header "Report" "Generating self-contained HTML report"
    local report_path="${OUTPUT_DIR}/GregrepOverlord-Report_${HOSTNAME_VAL}_$(date '+%Y%m%d-%H%M%S').html"

    local total_findings=$((CRIT_COUNT + HIGH_COUNT + MED_COUNT + LOW_COUNT + INFO_COUNT))
    local risk_level="LOW"; local risk_color="#00cc66"
    [[ "$CRIT_COUNT" -gt 0 ]] && risk_level="CRITICAL" && risk_color="#ff3b3b"
    [[ "$CRIT_COUNT" -eq 0 && "$HIGH_COUNT" -gt 0 ]] && risk_level="HIGH" && risk_color="#ff8c00"
    [[ "$CRIT_COUNT" -eq 0 && "$HIGH_COUNT" -eq 0 && "$MED_COUNT" -gt 0 ]] && risk_level="MEDIUM" && risk_color="#ffd700"

    local end_time; end_time=$(date "+%Y-%m-%d %H:%M:%S")
    local end_epoch; end_epoch=$(date +%s)
    local duration=$((end_epoch - START_EPOCH))

    # Build findings table rows from TSV
    local finding_rows=""
    while IFS=$'\t' read -r sev mod title detail indicator time; do
        [[ "$sev" == "Severity" ]] && continue
        local css_class="sev-info"
        case "$sev" in
            CRITICAL) css_class="sev-critical" ;;
            HIGH)     css_class="sev-high" ;;
            MEDIUM)   css_class="sev-medium" ;;
            LOW)      css_class="sev-low" ;;
        esac
        finding_rows+="<tr class='$css_class'><td><span class='badge badge-$css_class'>$sev</span></td><td>$mod</td><td>$title</td><td class='detail-cell'>$(echo "$detail" | sed 's/</\&lt;/g; s/>/\&gt;/g' | cut -c1-400)</td><td>$time</td></tr>"$'\n'
    done < "$FINDINGS_FILE"

    cat > "$report_path" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Gregrep-Overlord Triage Report — ${HOSTNAME_VAL}</title>
<style>
  :root { --bg:#0d0f14;--surface:#151820;--surface2:#1c2030;--border:#2a2f3e;--text:#e0e4f0;--text-dim:#7a8099;--accent:#4f8ef7;--critical:#ff3b3b;--high:#ff8c00;--medium:#ffd700;--low:#00cc66;--info:#4f8ef7;--font:'Segoe UI',system-ui,sans-serif;--mono:'Cascadia Code','Consolas',monospace; }
  *{box-sizing:border-box;margin:0;padding:0} body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.6}
  .header{background:linear-gradient(135deg,#0d0f14,#151c2e);padding:32px 40px;border-bottom:1px solid var(--border)}
  .header-top{display:flex;justify-content:space-between;align-items:flex-start}
  .tool-name{font-size:28px;font-weight:700;color:var(--accent);letter-spacing:1px}
  .tool-sub{font-size:13px;color:var(--text-dim);margin-top:4px}
  .risk-badge{font-size:22px;font-weight:700;padding:10px 24px;border-radius:8px;color:#fff;background:${risk_color};box-shadow:0 0 20px ${risk_color}55}
  .meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-top:24px}
  .meta-item{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:12px 16px}
  .meta-label{font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px}
  .meta-value{font-size:15px;font-weight:600;margin-top:4px}
  .stats-bar{display:flex;gap:12px;padding:20px 40px;background:var(--surface);border-bottom:1px solid var(--border);flex-wrap:wrap}
  .stat-box{flex:1;min-width:100px;text-align:center;padding:16px;border-radius:8px;border:1px solid var(--border)}
  .s-critical{border-color:var(--critical);background:#ff3b3b15}
  .s-high{border-color:var(--high);background:#ff8c0015}
  .s-medium{border-color:var(--medium);background:#ffd70015}
  .s-low{border-color:var(--low);background:#00cc6615}
  .s-info{border-color:var(--info);background:#4f8ef715}
  .stat-num{font-size:32px;font-weight:700} .stat-label{font-size:12px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px}
  .content{padding:32px 40px}
  h2{font-size:18px;font-weight:600;color:var(--accent);margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--border)}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;margin:2px}
  .badge-sev-critical{background:#ff3b3b30;color:#ff6b6b;border:1px solid var(--critical)}
  .badge-sev-high{background:#ff8c0030;color:#ffaa44;border:1px solid var(--high)}
  .badge-sev-medium{background:#ffd70030;color:#ffe066;border:1px solid var(--medium)}
  .badge-sev-low{background:#00cc6630;color:#33dd88;border:1px solid var(--low)}
  .badge-sev-info{background:#4f8ef730;color:#7aaaff;border:1px solid var(--info)}
  .filter-bar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
  .filter-btn{padding:6px 14px;border-radius:4px;border:1px solid var(--border);background:var(--surface);color:var(--text);cursor:pointer;font-size:12px}
  .filter-btn:hover,.filter-btn.active{border-color:var(--accent);color:var(--accent)}
  input[type=text]{padding:6px 12px;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font-size:12px;width:280px}
  input[type=text]:focus{outline:none;border-color:var(--accent)}
  .table-wrap{overflow-x:auto;margin-bottom:32px;border-radius:8px;border:1px solid var(--border)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  thead{background:var(--surface2)}
  th{padding:12px 14px;text-align:left;font-weight:600;color:var(--text-dim);text-transform:uppercase;font-size:11px;letter-spacing:.5px;border-bottom:1px solid var(--border)}
  td{padding:10px 14px;border-bottom:1px solid #1a1e2a;vertical-align:top}
  tr:hover td{background:var(--surface2)}
  tr.sev-critical td{border-left:3px solid var(--critical)}
  tr.sev-high td{border-left:3px solid var(--high)}
  tr.sev-medium td{border-left:3px solid var(--medium)}
  tr.sev-low td{border-left:3px solid var(--low)}
  tr.sev-info td{border-left:3px solid var(--info)}
  .detail-cell{font-family:var(--mono);font-size:12px;max-width:500px;word-break:break-all;color:var(--text-dim)}
  .footer{padding:20px 40px;text-align:center;color:var(--text-dim);font-size:12px;border-top:1px solid var(--border);margin-top:40px}
</style>
</head>
<body>
<div class="header">
  <div class="header-top">
    <div><div class="tool-name">🔍 GREGREP-OVERLORD</div>
    <div class="tool-sub">Forensic Triage Orchestrator v1.0.0 — macOS Engine</div></div>
    <div class="risk-badge">RISK: ${risk_level}</div>
  </div>
  <div class="meta-grid">
    <div class="meta-item"><div class="meta-label">Hostname</div><div class="meta-value">${HOSTNAME_VAL}</div></div>
    <div class="meta-item"><div class="meta-label">OS</div><div class="meta-value">macOS ${OS_VERSION}</div></div>
    <div class="meta-item"><div class="meta-label">Run As</div><div class="meta-value">${CURRENT_USER}</div></div>
    <div class="meta-item"><div class="meta-label">Triage Start</div><div class="meta-value">${START_TIME}</div></div>
    <div class="meta-item"><div class="meta-label">Duration</div><div class="meta-value">${duration}s</div></div>
    <div class="meta-item"><div class="meta-label">Timeframe</div><div class="meta-value">Last ${TIMEFRAME_DAYS} days</div></div>
  </div>
</div>
<div class="stats-bar">
  <div class="stat-box s-critical"><div class="stat-num" style="color:var(--critical)">${CRIT_COUNT}</div><div class="stat-label">Critical</div></div>
  <div class="stat-box s-high"><div class="stat-num" style="color:var(--high)">${HIGH_COUNT}</div><div class="stat-label">High</div></div>
  <div class="stat-box s-medium"><div class="stat-num" style="color:var(--medium)">${MED_COUNT}</div><div class="stat-label">Medium</div></div>
  <div class="stat-box s-low"><div class="stat-num" style="color:var(--low)">${LOW_COUNT}</div><div class="stat-label">Low</div></div>
  <div class="stat-box s-info"><div class="stat-num" style="color:var(--info)">${INFO_COUNT}</div><div class="stat-label">Info</div></div>
  <div class="stat-box" style="min-width:160px"><div class="stat-num">${total_findings}</div><div class="stat-label">Total Findings</div></div>
</div>
<div class="content">
<h2>Findings</h2>
<div class="filter-bar">
  <button class="filter-btn active" onclick="filterSev('ALL')">All</button>
  <button class="filter-btn" onclick="filterSev('CRITICAL')" style="color:var(--critical)">Critical</button>
  <button class="filter-btn" onclick="filterSev('HIGH')" style="color:var(--high)">High</button>
  <button class="filter-btn" onclick="filterSev('MEDIUM')" style="color:var(--medium)">Medium</button>
  <button class="filter-btn" onclick="filterSev('LOW')" style="color:var(--low)">Low</button>
  <button class="filter-btn" onclick="filterSev('INFO')" style="color:var(--info)">Info</button>
  <input type="text" id="searchBox" placeholder="Search findings..." oninput="searchFindings(this.value)">
</div>
<div class="table-wrap">
<table id="findingsTable">
<thead><tr><th>Severity</th><th>Module</th><th>Finding</th><th>Detail</th><th>Time</th></tr></thead>
<tbody id="findingsBody">
${finding_rows}
</tbody>
</table>
</div>
</div>
<div class="footer">Generated by Gregrep-Overlord v1.0.0 | ${end_time} | github.com/YOUR_USERNAME/Gregrep-Overlord</div>
<script>
function filterSev(sev){document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));event.target.classList.add('active');document.querySelectorAll('#findingsBody tr').forEach(row=>{row.style.display=(sev==='ALL'||row.classList.contains('sev-'+sev.toLowerCase()))?'':'none'});}
function searchFindings(q){const lq=q.toLowerCase();document.querySelectorAll('#findingsBody tr').forEach(row=>{row.style.display=row.textContent.toLowerCase().includes(lq)?'':'none';});}
</script>
</body>
</html>
HTMLEOF

    echo -e "    ${GREEN}✓ HTML Report: ${report_path}${NC}"
}

# ─── ORCHESTRATOR ─────────────────────────────────────────────────────────────
# Module list - bash 3.2 compatible (no associative arrays)
ALL_MODULES="UnifiedLogs BrowserArtifacts Persistence NetworkConnections ProcessTree UserActivity SecurityConfig MalwareArtifacts RemoteAccess NetworkConfig"

run_module() {
    local mod="$1"
    case "$mod" in
        UnifiedLogs)       module_unified_logs ;;
        BrowserArtifacts)  module_browser_artifacts ;;
        Persistence)       module_persistence ;;
        NetworkConnections) module_network ;;
        ProcessTree)       module_process_tree ;;
        UserActivity)      module_user_activity ;;
        SecurityConfig)    module_security_config ;;
        MalwareArtifacts)  module_malware_artifacts ;;
        RemoteAccess)      module_remote_access ;;
        NetworkConfig)     module_network_config ;;
        *) echo "  [WARN] Unknown module: $mod" ;;
    esac
}

for mod in $ALL_MODULES; do
    if should_run "$mod"; then
        run_module "$mod" || echo "  [WARN] Module $mod encountered errors"
    fi
done

generate_report

# ─── SUMMARY ──────────────────────────────────────────────────────────────────
END_EPOCH=$(date +%s)
DURATION=$((END_EPOCH - START_EPOCH))
TOTAL=$((CRIT_COUNT + HIGH_COUNT + MED_COUNT + LOW_COUNT + INFO_COUNT))

echo ""
echo -e "${GRAY}$(printf '─%.0s' {1..70})${NC}"
echo -e "  ${CYAN}${BOLD}GREGREP-OVERLORD COMPLETE${NC}"
echo -e "${GRAY}$(printf '─%.0s' {1..70})${NC}"
echo "  Duration    : ${DURATION}s"
echo "  Findings    : ${TOTAL} total"
echo -e "  CRITICAL    : ${CRIT_COUNT}" 
echo "  HIGH        : ${HIGH_COUNT}"
echo "  MEDIUM      : ${MED_COUNT}"
echo "  Output      : ${OUTPUT_DIR}"
echo -e "${GRAY}$(printf '─%.0s' {1..70})${NC}"

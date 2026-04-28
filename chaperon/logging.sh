#! /bin/bash --
# chaperon/logging.sh — Structured logging for the chaperon process
#
# Provides leveled, timestamped logging to a per-session log file.
# Each chaperon instance gets its own log file, named to be unique
# across multiple sandboxes on the same or different machines sharing
# an NFS home directory.
#
# Log directory:  ${XDG_STATE_HOME:-~/.local/state}/agent-sandbox/chaperon/
# Log filename:   <hostname>_<PID>_<ISO-timestamp>.log
# Retention:      Configurable via CHAPERON_LOG_RETAIN_DAYS (default: 7)
#
# Usage (sourced by chaperon.sh):
#   source logging.sh
#   chaperon_log_init "$project_dir"    # sets up log file, runs cleanup
#   chaperon_log info "message"         # leveled logging
#   chaperon_log error "message"

# ── Log levels ──────────────────────────────────────────────────

declare -A _CHAPERON_LOG_LEVELS=( [debug]=0 [info]=1 [warn]=2 [error]=3 )

_CHAPERON_LOG_LEVEL_NUM=1   # default: info
_CHAPERON_LOG_FILE=""
_CHAPERON_LOG_DIR=""
_CHAPERON_SESSION_ID=""

# ── Public API ──────────────────────────────────────────────────

# chaperon_log_init <project_dir>
#
# Creates the log directory, opens a per-session log file, writes a
# session header, and prunes stale logs in the background.
chaperon_log_init() {
    local project_dir="${1:-}"
    local level="${CHAPERON_LOG_LEVEL:-info}"
    local retain_days="${CHAPERON_LOG_RETAIN_DAYS:-7}"

    # Resolve log level
    level="${level,,}"  # lowercase
    if [[ -n "${_CHAPERON_LOG_LEVELS[$level]+x}" ]]; then
        _CHAPERON_LOG_LEVEL_NUM="${_CHAPERON_LOG_LEVELS[$level]}"
    else
        _CHAPERON_LOG_LEVEL_NUM=1  # fallback to info
    fi

    # Log directory (XDG-compliant, owner-only permissions).
    # Logs may contain argument values and handler denial details that
    # could reveal project structure or resource requests. Restrict to
    # owner-only to prevent group/other access on shared NFS.
    _CHAPERON_LOG_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/agent-sandbox/chaperon"
    mkdir -p "$_CHAPERON_LOG_DIR" 2>/dev/null || {
        # Can't create log dir — disable file logging, write to stderr only
        _CHAPERON_LOG_FILE=""
        return 0
    }
    chmod 700 "$_CHAPERON_LOG_DIR" 2>/dev/null || true

    # Session ID: compact, unique across hosts and PIDs
    local hostname
    hostname="$(hostname -s 2>/dev/null || echo unknown)"
    local timestamp
    timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"
    _CHAPERON_SESSION_ID="${hostname}_$$_${timestamp}"

    _CHAPERON_LOG_FILE="${_CHAPERON_LOG_DIR}/${_CHAPERON_SESSION_ID}.log"

    # Write session header
    {
        echo "# chaperon session log"
        echo "# host:       $hostname"
        echo "# pid:        $$"
        echo "# ppid:       $PPID"
        echo "# started:    $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "# project:    ${project_dir:-<unknown>}"
        echo "# slurm_scope: ${SLURM_SCOPE:-<unset>}"
        echo "# log_level:  $level"
        echo "# retain_days: $retain_days"
        echo "#"
    } > "$_CHAPERON_LOG_FILE" 2>/dev/null || {
        _CHAPERON_LOG_FILE=""
        return 0
    }
    chmod 600 "$_CHAPERON_LOG_FILE" 2>/dev/null || true

    # Prune old logs (non-blocking, best-effort)
    _chaperon_log_prune "$retain_days" &
    disown $! 2>/dev/null || true
}

# chaperon_log <level> <message...>
#
# Write a structured log line. Filters by configured log level.
# Format: ISO-8601 LEVEL message
chaperon_log() {
    local level="${1,,}"
    shift
    local msg="$*"

    local level_num="${_CHAPERON_LOG_LEVELS[$level]:-1}"
    if (( level_num < _CHAPERON_LOG_LEVEL_NUM )); then
        return 0
    fi

    local ts
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    local tag="${level^^}"

    local line="$ts [$tag] $msg"

    # Write to log file if available
    if [[ -n "$_CHAPERON_LOG_FILE" ]]; then
        echo "$line" >> "$_CHAPERON_LOG_FILE" 2>/dev/null || true
    fi

    # Also write to stderr (captured per-request or by sandbox-exec redirect)
    echo "$line" >&2
}

# chaperon_log_file — returns the current log file path (for diagnostics)
chaperon_log_file() {
    echo "${_CHAPERON_LOG_FILE:-<none>}"
}

# ── Cleanup / Retention ─────────────────────────────────────────

# _chaperon_log_prune <retain_days>
#
# Remove log files older than retain_days. Also enforces a total size
# cap (default 50 MiB) by removing oldest files first.
_chaperon_log_prune() {
    local retain_days="${1:-7}"
    local max_total_bytes=$(( 50 * 1024 * 1024 ))  # 50 MiB

    [[ -d "$_CHAPERON_LOG_DIR" ]] || return 0

    # Phase 1: age-based pruning
    find "$_CHAPERON_LOG_DIR" -maxdepth 1 -name '*.log' -type f \
        -mtime +"$retain_days" -delete 2>/dev/null || true

    # Phase 2: size-based pruning (oldest first)
    # Sum all log file sizes; if over cap, delete oldest until under.
    local total_bytes=0
    local -a files_by_age=()

    while IFS= read -r -d '' entry; do
        files_by_age+=("$entry")
    done < <(find "$_CHAPERON_LOG_DIR" -maxdepth 1 -name '*.log' -type f \
        -printf '%T@\t%s\t%p\0' 2>/dev/null | sort -z -n)

    # Calculate total size
    for entry in "${files_by_age[@]}"; do
        local size
        size="$(echo "$entry" | cut -f2)"
        total_bytes=$(( total_bytes + size ))
    done

    # Remove oldest until under cap
    for entry in "${files_by_age[@]}"; do
        if (( total_bytes <= max_total_bytes )); then
            break
        fi
        local size filepath
        size="$(echo "$entry" | cut -f2)"
        filepath="$(echo "$entry" | cut -f3)"
        # Don't delete the current session's log
        [[ "$filepath" == "$_CHAPERON_LOG_FILE" ]] && continue
        rm -f "$filepath" 2>/dev/null || true
        total_bytes=$(( total_bytes - size ))
    done
}

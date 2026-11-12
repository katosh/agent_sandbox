#! /bin/bash --
# chaperon/chaperon.sh — Secure Slurm proxy (runs OUTSIDE the sandbox)
#
# Reads CHAPERON/1 requests from a named pipe and writes responses to
# per-request response FIFOs. Launched by sandbox-exec.sh as a background
# child.
#
# Communication design:
#   - One persistent request FIFO: stubs open → write request → close
#   - Per-request response FIFO: stub creates it, path sent in request,
#     chaperon writes response → stub reads → stub removes FIFO
#   - The chaperon keeps its read end of the req pipe open via a write
#     FD held by the chaperon itself (prevents EOF between requests).
#
# Lifecycle:
#   - Spawned by sandbox-exec.sh before entering the sandbox
#   - Exits on SIGTERM/SIGINT (parent killed) or explicit shutdown
#   - Sets PR_SET_PDEATHSIG for orphan prevention
#
# Usage (internal — called by sandbox-exec.sh):
#   chaperon.sh <fifo_dir> <project_dir> <sandbox_exec_path> [cleanup_dir ...]
#
# Optional trailing cleanup_dir arguments name other per-launch
# directories (proxy socket dir, mail-block stub dir) that the chaperon
# removes together with <fifo_dir> when it shuts down. The chaperon is
# the launch's long-lived host-side process, so it is the natural owner
# of that cleanup after sandbox-exec.sh has exec'd into the backend.

set -euo pipefail

CHAPERON_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$CHAPERON_DIR/protocol.sh"
source "$CHAPERON_DIR/logging.sh"

# ── Arguments ────────────────────────────────────────────────────

FIFO_DIR="${1:-}"
PROJECT_DIR="${2:-}"
SANDBOX_EXEC="${3:-}"

if [[ -z "$FIFO_DIR" || -z "$PROJECT_DIR" || -z "$SANDBOX_EXEC" ]]; then
    echo "chaperon: usage: chaperon.sh <fifo_dir> <project_dir> <sandbox_exec_path> [cleanup_dir ...]" >&2
    exit 1
fi
shift 3
# Only accept the per-launch dir shapes sandbox-exec.sh creates, owned
# by us and not symlinks — the rm -rf at shutdown must not be steerable.
_CHAPERON_CLEANUP_DIRS=()
for _cd in "$@"; do
    case "${_cd##*/}" in
        agent-sandbox-proxy-*|agent-sandbox-mailblock-*) ;;
        *) continue ;;
    esac
    [[ -d "$_cd" && ! -L "$_cd" && -O "$_cd" ]] || continue
    _CHAPERON_CLEANUP_DIRS+=("$_cd")
done
unset _cd

# ── Handlers: load ALL of them once, now ─────────────────────────
# Handlers are sourced at startup and never re-read. Re-sourcing
# handlers/<cmd>.sh per request would let anyone who can modify the
# install tree after launch (e.g. a landlock session whose writable
# rules cover it) run code in this host-side process. Loading first
# also gives logging.sh the _sandbox_state_safe_mkdir helper.
declare -A _CHAPERON_HANDLERS=()
for _hf in "$CHAPERON_DIR"/handlers/*.sh; do
    _hn="${_hf##*/}"
    _hn="${_hn%.sh}"
    [[ "$_hn" == _* ]] && continue          # libraries, not handlers
    [[ "$_hn" =~ ^[a-z][a-z0-9_]*$ ]] || continue
    # shellcheck disable=SC1090
    source "$_hf"
    if declare -F "handle_${_hn}" >/dev/null; then
        _CHAPERON_HANDLERS[$_hn]=1
    fi
done
unset _hf _hn
if ! declare -F handle_blocked >/dev/null; then
    echo "chaperon: handlers/blocked.sh missing — refusing to start" >&2
    exit 1
fi

# ── Logging ─────────────────────────────────────────────────────
chaperon_log_init "$PROJECT_DIR" "$FIFO_DIR"
chaperon_log info "starting (pid=$$, ppid=$PPID, fifo=$FIFO_DIR)"

# ── Live reload: the chaperon's host-side view ───────────────────
# `agent-sandbox reload` rewrites <session dir>/chaperon-view (a host-only
# directory the sandbox cannot see) and sends this process SIGUSR1; the
# view is then re-read HERE, by the chaperon itself. It lists the paths
# the session has writable (chaperon_path_is_writable in
# handlers/_handler_lib.sh) and the log level. Handlers and the job
# wrapper still load their config fresh per launch; this is only the
# long-lived state. CHAPERON_SESSION_DIR is read once and unset, so it
# reaches neither handlers nor submitted jobs.
_CHAPERON_SESSION_DIR=""
_CHAPERON_VIEW_WRITABLE=()
_chaperon_reload_requested=false
if [[ -n "${CHAPERON_SESSION_DIR:-}" ]]; then
    _sd="$CHAPERON_SESSION_DIR"
    if [[ "$_sd" == /* && "${_sd##*/}" =~ ^[0-9a-f]{8}$ && -d "$_sd" && ! -L "$_sd" && -O "$_sd" ]]; then
        _CHAPERON_SESSION_DIR="$_sd"
    fi
    unset _sd
fi
unset CHAPERON_SESSION_DIR

# _chaperon_load_view — replace the view from <session dir>/chaperon-view.
# Lines are "<key><TAB><value>": writable (absolute path), log_level.
_chaperon_load_view() {
    local _f="$_CHAPERON_SESSION_DIR/chaperon-view" _k _v _lvl=""
    local -a _w=()
    [[ -n "$_CHAPERON_SESSION_DIR" && -f "$_f" && ! -L "$_f" ]] || return 0
    while IFS=$'\t' read -r _k _v || [[ -n "$_k" ]]; do
        case "$_k" in
            writable)
                [[ "$_v" == /* && "$_v" != *$'\n'* && "/$_v/" != */../* ]] && _w+=("${_v%/}") ;;
            log_level)
                [[ "$_v" =~ ^[a-z]+$ && -n "${_CHAPERON_LOG_LEVELS[$_v]+x}" ]] && _lvl="$_v" ;;
        esac
    done < "$_f"
    _CHAPERON_VIEW_WRITABLE=("${_w[@]+"${_w[@]}"}")
    if [[ -n "$_lvl" ]]; then
        CHAPERON_LOG_LEVEL="$_lvl"
        _CHAPERON_LOG_LEVEL_NUM="${_CHAPERON_LOG_LEVELS[$_lvl]}"
    fi
    chaperon_log info "view loaded (${#_CHAPERON_VIEW_WRITABLE[@]} writable path(s), log level ${CHAPERON_LOG_LEVEL:-info})"
    return 0
}
_chaperon_load_view

# Catch unexpected deaths from set -e. Without this, a failed command
# kills the process silently (stderr is chaperon.err, but the bash
# error message gives no context). Log the failing line before exit.
trap 'chaperon_log error "unexpected exit at line $LINENO (exit=$?)"' ERR

# ── Orphan prevention ────────────────────────────────────────────
# NOTE: prctl() below runs in the python3 child, so PR_SET_PDEATHSIG
# applies to that short-lived child, not to this shell. Parent death is
# actually detected by the `kill -0 $PPID` poll in the main loop, which
# then exits through _chaperon_cleanup (EXIT trap).
if command -v python3 &>/dev/null; then
    python3 -c "
import ctypes, signal
try:
    libc = ctypes.CDLL('libc.so.6', use_errno=True)
    PR_SET_PDEATHSIG = 1
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
except Exception:
    pass  # Best-effort
" 2>/dev/null || true
fi

# ── Signal handling / cleanup ────────────────────────────────────

_chaperon_exiting=false
_chaperon_cleanup() {
    "$_chaperon_exiting" && return 0
    _chaperon_exiting=true
    chaperon_log info "shutting down (pid=$$)"
    exec 3<&- 2>/dev/null || true
    rm -rf "$FIFO_DIR" 2>/dev/null || true
    # The session record dies with the session (agent-sandbox sessions).
    if [[ -n "${_CHAPERON_SESSION_DIR:-}" && -d "$_CHAPERON_SESSION_DIR" && ! -L "$_CHAPERON_SESSION_DIR" && -O "$_CHAPERON_SESSION_DIR" ]]; then
        rm -rf -- "$_CHAPERON_SESSION_DIR" 2>/dev/null || true
    fi
    local _d
    for _d in "${_CHAPERON_CLEANUP_DIRS[@]+"${_CHAPERON_CLEANUP_DIRS[@]}"}"; do
        [[ -d "$_d" && ! -L "$_d" ]] && rm -rf -- "$_d" 2>/dev/null
    done
    exit 0
}

trap _chaperon_cleanup SIGTERM SIGINT SIGHUP EXIT
trap '_chaperon_reload_requested=true' USR1

# ── Open request FIFO ────────────────────────────────────────────
# Open read+write (O_RDWR) on the req FIFO. This:
#   1. Doesn't block (O_RDWR on a FIFO doesn't wait for a peer)
#   2. Keeps a write reference alive, preventing EOF between requests
#      when stubs close their write ends
exec 3<>"$FIFO_DIR/req"

READ_FD=3

# ── FD conventions ──────────────────────────────────────────────
# FD 3 — request FIFO (read end, opened above)

# ── Handler dispatch ─────────────────────────────────────────────

dispatch_handler() {
    local command="$1"

    # Validate command name (defense in depth; lookup is table-based).
    if [[ ! "$command" =~ ^[a-z_][a-z0-9_]*$ ]]; then
        chaperon_log error "rejected invalid command name: $(chaperon_log_escape "$command")"
        return 1
    fi

    # Dispatch only to handlers loaded at startup; never source here.
    if [[ -n "${_CHAPERON_HANDLERS[$command]+x}" ]]; then
        "handle_${command}" "$PROJECT_DIR" "$SANDBOX_EXEC"
        return $?
    fi

    handle_blocked
    return $?
}

# ── Response FIFO ────────────────────────────────────────────────

# Check REQ_RESP_FIFO before anything is written to it. Logs and
# returns 1 on failure.
_chaperon_resp_fifo_ok() {
    # Validate RESP_FIFO: must be FIFO_DIR/resp-XXXXXX/fifo, no ".." components,
    # not a symlink. The stub creates an atomic directory (mktemp -d) with a
    # FIFO inside, so the expected structure is deterministic.
    if [[ "$REQ_RESP_FIFO" != "$FIFO_DIR/"*/fifo ]] || [[ "$REQ_RESP_FIFO" == *".."* ]]; then
        chaperon_log error "RESP_FIFO path validation failed: $(chaperon_log_escape "$REQ_RESP_FIFO")"
        return 1
    fi

    # Reject symlinks: -p follows symlinks, so a symlink → FIFO would pass.
    # A malicious process could race to replace the FIFO with a symlink
    # pointing outside the FIFO directory to intercept the response.
    #
    # This is an early filter only. The load-bearing protection against
    # the symlink-swap race is the O_NOFOLLOW + fstat(S_ISFIFO) open in
    # the python3 writer below, because bash's `>` redirection follows
    # symlinks at open time.
    if [[ -L "$REQ_RESP_FIFO" ]] || [[ ! -p "$REQ_RESP_FIFO" ]]; then
        chaperon_log error "RESP_FIFO is symlink or not a FIFO: $(chaperon_log_escape "$REQ_RESP_FIFO")"
        return 1
    fi
    return 0
}

# Write a response to REQ_RESP_FIFO.
# Usage: _chaperon_send_response <exit_code> <stdout_b64> <stderr_b64> <log_cmd>
_chaperon_send_response() {
    local _exit_code="$1" _stdout_b64="$2" _stderr_b64="$3" _log_cmd="$4"

    # Validate exit code is numeric before sending
    if [[ ! "$_exit_code" =~ ^[0-9]+$ ]]; then
        _exit_code=1
    fi

    # Send response via python3 with O_NOFOLLOW + fstat(S_ISFIFO) verify.
    #
    # Bash's `exec {fd}>"$path"` follows symlinks at open time (O_WRONLY|
    # O_CREAT|O_TRUNC), which lets a same-UID attacker inside the sandbox
    # race the [[ -L ]] / [[ ! -p ]] check above: unlink the FIFO, drop
    # a symlink → ~/.bashrc / ~/.ssh/authorized_keys, and the chaperon's
    # open() truncates the target.
    #
    # python3's os.open(O_WRONLY | O_NOFOLLOW) returns ELOOP if the leaf
    # is a symlink, and fstat+S_ISFIFO rejects a regular-file swap via
    # any other race. No O_CREAT and no O_TRUNC: under any race, the
    # chaperon cannot damage an unintended target. `timeout 10` protects
    # against a dead stub that never reads.
    local _write_rc=0
    printf 'CHAPERON/1 RESULT\nEXIT %s\nSTDOUT %s\nSTDERR %s\nEND\n' \
        "$_exit_code" "$_stdout_b64" "$_stderr_b64" \
        | timeout 10 python3 -c '
import os, stat, sys
path = sys.argv[1]
try:
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
except OSError:
    sys.exit(1)
try:
    st = os.fstat(fd)
    if not stat.S_ISFIFO(st.st_mode):
        sys.exit(2)
    data = sys.stdin.buffer.read()
    while data:
        n = os.write(fd, data)
        data = data[n:]
finally:
    os.close(fd)
' "$REQ_RESP_FIFO" 2>/dev/null || _write_rc=$?
    if [[ "$_write_rc" -ne 0 ]]; then
        case "$_write_rc" in
            1) chaperon_log warn "response open failed (ELOOP / missing) for $_log_cmd: $(chaperon_log_escape "$REQ_RESP_FIFO")" ;;
            2) chaperon_log warn "response target is not a FIFO after validation (race) for $_log_cmd: $(chaperon_log_escape "$REQ_RESP_FIFO")" ;;
            124) chaperon_log warn "response write timed out for $_log_cmd" ;;
            *) chaperon_log warn "response write failed (rc=$_write_rc) for $_log_cmd" ;;
        esac
    fi
}

# ── Main loop ────────────────────────────────────────────────────

while true; do
    if [[ "$_chaperon_reload_requested" == true ]]; then
        _chaperon_reload_requested=false
        _chaperon_load_view
    fi
    # Read next request with a timeout. If no request arrives within
    # 5 seconds, check if the parent is still alive. This handles the
    # case where PR_SET_PDEATHSIG doesn't fire (e.g., reparenting).
    _read_rc=0
    IFS= read -r -t 5 _header_line <&"$READ_FD" 2>/dev/null || _read_rc=$?
    if [[ "$_read_rc" -ne 0 ]]; then
        if [[ "$_read_rc" -gt 128 ]]; then
            # Timeout — check if parent is still alive
            if ! kill -0 "$PPID" 2>/dev/null; then
                break  # Parent died
            fi
            continue   # Parent alive, keep waiting
        fi
        break  # EOF or error
    fi

    # We got the header line; now read the rest of the request.
    # Push the header line back by prepending it to the request parser.
    if [[ "$_header_line" != CHAPERON/1\ * ]]; then
        continue  # Invalid header, skip
    fi
    REQ_COMMAND="${_header_line#CHAPERON/1 }"
    REQ_ARGS=()
    REQ_CWD=""
    REQ_SCRIPT=""
    REQ_SCRIPT_ARGS=()
    REQ_RESP_FIFO=""

    # Read body lines with a timeout to prevent a malicious sender from
    # blocking the chaperon by sending a header but never sending END.
    #
    # A request is MALFORMED, and is dropped without running anything, if
    # it is not a single intact message. The case that matters: a stub
    # whose write times out while the chaperon is busy is killed partway
    # through a message larger than the pipe buffer (64 KiB). The FIFO
    # then holds a truncated request, and the next stub's message is
    # appended to it. Without these checks the second request's lines
    # were parsed into the first (its ARGs, CWD, SCRIPT and RESP_FIFO
    # under the first's command, usually sbatch). Wherever the cut falls,
    # the next message's header "CHAPERON/1 <cmd>" lands in a body line:
    # on a line of its own, or glued to a cut keyword, payload or path.
    #   - a body line containing "CHAPERON/1 " (a second header);
    #   - an ARG/CWD/SCRIPT/SCRIPT_ARG payload outside the base64 alphabet;
    #   - CWD, SCRIPT or RESP_FIFO given twice;
    #   - no END before the body timeout (or EOF).
    # On a malformed body the rest is still read up to END, so the next
    # request starts on a clean header, and nothing more is decoded.
    _line=""
    _body_timeout=30
    _malformed=""
    _got_end=false
    _n_cwd=0; _n_script=0; _n_resp=0
    while IFS= read -r -t "$_body_timeout" _line <&"$READ_FD"; do
        if [[ "$_line" == END ]]; then
            _got_end=true
            break
        fi
        if [[ "$_line" == *"CHAPERON/1 "* ]]; then
            _malformed="${_malformed:-a second request header inside the body}"
        fi
        case "$_line" in
            ARG\ *)        _encoded="${_line#ARG }" ;;
            CWD\ *)        _encoded="${_line#CWD }";        (( ++_n_cwd )) ;;
            SCRIPT\ *)     _encoded="${_line#SCRIPT }";     (( ++_n_script )) ;;
            SCRIPT_ARG\ *) _encoded="${_line#SCRIPT_ARG }" ;;
            RESP_FIFO\ *)
                # Keep the LAST one: when two messages were glued, it is
                # the live stub's, and it is answered with an error below.
                REQ_RESP_FIFO="${_line#RESP_FIFO }"
                (( ++_n_resp ))
                (( _n_resp > 1 )) && _malformed="${_malformed:-RESP_FIFO given twice}"
                continue
                ;;
            *)  continue ;;  # Unknown line: ignored (forward compat)
        esac
        if (( _n_cwd > 1 || _n_script > 1 )); then
            _malformed="${_malformed:-CWD or SCRIPT given twice}"
        fi
        if ! chaperon_b64_valid "$_encoded"; then
            _malformed="${_malformed:-a payload outside the base64 alphabet (${_line%% *} line)}"
        fi
        [[ -n "$_malformed" ]] && continue
        # A failed decode (bad length or padding) is malformed too. It is
        # checked here because under `set -e` a failed command substitution
        # in a plain assignment would end the chaperon.
        if ! _decoded="$(printf '%s' "$_encoded" | chaperon_b64_decode 2>/dev/null)"; then
            _malformed="a payload that does not decode as base64 (${_line%% *} line)"
            continue
        fi
        case "$_line" in
            ARG\ *)        REQ_ARGS+=("$_decoded") ;;
            CWD\ *)        REQ_CWD="$_decoded" ;;
            SCRIPT\ *)     REQ_SCRIPT="$_decoded" ;;
            SCRIPT_ARG\ *) REQ_SCRIPT_ARGS+=("$_decoded") ;;
        esac
    done
    if [[ -z "$_malformed" ]] && ! "$_got_end"; then
        _malformed="no END before the body timeout or EOF"
    fi

    if [[ -z "$REQ_COMMAND" ]]; then
        continue
    fi

    if [[ -n "$_malformed" ]]; then
        chaperon_log error "dropped malformed request (command=$(chaperon_log_escape "$REQ_COMMAND")): ${_malformed}; nothing was run"
        # Answer the stub that is waiting, if its RESP_FIFO checks out, so it
        # fails at once with a reason instead of timing out.
        if [[ -n "$REQ_RESP_FIFO" ]] && _chaperon_resp_fifo_ok; then
            _chaperon_send_response 1 "" \
                "$(printf 'error: the chaperon received a malformed request (%s) and dropped it without running anything; run the command again\n' \
                    "$_malformed" | chaperon_b64_encode)" \
                "dropped request"
        fi
        continue
    fi

    # The request includes a RESP_FIFO line with the path to the
    # per-request response FIFO. The stub creates it before sending.
    if [[ -z "${REQ_RESP_FIFO:-}" ]]; then
        chaperon_log warn "request missing RESP_FIFO (command=$(chaperon_log_escape "$REQ_COMMAND"))"
        continue
    fi

    _chaperon_resp_fifo_ok || continue

    # Log full request details for audit trail. Every agent-controlled
    # field goes through chaperon_log_escape so each log call produces
    # exactly one line (no forged entries via newline in args / cwd).
    _log_args="$(chaperon_log_escape "${REQ_ARGS[*]:-}")"
    _log_cwd="$(chaperon_log_escape "${REQ_CWD:-<unset>}")"
    _log_cmd="$(chaperon_log_escape "$REQ_COMMAND")"
    chaperon_log info "request: $_log_cmd args=[${_log_args}] cwd=${_log_cwd}"
    if [[ -n "${REQ_SCRIPT:-}" ]]; then
        # Log size and shebang only. Script body is intentionally NOT logged
        # because it may contain secrets (API keys, DB credentials) or
        # PHI/PII. The args, CWD, and handler denials provide sufficient
        # audit trail without the secret exposure risk.
        _log_shebang=""
        if [[ "$REQ_SCRIPT" == "#!"* ]]; then
            _log_shebang=" shebang=$(chaperon_log_escape "${REQ_SCRIPT%%$'\n'*}")"
        fi
        chaperon_log info "request: $_log_cmd script=${#REQ_SCRIPT} bytes${_log_shebang}"
    fi

    # Dispatch to handler, capturing stdout and stderr
    _ch_stdout="$(mktemp "${TMPDIR:-/tmp}/chaperon-out-XXXXXX")"
    _ch_stderr="$(mktemp "${TMPDIR:-/tmp}/chaperon-err-XXXXXX")"

    _exit_code=0
    # Close the req FIFO FD for handler subprocesses to prevent:
    #   1. Child processes (squeue, scancel, etc.) from inheriting FD 3
    #   2. Potential hangs if a child holds the FIFO open
    # We re-use READ_FD (3) for the main loop, so only close in the
    # redirection context (child processes inherit the closed FD).
    dispatch_handler "$REQ_COMMAND" 3>&- >"$_ch_stdout" 2>"$_ch_stderr" || _exit_code=$?

    if [[ "$_exit_code" -ne 0 ]]; then
        chaperon_log warn "handler $_log_cmd exited $_exit_code"
    else
        chaperon_log debug "handler $_log_cmd exited 0"
    fi

    # Log handler stderr (contains deny/warn messages from _sandbox_deny/_sandbox_warn).
    # These are critical for security audit — they show what was blocked and why.
    if [[ -s "$_ch_stderr" ]]; then
        while IFS= read -r _stderr_line; do
            chaperon_log warn "handler $_log_cmd stderr: $(chaperon_log_escape "$_stderr_line")"
        done < "$_ch_stderr"
    fi

    _stdout_b64="$(chaperon_b64_encode < "$_ch_stdout")"
    _stderr_b64="$(chaperon_b64_encode < "$_ch_stderr")"

    rm -f "$_ch_stdout" "$_ch_stderr"

    _chaperon_send_response "$_exit_code" "$_stdout_b64" "$_stderr_b64" "$_log_cmd"
done

exit 0

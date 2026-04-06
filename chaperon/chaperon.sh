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
#   chaperon.sh <fifo_dir> <project_dir> <sandbox_exec_path>

set -euo pipefail

CHAPERON_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$CHAPERON_DIR/protocol.sh"

# ── Arguments ────────────────────────────────────────────────────

FIFO_DIR="${1:-}"
PROJECT_DIR="${2:-}"
SANDBOX_EXEC="${3:-}"

if [[ -z "$FIFO_DIR" || -z "$PROJECT_DIR" || -z "$SANDBOX_EXEC" ]]; then
    echo "chaperon: usage: chaperon.sh <fifo_dir> <project_dir> <sandbox_exec_path>" >&2
    exit 1
fi

# ── Orphan prevention ────────────────────────────────────────────
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

_chaperon_cleanup() {
    exec 3<&- 2>/dev/null || true
    rm -rf "$FIFO_DIR" 2>/dev/null || true
    exit 0
}

trap _chaperon_cleanup SIGTERM SIGINT EXIT

# ── Open request FIFO ────────────────────────────────────────────
# Open read+write (O_RDWR) on the req FIFO. This:
#   1. Doesn't block (O_RDWR on a FIFO doesn't wait for a peer)
#   2. Keeps a write reference alive, preventing EOF between requests
#      when stubs close their write ends
exec 3<>"$FIFO_DIR/req"

READ_FD=3

# ── Handler dispatch ─────────────────────────────────────────────

dispatch_handler() {
    local command="$1"

    # Validate command name to prevent path traversal (e.g. "../../etc/passwd")
    if [[ ! "$command" =~ ^[a-z_][a-z0-9_]*$ ]]; then
        echo "chaperon: rejected invalid command name: $command" >&2
        return 1
    fi

    local handler_script="$CHAPERON_DIR/handlers/${command}.sh"

    if [[ -f "$handler_script" ]]; then
        source "$handler_script"
        local handler_fn="handle_${command}"
        if declare -f "$handler_fn" &>/dev/null; then
            "$handler_fn" "$PROJECT_DIR" "$SANDBOX_EXEC"
            return $?
        fi
    fi

    source "$CHAPERON_DIR/handlers/blocked.sh"
    handle_blocked
    return $?
}

# ── Main loop ────────────────────────────────────────────────────

while true; do
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
    REQ_RESP_FIFO=""

    # Read body lines with a timeout to prevent a malicious sender from
    # blocking the chaperon by sending a header but never sending END.
    _line=""
    _body_timeout=30
    while IFS= read -r -t "$_body_timeout" _line <&"$READ_FD"; do
        case "$_line" in
            ARG\ *)
                _encoded="${_line#ARG }"
                REQ_ARGS+=("$(printf '%s' "$_encoded" | chaperon_b64_decode)")
                ;;
            CWD\ *)
                _encoded="${_line#CWD }"
                REQ_CWD="$(printf '%s' "$_encoded" | chaperon_b64_decode)"
                ;;
            SCRIPT\ *)
                _encoded="${_line#SCRIPT }"
                REQ_SCRIPT="$(printf '%s' "$_encoded" | chaperon_b64_decode)"
                ;;
            RESP_FIFO\ *)
                REQ_RESP_FIFO="${_line#RESP_FIFO }"
                ;;
            END)
                break
                ;;
        esac
    done

    if [[ -z "$REQ_COMMAND" ]]; then
        continue
    fi

    # The request includes a RESP_FIFO line with the path to the
    # per-request response FIFO. The stub creates it before sending.
    if [[ -z "${REQ_RESP_FIFO:-}" ]]; then
        echo "chaperon: request missing RESP_FIFO" >&2
        continue
    fi

    # Validate RESP_FIFO: must be FIFO_DIR/resp-XXXXXX/fifo, no ".." components,
    # not a symlink. The stub creates an atomic directory (mktemp -d) with a
    # FIFO inside, so the expected structure is deterministic.
    if [[ "$REQ_RESP_FIFO" != "$FIFO_DIR/"*/fifo ]] || [[ "$REQ_RESP_FIFO" == *".."* ]]; then
        echo "chaperon: RESP_FIFO path validation failed: $REQ_RESP_FIFO" >&2
        continue
    fi

    # Reject symlinks: -p follows symlinks, so a symlink → FIFO would pass.
    # A malicious process could race to replace the FIFO with a symlink
    # pointing outside the FIFO directory to intercept the response.
    if [[ -L "$REQ_RESP_FIFO" ]] || [[ ! -p "$REQ_RESP_FIFO" ]]; then
        echo "chaperon: RESP_FIFO is symlink or not a FIFO: $REQ_RESP_FIFO" >&2
        continue
    fi

    # Open the FIFO immediately after validation and hold the FD to prevent
    # TOCTOU: a symlink swap between validation and write.
    _resp_fd=""
    exec {_resp_fd}>"$REQ_RESP_FIFO" 2>/dev/null || {
        echo "chaperon: failed to open RESP_FIFO: $REQ_RESP_FIFO" >&2
        continue
    }

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

    _stdout_b64="$(chaperon_b64_encode < "$_ch_stdout")"
    _stderr_b64="$(chaperon_b64_encode < "$_ch_stderr")"

    rm -f "$_ch_stdout" "$_ch_stderr"

    # Validate exit code is numeric before sending
    if [[ ! "$_exit_code" =~ ^[0-9]+$ ]]; then
        _exit_code=1
    fi

    # Send response via the held FD (not the path) to avoid TOCTOU.
    # Use a timeout to prevent deadlock if the stub dies without reading.
    _write_ok=true
    {
        printf 'CHAPERON/1 RESULT\n'
        printf 'EXIT %s\n' "$_exit_code"
        printf 'STDOUT %s\n' "$_stdout_b64"
        printf 'STDERR %s\n' "$_stderr_b64"
        printf 'END\n'
    } >&"$_resp_fd" 2>/dev/null &
    _write_pid=$!

    # Wait up to 10 seconds for the write to complete
    _w=0
    while (( _w < 10 )) && kill -0 "$_write_pid" 2>/dev/null; do
        sleep 1
        (( _w++ )) || true
    done
    if kill -0 "$_write_pid" 2>/dev/null; then
        kill "$_write_pid" 2>/dev/null || true
        wait "$_write_pid" 2>/dev/null || true
        echo "chaperon: response write timed out for $REQ_COMMAND" >&2
    else
        wait "$_write_pid" 2>/dev/null || _write_ok=false
    fi

    exec {_resp_fd}>&-
done

exit 0

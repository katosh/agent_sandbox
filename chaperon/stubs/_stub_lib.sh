#! /bin/bash --
# chaperon/stubs/_stub_lib.sh — Stub-to-chaperon communication
#
# Used by PATH-shadowing stubs inside the sandbox to send requests
# to the chaperon process via named pipes (FIFOs).
#
# Environment:
#   _CHAPERON_FIFO_DIR — directory containing the request FIFO

_STUB_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
source "$_STUB_DIR/../protocol.sh"

# Send a request to the chaperon and print the response.
# Usage: chaperon_call <command> [args...]
#
# If _CHAPERON_SCRIPT is set, it's sent as the SCRIPT field.
# stdout/stderr from the remote command are printed locally.
# Returns the remote exit code.
chaperon_call() {
    local command="$1"
    shift

    local fifo_dir="${_CHAPERON_FIFO_DIR:-}"
    if [[ -z "$fifo_dir" || ! -p "$fifo_dir/req" ]]; then
        echo "error: chaperon request FIFO not found — not running inside sandbox?" >&2
        return 127
    fi

    local has_script=false
    if [[ -n "${_CHAPERON_SCRIPT:-}" ]]; then
        has_script=true
    fi

    # Create a per-request response FIFO with unpredictable name (mktemp)
    local resp_fifo
    resp_fifo="$(mktemp -u "$fifo_dir/resp-XXXXXX")"
    mkfifo "$resp_fifo" 2>/dev/null || {
        echo "error: cannot create response FIFO" >&2
        return 127
    }
    chmod 600 "$resp_fifo"

    # Build the entire request message into a variable first, then write
    # atomically. For messages under PIPE_BUF (4096 bytes on Linux) a single
    # write is guaranteed atomic, preventing interleaving from concurrent stubs.
    local msg=""
    msg+="$(printf 'CHAPERON/1 %s\n' "$command")"

    # Send arguments
    for arg in "$@"; do
        msg+="$(printf '\nARG %s' "$(printf '%s' "$arg" | chaperon_b64_encode)")"
    done

    # Send CWD
    msg+="$(printf '\nCWD %s' "$(printf '%s' "$(pwd)" | chaperon_b64_encode)")"

    # Send script content if available
    if "$has_script"; then
        msg+="$(printf '\nSCRIPT %s' "$(printf '%s' "$_CHAPERON_SCRIPT" | chaperon_b64_encode)")"
    fi

    # Tell chaperon where to send the response
    msg+="$(printf '\nRESP_FIFO %s' "$resp_fifo")"
    msg+="$(printf '\nEND')"

    # Write atomically: acquire flock to prevent interleaving from concurrent stubs.
    # For messages under PIPE_BUF (4096), a single write() is atomic on Linux,
    # but we always lock for safety with concurrent large+small messages.
    (
        flock 9
        printf '%s\n' "$msg" > "$fifo_dir/req"
    ) 9>"$fifo_dir/req.lock"

    # Read response from per-request FIFO with a timeout to prevent infinite
    # hangs if the chaperon process dies.
    local resp_fd
    exec {resp_fd}<"$resp_fifo"

    if ! chaperon_read_response "$resp_fd" 30; then
        echo "error: failed to read chaperon response (timeout or error)" >&2
        exec {resp_fd}<&-
        rm -f "$resp_fifo"
        return 127
    fi

    exec {resp_fd}<&-
    rm -f "$resp_fifo"

    # Print stdout
    if [[ -n "$RESP_STDOUT_B64" ]]; then
        printf '%s' "$RESP_STDOUT_B64" | chaperon_b64_decode
    fi

    # Print stderr
    if [[ -n "$RESP_STDERR_B64" ]]; then
        printf '%s' "$RESP_STDERR_B64" | chaperon_b64_decode >&2
    fi

    # Validate exit code is numeric; default to 1 if not
    if [[ ! "$RESP_EXIT" =~ ^[0-9]+$ ]]; then
        RESP_EXIT=1
    fi

    return "$RESP_EXIT"
}

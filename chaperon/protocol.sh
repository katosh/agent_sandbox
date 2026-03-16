#! /bin/bash --
# chaperon/protocol.sh — CHAPERON/1 wire protocol primitives
#
# Line-based protocol with base64-encoded payloads to prevent injection.
# All user data (arguments, paths, script content) is base64-encoded
# with -w 0 (single-line output).
#
# Request format:
#   CHAPERON/1 <command>
#   ARG <base64>
#   CWD <base64>
#   SCRIPT <base64>
#   END
#
# Response format:
#   CHAPERON/1 RESULT
#   EXIT <number>
#   STDOUT <base64>
#   STDERR <base64>
#   END
#
# Shared between chaperon.sh (reader) and stubs (writer), and vice versa.

# Encode arbitrary bytes to a single base64 line (no wrapping).
chaperon_b64_encode() {
    base64 -w 0
}

# Decode a single base64 line back to bytes.
chaperon_b64_decode() {
    base64 -d
}

# ── Request writing (used by stubs) ──────────────────────────────

# Write a complete request to the chaperon FD.
# Usage: chaperon_send_request <fd> <command> <cwd> [args...] [--script-stdin]
#
# If --script-stdin is the last argument, stdin is read as the script body.
chaperon_send_request() {
    local fd="$1" cmd="$2" cwd="$3"
    shift 3

    local has_script=false
    local args=()
    for arg in "$@"; do
        if [[ "$arg" == "--script-stdin" ]]; then
            has_script=true
        else
            args+=("$arg")
        fi
    done

    # Header
    printf 'CHAPERON/1 %s\n' "$cmd" >&"$fd"

    # Arguments
    for arg in "${args[@]}"; do
        printf 'ARG %s\n' "$(printf '%s' "$arg" | chaperon_b64_encode)" >&"$fd"
    done

    # Working directory
    printf 'CWD %s\n' "$(printf '%s' "$cwd" | chaperon_b64_encode)" >&"$fd"

    # Script body (from stdin)
    if "$has_script"; then
        printf 'SCRIPT %s\n' "$(chaperon_b64_encode)" >&"$fd"
    fi

    # End marker
    printf 'END\n' >&"$fd"
}

# ── Response writing (used by chaperon) ──────────────────────────

# Write a complete response to the stub FD.
# Usage: chaperon_send_response <fd> <exit_code> <stdout_b64> <stderr_b64>
chaperon_send_response() {
    local fd="$1" exit_code="$2" stdout_b64="$3" stderr_b64="$4"

    printf 'CHAPERON/1 RESULT\n' >&"$fd"
    printf 'EXIT %s\n' "$exit_code" >&"$fd"
    printf 'STDOUT %s\n' "$stdout_b64" >&"$fd"
    printf 'STDERR %s\n' "$stderr_b64" >&"$fd"
    printf 'END\n' >&"$fd"
}

# ── Request reading (used by chaperon) ───────────────────────────

# Read a complete request from the chaperon FD.
# Sets global variables: REQ_COMMAND, REQ_ARGS (array), REQ_CWD, REQ_SCRIPT
# Returns 0 on success, 1 on EOF/error.
chaperon_read_request() {
    local fd="$1"

    REQ_COMMAND=""
    REQ_ARGS=()
    REQ_CWD=""
    REQ_SCRIPT=""
    REQ_RESP_FIFO=""

    # Read header line
    local header
    IFS= read -r header <&"$fd" || return 1

    # Validate protocol version and extract command
    if [[ "$header" != CHAPERON/1\ * ]]; then
        return 1
    fi
    REQ_COMMAND="${header#CHAPERON/1 }"

    # Read body lines until END
    local line
    while IFS= read -r line <&"$fd"; do
        case "$line" in
            ARG\ *)
                local encoded="${line#ARG }"
                REQ_ARGS+=("$(printf '%s' "$encoded" | chaperon_b64_decode)")
                ;;
            CWD\ *)
                local encoded="${line#CWD }"
                REQ_CWD="$(printf '%s' "$encoded" | chaperon_b64_decode)"
                ;;
            SCRIPT\ *)
                local encoded="${line#SCRIPT }"
                REQ_SCRIPT="$(printf '%s' "$encoded" | chaperon_b64_decode)"
                ;;
            RESP_FIFO\ *)
                REQ_RESP_FIFO="${line#RESP_FIFO }"
                ;;
            END)
                break
                ;;
            *)
                # Unknown line — silently ignore (forward compat)
                ;;
        esac
    done

    [[ -n "$REQ_COMMAND" ]]
}

# ── Response reading (used by stubs) ─────────────────────────────

# Read a complete response from the chaperon FD.
# Sets global variables: RESP_EXIT, RESP_STDOUT_B64, RESP_STDERR_B64
# Returns 0 on success, 1 on EOF/error.
chaperon_read_response() {
    local fd="$1"
    local timeout="${2:-0}"  # Optional timeout in seconds; 0 means no timeout

    RESP_EXIT=1
    RESP_STDOUT_B64=""
    RESP_STDERR_B64=""

    local _read_opts=(-r)
    if [[ "$timeout" -gt 0 ]] 2>/dev/null; then
        _read_opts+=(-t "$timeout")
    fi

    # Read header line
    local header
    IFS= read "${_read_opts[@]}" header <&"$fd" || return 1

    if [[ "$header" != "CHAPERON/1 RESULT" ]]; then
        return 1
    fi

    # Read body lines until END
    local line
    while IFS= read "${_read_opts[@]}" line <&"$fd"; do
        case "$line" in
            EXIT\ *)
                RESP_EXIT="${line#EXIT }"
                # Validate exit code is numeric
                if [[ ! "$RESP_EXIT" =~ ^[0-9]+$ ]]; then
                    RESP_EXIT=1
                fi
                ;;
            STDOUT\ *)
                RESP_STDOUT_B64="${line#STDOUT }"
                ;;
            STDERR\ *)
                RESP_STDERR_B64="${line#STDERR }"
                ;;
            END)
                break
                ;;
            *)
                # Unknown line — silently ignore (forward compat)
                ;;
        esac
    done

    return 0
}

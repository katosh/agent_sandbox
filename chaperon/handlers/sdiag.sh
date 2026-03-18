#! /bin/bash --
# chaperon/handlers/sdiag.sh — Handle sdiag requests from sandbox
#
# sdiag shows scheduler diagnostics — read-only system information
# with no user-identifiable data.  Most flags are passed through.
#
# Allowed:
#   -a/--all, --help, --usage, --version, --json, --yaml, --sort-by-*
#
# Denied:
#   -r/--reset — clears scheduler stats (write operation)

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed sdiag flags ───────────────────────────────────────
_SDIAG_ALLOWED_FLAGS=" \
  -a --all \
  --help \
  --usage \
  --version \
  --json \
  --yaml \
"

_is_sdiag_allowed() {
    local base="${1%%=*}"
    [[ "$_SDIAG_ALLOWED_FLAGS" == *" $base "* ]]
}

handle_sdiag() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_sdiag="${REAL_SDIAG:-/usr/bin/sdiag}"
    if [[ ! -x "$real_sdiag" ]]; then
        _sandbox_warn "sdiag binary not found at $real_sdiag — is Slurm installed?"
        return 1
    fi

    local validated_flags=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Denied: write operation
            -r|--reset)
                _sandbox_deny "sdiag '--reset' is not allowed — resetting scheduler statistics is a write operation."
                return 1
                ;;
            --*=*)
                if _is_sdiag_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "sdiag flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            -*)
                if _is_sdiag_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "sdiag flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            *)
                _sandbox_warn "unexpected sdiag argument: '$arg'"
                return 1
                ;;
        esac
        (( i++ )) || true
    done

    local rc=0
    "$real_sdiag" "${validated_flags[@]}" || rc=$?
    return "$rc"
}

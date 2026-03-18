#! /bin/bash --
# chaperon/handlers/sprio.sh — Handle sprio requests from sandbox
#
# sprio shows priority factors for pending jobs.  The handler always
# injects --user=$(whoami) to scope output to the current user only.
# Explicit --user and --allusers flags are denied.

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed sprio flags ──────────────────────────────────────────
_SPRIO_ALLOWED_FLAGS=" \
  -j --jobs \
  -l --long \
  -n --noheader \
  -o --format \
  -S --sort \
  -w --weights \
  -h --usage \
  -v --verbose \
  --help \
  --version \
  --json \
  --yaml \
"

_SPRIO_VALUE_FLAGS=" \
  -j --jobs \
  -o --format \
  -S --sort \
"

_is_sprio_allowed() {
    local base="${1%%=*}"
    [[ "$_SPRIO_ALLOWED_FLAGS" == *" $base "* ]]
}

_is_sprio_value_flag() {
    [[ "$_SPRIO_VALUE_FLAGS" == *" $1 "* ]]
}

handle_sprio() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_sprio="${REAL_SPRIO:-/usr/bin/sprio}"
    if [[ ! -x "$real_sprio" ]]; then
        _sandbox_warn "sprio binary not found at $real_sprio — is Slurm installed?"
        return 1
    fi

    # Parse and validate arguments
    local validated_flags=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Deny --allusers
            --allusers)
                _sandbox_deny "sprio '--allusers' is not allowed — only your own jobs are shown inside the sandbox."
                return 1
                ;;
            # Intercept --user: we always override to $(whoami)
            -u|--user)
                _sandbox_deny "sprio '--user' is not allowed — the sandbox automatically scopes to your user."
                return 1
                ;;
            --user=*)
                _sandbox_deny "sprio '--user' is not allowed — the sandbox automatically scopes to your user."
                return 1
                ;;
            --*=*)
                if _is_sprio_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "sprio flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            -*)
                if _is_sprio_allowed "$arg"; then
                    validated_flags+=("$arg")
                    if _is_sprio_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ )) || true
                        validated_flags+=("${REQ_ARGS[$i]}")
                    fi
                else
                    _sandbox_warn "sprio flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            *)
                _sandbox_warn "unexpected sprio argument: '$arg'"
                return 1
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage
    for f in "${validated_flags[@]}"; do
        case "$f" in --help|--version|-h|--usage)
            local rc=0
            "$real_sprio" "${validated_flags[@]}" || rc=$?
            return "$rc"
            ;;
        esac
    done

    # Always scope to current user
    local rc=0
    "$real_sprio" --user="$(whoami)" "${validated_flags[@]}" || rc=$?
    return "$rc"
}

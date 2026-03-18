#! /bin/bash --
# chaperon/handlers/sinfo.sh — Handle sinfo requests from sandbox
#
# sinfo shows partition and node status.  It is read-only and does not
# expose per-user data, so no scoping is needed.  Unknown flags are
# denied as a precaution.

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed sinfo flags ──────────────────────────────────────────
_SINFO_ALLOWED_FLAGS=" \
  -l --long \
  -N --Node \
  -o --format \
  -O --Format \
  -p --partition \
  -t --states \
  -n --nodes \
  -S --sort \
  -h --noheader \
  -e --exact \
  -r --responding \
  -v --verbose \
  -Q --quiet \
  --json \
  --yaml \
  --help \
  --usage \
  --version \
"

_SINFO_VALUE_FLAGS=" \
  -o --format \
  -O --Format \
  -p --partition \
  -t --states \
  -n --nodes \
  -S --sort \
"

_is_sinfo_allowed() {
    local base="${1%%=*}"
    [[ "$_SINFO_ALLOWED_FLAGS" == *" $base "* ]]
}

_is_sinfo_value_flag() {
    [[ "$_SINFO_VALUE_FLAGS" == *" $1 "* ]]
}

handle_sinfo() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_sinfo="${REAL_SINFO:-/usr/bin/sinfo}"
    if [[ ! -x "$real_sinfo" ]]; then
        _sandbox_warn "sinfo binary not found at $real_sinfo — is Slurm installed?"
        return 1
    fi

    # Parse and validate arguments
    local validated_flags=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Deny --user (doesn't exist for sinfo, but block it to be safe)
            -u|--user|--user=*)
                _sandbox_warn "sinfo '--user' is not allowed — sinfo does not support user filtering."
                return 1
                ;;
            --*=*)
                if _is_sinfo_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "sinfo flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            -*)
                if _is_sinfo_allowed "$arg"; then
                    validated_flags+=("$arg")
                    if _is_sinfo_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ )) || true
                        validated_flags+=("${REQ_ARGS[$i]}")
                    fi
                else
                    _sandbox_warn "sinfo flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            *)
                _sandbox_warn "unexpected sinfo argument: '$arg'"
                return 1
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage
    for f in "${validated_flags[@]}"; do
        case "$f" in --help|--usage|--version)
            local rc=0
            "$real_sinfo" "${validated_flags[@]}" || rc=$?
            return "$rc"
            ;;
        esac
    done

    # sinfo is read-only system info — pass through directly
    local rc=0
    "$real_sinfo" "${validated_flags[@]}" || rc=$?
    return "$rc"
}

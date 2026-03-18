#! /bin/bash --
# chaperon/handlers/sacct.sh — Handle sacct requests from sandbox
#
# Scoped to the current user only.  Flags that would show other users'
# jobs (--allusers, --user=X) are denied.  The handler always injects
# --user=$(whoami) to enforce single-user scope.
#
# Job-level scoping (by chaperon comment) is not applied because sacct
# is retrospective (completed jobs) and the comment filter would be too
# restrictive for debugging.  User-level scoping is sufficient.

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed sacct flags ──────────────────────────────────────────
_SACCT_ALLOWED_FLAGS=" \
  -b --brief \
  -e --helpformat \
  -j --jobs \
  -l --long \
  -n --noheader \
  -o --format \
  -P --parsable \
  -p --parsable2 \
  -S --starttime \
  -E --endtime \
  -T --truncate \
  -s --state \
  -X --allocations \
  --name \
  --json \
  --yaml \
  -v --verbose \
  -Q --quiet \
  --help \
  --usage \
  --version \
  --units \
  --noconvert \
  --duplicates \
"

_SACCT_VALUE_FLAGS=" \
  -j --jobs \
  -o --format \
  -S --starttime \
  -E --endtime \
  -s --state \
  --name \
  --units \
"

_is_sacct_allowed() {
    local base="${1%%=*}"
    [[ "$_SACCT_ALLOWED_FLAGS" == *" $base "* ]]
}

_is_sacct_value_flag() {
    [[ "$_SACCT_VALUE_FLAGS" == *" $1 "* ]]
}

handle_sacct() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_sacct="${REAL_SACCT:-/usr/bin/sacct}"
    if [[ ! -x "$real_sacct" ]]; then
        _sandbox_warn "sacct binary not found at $real_sacct — is Slurm installed?"
        return 1
    fi

    local validated_flags=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Denied: user scope is enforced by the chaperon
            -a|--allusers)
                _sandbox_deny "sacct '--allusers' is not allowed — only your own jobs are shown inside the sandbox."
                return 1
                ;;
            -u|--user|--user=*)
                _sandbox_deny "sacct '--user' is not allowed — the sandbox automatically scopes to your user."
                return 1
                ;;
            --uid|--uid=*)
                _sandbox_deny "sacct '--uid' is not allowed — the sandbox automatically scopes to your user."
                return 1
                ;;
            -A|--accounts|--accounts=*)
                _sandbox_deny "sacct '--accounts' is not allowed — account-level queries could enumerate other users."
                return 1
                ;;
            -W|--wckeys|--wckeys=*)
                _sandbox_deny "sacct '--wckeys' is not allowed."
                return 1
                ;;
            --*=*)
                if _is_sacct_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "sacct flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            -*)
                if _is_sacct_allowed "$arg"; then
                    validated_flags+=("$arg")
                    if _is_sacct_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ )) || true
                        validated_flags+=("${REQ_ARGS[$i]}")
                    fi
                else
                    _sandbox_warn "sacct flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            *)
                _sandbox_warn "unexpected sacct argument: '$arg'"
                return 1
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage
    for f in "${validated_flags[@]}"; do
        case "$f" in --help|--usage|--version|-e|--helpformat)
            local rc=0
            "$real_sacct" "${validated_flags[@]}" || rc=$?
            return "$rc"
            ;;
        esac
    done

    # Always scope to current user; strip chaperon tags from output
    local rc=0
    "$real_sacct" --user="$(whoami)" "${validated_flags[@]}" | _strip_chaperon_tags || rc=$?
    return "$rc"
}

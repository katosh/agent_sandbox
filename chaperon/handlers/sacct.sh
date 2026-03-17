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
        echo "chaperon: real sacct not found at $real_sacct" >&2
        return 1
    fi

    local validated_flags=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Denied: user scope is enforced by the chaperon
            -a|--allusers)
                echo "chaperon: sacct --allusers denied (scoped to current user)" >&2
                return 1
                ;;
            -u|--user|--user=*)
                echo "chaperon: sacct --user denied (scoped to current user)" >&2
                return 1
                ;;
            --uid|--uid=*)
                echo "chaperon: sacct --uid denied (scoped to current user)" >&2
                return 1
                ;;
            -A|--accounts|--accounts=*)
                echo "chaperon: sacct --accounts denied (user enumeration)" >&2
                return 1
                ;;
            -W|--wckeys|--wckeys=*)
                echo "chaperon: sacct --wckeys denied" >&2
                return 1
                ;;
            --*=*)
                if _is_sacct_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    echo "chaperon: denied unknown sacct flag: ${arg%%=*}" >&2
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
                    echo "chaperon: denied unknown sacct flag: $arg" >&2
                    return 1
                fi
                ;;
            *)
                echo "chaperon: invalid sacct argument: $arg" >&2
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

    # Always scope to current user
    local rc=0
    "$real_sacct" --user="$(whoami)" "${validated_flags[@]}" || rc=$?
    return "$rc"
}

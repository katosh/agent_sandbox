#! /bin/bash --
# chaperon/handlers/sshare.sh — Handle sshare requests from sandbox
#
# Scoped to the current user only.  Always injects --user=$(whoami).
# Flags that would enumerate other users' fairshare data are denied.
#
# Allowed:
#   -l/--long, -n/--noheader, -p/--parsable, -P/--parsable2,
#   -o/--format, -v/--verbose, -Q/--quiet, --help, --usage, --version,
#   --json, --yaml
#
# Denied:
#   -a/--all/--allusers — enumerates all users
#   -u/--user           — intercepted; we force current user
#   -A/--accounts/--account — could enumerate accounts

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed sshare flags ──────────────────────────────────────
_SSHARE_ALLOWED_FLAGS=" \
  -l --long \
  -n --noheader \
  -p --parsable \
  -P --parsable2 \
  -o --format \
  -v --verbose \
  -Q --quiet \
  --help \
  --usage \
  --version \
  --json \
  --yaml \
"

_SSHARE_VALUE_FLAGS=" \
  -o --format \
"

_is_sshare_allowed() {
    local base="${1%%=*}"
    [[ "$_SSHARE_ALLOWED_FLAGS" == *" $base "* ]]
}

_is_sshare_value_flag() {
    [[ "$_SSHARE_VALUE_FLAGS" == *" $1 "* ]]
}

handle_sshare() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_sshare="${REAL_SSHARE:-/usr/bin/sshare}"
    if [[ ! -x "$real_sshare" ]]; then
        _sandbox_warn "sshare binary not found at $real_sshare — is Slurm installed?"
        return 1
    fi

    local validated_flags=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Denied: enumeration flags
            -a|--all|--allusers)
                _sandbox_deny "sshare '--allusers' is not allowed — only your own fairshare data is shown inside the sandbox."
                return 1
                ;;
            -u|--user|--user=*)
                _sandbox_deny "sshare '--user' is not allowed — the sandbox automatically scopes to your user."
                return 1
                ;;
            -A|--accounts|--account|--accounts=*|--account=*)
                _sandbox_deny "sshare '--accounts' is not allowed — account-level queries could enumerate other users."
                return 1
                ;;
            --*=*)
                if _is_sshare_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "sshare flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            -*)
                if _is_sshare_allowed "$arg"; then
                    validated_flags+=("$arg")
                    if _is_sshare_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ )) || true
                        validated_flags+=("${REQ_ARGS[$i]}")
                    fi
                else
                    _sandbox_warn "sshare flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            *)
                _sandbox_warn "unexpected sshare argument: '$arg'"
                return 1
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage
    for f in "${validated_flags[@]}"; do
        case "$f" in --help|--usage|--version)
            local rc=0
            "$real_sshare" "${validated_flags[@]}" || rc=$?
            return "$rc"
            ;;
        esac
    done

    # Always scope to current user
    local rc=0
    "$real_sshare" --user="$(whoami)" "${validated_flags[@]}" || rc=$?
    return "$rc"
}

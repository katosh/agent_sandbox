#! /bin/bash --
# chaperon/handlers/squeue.sh — Handle squeue requests from sandbox
#
# Filters squeue output to only show jobs within scope (project by default).
# Uses the same --comment tag set by the sbatch handler for scoping.
#
# Scope levels (configured via SLURM_SCOPE in sandbox.conf):
#   "project"  — jobs from any sandbox session with same project dir (default)
#   "session"  — only jobs submitted by THIS sandbox session
#   "user"     — all jobs of the current user
#   "none"     — no scope restriction

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed squeue flags ─────────────────────────────────────────
_SQUEUE_ALLOWED_FLAGS=" \
  -h --noheader \
  -l --long \
  -o --format \
  -O --Format \
  -S --sort \
  -t --states \
  -p --partition \
  -n --name \
  -j --jobs \
  -w --nodelist \
  --start \
  --array \
  -r --array-unique \
  -v --verbose \
  -Q --quiet \
  --help \
  --usage \
  --version \
  --json \
  --yaml \
"

_SQUEUE_VALUE_FLAGS=" \
  -o --format \
  -O --Format \
  -S --sort \
  -t --states \
  -p --partition \
  -n --name \
  -j --jobs \
  -w --nodelist \
"

_is_squeue_allowed() {
    local base="${1%%=*}"
    [[ "$_SQUEUE_ALLOWED_FLAGS" == *" $base "* ]]
}

_is_squeue_value_flag() {
    [[ "$_SQUEUE_VALUE_FLAGS" == *" $1 "* ]]
}

handle_squeue() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
    if [[ ! -x "$real_squeue" ]]; then
        _sandbox_warn "squeue binary not found at $real_squeue — is Slurm installed?"
        return 1
    fi

    local scope="${SLURM_SCOPE:-project}"

    # Parse and validate arguments
    local validated_flags=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Silently accept scope-widening flags — the sandbox already
            # scopes output, so these are no-ops.  Skip any attached value.
            -u|--user|--account)
                # These take a value argument — skip it
                if (( i + 1 < ${#REQ_ARGS[@]} )) && [[ "${REQ_ARGS[$((i+1))]}" != -* ]]; then
                    (( i++ )) || true
                fi
                ;;
            --user=*|--account=*|--me)
                # Self-contained — just skip
                ;;
            --*=*)
                if _is_squeue_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "squeue flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            -*)
                if _is_squeue_allowed "$arg"; then
                    validated_flags+=("$arg")
                    if _is_squeue_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ )) || true
                        validated_flags+=("${REQ_ARGS[$i]}")
                    fi
                else
                    _sandbox_warn "squeue flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            *)
                _sandbox_warn "unexpected squeue argument: '$arg'"
                return 1
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage
    for f in "${validated_flags[@]}"; do
        case "$f" in --help|--usage|--version)
            local rc=0
            "$real_squeue" "${validated_flags[@]}" || rc=$?
            return "$rc"
            ;;
        esac
    done

    # For "user" and "none" scopes, just show all user jobs directly
    if [[ "$scope" == "user" || "$scope" == "none" ]]; then
        local rc=0
        "$real_squeue" --me "${validated_flags[@]}" | _strip_chaperon_tags || rc=$?
        return "$rc"
    fi

    # For session/project scopes, filter by chaperon tag
    local scoped_job_ids
    scoped_job_ids="$(_get_scoped_jobs "$scope" "$project_dir")"

    if [[ -z "$scoped_job_ids" ]]; then
        # No jobs in scope — output nothing
        return 0
    fi

    # Build comma-separated job ID list for -j filter
    local job_id_list
    job_id_list="$(echo "$scoped_job_ids" | tr '\n' ',' | sed 's/,$//')"

    local rc=0
    "$real_squeue" --me -j "$job_id_list" "${validated_flags[@]}" | _strip_chaperon_tags || rc=$?
    return "$rc"
}

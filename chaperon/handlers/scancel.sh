#! /bin/bash --
# chaperon/handlers/scancel.sh — Handle scancel requests from sandbox
#
# Cancels Slurm jobs, scoped by querying the chaperon tag in --comment.
#
# Scope levels (configured via CHAPERON_SCANCEL_SCOPE in sandbox.conf):
#   "session"  — only jobs tagged with THIS session's ID (default)
#   "project"  — jobs tagged with the same project hash (any session)
#   "user"     — any job tagged by any chaperon instance of this user
#
# The tag is set by the sbatch handler:
#   --comment="chaperon:sid=<session_id>,proj=<project_hash>[,user=<comment>]"
#
# This handler queries squeue to resolve which jobs match the scope,
# then passes only those job IDs to the real scancel.  No file-based
# tracking — the tag survives array expansion and preemption.

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed scancel flags ───────────────────────────────────────
_SCANCEL_ALLOWED_FLAGS=" \
  --batch \
  --full \
  --hurry \
  --interactive \
  -n --name \
  -p --partition \
  -q --qos \
  -t --state \
  -v --verbose \
  --help \
  --usage \
  --version \
  -Q --quiet \
  --signal \
"

_SCANCEL_VALUE_FLAGS=" \
  -n --name \
  -p --partition \
  -q --qos \
  -t --state \
  --signal \
"

_is_scancel_allowed() {
    local flag="$1"
    local base="${flag%%=*}"
    [[ "$_SCANCEL_ALLOWED_FLAGS" == *" $base "* ]]
}

_is_scancel_value_flag() {
    [[ "$_SCANCEL_VALUE_FLAGS" == *" $1 "* ]]
}

# ── Scope queries ────────────────────────────────────────────────

# Get the set of job IDs that this scope is allowed to cancel.
# Prints job IDs one per line.
_get_scoped_jobs() {
    local scope="$1" project_dir="$2"

    case "$scope" in
        session)
            # Match this exact session ID
            _query_chaperon_jobs "chaperon:sid=${_CHAPERON_SESSION_ID}[,.]"
            ;;
        project)
            # Match any session with this project hash
            local proj_hash
            proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"
            _query_chaperon_jobs "chaperon:.*proj=${proj_hash}"
            ;;
        user)
            # Match any chaperon-submitted job
            _query_chaperon_jobs "chaperon:"
            ;;
        *)
            echo "chaperon: unknown CHAPERON_SCANCEL_SCOPE: $scope" >&2
            return 1
            ;;
    esac
}

# ── Handler ─────────────────────────────────────────────────────

handle_scancel() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_scancel="${REAL_SCANCEL:-/usr/bin/scancel}"
    if [[ ! -x "$real_scancel" ]]; then
        echo "chaperon: real scancel not found at $real_scancel" >&2
        return 1
    fi

    local scope="${CHAPERON_SCANCEL_SCOPE:-session}"

    # Parse and validate arguments
    local validated_flags=()
    local requested_ids=()
    local cancel_all=false
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Denied: scope is controlled by the chaperon
            -u|--user|--user=*|--me|--account|--account=*|--wckey|--wckey=*)
                echo "chaperon: scancel flag '$arg' not allowed (scope controlled by chaperon)" >&2
                return 1
                ;;
            --*=*)
                if _is_scancel_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    echo "chaperon: denied unknown scancel flag: ${arg%%=*}" >&2
                    return 1
                fi
                ;;
            -*)
                if _is_scancel_allowed "$arg"; then
                    validated_flags+=("$arg")
                    if _is_scancel_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ )) || true
                        validated_flags+=("${REQ_ARGS[$i]}")
                    fi
                else
                    echo "chaperon: denied unknown scancel flag: $arg" >&2
                    return 1
                fi
                ;;
            all)
                # "scancel all" — cancel all jobs within scope
                cancel_all=true
                ;;
            *)
                # Positional: should be a job ID (with optional array index)
                if [[ "$arg" =~ ^[0-9]+(_[0-9]+)?$ ]]; then
                    requested_ids+=("$arg")
                else
                    echo "chaperon: invalid job ID: $arg" >&2
                    return 1
                fi
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage (no job IDs needed)
    if [[ ${#requested_ids[@]} -eq 0 ]] && ! "$cancel_all"; then
        for f in "${validated_flags[@]}"; do
            case "$f" in --help|--usage|--version)
                local rc=0
                "$real_scancel" "${validated_flags[@]}" || rc=$?
                return "$rc"
                ;;
            esac
        done
    fi

    # Get the set of jobs allowed by this scope
    local allowed_jobs
    allowed_jobs="$(_get_scoped_jobs "$scope" "$project_dir")"

    if [[ -z "$allowed_jobs" ]] && ! "$cancel_all"; then
        # No chaperon jobs in queue — check if the requested IDs even exist
        local any_exist=false
        for req_id in "${requested_ids[@]}"; do
            if squeue -j "$req_id" -h -o "%i" &>/dev/null; then
                any_exist=true
                break
            fi
        done
        if "$any_exist"; then
            echo "chaperon: scancel denied — requested job(s) not submitted by this $scope" >&2
        else
            echo "chaperon: no sandbox-submitted jobs found in queue" >&2
        fi
        return 1
    fi

    local final_ids=()

    if "$cancel_all"; then
        # Cancel everything in scope
        while IFS= read -r jid; do
            [[ -n "$jid" ]] && final_ids+=("$jid")
        done <<< "$allowed_jobs"
    else
        # Filter requested IDs against scope
        for req_id in "${requested_ids[@]}"; do
            local base_id="${req_id%%_*}"
            local matched=false
            while IFS= read -r allowed_id; do
                local allowed_base="${allowed_id%%_*}"
                if [[ "$allowed_id" == "$req_id" || "$allowed_base" == "$base_id" ]]; then
                    matched=true
                    break
                fi
            done <<< "$allowed_jobs"
            if "$matched"; then
                final_ids+=("$req_id")
            else
                echo "chaperon: scancel denied for job $req_id (not in $scope scope)" >&2
            fi
        done
    fi

    if [[ ${#final_ids[@]} -eq 0 ]]; then
        if [[ ${#requested_ids[@]} -gt 0 ]]; then
            echo "chaperon: none of the requested jobs are in $scope scope" >&2
        else
            echo "chaperon: no job IDs specified for scancel" >&2
        fi
        return 1
    fi

    local rc=0
    "$real_scancel" "${validated_flags[@]}" "${final_ids[@]}" || rc=$?
    return "$rc"
}

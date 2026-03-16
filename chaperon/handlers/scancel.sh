#! /bin/bash --
# chaperon/handlers/scancel.sh — Handle scancel requests from sandbox
#
# Cancels Slurm jobs, scoped to what this sandbox (or user) submitted.
#
# Scope levels (configured via CHAPERON_SCANCEL_SCOPE in sandbox.conf):
#   "session"  — only jobs submitted by THIS sandbox session (default)
#   "project"  — jobs submitted by any sandbox with the same project dir
#   "user"     — all jobs submitted by any sandbox of the same user
#
# Job tracking: the sbatch handler records submitted job IDs in
# $FIFO_DIR/jobs (one per line). For "project" scope, a shared file
# at $HOME/.claude/sandbox/chaperon-jobs-<project_hash> is used.
# For "user" scope, no filtering is applied (scancel --me equivalent).

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed scancel flags ───────────────────────────────────────
# Conservative whitelist: only flags that filter or display.
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

# ── Job ID tracking ─────────────────────────────────────────────

# File where this session's submitted job IDs are recorded.
# Set by the sbatch handler after successful submission.
_get_session_jobs_file() {
    echo "${FIFO_DIR:-/dev/null}/jobs"
}

# File for project-scoped job tracking.
_get_project_jobs_file() {
    local project_dir="$1"
    local hash
    hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"
    local dir="$HOME/.claude/sandbox"
    mkdir -p "$dir" 2>/dev/null || true
    echo "$dir/chaperon-jobs-${hash}"
}

# Read job IDs from a tracking file.
# Uses flock for the project-level file (shared across sessions).
_read_tracked_jobs() {
    local file="$1"
    if [[ -f "$file" ]]; then
        (
            flock -s -w 2 9 || true  # shared lock, best-effort
            cat "$file"
        ) 9<"$file" 2>/dev/null
    fi
}

# Check if a job ID is in the allowed set.
_is_job_allowed() {
    local job_id="$1"
    shift
    local allowed_jobs="$*"
    for j in $allowed_jobs; do
        # Handle array jobs: "123_4" should match if "123" is tracked
        local base_id="${job_id%%_*}"
        if [[ "$j" == "$base_id" || "$j" == "$job_id" ]]; then
            return 0
        fi
    done
    return 1
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

    # Determine scope
    local scope="${CHAPERON_SCANCEL_SCOPE:-session}"

    # Parse and validate arguments
    local validated_flags=()
    local job_ids=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Denied flags
            -u|--user|--me|--account|--wckey)
                echo "chaperon: scancel flag '$arg' not allowed (scope is controlled by chaperon)" >&2
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
            *)
                # Positional: should be a job ID
                if [[ "$arg" =~ ^[0-9]+(_[0-9]+)?$ ]]; then
                    job_ids+=("$arg")
                else
                    echo "chaperon: invalid job ID: $arg" >&2
                    return 1
                fi
                ;;
        esac
        (( i++ )) || true
    done

    # If no job IDs given and flags like --help/--version, just pass through
    if [[ ${#job_ids[@]} -eq 0 ]]; then
        local has_help=false
        for f in "${validated_flags[@]}"; do
            case "$f" in --help|--usage|--version) has_help=true ;; esac
        done
        if "$has_help"; then
            local rc=0
            "$real_scancel" "${validated_flags[@]}" || rc=$?
            return "$rc"
        fi
        echo "chaperon: no job IDs specified for scancel" >&2
        return 1
    fi

    # Filter job IDs based on scope
    case "$scope" in
        session)
            local allowed
            allowed="$(_read_tracked_jobs "$(_get_session_jobs_file)")"
            local filtered=()
            for jid in "${job_ids[@]}"; do
                if _is_job_allowed "$jid" $allowed; then
                    filtered+=("$jid")
                else
                    echo "chaperon: scancel denied for job $jid (not submitted by this session)" >&2
                fi
            done
            if [[ ${#filtered[@]} -eq 0 ]]; then
                echo "chaperon: no allowed jobs to cancel" >&2
                return 1
            fi
            job_ids=("${filtered[@]}")
            ;;
        project)
            local allowed
            allowed="$(_read_tracked_jobs "$(_get_project_jobs_file "$project_dir")")"
            local filtered=()
            for jid in "${job_ids[@]}"; do
                if _is_job_allowed "$jid" $allowed; then
                    filtered+=("$jid")
                else
                    echo "chaperon: scancel denied for job $jid (not submitted by this project)" >&2
                fi
            done
            if [[ ${#filtered[@]} -eq 0 ]]; then
                echo "chaperon: no allowed jobs to cancel" >&2
                return 1
            fi
            job_ids=("${filtered[@]}")
            ;;
        user)
            # No filtering — allow canceling any job owned by the user
            ;;
        *)
            echo "chaperon: unknown CHAPERON_SCANCEL_SCOPE: $scope" >&2
            return 1
            ;;
    esac

    local rc=0
    "$real_scancel" "${validated_flags[@]}" "${job_ids[@]}" || rc=$?
    return "$rc"
}

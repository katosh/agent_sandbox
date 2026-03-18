#! /bin/bash --
# chaperon/handlers/scancel.sh — Handle scancel requests from sandbox
#
# Cancels Slurm jobs, scoped by querying the chaperon tag in --comment.
#
# Scope levels (configured via SLURM_SCOPE in sandbox.conf):
#   "project"  — jobs tagged with the same project hash, any session (default)
#   "session"  — only jobs tagged with THIS session's ID
#   "user"     — all jobs of the current user (including non-sandbox jobs)
#   "none"     — no scope restriction (full access to your own jobs)
#
# The tag is set by the sbatch handler:
#   --comment="chaperon:sid=<session_id>,proj=<project_hash>[,user=<comment>]:END"
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

# ── Handler ─────────────────────────────────────────────────────

handle_scancel() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_scancel="${REAL_SCANCEL:-/usr/bin/scancel}"
    if [[ ! -x "$real_scancel" ]]; then
        _sandbox_warn "scancel binary not found at $real_scancel — is Slurm installed?"
        return 1
    fi

    local scope="${SLURM_SCOPE:-project}"

    # Parse and validate arguments
    local validated_flags=()
    local requested_ids=()
    local cancel_all=false
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Scope-widening flags: map to "cancel all in scope".
            # The user expects these to work — the sandbox just limits
            # the scope silently.
            --all|-u|--user|--account)
                cancel_all=true
                # Skip value argument if present (e.g., -u dotto)
                if [[ "$arg" != "--all" ]] && (( i + 1 < ${#REQ_ARGS[@]} )) && [[ "${REQ_ARGS[$((i+1))]}" != -* ]]; then
                    (( i++ )) || true
                fi
                ;;
            --user=*|--account=*|--me|--wckey|--wckey=*)
                cancel_all=true
                ;;
            --*=*)
                if _is_scancel_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "scancel flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
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
                    _sandbox_warn "scancel flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            all)
                # "scancel all" — cancel all jobs within scope
                cancel_all=true
                ;;
            *)
                # Positional: should be a job ID (with optional array index)
                # Accept: 12345, 12345_0, 12345_[0-10], 12345_0-10:2, etc.
                # Validate the base job ID (before _) is numeric.
                local base_id="${arg%%_*}"
                if [[ "$base_id" =~ ^[0-9]+$ ]]; then
                    requested_ids+=("$arg")
                else
                    _sandbox_warn "'$arg' is not a valid job ID. Job IDs must start with a number (e.g., 12345, 12345_0, 12345_[0-10])."
                    return 1
                fi
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage (no job IDs needed)
    for f in "${validated_flags[@]}"; do
        case "$f" in --help|--usage|--version)
            local rc=0
            "$real_scancel" "${validated_flags[@]}" || rc=$?
            return "$rc"
            ;;
        esac
    done

    # Bare scancel (no job IDs, no --all/--me) → cancel all in scope
    if [[ ${#requested_ids[@]} -eq 0 ]] && ! "$cancel_all"; then
        cancel_all=true
    fi

    # Get the set of jobs allowed by this scope
    local allowed_jobs
    allowed_jobs="$(_get_scoped_jobs "$scope" "$project_dir")"

    if [[ -z "$allowed_jobs" ]] && ! "$cancel_all"; then
        # No chaperon jobs in queue — check if the requested IDs even exist
        local any_exist=false
        local _real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
        for req_id in "${requested_ids[@]}"; do
            if timeout 10 "$_real_squeue" -j "$req_id" -h -o "%i" &>/dev/null; then
                any_exist=true
                break
            fi
        done
        if "$any_exist"; then
            _sandbox_deny "cannot cancel — the requested job(s) were not submitted by this $scope. Only sandbox-submitted jobs can be cancelled."
        else
            echo "sandbox: no sandbox-submitted jobs found in queue." >&2
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
                _sandbox_deny "cannot cancel job $req_id — it was not submitted by this $scope."
            fi
        done
    fi

    if [[ ${#final_ids[@]} -eq 0 ]]; then
        if "$cancel_all"; then
            # No jobs to cancel — not an error
            return 0
        elif [[ ${#requested_ids[@]} -gt 0 ]]; then
            _sandbox_deny "none of the requested jobs were submitted by this $scope."
            return 1
        fi
        return 0
    fi

    local rc=0
    "$real_scancel" "${validated_flags[@]}" "${final_ids[@]}" || rc=$?
    return "$rc"
}

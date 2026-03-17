#! /bin/bash --
# chaperon/handlers/scontrol.sh — Handle scontrol requests from sandbox
#
# Allows read-only scontrol commands (show) and scoped job modifications.
# Job modifications are restricted to jobs within the chaperon scope.
#
# Allowed subcommands:
#   show job [JOBID]     — show job details (scoped)
#   show node [NODENAME] — show node details (read-only, unscoped)
#   show partition [NAME] — show partition details (read-only, unscoped)
#   show config           — show Slurm config (read-only)
#   hold JOBID            — hold a job (scoped)
#   release JOBID         — release a held job (scoped)
#   requeue JOBID         — requeue a job (scoped)
#   update job JOBID ...  — update job parameters (scoped, limited flags)
#
# Denied subcommands:
#   Everything else (shutdown, reconfigure, create, delete, etc.)

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed update parameters ────────────────────────────────────
# Only these JobId update keys are forwarded.  Security-sensitive keys
# (e.g. UserId, GroupId, WorkDir, AdminComment) are denied.
_SCONTROL_ALLOWED_UPDATE_KEYS=" \
  Comment \
  Deadline \
  Nice \
  Priority \
  Requeue \
  TimeLimit \
  MinMemoryNode \
  MinMemoryCPU \
  NumCPUs \
  NumNodes \
  NumTasks \
  EndTime \
  StartTime \
  Name \
  Partition \
  QOS \
  ReservationName \
"

_is_update_key_allowed() {
    local key="${1%%=*}"
    [[ "$_SCONTROL_ALLOWED_UPDATE_KEYS" == *" $key "* ]]
}

# ── Validate that a single job ID is in scope ────────────────────
# Uses a targeted squeue query instead of fetching all scoped jobs.
_validate_job_in_scope() {
    local job_id="$1" scope="$2" project_dir="$3"

    local base_id="${job_id%%_*}"
    if [[ ! "$base_id" =~ ^[0-9]+$ ]]; then
        echo "chaperon: invalid job ID: $job_id" >&2
        return 1
    fi

    # Query only this specific job's comment
    local comment
    comment="$(squeue -j "$base_id" --me -h -o "%k" 2>/dev/null)" || true

    if [[ -z "$comment" ]]; then
        echo "chaperon: scontrol denied for job $job_id (not found or not owned)" >&2
        return 1
    fi

    # Check if the comment matches the scope
    local match=false
    case "$scope" in
        session)
            [[ "$comment" == *"chaperon:sid=${_CHAPERON_SESSION_ID}"* ]] && match=true
            ;;
        project)
            local proj_hash
            proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"
            [[ "$comment" == *"proj=${proj_hash}"* ]] && match=true
            ;;
        user)
            [[ "$comment" == *"chaperon:"* ]] && match=true
            ;;
    esac

    if ! "$match"; then
        echo "chaperon: scontrol denied for job $job_id (not in $scope scope)" >&2
        return 1
    fi
    return 0
}

handle_scontrol() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_scontrol="${REAL_SCONTROL:-/usr/bin/scontrol}"
    if [[ ! -x "$real_scontrol" ]]; then
        echo "chaperon: real scontrol not found at $real_scontrol" >&2
        return 1
    fi

    local scope="${CHAPERON_SCANCEL_SCOPE:-project}"

    if [[ ${#REQ_ARGS[@]} -eq 0 ]]; then
        echo "chaperon: scontrol requires a subcommand" >&2
        return 1
    fi

    local subcmd="${REQ_ARGS[0]}"

    case "$subcmd" in
        # ── Read-only show commands ──
        show)
            if [[ ${#REQ_ARGS[@]} -lt 2 ]]; then
                echo "chaperon: scontrol show requires a target (job, node, partition, config)" >&2
                return 1
            fi
            local target="${REQ_ARGS[1]}"
            case "$target" in
                job|jobs)
                    # Show job — scoped to chaperon-submitted jobs
                    if [[ ${#REQ_ARGS[@]} -ge 3 ]]; then
                        # Specific job ID requested — validate scope
                        local job_id="${REQ_ARGS[2]}"
                        if ! _validate_job_in_scope "$job_id" "$scope" "$project_dir"; then
                            return 1
                        fi
                        local rc=0
                        "$real_scontrol" "${REQ_ARGS[@]}" || rc=$?
                        return "$rc"
                    else
                        # No job ID — show all jobs in scope
                        local scoped_ids
                        scoped_ids="$(_get_scoped_jobs "$scope" "$project_dir")"
                        if [[ -z "$scoped_ids" ]]; then
                            echo "No sandbox-submitted jobs found in queue" >&2
                            return 0
                        fi
                        local rc=0
                        while IFS= read -r jid; do
                            [[ -n "$jid" ]] && "$real_scontrol" show job "$jid" || true
                        done <<< "$scoped_ids"
                        return 0
                    fi
                    ;;
                node|nodes|partition|partitions|config|step|steps)
                    # Read-only, unscoped
                    local rc=0
                    "$real_scontrol" "${REQ_ARGS[@]}" || rc=$?
                    return "$rc"
                    ;;
                assoc_mgr|burstbuffer|dwstat|federation|frontend|lic|licenses|topology)
                    echo "chaperon: scontrol show '$target' denied (may expose user/account data)" >&2
                    return 1
                    ;;
                *)
                    echo "chaperon: scontrol show '$target' not allowed" >&2
                    return 1
                    ;;
            esac
            ;;

        # ── Scoped job actions ──
        hold|release|requeue)
            if [[ ${#REQ_ARGS[@]} -lt 2 ]]; then
                echo "chaperon: scontrol $subcmd requires a job ID" >&2
                return 1
            fi
            local job_id="${REQ_ARGS[1]}"
            if ! _validate_job_in_scope "$job_id" "$scope" "$project_dir"; then
                return 1
            fi
            local rc=0
            "$real_scontrol" "$subcmd" "$job_id" || rc=$?
            return "$rc"
            ;;

        # ── Scoped job update ──
        update)
            if [[ ${#REQ_ARGS[@]} -lt 3 ]]; then
                echo "chaperon: scontrol update requires 'job JOBID key=value...'" >&2
                return 1
            fi
            local update_target="${REQ_ARGS[1]}"
            if [[ "$update_target" != "job" && "$update_target" != "JobId" && "$update_target" != "jobid" ]]; then
                echo "chaperon: scontrol update '$update_target' not allowed (only job updates)" >&2
                return 1
            fi

            # Parse JobId from the arguments
            local job_id=""
            local update_params=()
            local j=2
            while (( j < ${#REQ_ARGS[@]} )); do
                local param="${REQ_ARGS[$j]}"
                if [[ "$param" == JobId=* || "$param" == jobid=* ]]; then
                    job_id="${param#*=}"
                elif [[ -z "$job_id" && "$param" =~ ^[0-9]+$ ]]; then
                    # scontrol update job 12345 Key=Value
                    job_id="$param"
                else
                    # Validate update key
                    local key="${param%%=*}"
                    if _is_update_key_allowed "$key"; then
                        update_params+=("$param")
                    else
                        echo "chaperon: scontrol update key '$key' not allowed" >&2
                        return 1
                    fi
                fi
                (( j++ )) || true
            done

            if [[ -z "$job_id" ]]; then
                echo "chaperon: scontrol update requires a job ID" >&2
                return 1
            fi
            if ! _validate_job_in_scope "$job_id" "$scope" "$project_dir"; then
                return 1
            fi
            if [[ ${#update_params[@]} -eq 0 ]]; then
                echo "chaperon: scontrol update requires at least one key=value pair" >&2
                return 1
            fi

            local rc=0
            "$real_scontrol" update JobId="$job_id" "${update_params[@]}" || rc=$?
            return "$rc"
            ;;

        # ── Info-only commands ──
        --help|--version|--usage|help|version)
            local rc=0
            "$real_scontrol" "${REQ_ARGS[@]}" || rc=$?
            return "$rc"
            ;;

        # ── Everything else denied ──
        *)
            echo "chaperon: scontrol '$subcmd' is not allowed inside the sandbox" >&2
            echo "Hint: allowed subcommands: show, hold, release, requeue, update job" >&2
            return 1
            ;;
    esac
}

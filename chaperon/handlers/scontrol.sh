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
# are denied:
#   Comment        — would strip/forge chaperon scope tag
#   UserId/GroupId  — impersonation
#   WorkDir        — escape project directory
#   AdminComment   — admin-only field
# Partition/QOS/Priority/ReservationName are allowed because all jobs
# are wrapped in sandbox-exec.sh regardless of partition or priority.
_SCONTROL_ALLOWED_UPDATE_KEYS=" \
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

handle_scontrol() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_scontrol="${REAL_SCONTROL:-/usr/bin/scontrol}"
    if [[ ! -x "$real_scontrol" ]]; then
        _sandbox_warn "scontrol binary not found at $real_scontrol — is Slurm installed?"
        return 1
    fi

    local scope="${SLURM_SCOPE:-project}"

    if [[ ${#REQ_ARGS[@]} -eq 0 ]]; then
        _sandbox_warn "scontrol requires a subcommand. Allowed: show, hold, release, requeue, update job"
        return 1
    fi

    # Lowercase for case-insensitive matching (scontrol accepts Show, SHOW, etc.)
    local subcmd="${REQ_ARGS[0],,}"

    case "$subcmd" in
        # ── Read-only show commands ──
        show)
            if [[ ${#REQ_ARGS[@]} -lt 2 ]]; then
                _sandbox_warn "scontrol show requires a target: job, node, partition, config, step"
                return 1
            fi
            local target="${REQ_ARGS[1],,}"
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
                        "$real_scontrol" "${REQ_ARGS[@]}" | _strip_chaperon_tags || rc=$?
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
                        done <<< "$scoped_ids" | _strip_chaperon_tags
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
                    _sandbox_deny "scontrol show '$target' is not allowed — it may expose user or account data."
                    return 1
                    ;;
                *)
                    _sandbox_deny "scontrol show '$target' is not allowed. Allowed targets: job, node, partition, config, step"
                    return 1
                    ;;
            esac
            ;;

        # ── Scoped job actions ──
        hold|release|requeue)
            if [[ ${#REQ_ARGS[@]} -lt 2 ]]; then
                _sandbox_warn "scontrol $subcmd requires a job ID."
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
                _sandbox_warn "usage: scontrol update job <JOBID> <Key>=<Value> ..."
                return 1
            fi
            local update_target="${REQ_ARGS[1]}"
            if [[ "$update_target" != "job" && "$update_target" != "JobId" && "$update_target" != "jobid" ]]; then
                _sandbox_deny "scontrol update is only allowed for jobs (e.g., scontrol update job 12345 TimeLimit=2:00:00)."
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
                        _sandbox_deny "scontrol update key '$key' is not allowed. Allowed keys: Comment, Deadline, Nice, Priority, TimeLimit, NumCPUs, NumNodes, Partition, QOS, etc."
                        return 1
                    fi
                fi
                (( j++ )) || true
            done

            if [[ -z "$job_id" ]]; then
                _sandbox_warn "scontrol update requires a job ID."
                return 1
            fi
            if ! _validate_job_in_scope "$job_id" "$scope" "$project_dir"; then
                return 1
            fi
            if [[ ${#update_params[@]} -eq 0 ]]; then
                _sandbox_warn "scontrol update requires at least one Key=Value pair (e.g., TimeLimit=2:00:00)."
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
            _sandbox_deny "scontrol '$subcmd' is not allowed. Allowed: show, hold, release, requeue, update job"
            return 1
            ;;
    esac
}

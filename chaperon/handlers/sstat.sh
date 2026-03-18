#! /bin/bash --
# chaperon/handlers/sstat.sh — Handle sstat requests from sandbox
#
# sstat shows statistics for running job steps.  Job step IDs have the
# form jobid.stepid — the handler validates that the base job ID (the
# part before the dot) belongs to the current user's scoped jobs.

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed sstat flags ──────────────────────────────────────────
_SSTAT_ALLOWED_FLAGS=" \
  -j --jobs \
  -o --format \
  -p --parsable \
  -P --parsable2 \
  -n --noheader \
  -a --allsteps \
  -e --helpformat \
  -v --verbose \
  --help \
  --usage \
  --version \
"

_SSTAT_VALUE_FLAGS=" \
  -j --jobs \
  -o --format \
"

_is_sstat_allowed() {
    local base="${1%%=*}"
    [[ "$_SSTAT_ALLOWED_FLAGS" == *" $base "* ]]
}

_is_sstat_value_flag() {
    [[ "$_SSTAT_VALUE_FLAGS" == *" $1 "* ]]
}

# Validate that all job IDs in a comma-separated list are in scope.
# Job step IDs (e.g. 12345.0) are accepted — the base job ID is checked.
_validate_sstat_jobs_in_scope() {
    local jobs_str="$1" scope="$2" project_dir="$3"

    IFS=',' read -ra job_entries <<< "$jobs_str"
    for entry in "${job_entries[@]}"; do
        # Extract base job ID (before the dot for step IDs)
        local base_id="${entry%%.*}"
        # Strip array task suffix if present
        base_id="${base_id%%_*}"
        if [[ ! "$base_id" =~ ^[0-9]+$ ]]; then
            _sandbox_warn "sstat '$entry' is not a valid job step ID."
            return 1
        fi
        if ! _validate_job_in_scope "$base_id" "$scope" "$project_dir"; then
            return 1
        fi
    done
    return 0
}

handle_sstat() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_sstat="${REAL_SSTAT:-/usr/bin/sstat}"
    if [[ ! -x "$real_sstat" ]]; then
        _sandbox_warn "sstat binary not found at $real_sstat — is Slurm installed?"
        return 1
    fi

    local scope="${SLURM_SCOPE:-project}"

    # Parse and validate arguments
    local validated_flags=()
    local jobs_value=""
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Deny --allusers (doesn't exist but block to be safe)
            --allusers)
                _sandbox_deny "sstat '--allusers' is not allowed — only your own jobs are accessible inside the sandbox."
                return 1
                ;;
            # Capture --jobs value for scope validation
            --jobs=*)
                if _is_sstat_allowed "$arg"; then
                    jobs_value="${arg#--jobs=}"
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "sstat flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            -j|--jobs)
                if (( i + 1 < ${#REQ_ARGS[@]} )); then
                    validated_flags+=("$arg")
                    (( i++ )) || true
                    jobs_value="${REQ_ARGS[$i]}"
                    validated_flags+=("${REQ_ARGS[$i]}")
                else
                    _sandbox_warn "sstat '$arg' requires a value (job step ID list)."
                    return 1
                fi
                ;;
            --*=*)
                if _is_sstat_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "sstat flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            -*)
                if _is_sstat_allowed "$arg"; then
                    validated_flags+=("$arg")
                    if _is_sstat_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ )) || true
                        validated_flags+=("${REQ_ARGS[$i]}")
                    fi
                else
                    _sandbox_warn "sstat flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            *)
                _sandbox_warn "unexpected sstat argument: '$arg'"
                return 1
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage/--helpformat
    for f in "${validated_flags[@]}"; do
        case "$f" in --help|--usage|--version|-e|--helpformat)
            local rc=0
            "$real_sstat" "${validated_flags[@]}" || rc=$?
            return "$rc"
            ;;
        esac
    done

    # sstat requires --jobs; validate that requested jobs are in scope
    if [[ -z "$jobs_value" ]]; then
        _sandbox_warn "sstat requires --jobs/-j with a job step ID list (e.g., sstat -j 12345.0)."
        return 1
    fi

    if ! _validate_sstat_jobs_in_scope "$jobs_value" "$scope" "$project_dir"; then
        return 1
    fi

    local rc=0
    "$real_sstat" "${validated_flags[@]}" || rc=$?
    return "$rc"
}

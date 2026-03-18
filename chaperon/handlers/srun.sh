#! /bin/bash --
# chaperon/handlers/srun.sh — Handle srun requests from sandbox
#
# Proxies srun through the chaperon so it can authenticate with munge
# (which is blocked inside the sandbox).  Two modes:
#
#   Step mode (SLURM_JOB_ID set):
#     Validates flags against step whitelist, execs real srun directly.
#     The command runs within the existing sandboxed allocation.
#
#   Allocation mode (no SLURM_JOB_ID):
#     Validates flags against allocation whitelist, wraps the command in
#     sandbox-exec.sh so compute-node processes inherit sandbox restrictions,
#     then execs real srun.  --pty is denied (no PTY passthrough via protocol).
#
# Security: munge is intentionally blocked inside the sandbox.  The chaperon
# runs outside and has munge access.  All flags are validated against a
# whitelist.  In allocation mode, the command is always sandboxed.

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Flags allowed in BOTH modes ──────────────────────────────────
_SRUN_COMMON_FLAGS=" \
  -n --ntasks \
  -N --nodes \
  -c --cpus-per-task \
  -G --gpus \
  --gpus-per-node \
  --gpus-per-task \
  --cpus-per-gpu \
  --mem \
  --mem-per-cpu \
  --mem-per-gpu \
  --gres \
  -w --nodelist \
  -x --exclude \
  --exclusive \
  -l --label \
  -o --output \
  -e --error \
  -i --input \
  --mpi \
  --distribution \
  --ntasks-per-node \
  --ntasks-per-gpu \
  --threads-per-core \
  --cpu-bind \
  --mem-bind \
  --gpu-bind \
  --spread-job \
  --exact \
  --overlap \
  --het-group \
  --multi-prog \
  --kill-on-bad-exit \
  --unbuffered \
  -v --verbose \
  -Q --quiet \
  --help \
  --usage \
  --version \
"

# ── Additional flags allowed ONLY in allocation mode ─────────────
_SRUN_ALLOC_FLAGS=" \
  -A --account \
  -p --partition \
  -q --qos \
  -t --time \
  -J --job-name \
  --reservation \
  --begin \
  --deadline \
  --constraint \
  --nice \
  --priority \
  --signal \
  --wckey \
  --comment \
"

# ── Value flags (consume the next argument) ──────────────────────
_SRUN_VALUE_FLAGS=" \
  -n --ntasks \
  -N --nodes \
  -c --cpus-per-task \
  -G --gpus \
  --gpus-per-node \
  --gpus-per-task \
  --cpus-per-gpu \
  --mem \
  --mem-per-cpu \
  --mem-per-gpu \
  --gres \
  -w --nodelist \
  -x --exclude \
  -o --output \
  -e --error \
  -i --input \
  --mpi \
  --distribution \
  --ntasks-per-node \
  --ntasks-per-gpu \
  --threads-per-core \
  --cpu-bind \
  --mem-bind \
  --gpu-bind \
  --het-group \
  --multi-prog \
  --kill-on-bad-exit \
  -A --account \
  -p --partition \
  -q --qos \
  -t --time \
  -J --job-name \
  --reservation \
  --begin \
  --deadline \
  --constraint \
  --nice \
  --priority \
  --signal \
  --wckey \
  --comment \
"

_is_srun_allowed() {
    local base="${1%%=*}"
    local mode="$2"  # "step" or "alloc"
    if [[ "$_SRUN_COMMON_FLAGS" == *" $base "* ]]; then
        return 0
    fi
    if [[ "$mode" == "alloc" && "$_SRUN_ALLOC_FLAGS" == *" $base "* ]]; then
        return 0
    fi
    return 1
}

_is_srun_value_flag() {
    [[ "$_SRUN_VALUE_FLAGS" == *" $1 "* ]]
}

handle_srun() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_srun="${REAL_SRUN:-/usr/bin/srun}"
    if [[ ! -x "$real_srun" ]]; then
        _sandbox_warn "srun binary not found at $real_srun — is Slurm installed?"
        return 1
    fi

    # Determine mode: step (inside allocation) or alloc (new allocation)
    local mode="alloc"
    if [[ -n "${SLURM_JOB_ID:-}" ]]; then
        mode="step"
    fi

    # Validate CWD
    if [[ -n "$REQ_CWD" ]]; then
        if ! validate_cwd "$REQ_CWD" "$project_dir"; then
            return 1
        fi
    fi

    # Validate and filter arguments; collect the command after flags
    local validated_flags=()
    local command_args=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"

        # After "--", everything is the command
        if [[ "$arg" == "--" ]]; then
            (( i++ )) || true
            while (( i < ${#REQ_ARGS[@]} )); do
                command_args+=("${REQ_ARGS[$i]}")
                (( i++ )) || true
            done
            break
        fi

        case "$arg" in
            # ── Always denied ──
            --pty)
                _sandbox_deny "srun '--pty' is not allowed — interactive PTY sessions cannot be proxied through the sandbox. Use 'sbatch' for job submission or 'srun' without --pty."
                return 1
                ;;
            --jobid|--jobid=*|-j)
                _sandbox_deny "srun '$arg' is not allowed — attaching to other jobs' allocations is restricted."
                return 1
                ;;
            --uid|--uid=*|--gid|--gid=*)
                _sandbox_deny "srun '$arg' is not allowed — jobs must run as your own user."
                return 1
                ;;
            --export|--export=*)
                _sandbox_deny "srun '$arg' is not allowed — environment variable injection could bypass sandbox restrictions."
                return 1
                ;;
            --chdir|--chdir=*|-D)
                _sandbox_deny "srun '$arg' is not allowed — the working directory is set automatically."
                return 1
                ;;
            --get-user-env|--get-user-env=*)
                _sandbox_deny "srun '$arg' is not allowed — it can leak environment variables from outside the sandbox."
                return 1
                ;;
            --propagate|--propagate=*)
                _sandbox_deny "srun '$arg' is not allowed — resource limit propagation is restricted."
                return 1
                ;;
            --prolog|--prolog=*|--epilog|--epilog=*|--task-prolog|--task-prolog=*|--task-epilog|--task-epilog=*)
                _sandbox_deny "srun '$arg' is not allowed — custom prolog/epilog scripts could run outside sandbox control."
                return 1
                ;;
            --bcast|--bcast=*)
                _sandbox_deny "srun '$arg' is not allowed — binary broadcasting could bypass sandbox wrapping."
                return 1
                ;;
            --container|--container=*)
                _sandbox_deny "srun '$arg' is not allowed — OCI containers would bypass sandbox restrictions."
                return 1
                ;;
            --network|--network=*)
                _sandbox_deny "srun '$arg' is not allowed — network namespace manipulation is restricted."
                return 1
                ;;
            # ── Allocation flags: allowed in alloc mode, denied in step mode ──
            -A|--account|--account=*|-p|--partition|--partition=*|-q|--qos|--qos=*|-t|--time|--time=*|--reservation|--reservation=*|-J|--job-name|--job-name=*|--begin|--begin=*|--deadline|--deadline=*|--constraint|--constraint=*|--nice|--nice=*|--priority|--priority=*|--signal|--signal=*|--wckey|--wckey=*|--comment|--comment=*)
                if [[ "$mode" == "step" ]]; then
                    _sandbox_warn "srun '$arg' is not allowed in step mode — steps inherit the parent job's resources. Use these flags with sbatch instead."
                    return 1
                fi
                validated_flags+=("$arg")
                if [[ "$arg" != *=* ]] && _is_srun_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                    (( i++ )) || true
                    validated_flags+=("${REQ_ARGS[$i]}")
                fi
                ;;
            # ── --flag=value form ──
            --*=*)
                if _is_srun_allowed "$arg" "$mode"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "srun flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            # ── -flag or --flag form ──
            -*)
                if _is_srun_allowed "$arg" "$mode"; then
                    validated_flags+=("$arg")
                    if _is_srun_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ )) || true
                        validated_flags+=("${REQ_ARGS[$i]}")
                    fi
                else
                    _sandbox_warn "srun flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            # ── Positional: start of command ──
            *)
                command_args+=("$arg")
                (( i++ )) || true
                while (( i < ${#REQ_ARGS[@]} )); do
                    command_args+=("${REQ_ARGS[$i]}")
                    (( i++ )) || true
                done
                break
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage (no command needed)
    if [[ ${#command_args[@]} -eq 0 ]]; then
        for f in "${validated_flags[@]}"; do
            case "$f" in --help|--usage|--version)
                local rc=0
                "$real_srun" "${validated_flags[@]}" || rc=$?
                return "$rc"
                ;;
            esac
        done
        _sandbox_warn "srun requires a command to run (e.g., srun -n 4 ./my_program)"
        return 1
    fi

    # In allocation mode, inject chaperon comment tag for job scoping
    # (same as sbatch handler — enables scancel/squeue to find these jobs).
    if [[ "$mode" == "alloc" ]]; then
        local chaperon_comment
        chaperon_comment="$(_build_chaperon_comment "$project_dir")"
        validated_flags+=("--comment=$chaperon_comment")
    fi

    local rc=0

    if [[ "$mode" == "step" ]]; then
        # Step mode: exec real srun directly — the command runs within
        # the existing sandboxed allocation.
        if [[ -n "$REQ_CWD" ]]; then
            (cd "$REQ_CWD" && "$real_srun" "${validated_flags[@]}" -- "${command_args[@]}") || rc=$?
        else
            "$real_srun" "${validated_flags[@]}" -- "${command_args[@]}" || rc=$?
        fi
    else
        # Allocation mode: wrap the command in sandbox-exec.sh so
        # compute-node processes inherit sandbox restrictions.
        # srun [flags] -- sandbox-exec.sh --project-dir $DIR -- <command>
        if [[ -n "$REQ_CWD" ]]; then
            (cd "$REQ_CWD" && "$real_srun" "${validated_flags[@]}" -- \
                "$sandbox_exec" --project-dir "$project_dir" -- "${command_args[@]}") || rc=$?
        else
            "$real_srun" "${validated_flags[@]}" -- \
                "$sandbox_exec" --project-dir "$project_dir" -- "${command_args[@]}" || rc=$?
        fi
    fi

    return "$rc"
}

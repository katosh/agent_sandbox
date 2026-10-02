#! /bin/bash --
# chaperon/handlers/srun.sh — Handle srun requests from sandbox
#
# Proxies srun through the chaperon so it can authenticate with munge
# (which is blocked inside the sandbox).  Two modes:
#
#   Step mode (SLURM_JOB_ID set):
#     Validates flags against the step whitelist (no allocation flags),
#     wraps the command in sandbox-exec.sh, execs real srun. The step's
#     tasks are started by slurmstepd on the allocated nodes, i.e. OUTSIDE
#     any sandbox — the enclosing allocation's sandbox does not extend to
#     them — so each task must re-enter the sandbox itself.
#
#   Allocation mode (no SLURM_JOB_ID):
#     Validates flags against allocation whitelist, wraps the command in
#     sandbox-exec.sh so compute-node processes inherit sandbox restrictions,
#     then execs real srun.
#
#   In both modes --pty is denied (no PTY passthrough via protocol) and
#   every task runs its own `sandbox-exec.sh --project-dir <dir> -- cmd`.
#   --export is not on the srun allow-list (rejected as unrecognized), so
#   no agent-chosen value can reach the host-side task environment.
#
# Security: munge is intentionally blocked inside the sandbox.  The chaperon
# runs outside and has munge access.  All flags are validated against a
# whitelist.  The command is always sandboxed.

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

# ── Option-argument classes (see "Slurm option-argument classes" in
#    _handler_lib.sh; classified against srun 23.11) ─────────────
# _SRUN_VALUE_FLAGS: REQUIRED argument — consumes the next token when
# given without `=`.
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
  -A --account \
  -p --partition \
  -q --qos \
  -t --time \
  -J --job-name \
  --reservation \
  --begin \
  --deadline \
  --constraint \
  --priority \
  --signal \
  --wckey \
  --comment \
"

# _SRUN_OPTARG_FLAGS: OPTIONAL argument (`--flag[=value]`): a value
# binds only with `=`; the next token is NEVER consumed (Slurm would run
# it as the command). `--overlap` accepts an undocumented `=force`.
_SRUN_OPTARG_FLAGS=" --exclusive --overlap --kill-on-bad-exit --nice "
# Every other allowed flag takes no argument.

# srun -o/-e/-i: slurmstepd opens these OUTSIDE the sandbox, as the
# host user, before the compute-node sandbox boundary applies, and srun
# has no staging redirect on any backend. An unrestricted path is an
# arbitrary host-file write (--output/--error → e.g. ~/.bashrc) or read
# (--input → e.g. ~/.aws/credentials piped into the job). Validated by
# _validate_slurm_io_path (_handler_lib.sh): project-contained directory
# resolved against the validated submission cwd, no `..`, no symlink
# components, no existing symlink target, only directory-neutral %
# patterns and only in the file name.

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

    # Validate and filter arguments; collect the command after flags.
    # Every accepted flag is appended as ONE token (`--long=value` or the
    # bare flag, see _slurm_normalize_flag); optional-argument flags
    # never consume the next token.
    local validated_flags=()
    local command_args=()
    local i=0
    _srun_accept_flag() {  # <arg>; uses i / REQ_ARGS / validated_flags of handle_srun
        local _has_next=0
        (( i + 1 < ${#REQ_ARGS[@]} )) && _has_next=1
        _slurm_normalize_flag srun "$1" "$_SRUN_VALUE_FLAGS" "$_SRUN_OPTARG_FLAGS" \
            "$_has_next" "${REQ_ARGS[$((i + 1))]-}" || return 1
        if (( _SLURM_FLAG_CONSUMED )); then i=$((i + 1)); fi
        validated_flags+=("$_SLURM_FLAG_TOKEN")
        return 0
    }
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
            --multi-prog|--multi-prog=*)
                _sandbox_deny "srun '--multi-prog' is not allowed — it launches the executables named in an agent-supplied config file directly, bypassing the sandbox-exec.sh wrapping the chaperon appends (which would otherwise sandbox the compute-node task). Run a single command instead: srun [flags] -- your_program."
                return 1
                ;;
            # ── Output/error/input: opened by slurmstepd OUTSIDE the sandbox.
            #    Restrict to paths under the project dir (see
            #    _validate_slurm_io_path). Handles the space-separated
            #    forms here; the --flag=value forms are handled below. ──
            -o|--output|-e|--error|-i|--input)
                local _io_flag="$arg" _io_val=""
                if (( i + 1 < ${#REQ_ARGS[@]} )); then
                    (( i++ )) || true
                    _io_val="${REQ_ARGS[$i]}"
                fi
                if ! _validate_slurm_io_path "srun $_io_flag" "$_io_val" "$project_dir" "${REQ_CWD:-$project_dir}"; then
                    return 1
                fi
                validated_flags+=("$(_slurm_long_flag "$_io_flag")=$_io_val")
                ;;
            --output=*|--error=*|--input=*)
                local _io_val2="${arg#*=}"
                if ! _validate_slurm_io_path "srun ${arg%%=*}" "$_io_val2" "$project_dir" "${REQ_CWD:-$project_dir}"; then
                    return 1
                fi
                validated_flags+=("$arg")
                ;;
            # ── Allocation flags: allowed in alloc mode, denied in step mode ──
            -A|--account|--account=*|-p|--partition|--partition=*|-q|--qos|--qos=*|-t|--time|--time=*|--reservation|--reservation=*|-J|--job-name|--job-name=*|--begin|--begin=*|--deadline|--deadline=*|--constraint|--constraint=*|--nice|--nice=*|--priority|--priority=*|--signal|--signal=*|--wckey|--wckey=*|--comment|--comment=*)
                if [[ "$mode" == "step" ]]; then
                    _sandbox_warn "srun '$arg' is not allowed in step mode — steps inherit the parent job's resources. Use these flags with sbatch instead."
                    return 1
                fi
                _srun_accept_flag "$arg" || return 1
                ;;
            # ── -flag, --flag or --flag=value form ──
            -*)
                if _is_srun_allowed "$arg" "$mode"; then
                    _srun_accept_flag "$arg" || return 1
                else
                    _sandbox_warn "srun flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
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

    # The job name expands into %x (see _validate_slurm_job_name).
    local _vf
    for _vf in "${validated_flags[@]+"${validated_flags[@]}"}"; do
        if [[ "$_vf" == --job-name=* ]]; then
            _validate_slurm_job_name "srun --job-name" "${_vf#--job-name=}" || return 1
        fi
    done

    # In allocation mode, inject chaperon comment tag for job scoping
    # (same as sbatch handler — enables scancel/squeue to find these jobs).
    if [[ "$mode" == "alloc" ]]; then
        local chaperon_comment
        chaperon_comment="$(_build_chaperon_comment "$project_dir")"
        validated_flags+=("--comment=$chaperon_comment")
    fi

    local rc=0

    # Both modes: wrap the command in sandbox-exec.sh. srun starts one
    # copy of the command per task via slurmstepd, outside the sandbox,
    # so each task runs its own sandbox-exec.sh re-entry:
    #   srun [flags] -- [env SANDBOX_QUIET=true] sandbox-exec.sh --project-dir $DIR -- <command>
    # (Step mode used to exec the command bare, on the wrong assumption
    # that the enclosing allocation's sandbox applied to the step.)
    #
    # Retain the session's quiet decision (see create_wrapped_script in
    # _handler_lib.sh). When the chaperon was launched quiet, srun
    # launches the command directly (no shell), so an `env` prefix
    # carries SANDBOX_QUIET to the compute-node sandbox-exec.sh re-entry
    # — surviving `--export=NONE` and any in-sandbox unset. Only forced
    # when active; otherwise the compute node resolves normally.
    local _quiet_env=()
    case "${SANDBOX_QUIET:-false}" in
        [Tt]rue|[Yy]es|1) _quiet_env=(/usr/bin/env SANDBOX_QUIET=true) ;;
    esac
    # Defense in depth: nothing but self-contained flags may precede the
    # chaperon's `--`, so the first word Slurm executes is always
    # sandbox-exec.sh (or the /usr/bin/env prefix carrying it).
    _assert_slurm_flag_argv srun "$_SRUN_VALUE_FLAGS" "${validated_flags[@]}" || return 1
    if [[ -n "$REQ_CWD" ]]; then
        (cd "$REQ_CWD" && "$real_srun" "${validated_flags[@]}" -- \
            "${_quiet_env[@]+"${_quiet_env[@]}"}" \
            "$sandbox_exec" --project-dir "$project_dir" -- "${command_args[@]}") || rc=$?
    else
        "$real_srun" "${validated_flags[@]}" -- \
            "${_quiet_env[@]+"${_quiet_env[@]}"}" \
            "$sandbox_exec" --project-dir "$project_dir" -- "${command_args[@]}" || rc=$?
    fi

    return "$rc"
}

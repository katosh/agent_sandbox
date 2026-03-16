#! /bin/bash --
# chaperon/handlers/_handler_lib.sh — Shared handler utilities
#
# Argument whitelisting, CWD validation, and job wrapping for sbatch.

# ── Whitelisted sbatch flags ────────────────────────────────────
# Only these flags are forwarded to the real sbatch. This is a security
# boundary: flags that could bypass sandboxing are excluded.
#
# Excluded (security-critical):
#   --wrap        — reconstructed by handler (user data via protocol)
#   --chdir / -D  — CWD comes from protocol, validated against project dir
#   --uid / --gid — must not impersonate other users
#   --get-user-env — can leak host environment
#   --propagate   — can propagate unsafe rlimits
#   --export      — could inject env vars to bypass sandbox
#   --prolog / --epilog / --task-prolog / --task-epilog — run arbitrary scripts
#   --burst-buffer-file / --bbf — arbitrary file access
#   --bcast       — copy binary to nodes (bypass wrapping)
#
# Format: space-delimited, both short and long forms.
# Flags that take a value are marked with "=" suffix in _SBATCH_VALUE_FLAGS.

_SBATCH_ALLOWED_FLAGS=" \
  -A --account \
  -c --cpus-per-task \
  -d --dependency \
  -e --error \
  -H --hold \
  -J --job-name \
  -n --ntasks \
  -N --nodes \
  -o --output \
  -p --partition \
  -q --qos \
  -t --time \
  -G --gpus \
  -w --nodelist \
  -x --exclude \
  --begin \
  --comment \
  --constraint \
  --contiguous \
  --cpu-freq \
  --deadline \
  --exclusive \
  --gres \
  --gpus-per-node \
  --gpus-per-task \
  --mail-type \
  --mail-user \
  --mem \
  --mem-per-cpu \
  --mem-per-gpu \
  --nice \
  --ntasks-per-node \
  --cpus-per-gpu \
  --overcommit \
  --oversubscribe \
  --priority \
  --requeue \
  --no-requeue \
  --reservation \
  --signal \
  --switches \
  --threads-per-core \
  --tmp \
  --verbose \
  --wait \
  --wait-all-nodes \
  --wckey \
  --array \
  --parsable \
  --test-only \
  --help \
  --usage \
  --version \
"

# Flags that consume a value argument (space-separated form: --flag value)
_SBATCH_VALUE_FLAGS=" \
  -A --account \
  -c --cpus-per-task \
  -d --dependency \
  -e --error \
  -J --job-name \
  -n --ntasks \
  -N --nodes \
  -o --output \
  -p --partition \
  -q --qos \
  -t --time \
  -G --gpus \
  -w --nodelist \
  -x --exclude \
  --begin \
  --comment \
  --constraint \
  --cpu-freq \
  --deadline \
  --gres \
  --gpus-per-node \
  --gpus-per-task \
  --mail-type \
  --mail-user \
  --mem \
  --mem-per-cpu \
  --mem-per-gpu \
  --nice \
  --ntasks-per-node \
  --cpus-per-gpu \
  --priority \
  --reservation \
  --signal \
  --switches \
  --threads-per-core \
  --tmp \
  --wait-all-nodes \
  --wckey \
  --array \
"

# Check if a flag is in the allowed list.
_is_allowed_flag() {
    local flag="$1"
    # Strip =value for --flag=value forms
    local base="${flag%%=*}"
    [[ "$_SBATCH_ALLOWED_FLAGS" == *" $base "* ]]
}

# Check if a flag consumes a value argument.
_is_value_flag() {
    [[ "$_SBATCH_VALUE_FLAGS" == *" $1 "* ]]
}

# ── Argument validation ─────────────────────────────────────────

# Validate and filter sbatch arguments.
# Input:  REQ_ARGS array (from protocol)
# Output: VALIDATED_ARGS array (safe to pass to real sbatch)
# Returns 1 if a denied flag is found.
validate_sbatch_args() {
    VALIDATED_ARGS=()
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            --wrap|--wrap=*)
                # Denied: reconstructed by handler
                echo "chaperon: denied flag: --wrap (use protocol SCRIPT)" >&2
                return 1
                ;;
            --chdir|--chdir=*|-D)
                echo "chaperon: denied flag: --chdir/-D (CWD from protocol)" >&2
                return 1
                ;;
            --uid|--uid=*|--gid|--gid=*)
                echo "chaperon: denied flag: --uid/--gid" >&2
                return 1
                ;;
            --get-user-env|--get-user-env=*)
                echo "chaperon: denied flag: --get-user-env" >&2
                return 1
                ;;
            --propagate|--propagate=*)
                echo "chaperon: denied flag: --propagate" >&2
                return 1
                ;;
            --export|--export=*)
                echo "chaperon: denied flag: --export" >&2
                return 1
                ;;
            --prolog|--prolog=*|--epilog|--epilog=*|--task-prolog|--task-prolog=*|--task-epilog|--task-epilog=*)
                echo "chaperon: denied flag: --prolog/--epilog" >&2
                return 1
                ;;
            --burst-buffer-file|--burst-buffer-file=*|--bbf|--bbf=*)
                echo "chaperon: denied flag: --burst-buffer-file" >&2
                return 1
                ;;
            --bcast|--bcast=*)
                echo "chaperon: denied flag: --bcast" >&2
                return 1
                ;;
            --*=*)
                # Long option with inline value
                if _is_allowed_flag "$arg"; then
                    VALIDATED_ARGS+=("$arg")
                else
                    echo "chaperon: denied unknown flag: ${arg%%=*}" >&2
                    return 1
                fi
                ;;
            -*)
                # Short or long flag
                if _is_allowed_flag "$arg"; then
                    VALIDATED_ARGS+=("$arg")
                    # Consume value if this flag takes one
                    if _is_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ ))
                        VALIDATED_ARGS+=("${REQ_ARGS[$i]}")
                    fi
                else
                    echo "chaperon: denied unknown flag: $arg" >&2
                    return 1
                fi
                ;;
            *)
                # Positional argument — not expected for sbatch via chaperon
                # (script comes via SCRIPT in protocol). Reject.
                echo "chaperon: denied positional argument: (use protocol SCRIPT)" >&2
                return 1
                ;;
        esac
        (( i++ ))
    done
    return 0
}

# ── CWD validation ──────────────────────────────────────────────

# Validate that the requested CWD is under the project directory.
# Usage: validate_cwd <cwd> <project_dir>
validate_cwd() {
    local cwd="$1" project_dir="$2"

    # Resolve to physical path (no symlink tricks)
    local resolved
    resolved="$(cd "$cwd" 2>/dev/null && pwd -P)" || {
        echo "chaperon: CWD does not exist: $cwd" >&2
        return 1
    }

    local resolved_project
    resolved_project="$(cd "$project_dir" 2>/dev/null && pwd -P)" || {
        echo "chaperon: project dir does not exist: $project_dir" >&2
        return 1
    }

    if [[ "$resolved" != "$resolved_project" && "$resolved" != "$resolved_project"/* ]]; then
        echo "chaperon: CWD '$resolved' is not under project dir '$resolved_project'" >&2
        return 1
    fi
    return 0
}

# ── Job wrapping ────────────────────────────────────────────────

# Create a wrapped sbatch script that runs the user's command inside
# the sandbox on the compute node.
# Usage: create_wrapped_script <sandbox_exec> <project_dir> <script_content> <output_file>
create_wrapped_script() {
    local sandbox_exec="$1" project_dir="$2" script_content="$3" output_file="$4"

    # Filter #SBATCH directives: keep safe ones, strip dangerous ones.
    # This prevents bypassing the flag whitelist (e.g. #SBATCH --uid=0,
    # #SBATCH --export=ALL, #SBATCH --prolog=/evil.sh) while preserving
    # legitimate resource directives (--mem, --partition, --time, etc.).
    local safe_directives=""
    local stripped_count=0
    while IFS= read -r line; do
        if [[ "$line" == "#SBATCH"* ]]; then
            # Extract the flag from the directive
            local directive_body="${line#\#SBATCH}"
            directive_body="${directive_body# }"  # strip leading space
            # Get the flag name (before = or space)
            local flag_name
            case "$directive_body" in
                --*=*) flag_name="${directive_body%%=*}" ;;
                --*)   flag_name="${directive_body%% *}" ;;
                -*)    flag_name="${directive_body:0:2}" ;;
                *)     flag_name="" ;;
            esac
            if [[ -n "$flag_name" ]] && _is_allowed_flag "$flag_name"; then
                safe_directives+="$line"$'\n'
            else
                stripped_count=$((stripped_count + 1))
            fi
        fi
    done <<< "$script_content"

    if [[ "$stripped_count" -gt 0 ]]; then
        echo "chaperon: stripped $stripped_count unsafe #SBATCH directive(s) from script" >&2
    fi

    # Create a temp file for the original script (compute node needs it on NFS).
    # Strip #SBATCH directives from the script body — they'll be in the wrapper.
    local orig_script
    orig_script="$(mktemp "${TMPDIR:-/tmp}/chaperon-script-XXXXXX.sh")"
    printf '%s\n' "$script_content" | grep -v '^#SBATCH' >> "$orig_script" || true
    chmod +x "$orig_script"

    # Build wrapper with validated #SBATCH directives
    {
        printf '#!/bin/bash --\n'
        if [[ -n "$safe_directives" ]]; then
            printf '%s' "$safe_directives"
        fi
        printf '\n# --- Chaperon wrapper (auto-generated) ---\n'
        printf '# Clean up original script on exit\n'
        printf 'trap %s EXIT\n' "$(printf "'rm -f %q'" "$orig_script")"
        printf 'exec %q --project-dir %q -- %q\n' \
            "$sandbox_exec" "$project_dir" "$orig_script"
    } > "$output_file"
    chmod +x "$output_file"
}

# Create a --wrap style wrapped command.
# Usage: create_wrapped_command <sandbox_exec> <project_dir> <wrap_cmd>
# Prints the --wrap argument value to stdout.
create_wrapped_command() {
    local sandbox_exec="$1" project_dir="$2" wrap_cmd="$3"
    printf '%q --project-dir %q -- sh -c %q' \
        "$sandbox_exec" "$project_dir" "$wrap_cmd"
}

# ── Job ID tracking (for scancel scoping) ────────────────────────

# Extract job ID from sbatch output and record it.
# Usage: _track_job_id <sbatch_output> <project_dir>
_track_job_id() {
    local output="$1" project_dir="$2"

    # sbatch outputs "Submitted batch job NNNNN" or with --parsable "NNNNN"
    local job_id
    job_id="$(echo "$output" | grep -oP '\d+' | tail -1)"
    if [[ -z "$job_id" ]]; then
        return 0  # No job ID found — not an error (e.g., --test-only)
    fi

    # Session-level tracking (in FIFO_DIR — set by chaperon.sh).
    # The chaperon main loop is single-threaded so concurrent writes to
    # this file from the same session cannot happen.
    local session_file="${FIFO_DIR:-}/jobs"
    if [[ -n "${FIFO_DIR:-}" ]]; then
        echo "$job_id" >> "$session_file"
    fi

    # Project-level tracking (shared across sandbox sessions).
    # Multiple chaperons with the same project dir may append concurrently,
    # so use flock to serialize writes.
    local hash
    hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"
    local project_file="$HOME/.claude/sandbox/chaperon-jobs-${hash}"
    mkdir -p "$HOME/.claude/sandbox" 2>/dev/null || true
    (
        flock -w 2 9 || return 0  # best-effort; skip on timeout
        echo "$job_id" >> "$project_file"
    ) 9>>"$project_file" 2>/dev/null || true
}

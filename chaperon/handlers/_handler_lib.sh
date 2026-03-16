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
    _USER_COMMENT=""   # Captured here, injected by sbatch handler with chaperon tag
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            --wrap|--wrap=*)
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
            --container|--container=*)
                echo "chaperon: denied flag: --container (OCI containers bypass sandbox)" >&2
                return 1
                ;;
            --comment=*)
                # Intercept --comment: chaperon will inject its own tag.
                # Save the user's value to append later.
                _USER_COMMENT="${arg#--comment=}"
                ;;
            --comment)
                # --comment <value> form
                if (( i + 1 < ${#REQ_ARGS[@]} )); then
                    (( i++ ))
                    _USER_COMMENT="${REQ_ARGS[$i]}"
                fi
                ;;
            --*=*)
                if _is_allowed_flag "$arg"; then
                    VALIDATED_ARGS+=("$arg")
                else
                    echo "chaperon: denied unknown flag: ${arg%%=*}" >&2
                    return 1
                fi
                ;;
            -*)
                if _is_allowed_flag "$arg"; then
                    VALIDATED_ARGS+=("$arg")
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

# ── Job tagging via --comment (for scancel/squeue scoping) ───────
#
# Every job submitted through the chaperon gets a structured --comment
# tag that encodes the session and project identity.  This is queried
# by scancel/squeue to scope operations — no file-based tracking needed.
#
# Tag format:  chaperon:sid=<SESSION_ID>,proj=<PROJECT_HASH>[,user=<comment>]
#
#   sid  = unique per-chaperon-instance (PID + epoch, set once at startup)
#   proj = first 12 hex chars of md5(project_dir)
#   user = the user-supplied --comment value, if any (url-encoded to avoid commas)
#
# Query examples:
#   squeue --me -h -o "%i %k" | grep "chaperon:sid=$SID"   → session scope
#   squeue --me -h -o "%i %k" | grep "chaperon:.*proj=$H"  → project scope
#   squeue --me -h -o "%i %k" | grep "^chaperon:"          → user scope

# Session ID: unique per chaperon process.  Combine PID and epoch
# so that recycled PIDs from a later boot don't collide.
_CHAPERON_SESSION_ID="${BASHPID:-$$}.$(date +%s)"

# Build the --comment value for sbatch.
# Usage: _build_chaperon_comment <project_dir>
# Reads _USER_COMMENT (set by validate_sbatch_args).
_build_chaperon_comment() {
    local project_dir="$1"
    local proj_hash
    proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"

    local tag="chaperon:sid=${_CHAPERON_SESSION_ID},proj=${proj_hash}"

    # Append user's original comment (percent-encode commas to stay parseable)
    if [[ -n "${_USER_COMMENT:-}" ]]; then
        local safe_comment="${_USER_COMMENT//,/%2C}"
        tag+=",user=${safe_comment}"
    fi

    printf '%s' "$tag"
}

# Query squeue for job IDs matching a chaperon tag pattern.
# Usage: _query_chaperon_jobs <grep_pattern>
# Prints matching job IDs (one per line).
_query_chaperon_jobs() {
    local pattern="$1"
    squeue --me -h -o "%i %k" 2>/dev/null \
        | grep -E "$pattern" \
        | awk '{print $1}' \
        || true
}

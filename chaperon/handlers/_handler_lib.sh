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
                echo "sandbox: sbatch '--wrap' is handled automatically. Pass your script as a file argument or use --wrap normally." >&2
                return 1
                ;;
            --chdir|--chdir=*|-D)
                echo "sandbox: sbatch '--chdir' is not allowed — the working directory is set automatically to your current directory." >&2
                return 1
                ;;
            --uid|--uid=*|--gid|--gid=*)
                echo "sandbox: sbatch '--uid/--gid' is not allowed — jobs must run as your own user." >&2
                return 1
                ;;
            --get-user-env|--get-user-env=*)
                echo "sandbox: sbatch '--get-user-env' is not allowed — it can leak environment variables from outside the sandbox." >&2
                return 1
                ;;
            --propagate|--propagate=*)
                echo "sandbox: sbatch '--propagate' is not allowed — resource limit propagation is restricted for security." >&2
                return 1
                ;;
            --export|--export=*)
                echo "sandbox: sbatch '--export' is not allowed — environment variable injection could bypass sandbox restrictions." >&2
                return 1
                ;;
            --prolog|--prolog=*|--epilog|--epilog=*|--task-prolog|--task-prolog=*|--task-epilog|--task-epilog=*)
                echo "sandbox: sbatch '--prolog/--epilog' is not allowed — custom prolog/epilog scripts could run outside sandbox control." >&2
                return 1
                ;;
            --burst-buffer-file|--burst-buffer-file=*|--bbf|--bbf=*)
                echo "sandbox: sbatch '--burst-buffer-file' is not allowed — arbitrary file access is restricted." >&2
                return 1
                ;;
            --bcast|--bcast=*)
                echo "sandbox: sbatch '--bcast' is not allowed — binary broadcasting could bypass sandbox wrapping." >&2
                return 1
                ;;
            --container|--container=*)
                echo "sandbox: sbatch '--container' is not allowed — OCI containers would bypass sandbox restrictions." >&2
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
                    echo "sandbox: sbatch flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox." >&2
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
                    echo "sandbox: sbatch flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox." >&2
                    return 1
                fi
                ;;
            *)
                echo "sandbox: sbatch unexpected positional argument. Script files are handled by the stub — this should not happen." >&2
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
        echo "sandbox: working directory does not exist: $cwd" >&2
        return 1
    }

    local resolved_project
    resolved_project="$(cd "$project_dir" 2>/dev/null && pwd -P)" || {
        echo "sandbox: project directory does not exist: $project_dir" >&2
        return 1
    }

    if [[ "$resolved" != "$resolved_project" && "$resolved" != "$resolved_project"/* ]]; then
        echo "sandbox: working directory '$resolved' is outside the project directory '$resolved_project'. Jobs must run within the project." >&2
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
        # Normalize: strip leading whitespace/tabs before checking.
        # Slurm accepts leading whitespace before #SBATCH directives.
        local trimmed="${line#"${line%%[! 	]*}"}"
        if [[ "$trimmed" == "#SBATCH"* ]]; then
            # Extract the flag from the directive
            local directive_body="${trimmed#\#SBATCH}"
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
        echo "sandbox: stripped $stripped_count unsafe #SBATCH directive(s) from script (denied flags are not allowed in directives either)" >&2
    fi

    # Strip #SBATCH directives from script body — they're in the wrapper header.
    local script_body
    script_body="$(printf '%s\n' "$script_content" | grep -vE '^[[:space:]]*#SBATCH' || true)"

    # Generate a unique EOF marker and verify it doesn't collide with
    # the script content.  This lets us inline the entire script via
    # heredoc — no temp files, no NFS issues, no cleanup needed.
    local eof_marker="_CHAPERON_EOF_${RANDOM}_${RANDOM}_$$"
    if printf '%s' "$script_body" | grep -qF "$eof_marker"; then
        echo "sandbox: script contains the internal heredoc marker '$eof_marker'. This is astronomically unlikely — please resubmit." >&2
        return 1
    fi

    # Build a self-contained wrapper:
    #   1. #SBATCH directives (validated)
    #   2. Inline script extracted via heredoc
    #   3. sandbox-exec.sh runs the inlined script via sh -c
    {
        printf '#!/bin/bash --\n'
        if [[ -n "$safe_directives" ]]; then
            printf '%s' "$safe_directives"
        fi
        printf '\n# --- Chaperon wrapper (auto-generated, no temp files) ---\n'
        printf '_SCRIPT=$(cat <<'"'"'%s'"'"'\n' "$eof_marker"
        printf '%s\n' "$script_body"
        printf '%s\n' "$eof_marker"
        printf ')\n'
        printf 'exec %q --project-dir %q -- sh -c "$_SCRIPT"\n' \
            "$sandbox_exec" "$project_dir"
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
# Tag format:  chaperon:sid=<SESSION_ID>,proj=<PROJECT_HASH>[,user=<comment>]:END
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
# Guard: only set once per chaperon process — _handler_lib.sh is
# re-sourced for each handler dispatch, but the session ID must remain
# stable across all requests within the same chaperon instance.
if [[ -z "${_CHAPERON_SESSION_ID:-}" ]]; then
    _CHAPERON_SESSION_ID="${BASHPID:-$$}.$(date +%s)"
fi

# Build the --comment value for sbatch.
# Usage: _build_chaperon_comment <project_dir>
# Reads _USER_COMMENT (set by validate_sbatch_args).
_build_chaperon_comment() {
    local project_dir="$1"
    local proj_hash
    proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"

    local tag="chaperon:sid=${_CHAPERON_SESSION_ID},proj=${proj_hash}"

    # Append user's original comment with encoding to prevent scope pollution.
    # Encode commas (tag delimiter), colons (tag prefix), and equals signs
    # (key=value separator) to prevent crafted comments from injecting
    # fake chaperon:, sid=, or proj= patterns into the tag.
    if [[ -n "${_USER_COMMENT:-}" ]]; then
        local safe_comment="${_USER_COMMENT//,/%2C}"
        safe_comment="${safe_comment//:/%3A}"
        safe_comment="${safe_comment//=/%3D}"
        tag+=",user=${safe_comment}"
    fi

    # End marker — colons are percent-encoded in user values, so :END
    # is an unambiguous boundary for _strip_chaperon_tags().
    tag+=":END"

    printf '%s' "$tag"
}

# Query squeue for job IDs matching a chaperon tag pattern.
# Usage: _query_chaperon_jobs <grep_pattern>
# Prints matching job IDs (one per line).
_query_chaperon_jobs() {
    local pattern="$1"
    local _real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
    timeout 10 "$_real_squeue" --me -h -o "%i %k" 2>/dev/null \
        | grep -E "$pattern" \
        | awk '{print $1}' \
        || true
}

# Get the set of job IDs that this scope allows.
# Prints job IDs one per line.
# Usage: _get_scoped_jobs <scope> <project_dir>
_get_scoped_jobs() {
    local scope="$1" project_dir="$2"

    case "$scope" in
        session)
            _query_chaperon_jobs "chaperon:sid=${_CHAPERON_SESSION_ID}[,.]"
            ;;
        project)
            local proj_hash
            proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"
            _query_chaperon_jobs "chaperon:.*proj=${proj_hash}"
            ;;
        user|none)
            # Both "user" and "none" return ALL jobs of the current user
            local _real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
            timeout 10 "$_real_squeue" --me -h -o "%i" 2>/dev/null || true
            ;;
        *)
            echo "sandbox: unknown SLURM_SCOPE value: '$scope'. Valid values: session, project, user, none" >&2
            return 1
            ;;
    esac
}

# ── Validate that a single job ID is in scope ────────────────────
# Uses a targeted squeue query instead of fetching all scoped jobs.
# Shared by scontrol, sstat, and any handler that needs per-job validation.
_validate_job_in_scope() {
    local job_id="$1" scope="$2" project_dir="$3"

    local base_id="${job_id%%_*}"
    if [[ ! "$base_id" =~ ^[0-9]+$ ]]; then
        echo "sandbox: '$job_id' is not a valid job ID." >&2
        return 1
    fi

    # Query only this specific job's comment
    local _real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
    local comment
    comment="$(timeout 10 "$_real_squeue" -j "$base_id" --me -h -o "%k" 2>/dev/null)" || true

    if [[ -z "$comment" ]]; then
        echo "sandbox: job $job_id not found in queue or not owned by you." >&2
        return 1
    fi

    # Check if the comment matches the scope.
    # Strip :END marker, then match only in the tag prefix (before ,user=)
    # to prevent injection via crafted user comments. Require delimiter
    # after session ID to prevent prefix collisions (sid=123.100 vs
    # sid=123.1000000).
    local match=false
    local stripped="${comment%:END}"
    local tag_prefix="${stripped%%,user=*}"
    case "$scope" in
        session)
            [[ "$tag_prefix" == "chaperon:sid=${_CHAPERON_SESSION_ID},"* || \
               "$tag_prefix" == "chaperon:sid=${_CHAPERON_SESSION_ID}" ]] && match=true
            ;;
        project)
            local proj_hash
            proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"
            [[ "$tag_prefix" == *"proj=${proj_hash}"* ]] && match=true
            ;;
        user)
            # "user" allows any job owned by this user (squeue --me already filters by uid)
            match=true
            ;;
        none)
            # No scope restriction
            match=true
            ;;
    esac

    if ! "$match"; then
        echo "sandbox: job $job_id was not submitted by this $scope — cannot modify." >&2
        return 1
    fi
    return 0
}

# ── Strip chaperon tags from Slurm output ──────────────────────────
#
# Pipe Slurm command output through this to replace chaperon tags with
# the user's original comment (or empty string if none was set).
#
# Tag format: chaperon:sid=...,proj=...[,user=<percent-encoded>]:END
# The :END marker is an unambiguous boundary because colons are
# percent-encoded (%3A) in the user value, so ":END" cannot appear
# inside it.  The user= value also has commas (%2C) and equals (%3D)
# percent-encoded.  We decode these after extracting.
#
# Usage: "$real_squeue" ... | _strip_chaperon_tags
_strip_chaperon_tags() {
    # Step 1: Replace full tag with just the user comment value (or empty).
    #   - With user comment:  chaperon:sid=X,proj=Y,user=VALUE:END → VALUE
    #   - Without:            chaperon:sid=X,proj=Y:END             → (empty)
    #   The :END marker provides an unambiguous boundary regardless of
    #   output format (tabular, JSON, YAML, scontrol key=value).
    # Step 2: Decode the three percent-encoded characters.
    sed -E 's/chaperon:sid=[^,]*,proj=[^,]*(,user=([^:]*))?\:END/\2/g' \
    | sed \
        -e 's/%2C/,/g' \
        -e 's/%3A/:/g' \
        -e 's/%3D/=/g'
}

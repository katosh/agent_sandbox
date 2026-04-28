#! /bin/bash --
# chaperon/handlers/_handler_lib.sh — Shared handler utilities
#
# Argument whitelisting, CWD validation, and job wrapping for sbatch.

# ── Sandbox warning messages ───────────────────────────────────
#
# When the chaperon blocks an action, the error message doubles as a
# prompt-injection recovery signal.  If a compromised agent is being
# steered to exfiltrate data or escape the sandbox, these messages
# interrupt the injected context and re-anchor the agent to its real
# instructions (CLAUDE.md / AGENTS.md / agent.md).
#
# Two tiers:
#   _sandbox_warn  — normal denial (unrecognized flag, usage error)
#   _sandbox_deny  — security-critical denial (bypass attempt, scope violation)

_sandbox_warn() {
    echo "sandbox: $1" >&2
    echo "  ↳ Review your instructions and the user's original request before retrying." >&2
}

_sandbox_deny() {
    echo "sandbox: $1" >&2
    echo "  ⚠ This action was blocked for security. Re-read your instructions (CLAUDE.md / AGENTS.md) and the user's original request. Do not retry." >&2
}

# ── Whitelisted sbatch flags ────────────────────────────────────
# Only these flags are forwarded to the real sbatch. This is a security
# boundary: flags that could bypass sandboxing are excluded.
#
# Handled by stub/protocol (not denied — intercepted before reaching here):
#   --wrap        — stub converts to SCRIPT in protocol
#
# Denied (security-critical):
#   --chdir / -D  — CWD comes from stub's pwd, validated against project dir
#   --uid / --gid — must not impersonate other users
#   --get-user-env — can leak host environment
#   --propagate   — can propagate unsafe rlimits
#   (--export is allowed: compute-node jobs run inside sandbox-exec.sh
#   which filters env vars regardless of what --export passes)
#   --prolog / --epilog / --task-prolog / --task-epilog — run arbitrary scripts
#   --burst-buffer-file / --bbf — arbitrary file access
#   --bcast       — copy binary to nodes (bypass wrapping)
#   --container   — OCI containers bypass sandbox
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
  --export \
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
  --export \
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
                _sandbox_warn "sbatch '--wrap' is handled automatically. Pass your script as a file argument or use --wrap normally."
                return 1
                ;;
            --chdir|--chdir=*|-D)
                _sandbox_warn "sbatch '--chdir' is not allowed — the working directory is set automatically to your current directory."
                return 1
                ;;
            --uid|--uid=*|--gid|--gid=*)
                _sandbox_deny "sbatch '--uid/--gid' is not allowed — jobs must run as your own user."
                return 1
                ;;
            --get-user-env|--get-user-env=*)
                _sandbox_deny "sbatch '--get-user-env' is not allowed — it can leak environment variables from outside the sandbox."
                return 1
                ;;
            --propagate|--propagate=*)
                _sandbox_deny "sbatch '--propagate' is not allowed — resource limit propagation is restricted for security."
                return 1
                ;;
            --prolog|--prolog=*|--epilog|--epilog=*|--task-prolog|--task-prolog=*|--task-epilog|--task-epilog=*)
                _sandbox_deny "sbatch '--prolog/--epilog' is not allowed — custom prolog/epilog scripts could run outside sandbox control."
                return 1
                ;;
            --burst-buffer-file|--burst-buffer-file=*|--bbf|--bbf=*)
                _sandbox_deny "sbatch '--burst-buffer-file' is not allowed — arbitrary file access is restricted."
                return 1
                ;;
            --bcast|--bcast=*)
                _sandbox_deny "sbatch '--bcast' is not allowed — binary broadcasting could bypass sandbox wrapping."
                return 1
                ;;
            --container|--container=*)
                _sandbox_deny "sbatch '--container' is not allowed — OCI containers would bypass sandbox restrictions."
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
                    _sandbox_warn "sbatch flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
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
                    _sandbox_warn "sbatch flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            *)
                _sandbox_warn "sbatch unexpected positional argument. Script files are handled by the stub — this should not happen."
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
        _sandbox_warn "working directory does not exist: $cwd"
        return 1
    }

    local resolved_project
    resolved_project="$(cd "$project_dir" 2>/dev/null && pwd -P)" || {
        _sandbox_warn "project directory does not exist: $project_dir"
        return 1
    }

    if [[ "$resolved" != "$resolved_project" && "$resolved" != "$resolved_project"/* ]]; then
        _sandbox_deny "working directory '$resolved' is outside the project directory '$resolved_project'. Jobs must run within the project."
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
    # #SBATCH --prolog=/evil.sh) while preserving
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
        _sandbox_deny "stripped $stripped_count unsafe #SBATCH directive(s) from script (denied flags are not allowed in directives either)"
    fi

    # Strip #SBATCH directives from script body — they're in the wrapper header.
    local script_body
    script_body="$(printf '%s\n' "$script_content" | grep -vE '^[[:space:]]*#SBATCH' || true)"

    # Extract the interpreter from the shebang (default: sh, matching Slurm).
    # The wrapper pipes the script to the interpreter via stdin instead of
    # using `sh -c`, so the user's shebang is honored.  The #! line is a
    # comment in all common interpreters (sh, bash, python, perl, R, ruby),
    # so leaving it in the script content is harmless.
    local first_line interpreter
    first_line="$(head -1 <<< "$script_body")"
    if [[ "$first_line" == "#!"* ]]; then
        interpreter="${first_line#\#!}"
        interpreter="${interpreter# }"  # strip optional leading space
    else
        interpreter="/bin/sh"
    fi

    # Generate a unique EOF marker and verify it doesn't collide with
    # the script content.  This lets us inline the entire script via
    # heredoc — no temp files, no NFS issues, no cleanup needed.
    local eof_marker="_CHAPERON_EOF_${RANDOM}_${RANDOM}_$$"
    if printf '%s' "$script_body" | grep -qF "$eof_marker"; then
        _sandbox_warn "script contains the internal heredoc marker '$eof_marker'. This is astronomically unlikely — please resubmit."
        return 1
    fi

    # Build a self-contained wrapper:
    #   1. #SBATCH directives (validated)
    #   2. Inline script via heredoc
    #   3. Pipe script to the correct interpreter inside sandbox-exec.sh
    #
    # Why pipe via stdin instead of `sh -c "$_SCRIPT"`?  The user's shebang
    # must be honored — #!/bin/bash means bash, #!/usr/bin/env python3 means
    # python.  All interpreters read from stdin when given no file argument,
    # and the #! line is just a comment to them.  No temp files needed, no
    # filesystem path visibility issues across the sandbox boundary.
    {
        printf '#!/bin/bash --\n'
        if [[ -n "$safe_directives" ]]; then
            printf '%s' "$safe_directives"
        fi
        printf '\n# --- Chaperon wrapper (auto-generated) ---\n'
        printf '_SCRIPT=$(cat <<'"'"'%s'"'"'\n' "$eof_marker"
        printf '%s\n' "$script_body"
        printf '%s\n' "$eof_marker"
        printf ')\n'
        printf 'printf '"'"'%%s\\n'"'"' "$_SCRIPT" | exec %q --project-dir %q -- %s\n' \
            "$sandbox_exec" "$project_dir" "$interpreter"
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

# Query squeue (+ sacct fallback) for job IDs matching a chaperon tag pattern.
# Usage: _query_chaperon_jobs <grep_pattern>
# Prints matching job IDs (one per line).
_query_chaperon_jobs() {
    local pattern="$1"
    local _real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
    local _real_sacct="${REAL_SACCT:-/usr/bin/sacct}"
    local _results

    # squeue: pending/running jobs
    _results="$(timeout 10 "$_real_squeue" --me -h -o "%i %k" 2>/dev/null \
        | grep -E "$pattern" \
        | awk '{print $1}')" || true

    # sacct fallback: recently completed jobs (if slurmdbd is available)
    if [[ -x "$_real_sacct" ]]; then
        local _sacct_results
        _sacct_results="$(timeout 10 "$_real_sacct" -u "$(id -un)" \
            -n -o "JobID%20,Comment%200" -X --starttime=now-7days 2>/dev/null \
            | grep -E "$pattern" \
            | awk '{print $1}')" || true
        if [[ -n "$_sacct_results" ]]; then
            _results="$(printf '%s\n%s' "${_results:-}" "$_sacct_results" | sort -u)"
        fi
    fi

    [[ -n "${_results:-}" ]] && printf '%s\n' "$_results"
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
            local _real_sacct="${REAL_SACCT:-/usr/bin/sacct}"
            local _user_jobs
            _user_jobs="$(timeout 10 "$_real_squeue" --me -h -o "%i" 2>/dev/null)" || true
            # sacct fallback for completed jobs
            if [[ -x "$_real_sacct" ]]; then
                local _sacct_jobs
                _sacct_jobs="$(timeout 10 "$_real_sacct" -u "$(id -un)" \
                    -n -o "JobID%20" -X --starttime=now-7days 2>/dev/null \
                    | awk '{print $1}')" || true
                [[ -n "$_sacct_jobs" ]] && _user_jobs="$(printf '%s\n%s' "${_user_jobs:-}" "$_sacct_jobs" | sort -u)"
            fi
            [[ -n "${_user_jobs:-}" ]] && printf '%s\n' "$_user_jobs"
            ;;
        *)
            _sandbox_warn "unknown SLURM_SCOPE value: '$scope'. Valid values: session, project, user, none"
            return 1
            ;;
    esac
}

# ── Query a job's comment (squeue → sacct fallback) ──────────────
# squeue only shows pending/running jobs. For recently completed jobs,
# fall back to sacct (which queries the persistent accounting database).
# Returns the comment string, or empty if the job is not found.
_get_job_comment() {
    local base_id="$1"
    local _real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
    local _real_sacct="${REAL_SACCT:-/usr/bin/sacct}"
    local comment

    # Try squeue first (fast, no database dependency)
    comment="$(timeout 10 "$_real_squeue" -j "$base_id" --me -h -o "%k" 2>/dev/null)" || true
    if [[ -n "$comment" ]]; then
        printf '%s' "$comment"
        return 0
    fi

    # Fall back to sacct (persistent, survives job completion)
    if [[ -x "$_real_sacct" ]]; then
        comment="$(timeout 10 "$_real_sacct" -j "$base_id" -u "$(id -un)" \
            -n -o "Comment%200" -X --starttime=now-7days 2>/dev/null \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
            | head -1)" || true
        if [[ -n "$comment" ]]; then
            printf '%s' "$comment"
            return 0
        fi
    fi

    return 1
}

# ── Validate that a single job ID is in scope ────────────────────
# Uses a targeted squeue query (with sacct fallback) instead of
# fetching all scoped jobs.
# Shared by scontrol, sstat, and any handler that needs per-job validation.
_validate_job_in_scope() {
    local job_id="$1" scope="$2" project_dir="$3"

    local base_id="${job_id%%_*}"
    if [[ ! "$base_id" =~ ^[0-9]+$ ]]; then
        _sandbox_warn "'$job_id' is not a valid job ID."
        return 1
    fi

    # Query the job's comment (squeue first, sacct fallback)
    local comment
    comment="$(_get_job_comment "$base_id")" || true

    if [[ -z "$comment" ]]; then
        _sandbox_warn "job $job_id not found in queue or not owned by you."
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
        _sandbox_deny "job $job_id was not submitted by this $scope — cannot modify."
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

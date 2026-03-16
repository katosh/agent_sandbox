#! /bin/bash --
# chaperon/handlers/sbatch.sh — Handle sbatch requests from sandbox
#
# Validates arguments, wraps the job in sandbox-exec.sh, injects a
# chaperon tag into --comment for scoping, and submits via real sbatch.

# Source handler utilities
source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# handle_sbatch — Process an sbatch request.
#
# Globals read: REQ_ARGS, REQ_CWD, REQ_SCRIPT (set by chaperon_read_request)
# Arguments: $1 = project_dir, $2 = sandbox_exec_path
# Outputs:   stdout/stderr captured by chaperon main loop
# Returns:   exit code from real sbatch (or 1 on validation failure)
handle_sbatch() {
    local project_dir="$1"
    local sandbox_exec="$2"

    # Find real sbatch
    local real_sbatch="${REAL_SBATCH:-/usr/bin/sbatch}"
    if [[ ! -x "$real_sbatch" ]]; then
        echo "chaperon: real sbatch not found at $real_sbatch" >&2
        return 1
    fi

    # Validate CWD
    if ! validate_cwd "$REQ_CWD" "$project_dir"; then
        return 1
    fi

    # Validate arguments (also captures _USER_COMMENT if --comment was given)
    if ! validate_sbatch_args; then
        return 1
    fi

    # Build the chaperon tag and inject as --comment
    local chaperon_comment
    chaperon_comment="$(_build_chaperon_comment "$project_dir")"
    VALIDATED_ARGS+=("--comment=$chaperon_comment")

    # Determine submission mode: SCRIPT or --wrap
    if [[ -n "$REQ_SCRIPT" ]]; then
        # Script mode: wrap the script
        local wrapper
        wrapper="$(mktemp "${TMPDIR:-/tmp}/chaperon-wrapper-XXXXXX.sh")"

        create_wrapped_script "$sandbox_exec" "$project_dir" "$REQ_SCRIPT" "$wrapper"

        # Submit
        local rc=0
        "$real_sbatch" "${VALIDATED_ARGS[@]}" "$wrapper" || rc=$?

        # Clean up wrapper (original script cleaned up by wrapper's trap)
        rm -f "$wrapper"
        return "$rc"
    else
        # No script: pass through flags (e.g., --help, --version, --test-only)
        local rc=0
        "$real_sbatch" "${VALIDATED_ARGS[@]}" || rc=$?
        return "$rc"
    fi
}

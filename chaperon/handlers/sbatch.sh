#! /bin/bash --
# chaperon/handlers/sbatch.sh — Handle sbatch requests from sandbox
#
# Validates arguments, wraps the job in sandbox-exec.sh, injects a
# chaperon tag into --comment for scoping, and submits via real sbatch.

# Source handler utilities
source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# handle_sbatch — Process an sbatch request.
#
# Globals read: REQ_ARGS, REQ_CWD, REQ_SCRIPT, REQ_SCRIPT_ARGS
#               (set by chaperon_read_request)
# Arguments: $1 = project_dir, $2 = sandbox_exec_path
# Outputs:   stdout/stderr captured by chaperon main loop
# Returns:   exit code from real sbatch (or 1 on validation failure)
handle_sbatch() {
    local project_dir="$1"
    local sandbox_exec="$2"

    # Find real sbatch
    local real_sbatch="${REAL_SBATCH:-/usr/bin/sbatch}"
    if [[ ! -x "$real_sbatch" ]]; then
        _sandbox_warn "sbatch binary not found at $real_sbatch — is Slurm installed?"
        return 1
    fi

    # Validate CWD
    if ! validate_cwd "$REQ_CWD" "$project_dir"; then
        return 1
    fi

    # Expose PROJECT_DIR to validate_sbatch_args (which calls
    # _transform_slurm_output_path) — declared local in the caller
    # scope here so it doesn't leak across chaperon iterations.
    local PROJECT_DIR="$project_dir"

    # Validate arguments (also captures _USER_COMMENT if --comment was given,
    # and _USER_SLURM_OUTPUT / _STAGING_SLURM_OUTPUT for the --output /
    # --error path-transformation feature on bwrap/firejail).
    if ! validate_sbatch_args; then
        return 1
    fi

    # Build the chaperon tag and inject as --comment
    local chaperon_comment
    chaperon_comment="$(_build_chaperon_comment "$project_dir")"
    VALIDATED_ARGS+=("--comment=$chaperon_comment")

    # Ensure .sandbox-state/ exists and mkdir -p the parent dirs of the
    # transformed staging paths. Slurm doesn't do `mkdir -p` for
    # --output / --error dir components, so slurmstepd's `open()` would
    # fail without these dirs. Done in the chaperon (outside the
    # sandbox) where we have full FS access. For paths containing
    # %-patterns in directory components (e.g., `--output=job-%j/out`,
    # uncommon), this only creates the literal-component parent — the
    # user needs to handle %-dir creation themselves if they hit it.
    if [[ -n "${_STAGING_SLURM_OUTPUT:-}" || -n "${_STAGING_SLURM_ERROR:-}" ]]; then
        _ensure_sandbox_state_dir "$project_dir"
        if [[ -n "${_STAGING_SLURM_OUTPUT:-}" ]]; then
            mkdir -p -- "$(dirname -- "$_STAGING_SLURM_OUTPUT")" 2>/dev/null || true
        fi
        if [[ -n "${_STAGING_SLURM_ERROR:-}" ]]; then
            mkdir -p -- "$(dirname -- "$_STAGING_SLURM_ERROR")" 2>/dev/null || true
        fi
    fi

    # Change to the agent's CWD so Slurm sees the correct working directory.
    # This ensures SLURM_SUBMIT_DIR and relative --output/--error paths
    # resolve from the agent's directory, not the chaperon's.
    # CWD has already been validated by validate_cwd above.
    if [[ -n "$REQ_CWD" ]]; then
        cd "$REQ_CWD"
    fi

    # Determine submission mode: SCRIPT or --wrap
    if [[ -n "$REQ_SCRIPT" ]]; then
        # Script mode: build a self-contained wrapper with the script
        # inlined via heredoc (no temp files on NFS needed).
        local wrapper
        wrapper="$(mktemp "${TMPDIR:-/tmp}/chaperon-wrapper-XXXXXX.sh")"

        create_wrapped_script "$sandbox_exec" "$project_dir" "$REQ_SCRIPT" "$wrapper" \
            "${REQ_SCRIPT_ARGS[@]+"${REQ_SCRIPT_ARGS[@]}"}"

        # Submit and clean up the local wrapper (only needed on login node).
        local rc=0
        "$real_sbatch" "${VALIDATED_ARGS[@]}" "$wrapper" || rc=$?
        rm -f "$wrapper"
        return "$rc"
    else
        # No script: pass through flags (e.g., --help, --version, --test-only)
        local rc=0
        "$real_sbatch" "${VALIDATED_ARGS[@]}" || rc=$?
        return "$rc"
    fi
}

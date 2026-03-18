#! /bin/bash --
# chaperon/handlers/sreport.sh — Handle sreport requests from sandbox
#
# sreport is blocked entirely.  It generates accounting reports across
# many sub-report types, many of which enumerate users and accounts.
# The complexity of safely filtering all report types is not worth the
# risk.  Users can use sacct with formatting options to get most of
# the same information, scoped to their own jobs.

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

handle_sreport() {
    local project_dir="$1"
    local sandbox_exec="$2"

    # Allow --help/--version/--usage so users can still read docs
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            --help|--usage|--version)
                local real_sreport="${REAL_SREPORT:-/usr/bin/sreport}"
                if [[ -x "$real_sreport" ]]; then
                    local rc=0
                    "$real_sreport" "$arg" || rc=$?
                    return "$rc"
                else
                    _sandbox_warn "sreport binary not found at $real_sreport — is Slurm installed?"
                    return 1
                fi
                ;;
        esac
        (( i++ )) || true
    done

    _sandbox_deny "sreport is not allowed — its many report types can enumerate users and accounts."
    _sandbox_warn "use 'sacct' with formatting options instead (e.g., sacct --format=JobID,Account,User,Elapsed,State)."
    return 1
}

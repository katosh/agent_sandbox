#! /bin/bash --
# chaperon/handlers/blocked.sh — Generic "command blocked" handler
#
# Used for Slurm commands that are not allowed through the chaperon
# (salloc, sattach, etc.).

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

handle_blocked() {
    local command="${REQ_COMMAND:-unknown}"
    _sandbox_deny "'$command' is not allowed inside the sandbox."
    _sandbox_warn "Hint: sbatch, srun, scancel, squeue, scontrol, sacct, sacctmgr, sinfo, sstat, sprio, sshare, sdiag are supported. See CHAPERON.md."
    return 1
}

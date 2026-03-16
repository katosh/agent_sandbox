#! /bin/bash --
# chaperon/handlers/blocked.sh — Generic "command blocked" handler
#
# Used for Slurm commands that are not allowed through the chaperon
# (scontrol, salloc, sattach, etc.).

handle_blocked() {
    local command="${REQ_COMMAND:-unknown}"
    echo "chaperon: '$command' is not allowed inside the sandbox." >&2
    echo "Hint: 'sbatch', 'srun', and 'scancel' are supported. See CHAPERON.md for details." >&2
    return 1
}

#! /bin/bash --
# srun-sandbox.sh — Drop-in srun that wraps commands in the sandbox on the compute node
#
# Accepts the same arguments as real srun. Separates srun flags from the
# command, then runs:  /usr/bin/srun [flags] sandbox-exec.sh -- command
#
# Works with or without a -- separator:
#   srun-sandbox.sh -n 4 python train.py
#   srun-sandbox.sh -n 4 -- python train.py
#
# Flag parsing: unlike sbatch (where the script must be a file), srun
# commands can be any executable name. There is no reliable heuristic to
# distinguish a flag value from a command (e.g., "-J test" vs "test file.py").
# We therefore maintain a list of flags that consume a value argument.
# Using -- is always safest and avoids any ambiguity.

set -euo pipefail

REAL_SRUN="${REAL_SRUN:-/usr/bin/srun}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

PROJECT_DIR="${SANDBOX_PROJECT_DIR:-$(pwd)}"

# ── Known srun flags that consume a value argument ──────────────
# This list covers srun flags through Slurm 24.x. If a new Slurm
# version adds a flag with a value and it's not listed here, the
# parser may mistake the value for the user command. Using -- as a
# separator always works regardless of this list.
#
# Flags that accept --flag=value syntax don't strictly need to be here
# (handled by the --*=* case), but are included for the -f value form.
_SRUN_VALUE_FLAGS=" \
  -A --account -c --cpus-per-task -D --chdir -d --dependency \
  -e --error -J --job-name -n --ntasks -N --nodes -o --output \
  -p --partition -t --time -G --gpus -m --distribution -w --nodelist \
  -x --exclude -W --wait \
  --mem --mem-per-cpu --mem-per-gpu --gres --constraint --export \
  --mpi --cpu-bind --gpu-bind --gpus-per-node --gpus-per-task \
  --ntasks-per-node --cpus-per-gpu --signal --switches \
  --threads-per-core --network --begin --nice --priority --qos \
  --reservation --wckey --comment --mail-type --mail-user \
  --cpu-freq --deadline --delay-boot --epilog --prolog \
  --task-epilog --task-prolog --input --kill-on-bad-exit \
  --label --mcs-label --open-mode --profile --propagate \
  --quit-on-interrupt --slurmd-debug --tmp --bcast \
"

_is_value_flag() {
    [[ "$_SRUN_VALUE_FLAGS" == *" $1 "* ]]
}

# ── Parse arguments ─────────────────────────────────────────────
SRUN_FLAGS=()
USER_CMD=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --)
            # Explicit separator: everything after is the user command
            shift
            USER_CMD=("$@")
            break
            ;;
        --*=*)
            # Long option with inline value (e.g., --nodes=4)
            SRUN_FLAGS+=("$1")
            shift
            ;;
        -*)
            SRUN_FLAGS+=("$1")
            if [[ "$1" != *=* ]] && _is_value_flag "$1"; then
                if [[ $# -gt 1 ]]; then
                    shift
                    SRUN_FLAGS+=("$1")
                fi
            fi
            shift
            ;;
        *)
            # First positional argument: start of user command
            USER_CMD=("$@")
            break
            ;;
    esac
done

if [[ ${#USER_CMD[@]} -eq 0 ]]; then
    # No user command found; pass through to srun as-is (e.g., srun --help)
    exec "$REAL_SRUN" "${SRUN_FLAGS[@]}"
fi

exec "$REAL_SRUN" "${SRUN_FLAGS[@]}" \
    "$SCRIPT_DIR/sandbox-exec.sh" --project-dir "$PROJECT_DIR" -- "${USER_CMD[@]}"

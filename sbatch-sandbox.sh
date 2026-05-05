#! /bin/bash --
# sbatch-sandbox.sh — Submit Slurm jobs that run inside the sandbox
#
# Drop-in replacement for sbatch. The job itself executes inside the
# sandbox on the compute node (using whichever backend is available).
#
# Usage:
#   sbatch-sandbox.sh [sbatch-flags] --wrap="command"
#   sbatch-sandbox.sh [sbatch-flags] script.sh [script-args]
#
# Since sandbox scripts live on NFS, they're available on every compute
# node without extra setup.
#
# Flag parsing: this script does NOT maintain a list of sbatch flags.
# It only looks for --wrap (which it must intercept) and the job script
# (the first bare positional argument that exists as a file). Flag
# values are consumed by peeking ahead, making this future-proof
# against new Slurm versions adding flags.

set -euo pipefail

REAL_SBATCH="${REAL_SBATCH:-/usr/bin/sbatch}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
SANDBOX_EXEC="$SCRIPT_DIR/sandbox-exec.sh"

# Project dir: inherit from sandbox env, or use $PWD
PROJECT_DIR="${SANDBOX_PROJECT_DIR:-$(pwd)}"

# ── Parse arguments ─────────────────────────────────────────────
# Strategy: collect all arguments, looking only for --wrap (which we
# must intercept). Everything else is kept in order. After the scan,
# if there's no --wrap, we find the job script by walking the collected
# arguments with flag-value awareness:
#   - --long=value forms are self-contained (one arg)
#   - -x or --long followed by a non-flag arg: the next arg is consumed
#     as the flag's value (skip it)
#   - The first bare positional (not consumed as a flag value) that
#     exists as a regular file is the job script
# This avoids maintaining a list of which flags consume a value.

ALL_ARGS=()
WRAP_CMD=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wrap=*)
            WRAP_CMD="${1#--wrap=}"
            shift
            ;;
        --wrap)
            WRAP_CMD="${2:-}"
            shift 2
            ;;
        *)
            ALL_ARGS+=("$1")
            shift
            ;;
    esac
done

if [[ -n "$WRAP_CMD" ]]; then
    # --wrap mode: wrap the command in sandbox.
    # Use printf %q to safely escape the wrap command for shell evaluation.
    _escaped_cmd=$(printf '%q' "$WRAP_CMD")
    exec "$REAL_SBATCH" "${ALL_ARGS[@]}" \
        --wrap="$SANDBOX_EXEC --project-dir $(printf '%q' "$PROJECT_DIR") -- sh -c $_escaped_cmd"

else
    # Script mode: find the job script among the collected arguments.
    SBATCH_FLAGS=()
    SCRIPT_PATH=""
    SCRIPT_ARGS=()
    skip_next=false

    for ((i=0; i<${#ALL_ARGS[@]}; i++)); do
        arg="${ALL_ARGS[$i]}"

        if $skip_next; then
            # This argument is consumed as the previous flag's value
            SBATCH_FLAGS+=("$arg")
            skip_next=false
            continue
        fi

        case "$arg" in
            --*=*)
                # Long option with inline value (e.g., --mem=4G)
                SBATCH_FLAGS+=("$arg")
                ;;
            -*)
                # Flag that may consume the next argument as its value.
                # If the next arg doesn't start with -, assume it's this
                # flag's value. This safely skips values like "-o output.log"
                # or "-p gpu" without needing a flag list.
                SBATCH_FLAGS+=("$arg")
                if [[ $((i+1)) -lt ${#ALL_ARGS[@]} && "${ALL_ARGS[$((i+1))]}" != -* ]]; then
                    skip_next=true
                fi
                ;;
            *)
                # Bare positional argument not consumed as a flag value.
                if [[ -f "$arg" ]]; then
                    SCRIPT_PATH="$arg"
                    SCRIPT_ARGS=("${ALL_ARGS[@]:$((i+1))}")
                    break
                else
                    SBATCH_FLAGS+=("$arg")
                fi
                ;;
        esac
    done

    if [[ -z "$SCRIPT_PATH" ]]; then
        echo "Error: No --wrap command or script specified." >&2
        echo "Usage:" >&2
        echo "  sbatch-sandbox.sh [sbatch-flags] --wrap='command'" >&2
        echo "  sbatch-sandbox.sh [sbatch-flags] script.sh [args]" >&2
        exit 1
    fi

    SCRIPT_PATH="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)/$(basename "$SCRIPT_PATH")"

    # Extract #SBATCH directives from the original script
    SBATCH_DIRECTIVES=$(grep '^#SBATCH' "$SCRIPT_PATH" || true)

    WRAPPER=$(mktemp /tmp/sbatch-sandbox-XXXXXX.sh)
    trap "rm -f '$WRAPPER'" EXIT

    # Use a quoted heredoc to prevent expansion of SBATCH directive
    # contents (defense against $(cmd) in #SBATCH --comment="$(cmd)").
    # Variables for the exec line are written via printf.
    {
        printf '#!/bin/bash --\n'
        printf '%s\n' "$SBATCH_DIRECTIVES"
        printf '\n# --- Sandbox wrapper (auto-generated) ---\n'
        printf 'exec %q --project-dir %q -- %q' \
            "$SANDBOX_EXEC" "$PROJECT_DIR" "$SCRIPT_PATH"
        for _sa in "${SCRIPT_ARGS[@]+"${SCRIPT_ARGS[@]}"}"; do
            printf ' %q' "$_sa"
        done
        printf '\n'
    } > "$WRAPPER"

    chmod +x "$WRAPPER"
    exec "$REAL_SBATCH" "${SBATCH_FLAGS[@]}" "$WRAPPER"
fi

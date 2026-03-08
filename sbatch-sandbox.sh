#!/usr/bin/env bash
# sbatch-sandbox.sh — Submit Slurm jobs that run inside the bwrap sandbox
#
# Drop-in replacement for sbatch. The job itself executes inside a
# bubblewrap sandbox on the compute node.
#
# Usage:
#   sbatch-sandbox.sh [sbatch-flags] --wrap="command"
#   sbatch-sandbox.sh [sbatch-flags] script.sh [script-args]
#
# Since bwrap and all sandbox scripts live on NFS, they're available
# on every compute node without extra setup.

set -euo pipefail

REAL_SBATCH="${REAL_SBATCH:-/usr/bin/sbatch}"
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
BWRAP_SANDBOX="$SCRIPT_DIR/bwrap-sandbox.sh"

# Project dir: inherit from sandbox env, or use $PWD
PROJECT_DIR="${SANDBOX_PROJECT_DIR:-$(pwd)}"

# Separate sbatch flags from --wrap / script
SBATCH_FLAGS=()
WRAP_CMD=""
SCRIPT_PATH=""
SCRIPT_ARGS=()

parse_done=false
while [[ $# -gt 0 ]] && [[ "$parse_done" == false ]]; do
    case "$1" in
        --wrap=*)
            WRAP_CMD="${1#--wrap=}"
            shift
            ;;
        --wrap)
            WRAP_CMD="$2"
            shift 2
            ;;
        -*)
            SBATCH_FLAGS+=("$1")
            # Flags that consume a value argument
            case "$1" in
                -A|-p|-n|-c|-t|-J|-o|-e|-N|-D|--account|--partition|--ntasks|--cpus-per-task|--time|--job-name|--output|--error|--nodes|--mem|--gres|--constraint|--export|--dependency|--array|--mail-type|--mail-user|--qos|--chdir)
                    if [[ $# -gt 1 ]]; then
                        SBATCH_FLAGS+=("$2")
                        shift
                    fi
                    ;;
            esac
            shift
            ;;
        *)
            SCRIPT_PATH="$1"
            shift
            SCRIPT_ARGS=("$@")
            parse_done=true
            ;;
    esac
done

if [[ -n "$WRAP_CMD" ]]; then
    # --wrap mode: wrap the command in bwrap
    exec "$REAL_SBATCH" "${SBATCH_FLAGS[@]}" \
        --wrap="$BWRAP_SANDBOX --project-dir '$PROJECT_DIR' -- bash -c '${WRAP_CMD//\'/\'\\\'\'}'"

elif [[ -n "$SCRIPT_PATH" ]]; then
    # Script mode: create a wrapper that runs the original inside bwrap
    SCRIPT_PATH="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)/$(basename "$SCRIPT_PATH")"

    if [[ ! -f "$SCRIPT_PATH" ]]; then
        echo "Error: Script not found: $SCRIPT_PATH" >&2
        exit 1
    fi

    # Extract #SBATCH directives from the original script
    SBATCH_DIRECTIVES=$(grep '^#SBATCH' "$SCRIPT_PATH" || true)

    WRAPPER=$(mktemp /tmp/sbatch-sandbox-XXXXXX.sh)
    trap "rm -f '$WRAPPER'" EXIT

    cat > "$WRAPPER" <<WRAPPER_EOF
#!/usr/bin/env bash
${SBATCH_DIRECTIVES}

# --- Sandbox wrapper (auto-generated) ---
# Original script: $SCRIPT_PATH
exec "$BWRAP_SANDBOX" --project-dir "$PROJECT_DIR" -- bash "$SCRIPT_PATH" ${SCRIPT_ARGS[*]+"${SCRIPT_ARGS[*]}"}
WRAPPER_EOF

    chmod +x "$WRAPPER"
    exec sbatch "${SBATCH_FLAGS[@]}" "$WRAPPER"

else
    echo "Error: No --wrap command or script specified." >&2
    echo "Usage:" >&2
    echo "  sbatch-sandbox.sh [sbatch-flags] --wrap='command'" >&2
    echo "  sbatch-sandbox.sh [sbatch-flags] script.sh [args]" >&2
    exit 1
fi

#!/usr/bin/env bash
# sbatch-token-wrapper.sh — System-wide sbatch wrapper enforcing sandbox on agent jobs
#
# Replaces /usr/bin/sbatch (or shadows it via PATH). Reads the eBPF-
# protected bypass token and injects it as an environment variable so
# the job submit plugin lets the job through unsandboxed. Sandboxed
# processes cannot read the token, so the plugin sandboxes their jobs.
#
# The token is never passed as a CLI argument (invisible in /proc/*/cmdline).
# Any _SANDBOX_BYPASS in --export= flags is stripped.
#
# Deployment — see sandbox-wrapper.conf for path configuration.
#
#   sudo mkdir -p /usr/libexec/slurm
#   sudo mv /usr/bin/sbatch /usr/libexec/slurm/sbatch
#   sudo cp sbatch-token-wrapper.sh /usr/bin/sbatch
#   sudo chmod +x /usr/bin/sbatch
#   sudo cp sandbox-wrapper.conf /etc/slurm/sandbox-wrapper.conf

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# Source configuration (check next to script, then /etc/slurm)
if [[ -f "$SCRIPT_DIR/sandbox-wrapper.conf" ]]; then
    source "$SCRIPT_DIR/sandbox-wrapper.conf"
elif [[ -f /etc/slurm/sandbox-wrapper.conf ]]; then
    source /etc/slurm/sandbox-wrapper.conf
fi

# Defaults if not set by config
TOKEN_FILE="${TOKEN_FILE:-/etc/slurm/.sandbox-bypass-token}"
REAL_SBATCH="${REAL_SBATCH:-/usr/libexec/slurm/sbatch}"

# Fall back to /usr/bin/sbatch if relocated binary doesn't exist
if [[ ! -x "$REAL_SBATCH" ]]; then
    REAL_SBATCH=/usr/bin/sbatch
fi

# Strip any _SANDBOX_BYPASS from --export= flags (prevent manual injection
# via command line, which would be visible in the process table).
ARGS=()
for arg in "$@"; do
    case "$arg" in
        --export=*)
            cleaned=$(echo "${arg#--export=}" | sed 's/,\?_SANDBOX_BYPASS=[^,]*//' | sed 's/^,//')
            if [[ -n "$cleaned" ]]; then
                ARGS+=("--export=$cleaned")
            fi
            ;;
        *)
            ARGS+=("$arg")
            ;;
    esac
done

# Clear any _SANDBOX_BYPASS from the inherited environment
unset _SANDBOX_BYPASS

# Try to read the token. Succeeds for normal users, fails for sandboxed
# processes (eBPF returns EACCES when no_new_privs is set).
TOKEN=$(cat "$TOKEN_FILE" 2>/dev/null) || true

if [[ -n "$TOKEN" ]]; then
    export _SANDBOX_BYPASS="$TOKEN"
fi

exec "$REAL_SBATCH" "${ARGS[@]}"

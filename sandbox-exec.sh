#! /bin/bash --
# sandbox-exec.sh — Run a command inside the sandbox (auto-selects backend)
#
# Usage:
#   sandbox-exec.sh [OPTIONS] -- CMD [ARGS...]
#
# Options:
#   --project-dir DIR   Directory with write access (default: $PWD)
#   --backend BACKEND   Force a specific backend (bwrap, landlock, auto)
#   --dry-run           Print the sandbox command without executing
#   --help              Show this help
#
# Examples:
#   sandbox-exec.sh -- claude                        # Claude Code sandboxed
#   sandbox-exec.sh -- bash                          # interactive shell
#   sandbox-exec.sh --backend landlock -- bash       # force Landlock backend

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

PROJECT_DIR=""
DRY_RUN=false
BACKEND_OVERRIDE=""

usage() {
    echo "Usage: sandbox-exec.sh [--project-dir DIR] [--backend BACKEND] [--dry-run] -- CMD [ARGS...]"
    echo ""
    echo "Options:"
    echo "  --project-dir DIR   Directory with write access (default: \$PWD)"
    echo "  --backend BACKEND   Force backend: bwrap, landlock, auto (default: auto)"
    echo "  --dry-run           Print the sandbox command without executing"
    echo "  --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  sandbox-exec.sh -- claude              # Claude Code in sandbox"
    echo "  sandbox-exec.sh -- bash                # interactive shell"
    echo "  sandbox-exec.sh --backend landlock -- cmd  # force Landlock"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)
            PROJECT_DIR="$2"
            shift 2
            ;;
        --backend)
            BACKEND_OVERRIDE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --)
            shift
            break
            ;;
        *)
            echo "Error: Unknown option '$1'" >&2
            usage >&2
            exit 1
            ;;
    esac
done

# Clear inherited sandbox env vars so Slurm jobs submitted from within a
# sandbox can start a fresh sandbox on the compute node.  This is safe
# because sandbox-exec.sh always sets up its own sandbox from scratch —
# the env vars are informational, not part of the enforcement mechanism
# (which is kernel-level: namespaces, Landlock rules, seccomp).
unset SANDBOX_ACTIVE SANDBOX_BACKEND SANDBOX_PROJECT_DIR CLAUDE_CONFIG_DIR

# Apply backend override before sourcing sandbox-lib.sh
if [[ -n "$BACKEND_OVERRIDE" ]]; then
    export SANDBOX_BACKEND="$BACKEND_OVERRIDE"
fi

source "$SCRIPT_DIR/sandbox-lib.sh"

# Default to current directory
if [[ -z "$PROJECT_DIR" ]]; then
    PROJECT_DIR="$(pwd)"
fi

# Resolve to absolute, physical path (follow symlinks).
# This ensures the project path inside the sandbox matches the path
# Claude Code sees outside, so session resume works across both.
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd -P)"

# Load per-project config overrides (conf.d/*.conf)
load_project_config "$PROJECT_DIR"

# Validate
if [[ ! -d "$PROJECT_DIR" ]]; then
    echo "Error: Project directory does not exist: $PROJECT_DIR" >&2
    exit 1
fi

validate_project_dir "$PROJECT_DIR"

if [[ $# -eq 0 ]]; then
    echo "Error: No command specified after --" >&2
    echo "Hint: sandbox-exec.sh -- bash       (interactive shell)" >&2
    echo "      sandbox-exec.sh -- claude      (Claude Code)" >&2
    exit 1
fi

# Detect and load backend
detect_backend
_BACKEND_DETECTED=true

# Create per-session config directory (backend-independent)
prepare_config_dir

# ── Chaperon: create FIFO directory ───────────────────────────────
# Create the FIFO directory BEFORE backend_prepare so backends can
# add bind-mounts for it. The chaperon process is started AFTER
# backend_prepare but before entering the sandbox.

_CHAPERON_PID=""
_CHAPERON_DIR=""

if [[ -x "$SCRIPT_DIR/chaperon/chaperon.sh" ]]; then
    _CHAPERON_DIR="$(mktemp -d "${TMPDIR:-/tmp}/chaperon-XXXXXX")"
    chmod 700 "$_CHAPERON_DIR"

    # request pipe: sandbox writes → chaperon reads
    mkfifo "$_CHAPERON_DIR/req"
    chmod 600 "$_CHAPERON_DIR/req"

    # Export the FIFO directory path — backends read this during prepare
    export _CHAPERON_FIFO_DIR="$_CHAPERON_DIR"
fi

# Prepare sandbox (reads _CHAPERON_FIFO_DIR for bind-mounts)
backend_prepare "$PROJECT_DIR"

if [[ "$DRY_RUN" == true ]]; then
    backend_dry_run "$@"
    # Clean up chaperon dir on dry-run
    [[ -n "$_CHAPERON_DIR" ]] && rm -rf "$_CHAPERON_DIR"
    exit 0
fi

# Start chaperon in background (opens FIFOs on its side)
if [[ -n "$_CHAPERON_DIR" ]]; then
    "$SCRIPT_DIR/chaperon/chaperon.sh" \
        "$_CHAPERON_DIR" "$PROJECT_DIR" "$SCRIPT_DIR/sandbox-exec.sh" &
    _CHAPERON_PID=$!
fi

# Close inherited file descriptors (3+) to prevent FD-based sandbox bypass.
# Open FDs from the parent process persist across exec and bypass filesystem
# isolation — a parent-opened FD to /etc/shadow would remain readable inside
# the sandbox even if the path is blocked.  Keep only stdin/stdout/stderr.
# EXCEPTION: the chaperon socketpair FD must survive into the sandbox.
if [[ -d /proc/self/fd ]]; then
    for _fd in /proc/self/fd/*; do
        _fd_num="${_fd##*/}"
        if [[ "$_fd_num" -gt 2 ]] 2>/dev/null; then
            eval "exec ${_fd_num}>&-" 2>/dev/null || true
        fi
    done
fi

backend_exec "$@"

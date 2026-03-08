#!/usr/bin/env bash
# bwrap-sandbox.sh — Run a command inside the bubblewrap sandbox
#
# Usage:
#   bwrap-sandbox.sh [OPTIONS] -- CMD [ARGS...]
#
# Options:
#   --project-dir DIR   Directory with write access (default: $PWD)
#   --dry-run           Print the bwrap command without executing
#   --help              Show this help
#
# Examples:
#   bwrap-sandbox.sh -- claude                     # start Claude Code sandboxed
#   bwrap-sandbox.sh -- bash                       # interactive shell
#   bwrap-sandbox.sh -- squeue --me                # single command
#   bwrap-sandbox.sh --project-dir ~/myproj -- bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/sandbox-lib.sh"

PROJECT_DIR=""
DRY_RUN=false

usage() {
    echo "Usage: bwrap-sandbox.sh [--project-dir DIR] [--dry-run] -- CMD [ARGS...]"
    echo ""
    echo "Options:"
    echo "  --project-dir DIR   Directory with write access (default: \$PWD)"
    echo "  --dry-run           Print the bwrap command without executing"
    echo "  --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  bwrap-sandbox.sh -- claude              # Claude Code in sandbox"
    echo "  bwrap-sandbox.sh -- bash                # interactive shell"
    echo "  bwrap-sandbox.sh --project-dir . -- cmd # explicit project dir"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-dir)
            PROJECT_DIR="$2"
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

# Default to current directory
if [[ -z "$PROJECT_DIR" ]]; then
    PROJECT_DIR="$(pwd)"
fi

# Resolve to absolute path
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

# Validate
if [[ ! -d "$PROJECT_DIR" ]]; then
    echo "Error: Project directory does not exist: $PROJECT_DIR" >&2
    exit 1
fi

validate_project_dir "$PROJECT_DIR"

if [[ $# -eq 0 ]]; then
    echo "Error: No command specified after --" >&2
    echo "Hint: bwrap-sandbox.sh -- bash       (interactive shell)" >&2
    echo "      bwrap-sandbox.sh -- claude      (Claude Code)" >&2
    exit 1
fi

# Build bwrap arguments
build_bwrap_args "$PROJECT_DIR"

if [[ "$DRY_RUN" == true ]]; then
    echo "# Sandbox command (dry run):"
    printf '%s \\\n' "$BWRAP"
    for arg in "${BWRAP_ARGS[@]}"; do
        printf '  %s \\\n' "$arg"
    done
    printf '  -- %s\n' "$*"
    exit 0
fi

exec "$BWRAP" "${BWRAP_ARGS[@]}" -- "$@"

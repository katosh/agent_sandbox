#!/usr/bin/env bash
# bwrap-sandbox.sh — Run a command inside the sandbox
#
# Backward-compatible entry point. Delegates to sandbox-exec.sh which
# auto-detects the best available backend (bwrap or landlock).
#
# To force a specific backend, use sandbox-exec.sh --backend <name>.
#
# Usage:
#   bwrap-sandbox.sh [OPTIONS] -- CMD [ARGS...]
#
# Options:
#   --project-dir DIR   Directory with write access (default: $PWD)
#   --dry-run           Print the sandbox command without executing
#   --help              Show this help

exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/sandbox-exec.sh" "$@"

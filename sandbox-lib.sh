#!/usr/bin/env bash
# sandbox-lib.sh — Core sandbox library (backend-agnostic)
#
# Sourced by sandbox-exec.sh, bwrap-sandbox.sh, sbatch-sandbox.sh, srun-sandbox.sh.
# Reads configuration from sandbox.conf, detects the best available backend,
# and provides:
#
#   detect_backend            — sets SANDBOX_BACKEND (bwrap or landlock)
#   validate_project_dir DIR  — checks DIR is allowed
#   backend_available         — can this backend work?
#   backend_prepare DIR       — set up the sandbox for DIR
#   backend_exec CMD...       — run CMD inside the sandbox (execs)
#   backend_dry_run CMD...    — print what would be run

set -euo pipefail

SANDBOX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_CONF="${SANDBOX_CONF:-$SANDBOX_DIR/sandbox.conf}"

# ── Defaults (overridden by sandbox.conf) ───────────────────────

ALLOWED_PROJECT_PARENTS=("/fh/fast" "/fh/scratch" "$HOME")

READONLY_MOUNTS=(
    "/usr" "/lib" "/lib64" "/bin" "/sbin" "/etc"
    "/app"
)

SCRATCH_MOUNTS=(
    "/fh/scratch/delete10"
    "/fh/scratch/delete30"
    "/fh/scratch/delete90"
)

DOTFILES_DIR=""

HOME_READONLY=(
    ".bashrc" ".bash_profile" ".profile"
    ".zshrc" ".zprofile"
    ".inputrc"
    ".gitconfig"
    ".vimrc" ".vim"
    ".tmux.conf"
    ".dircolors"
    ".pythonrc"
    ".linuxbrew"
    ".local/bin"
    ".local/share/jupyter"
    ".local/share/claude"
    ".cache/claude"
    ".cache/claude-cli-nodejs"
    "micromamba"
    ".condarc"
    ".mambarc"
)

HOME_SYMLINKS=()

HOME_WRITABLE=(
    ".claude"
    ".claude.json"
    ".local/state/claude"
    ".cache/uv"
)

BLOCKED_FILES=()

EXTRA_BLOCKED_PATHS=()

BLOCKED_ENV_VARS=(
    "GITHUB_PAT" "GITHUB_TOKEN" "GH_TOKEN"
    "OPENAI_API_KEY" "ANTHROPIC_API_KEY" "ZENODO_TOKEN" "HF_TOKEN"
    "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "AWS_SESSION_TOKEN"
    "ST_AUTH" "SW2_URL"
    "MUTT_EMAIL_ADDRESS" "MUTT_REALNAME" "MUTT_SMTP_URL"
    "KRB5CCNAME" "SSH_CLIENT" "SSH_CONNECTION" "SSH_TTY"
)

ALLOWED_CREDENTIALS=()

PASSTHROUGH_ENV_VARS=(
    BASH_ENV
    LMOD_CMD LMOD_DIR LMOD_PKG LMOD_ROOT LMOD_PACKAGE_PATH
    LMOD_VERSION LMOD_sys LMOD_COLORIZE
    MODULEPATH MODULEPATH_ROOT MODULESHOME
    LOADEDMODULES _LMFILES_
    LD_LIBRARY_PATH LIBRARY_PATH CPATH
    PKG_CONFIG_PATH CMAKE_PREFIX_PATH
    PYTHONPATH R_LIBS_SITE
    MAMBA_EXE MAMBA_ROOT_PREFIX
    CONDA_EXE CONDA_PREFIX CONDA_DEFAULT_ENV
    CONDA_SHLVL CONDA_PYTHON_EXE CONDA_PROMPT_MODIFIER
    _CE_CONDA _CE_M
    LANG LC_ALL SHELL USER LOGNAME EDITOR TERM
    MANPATH INFOPATH
    HOMEBREW_PREFIX HOMEBREW_CELLAR HOMEBREW_REPOSITORY
)

# ── Load user config ────────────────────────────────────────────

if [[ -f "$SANDBOX_CONF" ]]; then
    # shellcheck disable=SC1090
    source "$SANDBOX_CONF"
fi

# ── Helpers ─────────────────────────────────────────────────────

validate_project_dir() {
    local dir="$1"
    for parent in "${ALLOWED_PROJECT_PARENTS[@]}"; do
        parent="${parent/\$HOME/$HOME}"
        if [[ "$dir" == "$parent"* ]]; then
            return 0
        fi
    done
    echo "Error: Project directory not under an allowed parent path." >&2
    echo "  Got: $dir" >&2
    echo "  Allowed prefixes: ${ALLOWED_PROJECT_PARENTS[*]}" >&2
    echo "  Edit ALLOWED_PROJECT_PARENTS in $SANDBOX_CONF to allow more." >&2
    return 1
}

# ── Backend detection ───────────────────────────────────────────

# SANDBOX_BACKEND can be set in sandbox.conf or environment.
# Values: auto (picks best available), bwrap, landlock
SANDBOX_BACKEND="${SANDBOX_BACKEND:-auto}"

detect_backend() {
    if [[ "$SANDBOX_BACKEND" != "auto" ]]; then
        # User explicitly requested a backend
        if [[ ! -f "$SANDBOX_DIR/backends/${SANDBOX_BACKEND}.sh" ]]; then
            echo "Error: Unknown backend '$SANDBOX_BACKEND'" >&2
            echo "  Available: bwrap, landlock" >&2
            exit 1
        fi
        # shellcheck disable=SC1090
        source "$SANDBOX_DIR/backends/${SANDBOX_BACKEND}.sh"
        if ! backend_available; then
            echo "Error: Requested backend '$SANDBOX_BACKEND' is not available on this system." >&2
            exit 1
        fi
        return
    fi

    # Auto-detect: try bwrap first (mount namespace), then landlock (LSM)
    # shellcheck disable=SC1090
    source "$SANDBOX_DIR/backends/bwrap.sh"
    if backend_available; then
        SANDBOX_BACKEND=bwrap
        return
    fi

    # shellcheck disable=SC1090
    source "$SANDBOX_DIR/backends/landlock.sh"
    if backend_available; then
        SANDBOX_BACKEND=landlock
        return
    fi

    echo "Error: No sandbox backend available." >&2
    echo "" >&2
    echo "  Tried:" >&2
    echo "    bwrap    — not found or user namespaces blocked (AppArmor?)" >&2
    echo "    landlock — not available (kernel < 5.13 or Landlock disabled)" >&2
    echo "" >&2
    echo "  Install bubblewrap:  brew install bubblewrap" >&2
    echo "  Or ensure kernel ≥ 5.13 with Landlock enabled." >&2
    exit 1
}

# ── Legacy compatibility ────────────────────────────────────────
# These functions are kept so that existing code that sources sandbox-lib.sh
# and calls build_bwrap_args() directly (e.g., srun-sandbox.sh) still works.
# New code should use detect_backend + backend_prepare + backend_exec.

# Detect on source if not already done (for scripts that source sandbox-lib.sh
# and immediately call build_bwrap_args).
_BACKEND_DETECTED=false

build_bwrap_args() {
    if [[ "$_BACKEND_DETECTED" == false ]]; then
        detect_backend
        _BACKEND_DETECTED=true
    fi
    backend_prepare "$1"
}

# Expose BWRAP for legacy callers (resolved by bwrap backend)
# This is a no-op if landlock backend is loaded.

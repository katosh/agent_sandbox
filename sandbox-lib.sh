#!/usr/bin/env bash
# sandbox-lib.sh — Core bwrap argument builder
#
# Sourced by bwrap-sandbox.sh, sbatch-sandbox.sh, srun-sandbox.sh.
# Reads configuration from sandbox.conf, then provides:
#
#   build_bwrap_args PROJECT_DIR   — populates the BWRAP_ARGS array
#   BWRAP                          — resolved path to the bwrap binary
#   validate_project_dir DIR       — checks DIR is allowed

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

DOTFILES_DIR="$HOME/.dotfiles"

HOME_READONLY=(
    ".dotfiles"
    ".linuxbrew"
    ".local/bin"
    ".local/share/jupyter"
    "micromamba"
    ".condarc"
    ".mambarc"
)

HOME_SYMLINKS=(
    ".gitconfig"
    ".vimrc"
    ".zshrc"
    ".dircolors"
    ".tmux.conf"
    ".vim"
    ".pythonrc"
)

HOME_WRITABLE=(
    ".claude"
)

BLOCKED_FILES=(
    # Claude's own auth token is not blocked — it needs this to function.
    # Add files here to block specific items inside writable directories.
)

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

# ── Load user config ────────────────────────────────────────────

if [[ -f "$SANDBOX_CONF" ]]; then
    # shellcheck disable=SC1090
    source "$SANDBOX_CONF"
fi

# ── Resolve bwrap binary ────────────────────────────────────────

if [[ -n "${BWRAP:-}" ]]; then
    : # user override
elif command -v bwrap &>/dev/null; then
    BWRAP="$(command -v bwrap)"
else
    BWRAP="$HOME/.linuxbrew/bin/bwrap"
fi

if [[ ! -x "$BWRAP" ]]; then
    echo "Error: bwrap not found at $BWRAP" >&2
    echo "Install it:  brew install bubblewrap" >&2
    exit 1
fi

# ── Helpers ─────────────────────────────────────────────────────

validate_project_dir() {
    local dir="$1"
    for parent in "${ALLOWED_PROJECT_PARENTS[@]}"; do
        # Expand $HOME in parent
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

# ── Main builder ────────────────────────────────────────────────

# build_bwrap_args PROJECT_DIR
#   Populates the global BWRAP_ARGS array with all bwrap flags.
build_bwrap_args() {
    local project_dir="${1:?build_bwrap_args requires PROJECT_DIR}"
    BWRAP_ARGS=()

    # --- Kernel filesystems ---
    BWRAP_ARGS+=(--proc /proc)
    BWRAP_ARGS+=(--dev /dev)
    BWRAP_ARGS+=(--tmpfs /tmp)

    # --- Read-only system mounts ---
    for mount in "${READONLY_MOUNTS[@]}"; do
        if [[ -d "$mount" || -f "$mount" ]]; then
            BWRAP_ARGS+=(--ro-bind "$mount" "$mount")
        fi
    done

    # --- Blank home, then selectively re-mount ---
    # This is the core security mechanism: everything in $HOME is hidden,
    # then only safe subdirectories are added back.
    BWRAP_ARGS+=(--tmpfs "$HOME")

    # Read-only home subdirectories
    for subdir in "${HOME_READONLY[@]}"; do
        local full_path="$HOME/$subdir"
        if [[ -e "$full_path" ]]; then
            BWRAP_ARGS+=(--ro-bind "$full_path" "$full_path")
        fi
    done

    # Dotfile symlinks (only if dotfiles dir is set and exists)
    if [[ -n "$DOTFILES_DIR" && -d "$DOTFILES_DIR" ]]; then
        for name in "${HOME_SYMLINKS[@]}"; do
            if [[ -e "$DOTFILES_DIR/$name" ]]; then
                BWRAP_ARGS+=(--symlink "$DOTFILES_DIR/$name" "$HOME/$name")
            fi
        done
    fi

    # Writable home subdirectories
    for subdir in "${HOME_WRITABLE[@]}"; do
        local full_path="$HOME/$subdir"
        if [[ -d "$full_path" ]]; then
            BWRAP_ARGS+=(--bind "$full_path" "$full_path")
        fi
    done

    # Protect the sandbox scripts from modification inside the sandbox.
    # This overlays the writable ~/.claude bind with a read-only mount
    # for the sandbox directory, preventing the agent from tampering with
    # the wrapper scripts or config.
    BWRAP_ARGS+=(--ro-bind "$SANDBOX_DIR" "$SANDBOX_DIR")

    # Block specific files (overlay with /dev/null)
    for blocked in "${BLOCKED_FILES[@]}"; do
        blocked="${blocked/\$HOME/$HOME}"
        if [[ -e "$blocked" ]]; then
            BWRAP_ARGS+=(--ro-bind /dev/null "$blocked")
        fi
    done

    # --- CLAUDE.md overlay: inject sandbox instructions ---
    # Merges the user's real CLAUDE.md with sandbox-specific instructions
    # so the agent knows its restrictions. Only visible inside the sandbox.
    local claude_md_overlay="$SANDBOX_DIR/.claude-md-overlay"
    local sandbox_snippet="$SANDBOX_DIR/sandbox-claude.md"
    local claude_md_path="$HOME/.claude/CLAUDE.md"

    # Resolve symlink to find the actual file (for reading and for
    # determining the correct overlay target inside the sandbox)
    local claude_md_resolved="$claude_md_path"
    if [[ -L "$claude_md_path" ]]; then
        claude_md_resolved="$(readlink -f "$claude_md_path")"
    fi

    if [[ -f "$sandbox_snippet" ]]; then
        {
            if [[ -f "$claude_md_resolved" ]]; then
                cat "$claude_md_resolved"
            fi
            cat "$sandbox_snippet"
        } > "$claude_md_overlay"
        # Overlay the resolved target (not the symlink) so bwrap can bind it
        BWRAP_ARGS+=(--ro-bind "$claude_md_overlay" "$claude_md_resolved")
    fi

    # --- Scratch filesystems (read-only) ---
    for scratch in "${SCRATCH_MOUNTS[@]}"; do
        if [[ -d "$scratch" ]]; then
            BWRAP_ARGS+=(--ro-bind "$scratch" "$scratch")
        fi
    done

    # --- Extra blocked paths (overlaid with empty tmpfs) ---
    for blocked in "${EXTRA_BLOCKED_PATHS[@]}"; do
        if [[ -d "$blocked" ]]; then
            BWRAP_ARGS+=(--tmpfs "$blocked")
        fi
    done

    # --- Project directory: read-write overlay ---
    # This must come AFTER the read-only mount of its parent filesystem
    # so it overlays correctly.
    BWRAP_ARGS+=(--bind "$project_dir" "$project_dir")

    # --- Runtime: munge socket for Slurm auth ---
    BWRAP_ARGS+=(--dev-bind /run /run)
    if [[ -L /var/run ]]; then
        BWRAP_ARGS+=(--symlink /run /var/run)
    elif [[ -d /var/run ]]; then
        BWRAP_ARGS+=(--dev-bind /var/run /var/run)
    fi

    # --- Cleanup & working directory ---
    BWRAP_ARGS+=(--die-with-parent)
    BWRAP_ARGS+=(--chdir "$project_dir")

    # --- Environment: pass through useful vars ---
    BWRAP_ARGS+=(--setenv HOME "$HOME")
    BWRAP_ARGS+=(--setenv SANDBOX_ACTIVE 1)
    BWRAP_ARGS+=(--setenv SANDBOX_PROJECT_DIR "$project_dir")

    # Pass through HPC / tool environment if set
    local passthrough_vars=(
        BASH_ENV
        LMOD_CMD LMOD_DIR LMOD_PKG LMOD_ROOT LMOD_PACKAGE_PATH
        LMOD_VERSION LMOD_sys LMOD_COLORIZE
        MODULEPATH MODULEPATH_ROOT MODULESHOME
        MAMBA_EXE MAMBA_ROOT_PREFIX
        LANG LC_ALL SHELL USER LOGNAME EDITOR TERM
        MANPATH INFOPATH
        HOMEBREW_PREFIX HOMEBREW_CELLAR HOMEBREW_REPOSITORY
    )
    for var in "${passthrough_vars[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            BWRAP_ARGS+=(--setenv "$var" "${!var}")
        fi
    done

    # Prepend sandbox bin dir to PATH so that sbatch/srun resolve to the
    # sandbox wrappers by default. The wrappers call /usr/bin/sbatch and
    # /usr/bin/srun internally, avoiding recursion.
    BWRAP_ARGS+=(--setenv PATH "$SANDBOX_DIR/bin:${PATH}")

    # --- Block dangerous env vars ---
    for var in "${BLOCKED_ENV_VARS[@]}"; do
        BWRAP_ARGS+=(--unsetenv "$var")
    done

    # --- Allow specific credentials back through ---
    # (must come AFTER the block loop to override)
    for var in "${ALLOWED_CREDENTIALS[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            BWRAP_ARGS+=(--setenv "$var" "${!var}")
        fi
    done
}

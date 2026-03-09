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
    ".local/state/claude"
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
    ".cache/uv"
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

PASSTHROUGH_ENV_VARS=(
    # lmod infrastructure
    BASH_ENV
    LMOD_CMD LMOD_DIR LMOD_PKG LMOD_ROOT LMOD_PACKAGE_PATH
    LMOD_VERSION LMOD_sys LMOD_COLORIZE
    MODULEPATH MODULEPATH_ROOT MODULESHOME
    # lmod loaded-module state
    LOADEDMODULES _LMFILES_
    LD_LIBRARY_PATH LIBRARY_PATH CPATH
    PKG_CONFIG_PATH CMAKE_PREFIX_PATH
    PYTHONPATH R_LIBS_SITE
    # Conda / Mamba
    MAMBA_EXE MAMBA_ROOT_PREFIX
    CONDA_EXE CONDA_PREFIX CONDA_DEFAULT_ENV
    CONDA_SHLVL CONDA_PYTHON_EXE CONDA_PROMPT_MODIFIER
    _CE_CONDA _CE_M
    # Shell basics
    LANG LC_ALL SHELL USER LOGNAME EDITOR TERM
    MANPATH INFOPATH
    # Homebrew
    HOMEBREW_PREFIX HOMEBREW_CELLAR HOMEBREW_REPOSITORY
)

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

# Internal path where real Slurm binaries are mounted inside the
# sandbox.  Intentionally obscure and outside any PATH so the agent
# cannot accidentally call the unsandboxed binaries.  Referenced by
# sbatch-sandbox.sh and srun-sandbox.sh when SANDBOX_ACTIVE=1.
SLURM_REAL_DIR="/tmp/.sandbox-slurm-real"

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

    # --- Slurm binary isolation ---
    # Mount real sbatch/srun at an obscure internal path, then overlay
    # the originals in /usr/bin with small redirector scripts.  This
    # prevents the agent from bypassing the wrappers by calling
    # /usr/bin/sbatch or /usr/bin/srun directly.
    #
    # We generate dedicated overlay scripts (not reusing bin/) because
    # bin/sbatch uses a relative path that only works from $SANDBOX_DIR/bin.
    for bin in sbatch srun; do
        if [[ -x "/usr/bin/$bin" ]]; then
            local overlay="$SANDBOX_DIR/.${bin}-overlay"
            cat > "$overlay" <<SLURM_EOF
#!/usr/bin/env bash
exec "$SANDBOX_DIR/${bin}-sandbox.sh" "\$@"
SLURM_EOF
            chmod +x "$overlay"
            BWRAP_ARGS+=(--ro-bind "/usr/bin/$bin" "$SLURM_REAL_DIR/$bin")
            BWRAP_ARGS+=(--ro-bind "$overlay" "/usr/bin/$bin")
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

    # Writable home subdirectories (and files)
    for subdir in "${HOME_WRITABLE[@]}"; do
        local full_path="$HOME/$subdir"
        if [[ -e "$full_path" ]]; then
            BWRAP_ARGS+=(--bind "$full_path" "$full_path")
        fi
    done

    # Protect the sandbox scripts from modification inside the sandbox.
    # This overlays the writable ~/.claude bind with a read-only mount
    # for the sandbox directory, preventing the agent from tampering with
    # the wrapper scripts or config.
    BWRAP_ARGS+=(--ro-bind "$SANDBOX_DIR" "$SANDBOX_DIR")

    # --- CLAUDE.md overlay: inject sandbox instructions ---
    # Merges the user's real CLAUDE.md with sandbox-specific instructions
    # so the agent knows its restrictions. Only visible inside the sandbox.
    #
    # This must come BEFORE --remount-ro $HOME because if CLAUDE.md is a
    # symlink (e.g. via a dotfiles manager), bwrap needs to create
    # intermediate directories at the symlink target — which requires
    # the $HOME tmpfs to still be writable.
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
        # Ensure the target file exists so bwrap can bind onto it.
        # Creates an empty CLAUDE.md if the user doesn't have one yet —
        # harmless, and avoids bwrap creating an opaque mount-point file.
        [[ -f "$claude_md_resolved" ]] || touch "$claude_md_resolved"
        # Overlay the resolved target (not the symlink) so bwrap can bind it
        BWRAP_ARGS+=(--ro-bind "$claude_md_overlay" "$claude_md_resolved")
    fi

    # --- Settings overlay: inject sandbox permissions ---
    # Merges the user's settings.json with sandbox-specific permission
    # rules so that tools already restricted by bwrap (Bash, Edit, Write,
    # etc.) are auto-allowed without prompting.
    #
    # Same ordering requirement as CLAUDE.md — must precede --remount-ro.
    local settings_overlay="$SANDBOX_DIR/.settings-overlay"
    local sandbox_settings="$SANDBOX_DIR/sandbox-settings.json"
    local user_settings="$HOME/.claude/settings.json"

    # Resolve symlink (same reason as CLAUDE.md — bwrap can't mount
    # over a symlink, so we target the resolved path directly)
    local user_settings_resolved="$user_settings"
    if [[ -L "$user_settings" ]]; then
        user_settings_resolved="$(readlink -f "$user_settings")"
    fi

    if [[ -f "$sandbox_settings" ]]; then
        # Ensure target exists so bwrap can bind onto it.
        # Creates a minimal settings.json if the user doesn't have one yet.
        [[ -f "$user_settings_resolved" ]] || echo '{}' > "$user_settings_resolved"

        # Merge: keep all user settings, add sandbox allow rules
        python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        user = json.load(f)
except (ValueError, IOError):
    user = {}
with open(sys.argv[2]) as f:
    sandbox = json.load(f)
user.setdefault('permissions', {})
existing = user['permissions'].get('allow', [])
for rule in sandbox.get('permissions', {}).get('allow', []):
    if rule not in existing:
        existing.append(rule)
user['permissions']['allow'] = existing
json.dump(user, sys.stdout, indent=2)
" "$user_settings_resolved" "$sandbox_settings" > "$settings_overlay"

        BWRAP_ARGS+=(--ro-bind "$settings_overlay" "$user_settings_resolved")
    fi

    # Now that all HOME mounts/symlinks are in place, remount the tmpfs
    # base read-only so stray writes to $HOME fail loudly instead of
    # silently succeeding on ephemeral tmpfs. The bind mounts above
    # remain unaffected since --remount-ro is non-recursive.
    BWRAP_ARGS+=(--remount-ro "$HOME")

    # Block specific files (overlay with /dev/null)
    for blocked in "${BLOCKED_FILES[@]}"; do
        blocked="${blocked/\$HOME/$HOME}"
        if [[ -e "$blocked" ]]; then
            BWRAP_ARGS+=(--ro-bind /dev/null "$blocked")
        fi
    done

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
    for var in "${PASSTHROUGH_ENV_VARS[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            BWRAP_ARGS+=(--setenv "$var" "${!var}")
        fi
    done

    # Prepend sandbox bin dir to PATH so that sbatch/srun resolve to the
    # sandbox wrappers by default. The wrappers call the relocated real
    # binaries at $SLURM_REAL_DIR internally, avoiding recursion.
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

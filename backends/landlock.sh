#! /bin/bash --
# backends/landlock.sh — Landlock LSM sandbox backend
#
# Provides: backend_available, backend_name, backend_prepare, backend_exec
# Sourced by sandbox-lib.sh — has access to all config arrays.
#
# Landlock restricts filesystem access at the kernel level without needing
# user namespaces. This makes it work on Ubuntu 24.04 where AppArmor blocks
# unprivileged user namespace creation (which bwrap requires).
#
# Key differences from bwrap:
#   - Blocked paths return EACCES (not ENOENT) — functionally equivalent
#   - No mount namespace — cannot overlay files or relocate binaries.
#     This means:
#       * Slurm wrapping relies on PATH shadowing only — the real
#         /usr/bin/sbatch and /usr/bin/srun remain directly callable.
#       * Sandbox self-protection not possible — Landlock rules are
#         additive, so can't make a subdir read-only when parent is
#         writable. An agent could modify sandbox scripts to weaken
#         future sessions or submitted Slurm jobs.
#     See ADMIN_HARDENING.md §2 for mitigations.
#   - Cannot block Unix socket connect() — Landlock controls file
#     operations but not AF_UNIX socket connections. If systemd user
#     instances are running, systemd-run --user can escape the sandbox.
#     See ADMIN_HARDENING.md §0 for the fix (disable user@.service).
#   - CLAUDE.md/settings.json merging handled by prepare_config_dir() in
#     sandbox-lib.sh (CLAUDE_CONFIG_DIR per-session directory)
#   - Environment filtering done in shell (not via bwrap --unsetenv/--setenv)

LANDLOCK_SANDBOX="$SANDBOX_DIR/backends/landlock-sandbox.py"

# ── Backend interface ────────────────────────────────────────────

backend_available() {
    [[ "$(uname -s)" == "Linux" ]] || return 1
    command -v python3 &>/dev/null || return 1
    python3 "$LANDLOCK_SANDBOX" --check &>/dev/null
}

backend_name() {
    echo "landlock"
}

backend_prepare() {
    local project_dir="$1"
    _LANDLOCK_PROJECT_DIR="$project_dir"

    # CLAUDE.md and settings.json overlays are handled by prepare_config_dir()
    # in sandbox-lib.sh (sets CLAUDE_CONFIG_DIR to a per-session directory).

    # --- Build landlock-sandbox.py arguments ---
    LANDLOCK_ARGS=()

    # Read-only system mounts
    for mount in "${READONLY_MOUNTS[@]}"; do
        if [[ -d "$mount" ]]; then
            LANDLOCK_ARGS+=(--ro "$mount")
        fi
    done

    # Kernel/virtual filesystems
    for vfs in /proc /dev /tmp; do
        [[ -d "$vfs" ]] && LANDLOCK_ARGS+=(--rw "$vfs")
    done

    # Selectively grant /run subdirs — granting all of /run exposes
    # D-Bus and systemd user sockets, allowing sandbox escape via
    # systemd-run --user.
    [[ -d /run/munge ]]            && LANDLOCK_ARGS+=(--ro /run/munge)
    [[ -d /run/nscd ]]             && LANDLOCK_ARGS+=(--ro /run/nscd)
    [[ -d /run/systemd/resolve ]]  && LANDLOCK_ARGS+=(--ro /run/systemd/resolve)

    # Read-only home paths (files and directories)
    for subdir in "${HOME_READONLY[@]}"; do
        local full_path="$HOME/$subdir"
        if [[ -e "$full_path" ]]; then
            LANDLOCK_ARGS+=(--ro "$full_path")
        fi
    done

    # Writable home paths (files and directories)
    for subdir in "${HOME_WRITABLE[@]}"; do
        local full_path="$HOME/$subdir"
        if [[ -e "$full_path" ]]; then
            LANDLOCK_ARGS+=(--rw "$full_path")
        fi
    done


    # Project directory: writable
    LANDLOCK_ARGS+=(--rw "$project_dir")

    # Additional writable directories
    for _extra_rw in "${EXTRA_WRITABLE_PATHS[@]}"; do
        [[ -d "$_extra_rw" ]] && LANDLOCK_ARGS+=(--rw "$_extra_rw")
    done

    # --- Filter environment variables ---
    for var in "${BLOCKED_ENV_VARS[@]}"; do
        unset "$var" 2>/dev/null || true
    done

    # Also block any SSH_* vars not in the explicit blocklist
    while IFS='=' read -r name _; do
        [[ "$name" == SSH_* ]] && unset "$name" 2>/dev/null || true
    done < <(env)

    # Set sandbox env vars
    export SANDBOX_ACTIVE=1
    export SANDBOX_BACKEND=landlock
    export SANDBOX_PROJECT_DIR="$project_dir"
    export PATH="$SANDBOX_DIR/bin:${PATH}"
}

backend_exec() {
    python3 "$LANDLOCK_SANDBOX" "${LANDLOCK_ARGS[@]}" -- "$@"
    exit $?
}

backend_dry_run() {
    echo "# Backend: landlock"
    echo "# Helper: $LANDLOCK_SANDBOX"
    printf 'python3 %s \\\n' "$LANDLOCK_SANDBOX"
    for arg in "${LANDLOCK_ARGS[@]}"; do
        printf '  %s \\\n' "$arg"
    done
    printf '  -- %s\n' "$*"
}

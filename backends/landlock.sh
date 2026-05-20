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
#       * Munge socket is also accessible (Landlock cannot block
#         AF_UNIX connect), so agents can bypass chaperon entirely.
#         SPANK plugin enforcement (docs/admin/hardening.md §1) is mandatory.
#       * Sandbox self-protection not possible — Landlock rules are
#         additive, so can't make a subdir read-only when parent is
#         writable. An agent could modify sandbox scripts to weaken
#         future sessions or submitted Slurm jobs.
#     See docs/admin/hardening.md §2 for mitigations.
#   - Cannot block Unix socket connect() — Landlock controls file
#     operations but not AF_UNIX socket connections. If systemd user
#     instances are running, systemd-run --user can escape the sandbox.
#     See docs/admin/hardening.md §0 for the fix (disable user@.service).
#   - Agent config merging handled by prepare_agent_configs() in sandbox-lib.sh
#   - Environment filtering done in shell (not via bwrap --unsetenv/--setenv)

LANDLOCK_SANDBOX="$SANDBOX_DIR/backends/landlock-sandbox.py"

# ── Backend interface ────────────────────────────────────────────

backend_available() {
    [[ "$(uname -s)" == "Linux" ]] || return 1
    command -v python3 &>/dev/null || return 1
    # Pass the ABI floor through to --check so a stale-kernel host is
    # rejected at backend selection (auto-detect path), not silently
    # selected and then bypassed at exec time.
    local _check_args=()
    _landlock_abi_args _check_args
    python3 "$LANDLOCK_SANDBOX" --check "${_check_args[@]}" &>/dev/null
}

# Build --required-abi / --hard-requirement (or --no-hard-requirement)
# CLI args from the LANDLOCK_REQUIRED_ABI / LANDLOCK_HARD_REQUIREMENT env
# vars. Out-param is an array variable name.
_landlock_abi_args() {
    local -n _out=$1
    if [[ -n "${LANDLOCK_REQUIRED_ABI:-}" ]]; then
        _out+=(--required-abi "$LANDLOCK_REQUIRED_ABI")
    fi
    if [[ -n "${LANDLOCK_HARD_REQUIREMENT:-}" ]]; then
        if _is_true "$LANDLOCK_HARD_REQUIREMENT"; then
            _out+=(--hard-requirement)
        else
            _out+=(--no-hard-requirement)
        fi
    fi
}

backend_name() {
    echo "landlock"
}

backend_prepare() {
    local project_dir="$1"
    _LANDLOCK_PROJECT_DIR="$project_dir"

    # Agent config overlays are handled by prepare_agent_configs() in sandbox-lib.sh.

    # --- Network filter ---
    # Landlock has neither a mount nor a network namespace, so the only
    # mode it can actually deliver is 'open'. The resolver applies the
    # configured fallback policy: 'stricter' fails (nothing stricter than
    # 'open' is possible on landlock); 'open' falls back silently to open
    # with a loud warning; 'strict' fails. The user picks the policy.
    resolve_network_filter_mode landlock

    # --- Build landlock-sandbox.py arguments ---
    LANDLOCK_ARGS=()

    # ABI floor: refuse (or warn) on stale-kernel hosts where the policy's
    # expected capabilities aren't advertised. Defaults to hard / v3
    # inside the helper; LANDLOCK_REQUIRED_ABI and LANDLOCK_HARD_REQUIREMENT
    # in sandbox.conf override.
    _landlock_abi_args LANDLOCK_ARGS

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
    #
    # WARNING: Munge socket (/run/munge) is NOT granted, but this does
    # NOT block access. Landlock cannot restrict AF_UNIX connect() —
    # path resolution during connect() bypasses Landlock filesystem
    # rules entirely. A sandboxed process can connect to
    # /run/munge/munge.socket.2, forge credentials, and call
    # /usr/bin/sbatch directly (also not blockable without mount
    # namespace). The chaperon is bypassed completely on Landlock.
    # docs/admin/hardening.md §1 (SPANK plugin) is MANDATORY for Landlock
    # deployments with Slurm.
    [[ -d /run/nscd ]]             && LANDLOCK_ARGS+=(--ro /run/nscd)
    [[ -d /run/systemd/resolve ]]  && LANDLOCK_ARGS+=(--ro /run/systemd/resolve)

    # --- Home directory ---
    if [[ "${HOME_ACCESS:-restricted}" == "restricted" || "${HOME_ACCESS}" == "tmpwrite" ]]; then
        # tmpwrite note: Landlock has no tmpfs — falls back to restricted
        # (only listed paths accessible). Use bwrap/firejail for tmpwrite.

        # HOME_SEEDED_FILES degrades to read-only on Landlock. Without
        # a mount namespace there's no tmpfs HOME to seed into — granting
        # writable access would let modifications hit the real host file.
        # Warn once and treat each seeded entry as HOME_READONLY.
        local _landlock_seeded_relpaths=()
        local seedf
        for seedf in "${HOME_SEEDED_FILES[@]}"; do
            [[ -f "$HOME/$seedf" ]] || continue
            _landlock_seeded_relpaths+=("$seedf")
        done
        if [[ ${#_landlock_seeded_relpaths[@]} -gt 0 ]] && ! _is_true "${SANDBOX_QUIET:-false}"; then
            echo "sandbox: landlock backend does not support HOME_SEEDED_FILES — bound read-only:" >&2
            local _r
            for _r in "${_landlock_seeded_relpaths[@]}"; do
                echo "  ~/$_r" >&2
            done
        fi

        # Grant individual paths only
        for subdir in "${HOME_READONLY[@]}"; do
            # Don't double-grant when the same entry is also seeded
            local _is_seeded=false
            local _s
            for _s in "${_landlock_seeded_relpaths[@]}"; do
                [[ "$subdir" == "$_s" ]] && { _is_seeded=true; break; }
            done
            $_is_seeded && continue
            local full_path="$HOME/$subdir"
            if [[ -e "$full_path" ]]; then
                LANDLOCK_ARGS+=(--ro "$full_path")
            fi
        done

        # Seeded entries — granted read-only (degradation; see warning above).
        for subdir in "${_landlock_seeded_relpaths[@]}"; do
            LANDLOCK_ARGS+=(--ro "$HOME/$subdir")
        done

        for subdir in "${HOME_WRITABLE[@]}"; do
            local full_path="$HOME/$subdir"
            if [[ -e "$full_path" ]]; then
                LANDLOCK_ARGS+=(--rw "$full_path")
            fi
        done
    else
        # read/write: grant full HOME
        # NOTE: Landlock cannot hide subdirs (.ssh, .aws, .gnupg) when
        # the parent directory is already granted — rules are additive.
        echo "sandbox: note: HOME_ACCESS=${HOME_ACCESS} with landlock cannot hide ~/.ssh, ~/.aws, ~/.gnupg (Landlock limitation)" >&2
        if [[ "${HOME_ACCESS}" == "read" ]]; then
            LANDLOCK_ARGS+=(--ro "$HOME")
            for subdir in "${HOME_WRITABLE[@]}"; do
                local full_path="$HOME/$subdir"
                [[ -e "$full_path" ]] && LANDLOCK_ARGS+=(--rw "$full_path")
            done
        else
            LANDLOCK_ARGS+=(--rw "$HOME")
        fi
    fi

    # Sandbox scripts directory: read-only (for chaperon stubs, bin/, etc.)
    LANDLOCK_ARGS+=(--ro "$SANDBOX_DIR")

    # Project directory: writable
    LANDLOCK_ARGS+=(--rw "$project_dir")

    # Additional writable directories
    for _extra_rw in "${EXTRA_WRITABLE_PATHS[@]}"; do
        [[ -d "$_extra_rw" ]] && LANDLOCK_ARGS+=(--rw "$_extra_rw")
    done

    # --- Filter environment variables ---
    _warn_pattern_blocked_vars
    for var in "${BLOCKED_ENV_VARS[@]}"; do
        _is_allowed_env "$var" || unset "$var" 2>/dev/null || true
    done

    # Block credential-pattern vars (SSH_*, *_TOKEN, CI_*, etc.) from BLOCKED_ENV_PATTERNS.
    # To let a specific variable through, add it to ALLOWED_ENV_VARS.
    while IFS='=' read -r name _; do
        _is_blocked_by_pattern "$name" && { unset "$name" 2>/dev/null || true; } || true
    done < <(env)

    # Agent sandbox-config directories: landlock has no mount namespace,
    # so the real host path must be granted readable so the agent can
    # read the merged CLAUDE.md / settings.json. Overlay.sh merges these
    # host-side before the sandbox starts, so read-only suffices.
    for _agent_dir in "${_AGENT_SANDBOX_CONFIG_DIRS[@]:-}"; do
        if [[ -n "$_agent_dir" && -d "$_agent_dir" ]]; then
            LANDLOCK_ARGS+=(--ro "$_agent_dir")
        fi
    done

    # Agent-specific environment exports (e.g., CLAUDE_CONFIG_DIR)
    for _agent_export in "${_AGENT_ENV_EXPORTS[@]}"; do
        export "$_agent_export"
    done

    # Set sandbox env vars
    export SANDBOX_ACTIVE=1
    export SANDBOX_BACKEND=landlock
    export SANDBOX_PROJECT_DIR="$project_dir"
    # Prepend chaperon stubs to PATH (before bin/ for sbatch/srun override)
    export PATH="$SANDBOX_DIR/chaperon/stubs:$SANDBOX_DIR/bin:${PATH}"

    # Pass chaperon FIFO directory into the sandbox (needs write for response FIFOs)
    if [[ -n "${_CHAPERON_FIFO_DIR:-}" && -d "${_CHAPERON_FIFO_DIR:-}" ]]; then
        LANDLOCK_ARGS+=(--rw "$_CHAPERON_FIFO_DIR")
        export _CHAPERON_FIFO_DIR
    fi

    # .sandbox-state/ — chaperon-owned state subdir. On bwrap/firejail
    # this gets a RO overlay to defend slurmstepd's open(--output)
    # against in-sandbox symlink-plant. Landlock cannot make a subtree
    # RO under a writable parent (additive-rules limitation), so the
    # symlink-plant defense is unavailable here. The chaperon-side
    # handler detects $SANDBOX_BACKEND=landlock and disables the
    # path-transformation feature entirely (no transformation, no
    # symlink, no chaperon log under .sandbox-state). One-time warning
    # so operators on landlock know about the missing defense.
    local _state_dir="$project_dir/.sandbox-state"
    if [[ -d "$_state_dir" ]] && ! _is_true "${SANDBOX_QUIET:-false}"; then
        echo "sandbox: NOTE — .sandbox-state/ exists at '$_state_dir' but landlock cannot RO-overlay it." >&2
        echo "  Slurm --output / --error path-transformation feature is disabled on landlock." >&2
        echo "  Use bwrap or firejail backend for the symlink-plant defense against slurmstepd." >&2
    fi

}

backend_exec() {
    # Fork bomb defense-in-depth: set per-UID RLIMIT_NPROC before exec.
    if [[ -n "${SANDBOX_NPROC_LIMIT:-}" ]]; then
        ulimit -u "$SANDBOX_NPROC_LIMIT" 2>/dev/null || true
    fi

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

#! /bin/bash --
# backends/firejail.sh — Firejail sandbox backend
#
# Provides: backend_available, backend_name, backend_prepare, backend_exec
# Sourced by sandbox-lib.sh — has access to all config arrays.
#
# Firejail is a setuid-root SUID sandbox that uses Linux namespaces and
# seccomp-bpf. It works even when AppArmor blocks unprivileged user
# namespaces (which bwrap requires) and provides stronger isolation than
# Landlock:
#
#   - Mount namespace: hides files (ENOENT, like bwrap, not EACCES like Landlock)
#   - PID namespace: isolated by default (no extra flag needed)
#   - Network namespace: --net=none or --netfilter restricts network access
#   - Seccomp: built-in filter (--seccomp)
#   - Unix socket isolation: mount namespace hides /run/user sockets
#     (Landlock cannot block AF_UNIX connect)
#
# Key differences from bwrap:
#   - Uses --whitelist/--read-only/--blacklist instead of --bind/--ro-bind
#   - Uses --private-cwd=DIR instead of --chdir
#   - Uses --noprofile to ignore system-wide Firejail profiles
#   - Slurm wrapping via PATH shadowing (like landlock)
#   - PID namespace is always on (no --unshare-pid flag)
#
# Key differences from landlock:
#   - Full mount namespace — can hide files, overlay binaries
#   - Can block Unix socket connect() (mount namespace hides sockets)
#   - Built-in seccomp (no custom BPF needed)
#   - Requires setuid binary (firejail) — not unprivileged like Landlock
#
# Known limitations:
#   - Firejail filters /etc/passwd, removing users with UIDs in the dynamic
#     allocation range (roughly 1000–64999 except the current user). If the
#     slurm user has a high UID (e.g., 64030), sbatch fails because it can't
#     resolve SlurmUser. Fix: assign slurm a system-range UID (< 1000):
#       sudo usermod -u 120 slurm && sudo groupmod -g 120 slurm
#   - Firejail's default seccomp blacklist does not include io_uring,
#     userfaultfd, or kexec. We add them via --seccomp.drop (matching the
#     Landlock and bwrap backends' seccomp filters). kexec is already
#     blocked by --caps.drop=all (requires CAP_SYS_BOOT), but seccomp
#     provides defense-in-depth.
#     Note: firejail 0.9.72 seccomp is broken on aarch64 (filter loads but
#     doesn't block). Works correctly on x86_64.
#
# Agent config merging (e.g., CLAUDE.md/settings.json) is handled by
# agent profiles via prepare_agent_configs() in sandbox-lib.sh.

# ── Backend interface ────────────────────────────────────────────

backend_available() {
    [[ "$(uname -s)" == "Linux" ]] || return 1
    command -v firejail &>/dev/null || return 1
    # Quick smoke test: can firejail run at all?
    firejail --noprofile -- true 2>/dev/null
}

backend_name() {
    echo "firejail"
}

backend_prepare() {
    local project_dir="$1"
    _FIREJAIL_PROJECT_DIR="$project_dir"

    # Agent config overlays are handled by prepare_agent_configs() in sandbox-lib.sh.

    # --- Build firejail arguments ---
    FIREJAIL_ARGS=(
        --noprofile
        --quiet
        --private-cwd="$project_dir"
        --caps.drop=all
        --nonewprivs
        --seccomp.drop=io_uring_setup,io_uring_enter,io_uring_register,userfaultfd,kexec_load,kexec_file_load
        --nosound
        --no3d
        --restrict-namespaces
        --allusers
        # --allusers: disable /etc/passwd filtering. Firejail removes UIDs
        # >= UID_MIN (typically 1000) from /etc/passwd inside the sandbox.
        # On HPC systems the slurm user often has a UID in that range (e.g.,
        # from LDAP), causing sbatch to fail when resolving SlurmUser. This
        # is safe because: /etc/passwd is world-readable anyway, --nonewprivs
        # prevents setuid escalation, and --whitelist already hides other
        # users' home directories via tmpfs.
        #
        # Note: --nogroups is intentionally omitted. HPC file access relies
        # on supplementary group membership (e.g., lab groups for /fh/fast/).
        # Dropping groups would silently break access to group-owned data.
    )

    # --private-tmp: isolate /tmp with a clean tmpfs.
    # Enabled by default for security (prevents cross-session /tmp leakage).
    # Disable via PRIVATE_TMP=false in sandbox.conf if MPI, NCCL, or other
    # multi-process frameworks need shared /tmp for inter-rank communication.
    if _is_true "${PRIVATE_TMP:-true}"; then
        FIREJAIL_ARGS+=(--private-tmp)
    fi

    # PID namespace is enabled by default in firejail (no flag needed).
    # --restrict-namespaces prevents the sandboxed process from creating
    # new namespaces to escape.

    # --- Filesystem isolation ---
    # Using --whitelist on $HOME paths automatically creates a tmpfs $HOME
    # and only exposes whitelisted entries. No --private needed.
    # --whitelist works under $HOME, /tmp, /opt, /srv, and /run.

    # Read-only system mounts — visible by default (firejail only isolates
    # $HOME via whitelist). Mark read-only explicitly for defense in depth.
    for mount in "${READONLY_MOUNTS[@]}"; do
        if [[ -d "$mount" || -f "$mount" ]]; then
            FIREJAIL_ARGS+=(--read-only="$mount")
        fi
    done

    # --- /run isolation ---
    # Firejail cannot blacklist /run entirely (it needs /run during setup).
    # Instead, blacklist the dangerous subdirectories that enable escape:
    #   - /run/dbus: D-Bus system bus
    #   - /run/user: systemd user sockets (systemd-run --user escape)
    #   - /run/systemd/private: systemd private socket
    #   - /run/containerd: container runtime socket
    for _run_danger in \
        /run/dbus /run/user /run/systemd/private /run/containerd \
        /run/snapd.socket /run/snapd-snap.socket \
        /run/systemd/notify \
        /run/lxd-installer.socket; do
        if [[ -e "$_run_danger" ]]; then
            FIREJAIL_ARGS+=(--blacklist="$_run_danger")
        fi
    done

    # Munge socket: BLOCKED inside sandbox (chaperon handles auth outside).
    # This is intentionally blocked even on compute nodes: exposing munge
    # would allow crafting arbitrary Slurm submissions that bypass the
    # chaperon and don't inherit sandbox restrictions.
    if [[ -e /run/munge ]]; then
        FIREJAIL_ARGS+=(--blacklist=/run/munge)
    fi

    # Slurm binaries: BLOCKED inside sandbox (chaperon stubs in PATH).
    # Block Slurm binaries (list derived from chaperon/stubs/ + defaults).
    _build_chaperon_blocked_binaries
    for _slurm_bin in "${CHAPERON_BLOCKED_BINARIES[@]}"; do
        if [[ -x "/usr/bin/$_slurm_bin" ]]; then
            FIREJAIL_ARGS+=(--blacklist="/usr/bin/$_slurm_bin")
        fi
    done

    # Slurm config (leaks controller address, enables direct Slurm access)
    for _slurm_conf in /etc/slurm /etc/slurm-llnl; do
        if [[ -d "$_slurm_conf" ]]; then
            FIREJAIL_ARGS+=(--blacklist="$_slurm_conf")
        fi
    done

    # /run/systemd/resolve remains accessible (DNS).

    # --- Passwd filtering (block NSS daemon sockets) ---
    # Blacklist sockets used by NSS daemons that proxy LDAP/AD queries:
    # nscd (caching), nslcd (LDAP), sssd (AD/LDAP/Kerberos).
    # Without these sockets, getent passwd returns only local users.
    if _is_true "${FILTER_PASSWD:-true}"; then
        for _nss_sock in /run/nscd /run/nslcd /var/run/nscd /var/run/nslcd \
                         /run/sssd /var/lib/sss/pipes; do
            if [[ -e "$_nss_sock" ]]; then
                FIREJAIL_ARGS+=(--blacklist="$_nss_sock")
            fi
        done
    fi

    # Nested firejail: --nonewprivs prevents the setuid binary from
    # gaining privileges, --restrict-namespaces blocks new namespace
    # creation, and --join is blocked by --shell=none. The nested
    # instance runs with fewer privileges than the parent sandbox.

    # --- Home directory paths ---
    if [[ "${HOME_ACCESS:-restricted}" == "restricted" || "${HOME_ACCESS}" == "tmpwrite" ]]; then
        # Whitelist mode: tmpfs $HOME, selectively mount listed paths
        for subdir in "${HOME_READONLY[@]}"; do
            local full_path="$HOME/$subdir"
            if [[ -e "$full_path" ]]; then
                FIREJAIL_ARGS+=(--whitelist="$full_path")
                FIREJAIL_ARGS+=(--read-only="$full_path")
            fi
        done

        for subdir in "${HOME_WRITABLE[@]}"; do
            local full_path="$HOME/$subdir"
            if [[ -e "$full_path" ]]; then
                FIREJAIL_ARGS+=(--whitelist="$full_path")
            fi
        done

        # Sandbox scripts
        if [[ "$SANDBOX_DIR" == "$HOME"* ]]; then
            FIREJAIL_ARGS+=(--whitelist="$SANDBOX_DIR")
        fi

        # Project directory
        if [[ "$project_dir" == "$HOME"* ]]; then
            FIREJAIL_ARGS+=(--whitelist="$project_dir")
        fi

        if [[ "${HOME_ACCESS}" == "restricted" ]]; then
            # Lock HOME read-only, then re-enable writable paths
            FIREJAIL_ARGS+=(--read-only="$HOME")

            for subdir in "${HOME_WRITABLE[@]}"; do
                local full_path="$HOME/$subdir"
                if [[ -e "$full_path" ]]; then
                    FIREJAIL_ARGS+=(--read-write="$full_path")
                fi
            done

            if [[ "$project_dir" == "$HOME"* ]]; then
                FIREJAIL_ARGS+=(--read-write="$project_dir")
            fi
        fi
        # tmpwrite: skip --read-only="$HOME" — tmpfs stays writable (ephemeral)
    else
        # read/write: full HOME visible, blacklist credential dirs
        for _blocked_sub in "${_HOME_ALWAYS_BLOCKED[@]}"; do
            local _bp="$HOME/$_blocked_sub"
            [[ -e "$_bp" ]] && FIREJAIL_ARGS+=(--blacklist="$_bp")
        done

        if [[ "${HOME_ACCESS}" == "read" ]]; then
            FIREJAIL_ARGS+=(--read-only="$HOME")
            for subdir in "${HOME_WRITABLE[@]}"; do
                local full_path="$HOME/$subdir"
                if [[ -e "$full_path" ]]; then
                    FIREJAIL_ARGS+=(--read-write="$full_path")
                fi
            done
            if [[ "$project_dir" == "$HOME"* ]]; then
                FIREJAIL_ARGS+=(--read-write="$project_dir")
            fi
        fi
        # write mode: full HOME writable, project dir already writable
    fi

    # Sandbox scripts (read-only inside sandbox, unless it IS the project dir)
    if [[ "$SANDBOX_DIR" != "$project_dir" ]]; then
        FIREJAIL_ARGS+=(--read-only="$SANDBOX_DIR")
    fi

    # Additional writable directories
    for _extra_rw in "${EXTRA_WRITABLE_PATHS[@]}"; do
        if [[ -d "$_extra_rw" ]]; then
            if [[ "${HOME_ACCESS:-restricted}" == "restricted" && "$_extra_rw" == "$HOME"* ]]; then
                FIREJAIL_ARGS+=(--whitelist="$_extra_rw")
            fi
            FIREJAIL_ARGS+=(--read-write="$_extra_rw")
        fi
    done

    # Agent-specific file hiding (e.g., CLAUDE.md, AGENTS.md) is handled
    # by BLOCKED_FILES, populated from agents/*/hide.conf by _apply_agent_profiles().

    # --- Blocked files ---
    for blocked in "${BLOCKED_FILES[@]}"; do
        if [[ -e "$blocked" ]]; then
            # Resolve symlinks — firejail --blacklist may not follow them.
            # Blocking both the symlink and its target ensures coverage.
            FIREJAIL_ARGS+=(--blacklist="$blocked")
            if [[ -L "$blocked" ]]; then
                local _resolved
                _resolved="$(readlink -f "$blocked")"
                [[ "$_resolved" != "$blocked" ]] && FIREJAIL_ARGS+=(--blacklist="$_resolved")
            fi
        fi
    done

    # Make agent sandbox-config directories read-only inside the sandbox.
    for _agent_dir in "${_AGENT_SANDBOX_CONFIG_DIRS[@]:-}"; do
        if [[ -n "$_agent_dir" && -d "$_agent_dir" ]]; then
            FIREJAIL_ARGS+=(--read-only="$_agent_dir")
        fi
    done

    # Hide the sandbox bypass token if configured (see ADMIN_HARDENING.md §1)
    if [[ -n "${SANDBOX_BYPASS_TOKEN:-}" && -e "$SANDBOX_BYPASS_TOKEN" ]]; then
        FIREJAIL_ARGS+=(--blacklist="$SANDBOX_BYPASS_TOKEN")
    fi

    # Extra blocked paths
    for blocked in "${EXTRA_BLOCKED_PATHS[@]}"; do
        if [[ -e "$blocked" ]]; then
            FIREJAIL_ARGS+=(--blacklist="$blocked")
        fi
    done

    # --- Filter environment variables ---
    # Like landlock, we filter in-shell since firejail doesn't have
    # per-variable --unsetenv.
    for var in "${BLOCKED_ENV_VARS[@]}"; do
        _is_allowed_env "$var" || unset "$var" 2>/dev/null || true
    done

    # Also block any SSH_* vars not in the explicit blocklist.
    # To let a specific SSH_* variable through, add it to ALLOWED_ENV_VARS.
    while IFS='=' read -r name _; do
        [[ "$name" == SSH_* ]] && ! _is_allowed_env "$name" && unset "$name" 2>/dev/null || true
    done < <(env)

    # Agent-specific environment exports (e.g., CLAUDE_CONFIG_DIR)
    for _agent_export in "${_AGENT_ENV_EXPORTS[@]}"; do
        export "$_agent_export"
    done

    # Set sandbox env vars
    export SANDBOX_ACTIVE=1
    export SANDBOX_BACKEND=firejail
    export SANDBOX_PROJECT_DIR="$project_dir"
    # Prepend chaperon stubs to PATH (before bin/ for sbatch/srun override)
    export PATH="$SANDBOX_DIR/chaperon/stubs:$SANDBOX_DIR/bin:${PATH}"

    # Pass chaperon FIFO directory into the sandbox.
    # When --private-tmp is active, /tmp is replaced with a clean tmpfs,
    # so we must whitelist the FIFO dir to make it visible inside.
    if [[ -n "${_CHAPERON_FIFO_DIR:-}" && -d "${_CHAPERON_FIFO_DIR:-}" ]]; then
        export _CHAPERON_FIFO_DIR
        FIREJAIL_ARGS+=(--whitelist="$_CHAPERON_FIFO_DIR")
    fi

}

backend_exec() {
    firejail "${FIREJAIL_ARGS[@]}" -- "$@"
    exit $?
}

backend_dry_run() {
    echo "# Backend: firejail"
    echo "# Binary: $(command -v firejail)"
    printf 'firejail \\\n'
    for arg in "${FIREJAIL_ARGS[@]}"; do
        printf '  %s \\\n' "$arg"
    done
    printf '  -- %s\n' "$*"
}

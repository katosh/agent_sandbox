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
#   - Firejail's default seccomp blacklist does not include io_uring syscalls.
#     We add --seccomp.drop=io_uring_setup,io_uring_enter,io_uring_register
#     to close this gap (matching the Landlock backend's custom seccomp).
#     Note: firejail 0.9.72 seccomp is broken on aarch64 (filter loads but
#     doesn't block). Works correctly on x86_64.
#
# CLAUDE.md/settings.json: handled by prepare_config_dir() in sandbox-lib.sh.
#   CLAUDE_CONFIG_DIR points to a per-session directory with merged config,
#   so the user's real ~/.claude/ is never modified.

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

    # CLAUDE.md and settings.json overlays are handled by prepare_config_dir()
    # in sandbox-lib.sh (sets CLAUDE_CONFIG_DIR to a per-session directory).

    # --- Build firejail arguments ---
    FIREJAIL_ARGS=(
        --noprofile
        --quiet
        --caps.drop=all
        --nonewprivs
        --seccomp.drop=io_uring_setup,io_uring_enter,io_uring_register
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
    if [[ "${PRIVATE_TMP:-true}" == "true" ]]; then
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

    # /run/munge and /run/systemd/resolve remain accessible
    # (read-only by default in firejail's mount namespace).

    # --- Passwd filtering (block NSS daemon sockets) ---
    # Blacklist sockets used by NSS daemons that proxy LDAP/AD queries:
    # nscd (caching), nslcd (LDAP), sssd (AD/LDAP/Kerberos).
    # Without these sockets, getent passwd returns only local users.
    if [[ "${FILTER_PASSWD:-true}" == "true" ]]; then
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
    # --private gives us a clean tmpfs $HOME. --whitelist brings back
    # specific paths from the real home into the private home.

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

    # Sandbox scripts (read-only inside sandbox, unless it IS the project dir)
    if [[ "$SANDBOX_DIR" == "$HOME"* ]]; then
        FIREJAIL_ARGS+=(--whitelist="$SANDBOX_DIR")
    fi
    if [[ "$SANDBOX_DIR" != "$project_dir" ]]; then
        FIREJAIL_ARGS+=(--read-only="$SANDBOX_DIR")
    fi

    # --- Scratch mounts (read-only) ---
    for scratch in "${SCRATCH_MOUNTS[@]}"; do
        if [[ -d "$scratch" ]]; then
            FIREJAIL_ARGS+=(--read-only="$scratch")
        fi
    done

    # --- Project directory (writable) ---
    if [[ "$project_dir" == "$HOME"* ]]; then
        FIREJAIL_ARGS+=(--whitelist="$project_dir")
    fi
    # Paths outside $HOME are visible by default (--private only affects $HOME)

    # --- Make $HOME read-only, then re-enable writes for specific paths ---
    # The tmpfs created by --whitelist is writable by default. Lock it down
    # and then --read-write the specific paths that need write access.
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

    # --- Blocked files ---
    for blocked in "${BLOCKED_FILES[@]}"; do
        blocked="${blocked/\$HOME/$HOME}"
        if [[ -e "$blocked" ]]; then
            FIREJAIL_ARGS+=(--blacklist="$blocked")
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

    # --- Slurm PATH shadowing ---
    # Like the landlock backend, we shadow /usr/bin/sbatch and srun with
    # wrapper scripts via PATH. The sandbox bin/ directory is prepended
    # to PATH below.

    # --- Filter environment variables ---
    # Like landlock, we filter in-shell since firejail doesn't have
    # per-variable --unsetenv.
    declare -A _saved_creds
    for var in "${ALLOWED_CREDENTIALS[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            _saved_creds[$var]="${!var}"
        fi
    done

    for var in "${BLOCKED_ENV_VARS[@]}"; do
        unset "$var" 2>/dev/null || true
    done

    # Also block any SSH_* vars not in the explicit blocklist
    while IFS='=' read -r name _; do
        [[ "$name" == SSH_* ]] && unset "$name" 2>/dev/null || true
    done < <(env)

    for var in "${!_saved_creds[@]}"; do
        export "$var=${_saved_creds[$var]}"
    done

    # Set sandbox env vars
    export SANDBOX_ACTIVE=1
    export SANDBOX_BACKEND=firejail
    export SANDBOX_PROJECT_DIR="$project_dir"
    export PATH="$SANDBOX_DIR/bin:${PATH}"
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

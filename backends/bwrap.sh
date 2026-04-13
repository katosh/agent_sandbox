#! /bin/bash --
# backends/bwrap.sh — Bubblewrap sandbox backend
#
# Provides: backend_available, backend_name, backend_prepare, backend_exec
# Sourced by sandbox-lib.sh — has access to all config arrays.

# ── Resolve bwrap binary ────────────────────────────────────────

_resolve_bwrap() {
    if [[ -n "${BWRAP:-}" ]]; then
        : # user override
    elif command -v bwrap &>/dev/null; then
        BWRAP="$(command -v bwrap)"
    else
        BWRAP="$HOME/.linuxbrew/bin/bwrap"
    fi
}

# ── Backend interface ────────────────────────────────────────────

backend_available() {
    _resolve_bwrap
    [[ -x "${BWRAP:-}" ]] || return 1

    # Minimum version: 0.4.0 (for --chmod, --unsetenv)
    local _ver
    _ver=$("$BWRAP" --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+') || return 1
    local _major _minor _patch
    IFS='.' read -r _major _minor _patch <<< "$_ver"
    if (( _major == 0 && _minor < 4 )); then
        return 1
    fi

    # Quick smoke test: can bwrap actually create a user namespace?
    if ! "$BWRAP" --ro-bind / / true 2>/dev/null; then
        # In auto mode, detect_backend silently falls through to the next
        # backend — a noisy warning here would confuse users who end up on
        # a working landlock/firejail backend. Only diagnose when the user
        # explicitly requested bwrap.
        if [[ "${SANDBOX_BACKEND:-auto}" != "auto" ]]; then
            if sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null | grep -q 1; then
                echo "sandbox: bwrap $_ver found but blocked by AppArmor userns restriction." >&2
                echo "  On Ubuntu 24.04+, bwrap needs an AppArmor profile to create user namespaces." >&2
                echo "  Ask your admin to install a profile at /etc/apparmor.d/bwrap" >&2
            fi
        fi
        return 1
    fi
}

backend_name() {
    echo "bubblewrap"
}


backend_prepare() {
    local project_dir="$1"
    _resolve_bwrap
    BWRAP_ARGS=()

    # --- Kernel filesystems ---
    BWRAP_ARGS+=(--proc /proc)

    # BIND_DEV_PTS: use host /dev instead of bwrap's minimal devtmpfs.
    # Required for tmux on kernels < 5.4 (bwrap's devpts gets
    # ptmxmode=000). Exposes host /dev/pts — on kernels < 6.2 this
    # allows TIOCSTI keystroke injection into same-user terminals.
    # See sandbox.conf for details.
    if _is_true "${BIND_DEV_PTS:-false}"; then
        BWRAP_ARGS+=(--dev-bind /dev /dev)
    else
        BWRAP_ARGS+=(--dev /dev)
    fi

    # /tmp isolation: default is private tmpfs. Set PRIVATE_TMP=false in
    # sandbox.conf for MPI/NCCL workloads that need shared /tmp.
    if _is_true "${PRIVATE_TMP:-true}"; then
        BWRAP_ARGS+=(--tmpfs /tmp --chmod 1777 /tmp)
    else
        BWRAP_ARGS+=(--bind /tmp /tmp)
    fi

    # --- Read-only system mounts ---
    for mount in "${READONLY_MOUNTS[@]}"; do
        if [[ -d "$mount" || -f "$mount" ]]; then
            BWRAP_ARGS+=(--ro-bind "$mount" "$mount")
        fi
    done

    # --- Slurm binary blocking ---
    # Block all Slurm submission binaries inside the sandbox.
    # The chaperon proxy (via stubs in PATH) is the only way to submit jobs.
    # Block Slurm binaries (list derived from chaperon/stubs/ + defaults)
    _build_chaperon_blocked_binaries
    for bin in "${CHAPERON_BLOCKED_BINARIES[@]}"; do
        if [[ -x "/usr/bin/$bin" ]]; then
            BWRAP_ARGS+=(--ro-bind /dev/null "/usr/bin/$bin")
        fi
    done


    # Block Slurm config (leaks controller address)
    for _slurm_conf in /etc/slurm /etc/slurm-llnl; do
        if [[ -d "$_slurm_conf" ]]; then
            BWRAP_ARGS+=(--tmpfs "$_slurm_conf")
        fi
    done

    # --- Home directory ---
    # restricted/tmpwrite: tmpfs HOME + selective mounts from lists
    # read/write: bind real HOME + hide credential dirs
    if [[ "${HOME_ACCESS:-restricted}" == "restricted" || "${HOME_ACCESS}" == "tmpwrite" ]]; then
        # Blank home with tmpfs, selectively re-mount listed paths
        BWRAP_ARGS+=(--tmpfs "$HOME")

        for subdir in "${HOME_READONLY[@]}"; do
            local full_path="$HOME/$subdir"
            if [[ -e "$full_path" ]]; then
                BWRAP_ARGS+=(--ro-bind "$full_path" "$full_path")
            fi
        done

        for subdir in "${HOME_WRITABLE[@]}"; do
            local full_path="$HOME/$subdir"
            if [[ -e "$full_path" ]]; then
                BWRAP_ARGS+=(--bind "$full_path" "$full_path")
            fi
        done
    else
        # read/write: bind real HOME, then hide credential dirs
        if [[ "${HOME_ACCESS}" == "read" ]]; then
            BWRAP_ARGS+=(--ro-bind "$HOME" "$HOME")
        else
            BWRAP_ARGS+=(--bind "$HOME" "$HOME")
        fi

        # Always hide credential directories
        for _blocked_sub in "${_HOME_ALWAYS_BLOCKED[@]}"; do
            local _bp="$HOME/$_blocked_sub"
            [[ -e "$_bp" ]] && BWRAP_ARGS+=(--tmpfs "$_bp")
        done

        # In read mode, writable paths still need explicit rw bind
        if [[ "${HOME_ACCESS}" == "read" ]]; then
            for subdir in "${HOME_WRITABLE[@]}"; do
                local full_path="$HOME/$subdir"
                if [[ -e "$full_path" ]]; then
                    BWRAP_ARGS+=(--bind "$full_path" "$full_path")
                fi
            done
        fi
    fi

    BWRAP_ARGS+=(--ro-bind "$SANDBOX_DIR" "$SANDBOX_DIR")

    # If the project dir is under $HOME, bind it writable
    if [[ "$project_dir" == "$HOME"* ]]; then
        BWRAP_ARGS+=(--bind "$project_dir" "$project_dir")
    fi

    # In restricted mode, lock down the tmpfs HOME as read-only.
    # In tmpwrite mode, the tmpfs stays writable (ephemeral writes).
    if [[ "${HOME_ACCESS:-restricted}" == "restricted" ]]; then
        BWRAP_ARGS+=(--remount-ro "$HOME")
    fi

    # Agent-specific file hiding (e.g., CLAUDE.md, AGENTS.md) is handled
    # by BLOCKED_FILES, populated from agents/*/config.conf by _apply_agent_profiles().

    for blocked in "${BLOCKED_FILES[@]}"; do
        if [[ -e "$blocked" ]]; then
            # Resolve symlinks — bwrap can't bind-mount over a symlink.
            local _resolved
            _resolved="$(readlink -f "$blocked")"
            BWRAP_ARGS+=(--ro-bind /dev/null "$_resolved")
        fi
    done

    # Mount agent sandbox-config directories writable so the agent can
    # create lock files, session data, caches, etc.  Then overlay the
    # merged instruction files (CLAUDE.md, settings.json) as individual
    # read-only bind-mounts so the agent cannot modify them.
    for _agent_dir in "${_AGENT_SANDBOX_CONFIG_DIRS[@]:-}"; do
        if [[ -n "$_agent_dir" && -d "$_agent_dir" ]]; then
            BWRAP_ARGS+=(--bind "$_agent_dir" "$_agent_dir")
            # Protect merged config files — agent must not modify these
            for _protected in "${_AGENT_PROTECTED_FILES[@]:-}"; do
                if [[ -f "$_protected" ]]; then
                    BWRAP_ARGS+=(--ro-bind "$_protected" "$_protected")
                fi
            done
        fi
    done

    # Hide the sandbox bypass token if configured (see ADMIN_HARDENING.md §1)
    if [[ -n "${SANDBOX_BYPASS_TOKEN:-}" && -e "$SANDBOX_BYPASS_TOKEN" ]]; then
        BWRAP_ARGS+=(--ro-bind /dev/null "$(readlink -f "$SANDBOX_BYPASS_TOKEN")")
    fi

    for blocked in "${EXTRA_BLOCKED_PATHS[@]}"; do
        if [[ -d "$blocked" ]]; then
            BWRAP_ARGS+=(--tmpfs "$blocked")
        fi
    done

    # Project dir outside $HOME — bind after read-only mounts so it overlays correctly
    if [[ "$project_dir" != "$HOME"* ]]; then
        BWRAP_ARGS+=(--bind "$project_dir" "$project_dir")
    fi

    # Additional writable directories
    for _extra_rw in "${EXTRA_WRITABLE_PATHS[@]}"; do
        if [[ -d "$_extra_rw" ]]; then
            BWRAP_ARGS+=(--bind "$_extra_rw" "$_extra_rw")
        fi
    done

    # Mount /run as a tmpfs, then selectively bind only what's needed.
    # Mounting all of /run exposes D-Bus, systemd user sockets, and
    # containerd sockets — allowing sandbox escape via
    # systemd-run --user.
    BWRAP_ARGS+=(--tmpfs /run)

    # Munge socket: BLOCKED inside sandbox (chaperon handles auth outside).
    # /run/munge is not mounted — hidden by the /run tmpfs above.
    # This is intentionally blocked even on compute nodes: exposing munge
    # would allow crafting arbitrary Slurm submissions that bypass the
    # chaperon and don't inherit sandbox restrictions.

    # Note: real srun is NOT exposed inside the sandbox.  The srun stub
    # proxies through the chaperon, which runs outside and has munge access.

    # nscd socket (required for user/group lookups on NFS/LDAP systems).
    # When FILTER_PASSWD is enabled, skip nscd — we overlay nsswitch.conf
    # to use "files" only, so nscd is unnecessary and would leak LDAP data.
    if [[ -d /run/nscd ]] && ! _is_true "${FILTER_PASSWD:-true}"; then
        BWRAP_ARGS+=(--ro-bind /run/nscd /run/nscd)
    fi

    # systemd-resolved stub (DNS — /etc/resolv.conf often symlinks here)
    if [[ -d /run/systemd/resolve ]]; then
        BWRAP_ARGS+=(--ro-bind /run/systemd/resolve /run/systemd/resolve)
    fi

    if [[ -L /var/run ]]; then
        BWRAP_ARGS+=(--symlink /run /var/run)
    elif [[ -d /var/run ]]; then
        BWRAP_ARGS+=(--tmpfs /var/run)
    fi

    # --- Passwd/group filtering (LDAP/AD user enumeration prevention) ---
    # Overlay /etc/passwd, /etc/group, and /etc/nsswitch.conf with filtered
    # versions containing only system accounts + current user and disable LDAP.
    if _is_true "${FILTER_PASSWD:-true}"; then
        generate_filtered_passwd
        if [[ -n "${_FILTERED_PASSWD:-}" && -f "${_FILTERED_PASSWD:-}" ]]; then
            BWRAP_ARGS+=(--ro-bind "$_FILTERED_PASSWD" /etc/passwd)
            BWRAP_ARGS+=(--ro-bind "$_FILTERED_GROUP" /etc/group)
            BWRAP_ARGS+=(--ro-bind "$_FILTERED_NSSWITCH" /etc/nsswitch.conf)
        fi
    fi

    BWRAP_ARGS+=(--unshare-pid)

    # IPC namespace isolation: gives sandbox its own SysV IPC + /dev/shm.
    # Disable via PRIVATE_IPC=false in sandbox.conf if you need cross-sandbox
    # or host-to-sandbox shared memory (rare — MPI within a single job is fine
    # because all ranks share the same sandbox).
    if _is_true "${PRIVATE_IPC:-true}"; then
        BWRAP_ARGS+=(--unshare-ipc)
        BWRAP_ARGS+=(--tmpfs /dev/shm --chmod 1777 /dev/shm)
    fi

    BWRAP_ARGS+=(--die-with-parent)

    # --- Seccomp filter (block io_uring, userfaultfd, kexec) ---
    # Generated at runtime because HPC nodes sharing an NFS install may
    # have different architectures (x86_64 vs aarch64) — the BPF bytecode
    # is architecture-specific.
    #
    # bwrap --seccomp FD reads raw BPF instructions from a file descriptor.
    # The FD is NOT opened here — sandbox-exec.sh closes FDs > 2 before
    # calling backend_exec().  We store the temp file path and open the FD
    # in backend_exec() just before exec.
    #
    # Null bytes in the BPF binary mean we MUST use a temp file — bash
    # variables silently truncate at \0.
    _SECCOMP_TMPFILE=
    local _seccomp_py="${SANDBOX_DIR}/backends/generate-seccomp.py"
    if [[ -f "$_seccomp_py" ]] && command -v python3 &>/dev/null; then
        _SECCOMP_TMPFILE="$(mktemp "${TMPDIR:-/tmp}/bwrap-seccomp.XXXXXX")"
        if python3 "$_seccomp_py" > "$_SECCOMP_TMPFILE" 2>/dev/null; then
            local _bpf_size
            _bpf_size="$(stat -c%s "$_SECCOMP_TMPFILE" 2>/dev/null || echo 0)"
            if (( _bpf_size >= 8 )); then
                # Placeholder — replaced with real FD in backend_exec()
                BWRAP_ARGS+=(--seccomp __SECCOMP_FD__)
            else
                echo "sandbox: warning: seccomp BPF filter is empty, skipping" >&2
                rm -f "$_SECCOMP_TMPFILE"
                _SECCOMP_TMPFILE=
            fi
        else
            echo "sandbox: warning: seccomp filter generation failed, skipping" >&2
            rm -f "$_SECCOMP_TMPFILE"
            _SECCOMP_TMPFILE=
        fi
    fi

    BWRAP_ARGS+=(--chdir "$project_dir")

    # --- Environment ---
    # Inherit the host environment, then block sensitive vars.
    # This is more robust than --clearenv + explicit passthrough,
    # which breaks whenever a new tool or module adds env vars.
    BWRAP_ARGS+=(--setenv SANDBOX_ACTIVE 1)
    BWRAP_ARGS+=(--setenv SANDBOX_BACKEND bwrap)
    BWRAP_ARGS+=(--setenv SANDBOX_PROJECT_DIR "$project_dir")
    # Prepend chaperon stubs to PATH (before bin/ for sbatch/srun override)
    BWRAP_ARGS+=(--setenv PATH "$SANDBOX_DIR/chaperon/stubs:$SANDBOX_DIR/bin:${PATH}")

    # Bind-mount chaperon FIFO directory into the sandbox (writable for
    # per-request response FIFOs created by stubs)
    if [[ -n "${_CHAPERON_FIFO_DIR:-}" && -d "${_CHAPERON_FIFO_DIR:-}" ]]; then
        BWRAP_ARGS+=(--bind "$_CHAPERON_FIFO_DIR" "$_CHAPERON_FIFO_DIR")
        BWRAP_ARGS+=(--setenv _CHAPERON_FIFO_DIR "$_CHAPERON_FIFO_DIR")
    fi


    # Agent-specific environment exports (e.g., CLAUDE_CONFIG_DIR)
    for _agent_export in "${_AGENT_ENV_EXPORTS[@]}"; do
        local _key="${_agent_export%%=*}"
        local _val="${_agent_export#*=}"
        BWRAP_ARGS+=(--setenv "$_key" "$_val")
        export "$_key=$_val"
    done

    # Warn about pattern-blocked vars (helps users diagnose missing env vars)
    _warn_pattern_blocked_vars

    for var in "${BLOCKED_ENV_VARS[@]}"; do
        _is_allowed_env "$var" || BWRAP_ARGS+=(--unsetenv "$var")
    done

    # Block credential-pattern vars (SSH_*, *_TOKEN, CI_*, etc.) from BLOCKED_ENV_PATTERNS.
    # To let a specific variable through, add it to ALLOWED_ENV_VARS.
    while IFS='=' read -r name _; do
        _is_blocked_by_pattern "$name" && BWRAP_ARGS+=(--unsetenv "$name") || true
    done < <(env)

}

backend_exec() {
    # Scrub sensitive vars from OUR environment before exec'ing bwrap.
    # --unsetenv only cleans the child (PID 2); bwrap itself is PID 1
    # inside --unshare-pid and its /proc/1/environ retains whatever the
    # parent had.  By unsetting here, bwrap inherits a clean environment
    # and /proc/1/environ is safe.  The --unsetenv flags remain as
    # defense-in-depth.
    for _var in "${BLOCKED_ENV_VARS[@]}"; do
        _is_allowed_env "$_var" || unset "$_var" 2>/dev/null || true
    done
    # Credential-pattern vars (SSH_*, *_TOKEN, CI_*, etc.) — same set as backend_prepare
    while IFS='=' read -r _name _; do
        _is_blocked_by_pattern "$_name" && { unset "$_name" 2>/dev/null || true; } || true
    done < <(env)

    # Open seccomp FD now (after sandbox-exec.sh's FD cleanup) and
    # replace the placeholder with the actual FD number.
    if [[ -n "${_SECCOMP_TMPFILE:-}" && -f "${_SECCOMP_TMPFILE:-}" ]]; then
        local _seccomp_fd
        exec {_seccomp_fd}<"$_SECCOMP_TMPFILE"
        rm -f "$_SECCOMP_TMPFILE"
        BWRAP_ARGS=("${BWRAP_ARGS[@]/__SECCOMP_FD__/$_seccomp_fd}")
    fi

    # Fork bomb defense-in-depth: set per-UID RLIMIT_NPROC before exec.
    # Inherited by bwrap and all child processes inside the sandbox.
    if [[ -n "${SANDBOX_NPROC_LIMIT:-}" ]]; then
        ulimit -u "$SANDBOX_NPROC_LIMIT" 2>/dev/null || true
    fi

    exec "$BWRAP" "${BWRAP_ARGS[@]}" -- "$@"
}

backend_dry_run() {
    echo "# Backend: bubblewrap"
    echo "# Binary: $BWRAP"
    printf '%s \\\n' "$BWRAP"
    for arg in "${BWRAP_ARGS[@]}"; do
        printf '  %s \\\n' "$arg"
    done
    printf '  -- %s\n' "$*"
    # Clean up seccomp temp file (dry-run doesn't exec)
    [[ -n "${_SECCOMP_TMPFILE:-}" ]] && rm -f "$_SECCOMP_TMPFILE" 2>/dev/null || true
}

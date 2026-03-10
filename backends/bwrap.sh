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
    # Quick smoke test: can bwrap actually create a user namespace?
    "$BWRAP" --ro-bind / / true 2>/dev/null
}

backend_name() {
    echo "bubblewrap"
}

# Internal path where real Slurm binaries are mounted inside the
# sandbox.  Intentionally obscure and outside any PATH.
SLURM_REAL_DIR="/tmp/.sandbox-slurm-real"

backend_prepare() {
    local project_dir="$1"
    _resolve_bwrap
    BWRAP_ARGS=()

    # --- Kernel filesystems ---
    BWRAP_ARGS+=(--proc /proc)
    BWRAP_ARGS+=(--dev /dev)

    # /tmp isolation: default is private tmpfs. Set PRIVATE_TMP=false in
    # sandbox.conf for MPI/NCCL workloads that need shared /tmp.
    if [[ "${PRIVATE_TMP:-true}" == "true" ]]; then
        BWRAP_ARGS+=(--tmpfs /tmp)
    else
        BWRAP_ARGS+=(--bind /tmp /tmp)
    fi

    # --- Read-only system mounts ---
    for mount in "${READONLY_MOUNTS[@]}"; do
        if [[ -d "$mount" || -f "$mount" ]]; then
            BWRAP_ARGS+=(--ro-bind "$mount" "$mount")
        fi
    done

    # --- Slurm binary isolation ---
    for bin in sbatch srun; do
        if [[ -x "/usr/bin/$bin" ]]; then
            local overlay="$SANDBOX_DIR/.${bin}-overlay"
            cat > "$overlay" <<SLURM_EOF
#! /bin/bash --
exec "$SANDBOX_DIR/${bin}-sandbox.sh" "\$@"
SLURM_EOF
            chmod +x "$overlay"
            BWRAP_ARGS+=(--ro-bind "/usr/bin/$bin" "$SLURM_REAL_DIR/$bin")
            BWRAP_ARGS+=(--ro-bind "$overlay" "/usr/bin/$bin")
        fi
    done

    # --- Blank home, then selectively re-mount ---
    BWRAP_ARGS+=(--tmpfs "$HOME")

    for subdir in "${HOME_READONLY[@]}"; do
        local full_path="$HOME/$subdir"
        if [[ -e "$full_path" ]]; then
            BWRAP_ARGS+=(--ro-bind "$full_path" "$full_path")
        fi
    done

    if [[ -n "$DOTFILES_DIR" && -d "$DOTFILES_DIR" ]]; then
        for name in "${HOME_SYMLINKS[@]}"; do
            if [[ -e "$DOTFILES_DIR/$name" ]]; then
                BWRAP_ARGS+=(--symlink "$DOTFILES_DIR/$name" "$HOME/$name")
            fi
        done
    fi

    for subdir in "${HOME_WRITABLE[@]}"; do
        local full_path="$HOME/$subdir"
        if [[ -e "$full_path" ]]; then
            BWRAP_ARGS+=(--bind "$full_path" "$full_path")
        fi
    done

    BWRAP_ARGS+=(--ro-bind "$SANDBOX_DIR" "$SANDBOX_DIR")

    # If the project dir is under $HOME, bind it BEFORE remount-ro
    # so bwrap can create the mount point on the writable tmpfs.
    if [[ "$project_dir" == "$HOME"* ]]; then
        BWRAP_ARGS+=(--bind "$project_dir" "$project_dir")
    fi

    BWRAP_ARGS+=(--remount-ro "$HOME")

    # CLAUDE.md and settings.json overlays are handled by prepare_config_dir()
    # in sandbox-lib.sh (sets CLAUDE_CONFIG_DIR to a per-session directory).

    for blocked in "${BLOCKED_FILES[@]}"; do
        blocked="${blocked/\$HOME/$HOME}"
        if [[ -e "$blocked" ]]; then
            BWRAP_ARGS+=(--ro-bind /dev/null "$blocked")
        fi
    done

    # Hide the sandbox bypass token if configured (see ADMIN_HARDENING.md §1)
    if [[ -n "${SANDBOX_BYPASS_TOKEN:-}" && -e "$SANDBOX_BYPASS_TOKEN" ]]; then
        BWRAP_ARGS+=(--ro-bind /dev/null "$SANDBOX_BYPASS_TOKEN")
    fi

    for scratch in "${SCRATCH_MOUNTS[@]}"; do
        if [[ -d "$scratch" ]]; then
            BWRAP_ARGS+=(--ro-bind "$scratch" "$scratch")
        fi
    done

    for blocked in "${EXTRA_BLOCKED_PATHS[@]}"; do
        if [[ -d "$blocked" ]]; then
            BWRAP_ARGS+=(--tmpfs "$blocked")
        fi
    done

    # Project dir outside $HOME — bind after read-only mounts so it overlays correctly
    if [[ "$project_dir" != "$HOME"* ]]; then
        BWRAP_ARGS+=(--bind "$project_dir" "$project_dir")
    fi

    # Mount /run as a tmpfs, then selectively bind only what's needed.
    # Mounting all of /run exposes D-Bus, systemd user sockets, and
    # containerd sockets — allowing sandbox escape via
    # systemd-run --user.
    BWRAP_ARGS+=(--tmpfs /run)

    # Munge socket (required for Slurm authentication)
    if [[ -d /run/munge ]]; then
        BWRAP_ARGS+=(--ro-bind /run/munge /run/munge)
    fi

    # nscd socket (required for user/group lookups on NFS/LDAP systems).
    # When FILTER_PASSWD is enabled, skip nscd — we overlay nsswitch.conf
    # to use "files" only, so nscd is unnecessary and would leak LDAP data.
    if [[ -d /run/nscd ]] && [[ "${FILTER_PASSWD:-true}" != "true" ]]; then
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

    # --- Passwd filtering (LDAP/AD user enumeration prevention) ---
    # Overlay /etc/passwd and /etc/nsswitch.conf with filtered versions
    # that contain only system accounts + current user and disable LDAP.
    if [[ "${FILTER_PASSWD:-true}" == "true" ]]; then
        generate_filtered_passwd
        if [[ -n "${_FILTERED_PASSWD:-}" && -f "${_FILTERED_PASSWD:-}" ]]; then
            BWRAP_ARGS+=(--ro-bind "$_FILTERED_PASSWD" /etc/passwd)
            BWRAP_ARGS+=(--ro-bind "$_FILTERED_NSSWITCH" /etc/nsswitch.conf)
        fi
    fi

    BWRAP_ARGS+=(--unshare-pid)
    BWRAP_ARGS+=(--die-with-parent)
    BWRAP_ARGS+=(--chdir "$project_dir")

    # --- Environment ---
    # Inherit the host environment, then block sensitive vars.
    # This is more robust than --clearenv + explicit passthrough,
    # which breaks whenever a new tool or module adds env vars.
    BWRAP_ARGS+=(--setenv SANDBOX_ACTIVE 1)
    BWRAP_ARGS+=(--setenv SANDBOX_BACKEND bwrap)
    BWRAP_ARGS+=(--setenv SANDBOX_PROJECT_DIR "$project_dir")
    BWRAP_ARGS+=(--setenv PATH "$SANDBOX_DIR/bin:${PATH}")

    for var in "${BLOCKED_ENV_VARS[@]}"; do
        BWRAP_ARGS+=(--unsetenv "$var")
    done

    # Also block any SSH_* vars not in the explicit blocklist
    while IFS='=' read -r name _; do
        [[ "$name" == SSH_* ]] && BWRAP_ARGS+=(--unsetenv "$name")
    done < <(env)

    for var in "${ALLOWED_CREDENTIALS[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            BWRAP_ARGS+=(--setenv "$var" "${!var}")
        fi
    done
}

backend_exec() {
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
}

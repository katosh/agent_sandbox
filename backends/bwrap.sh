#!/usr/bin/env bash
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
#!/usr/bin/env bash
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

    # --- CLAUDE.md overlay ---
    # Applied AFTER remount-ro and the rw bind of ~/.claude so the
    # ro-bind takes precedence over the writable parent mount.
    local claude_md_overlay="$SANDBOX_DIR/.claude-md-overlay"
    local sandbox_snippet="$SANDBOX_DIR/sandbox-claude.md"
    local claude_md_path="$HOME/.claude/CLAUDE.md"
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
        BWRAP_ARGS+=(--ro-bind "$claude_md_overlay" "$claude_md_resolved")
    fi

    # --- Settings overlay ---
    local settings_overlay="$SANDBOX_DIR/.settings-overlay"
    local sandbox_settings="$SANDBOX_DIR/sandbox-settings.json"
    local user_settings="$HOME/.claude/settings.json"
    local user_settings_resolved="$user_settings"
    if [[ -L "$user_settings" ]]; then
        user_settings_resolved="$(readlink -f "$user_settings")"
    fi
    if [[ -f "$sandbox_settings" ]]; then
        [[ -f "$user_settings_resolved" ]] || echo '{}' > "$user_settings_resolved"
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
    # containerd sockets — allowing full sandbox escape via
    # systemd-run --user (pentest finding, 2026-03).
    BWRAP_ARGS+=(--tmpfs /run)

    # Munge socket (required for Slurm authentication)
    if [[ -d /run/munge ]]; then
        BWRAP_ARGS+=(--ro-bind /run/munge /run/munge)
    fi

    # nscd socket (required for user/group lookups on NFS/LDAP systems)
    if [[ -d /run/nscd ]]; then
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

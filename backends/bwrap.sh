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

# ── BEGIN probe section (probe-and-explain bwrap startup) ───────
# Inspired by cco's probe_linux_bwrap + explain_linux_bwrap_failure.
# Distinguishes "bwrap not installed" vs "AppArmor-blocked userns" vs
# "kernel too old / userns disabled" without admins reading dmesg, so
# the support loop currently routed through docs/admin/sandbox-help.md
# can self-resolve.
#
# _probe_bwrap captures the smoke-test stderr and maps known signatures
# to actionable explanations. On failure it sets three globals:
#
#   _BWRAP_PROBE_REASON   — token for callers (one of: not-installed,
#                           version-too-old, binary-broken,
#                           apparmor-userns, userns-disabled,
#                           clone-denied, unknown)
#   _BWRAP_PROBE_MESSAGE  — multi-line, user-facing explanation
#   _BWRAP_PROBE_STDERR   — raw stderr from the failing invocation
#
# Auto mode keeps the existing silent-fallthrough behaviour; explicit
# mode (SANDBOX_BACKEND=bwrap) prints the explanation. detect_backend
# in sandbox-lib.sh reads $_BWRAP_PROBE_REASON to render a specific
# bwrap line in the auto-mode "no backend available" diagnostic.

_probe_bwrap() {
    _BWRAP_PROBE_REASON=
    _BWRAP_PROBE_MESSAGE=
    _BWRAP_PROBE_STDERR=
    _resolve_bwrap

    if [[ ! -x "${BWRAP:-}" ]]; then
        _BWRAP_PROBE_REASON=not-installed
        _BWRAP_PROBE_MESSAGE="bwrap is not installed (looked at: ${BWRAP:-(unset)}).
  Install via your distribution package manager:
    sudo apt install bubblewrap        # Debian/Ubuntu
    sudo dnf install bubblewrap        # Fedora/RHEL
    brew install bubblewrap            # user-local, no root needed
  Or set BWRAP=/path/to/bwrap to point at an existing binary."
        return 1
    fi

    local _ver _major _minor _patch
    _ver=$("$BWRAP" --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+') || {
        _BWRAP_PROBE_REASON=binary-broken
        _BWRAP_PROBE_MESSAGE="$BWRAP --version did not produce parseable output.
  The binary may be corrupted, the wrong architecture, or not actually
  bubblewrap. Try: file '$BWRAP'  and  '$BWRAP' --version"
        return 1
    }
    IFS='.' read -r _major _minor _patch <<< "$_ver"
    if (( _major == 0 && _minor < 4 )); then
        _BWRAP_PROBE_REASON=version-too-old
        _BWRAP_PROBE_MESSAGE="bwrap $_ver at $BWRAP is too old.
  agent-sandbox needs ≥ 0.4.0 for --chmod and --unsetenv.
  Upgrade via your package manager, or: brew upgrade bubblewrap"
        return 1
    fi

    # Smoke test: can bwrap create an unprivileged user namespace here?
    # Capture stderr so we can fingerprint the failure mode.
    local _smoke_stderr _exit
    _smoke_stderr=$("$BWRAP" --ro-bind / / true 2>&1 >/dev/null) && return 0
    _exit=$?
    _BWRAP_PROBE_STDERR="$_smoke_stderr"

    # Pattern matchers run against bwrap's canonical English stderr.
    # Order matters: AppArmor's "Permission denied" is more specific than
    # the generic "Operation not permitted" of a disabled userns.
    case "$_smoke_stderr" in
        *"setting up uid map: Permission denied"*)
            _BWRAP_PROBE_REASON=apparmor-userns
            _BWRAP_PROBE_MESSAGE="bwrap $_ver was blocked while writing /proc/self/uid_map.
  This is the canonical signature of an LSM (AppArmor on Ubuntu 24.04+,
  or a SELinux policy) restricting unprivileged user namespaces.

  Diagnose:
    sysctl kernel.apparmor_restrict_unprivileged_userns   # 1 = blocked
    journalctl -k --grep=apparmor | tail                  # last DENIED events

  Fix (pick one, in order of preference):
    1) Install an AppArmor profile that permits bwrap (Ubuntu 24.04+):
         sudo cp /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \\
                 /etc/apparmor.d/
         sudo systemctl reload apparmor
    2) Disable the restriction host-wide (lowers host security):
         sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
    3) Fall back to a backend that doesn't need unprivileged userns:
         sandbox-exec.sh --backend landlock -- ..."
            ;;
        *"No permitted_caps"*)
            _BWRAP_PROBE_REASON=userns-disabled
            _BWRAP_PROBE_MESSAGE="bwrap $_ver reports 'No permitted_caps' — it has no capabilities
  to set up the new namespace. The kernel either lacks CONFIG_USER_NS
  or has unprivileged user namespaces disabled.

  Diagnose:
    sysctl kernel.unprivileged_userns_clone   # Debian-family knob
    cat /proc/sys/user/max_user_namespaces    # 0 = userns disabled
    uname -r                                  # need ≥ 3.8 for userns

  Fix (root required):
    sudo sysctl -w kernel.unprivileged_userns_clone=1
    sudo sysctl -w user.max_user_namespaces=15076
  If neither knob exists, the kernel was built without CONFIG_USER_NS;
  fall back to: sandbox-exec.sh --backend landlock -- ..."
            ;;
        *"setting up uid map: Operation not permitted"*|\
        *"creating new user namespace: Operation not permitted"*|\
        *"Creating new namespace failed: Operation not permitted"*|\
        *"clone: Operation not permitted"*|\
        *"clone(): Operation not permitted"*)
            _BWRAP_PROBE_REASON=clone-denied
            _BWRAP_PROBE_MESSAGE="bwrap $_ver could not create the new namespace (EPERM).
  Likely causes:
    • A seccomp filter from the launching process forbids clone/unshare
      (running inside Docker without --privileged, restrictive systemd
      unit, or another sandbox).
    • /proc/sys/user/max_user_namespaces is 0.
    • Kernel built without CONFIG_USER_NS.

  Diagnose:
    cat /proc/sys/user/max_user_namespaces
    cat /proc/self/status | grep -E 'Seccomp|CapEff'

  Fix: run from a less-restricted environment, raise max_user_namespaces,
  or fall back to: sandbox-exec.sh --backend landlock -- ..."
            ;;
        *"Failed to make / slave"*|\
        *"Can't make mount /"*"private"*|\
        *"pivot_root"*"Permission denied"*)
            _BWRAP_PROBE_REASON=mount-namespace-denied
            _BWRAP_PROBE_MESSAGE="bwrap $_ver could not set up its mount namespace.
  This typically means agent-sandbox is being run inside another
  mount-restricted environment — another bwrap, an unprivileged
  container, or a chroot — that blocks the propagation changes
  bwrap needs.

  If this is intentional (developing agent-sandbox itself from
  inside the sandbox): re-run from outside any wrapper.
  Otherwise: sandbox-exec.sh --backend landlock -- ..."
            ;;
        *)
            _BWRAP_PROBE_REASON=unknown
            local _stderr_indented
            _stderr_indented=$(printf '    %s\n' "${_smoke_stderr:-(empty stderr)}")
            _BWRAP_PROBE_MESSAGE="bwrap $_ver smoke test failed (exit $_exit) with an unrecognised
  signature. Raw stderr:
$_stderr_indented
  See docs/admin/sandbox-help.md → \"bwrap startup errors\" for the
  full mapping of known patterns. If your case isn't covered, please
  open an issue with the stderr verbatim and the output of:
    uname -a; '$BWRAP' --version; cat /sys/kernel/security/lsm"
            ;;
    esac
    return 1
}

# ── END probe section ───────────────────────────────────────────

# ── Backend interface ────────────────────────────────────────────

backend_available() {
    if _probe_bwrap; then
        return 0
    fi

    # Auto mode: silent — detect_backend renders one line via
    # $_BWRAP_PROBE_REASON in the consolidated diagnostic, so a noisy
    # warning here would confuse users who end up on a working
    # landlock/firejail backend.
    # Explicit mode (SANDBOX_BACKEND=bwrap): print the full explanation.
    if [[ "${SANDBOX_BACKEND:-auto}" != "auto" && -n "${_BWRAP_PROBE_MESSAGE:-}" ]]; then
        echo "sandbox: ${_BWRAP_PROBE_MESSAGE}" >&2
    fi
    return 1
}

backend_name() {
    echo "bubblewrap"
}


backend_prepare() {
    local project_dir="$1"
    _resolve_bwrap
    BWRAP_ARGS=()
    # HOME_SEEDED_FILES staging — always initialised so backend_exec /
    # backend_dry_run can iterate the array unconditionally even when
    # the seeded-files path isn't taken (e.g. HOME_ACCESS=read/write).
    _SEED_TMPFILES=()
    _SEED_DESTS=()

    # --- Kernel filesystems ---
    BWRAP_ARGS+=(--proc /proc)

    # Start with bwrap's minimal devtmpfs, then bind in only the device
    # nodes the user (and admin DEVICES_BLACKLIST) approve.
    # _resolve_devices populates DEVICES_RESOLVED — see
    # sandbox-lib.sh::_resolve_devices and docs/reference/device-passthrough.md.
    # The legacy BIND_DEV_PTS=true toggle is rewritten to
    # DEVICES+=(/dev/pts) earlier in sandbox-lib.sh.
    BWRAP_ARGS+=(--dev /dev)
    _resolve_devices
    local _devnode
    for _devnode in "${DEVICES_RESOLVED[@]}"; do
        BWRAP_ARGS+=(--dev-bind "$_devnode" "$_devnode")
    done

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

        # HOME_SEEDED_FILES: copy host file CONTENT into the tmpfs as a
        # writable file. The agent can edit it (gh auth setup-git, IDE
        # plugins, git config --global) without affecting the host file.
        # bwrap's --file FD DEST reads the data off an FD and writes a
        # regular file at DEST inside the new mount namespace, so the
        # result lives in the tmpfs and is discarded on sandbox exit.
        # The FDs are opened in backend_exec(), after sandbox-exec.sh's
        # FD-cleanup pass; here we stash temp files and emit placeholder
        # markers in BWRAP_ARGS that backend_exec() rewrites.
        local _seed_idx=0
        local seedf
        for seedf in "${HOME_SEEDED_FILES[@]}"; do
            local _src="$HOME/$seedf"
            local _dst="$HOME/$seedf"
            [[ -f "$_src" ]] || continue
            local _staged
            _staged="$(mktemp "${TMPDIR:-/tmp}/bwrap-seed.XXXXXX")"
            cp -- "$_src" "$_staged"
            chmod 600 "$_staged"
            _SEED_TMPFILES+=("$_staged")
            _SEED_DESTS+=("$_dst")
            BWRAP_ARGS+=(--file "__SEED_FD_${_seed_idx}__" "$_dst")
            _seed_idx=$((_seed_idx + 1))
        done

        for subdir in "${HOME_READONLY[@]}"; do
            # Skip entries that are also seeded — the seed wins, and a
            # following --ro-bind would clobber the writable copy.
            local _is_seeded=false
            local _s
            for _s in "${HOME_SEEDED_FILES[@]}"; do
                [[ "$subdir" == "$_s" ]] && { _is_seeded=true; break; }
            done
            $_is_seeded && continue
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
    #
    # Two binds per BLOCKED_FILES entry to close a symlink-bypass class:
    #
    #   1. The LITERAL path. Required when an ancestor of the BLOCKED_FILE
    #      is a symlink that lives inside a writable bind. Concrete shape:
    #      ~/.claude is in HOME_WRITABLE and exists on the host as a
    #      symlink to ~/dotfiles/claude/. bwrap's `--bind ~/.claude
    #      ~/.claude` follows the source symlink and surfaces the
    #      resolved directory's contents at the literal path, so
    #      ~/.claude/CLAUDE.md inside the sandbox is a real file dentry.
    #      The literal-path mount overlays /dev/null exactly where the
    #      agent opens the file. Without this bind, mount overlays are
    #      path-keyed (not inode-keyed): a /dev/null mount at
    #      ~/dotfiles/claude/CLAUDE.md does NOT apply when the agent
    #      reaches the same inode via ~/.claude/CLAUDE.md, so the
    #      BLOCKED_FILES rule was silently bypassed.
    #
    #   2. The RESOLVED path. Required when the BLOCKED_FILE itself is
    #      a symlink (test.sh::S04). bwrap's ensure_file rejects S_IFLNK
    #      destinations with ENOTSUP, so we cannot mount on the literal
    #      symlink — readlink -f gives a real-file path bwrap can mount.
    #      Read-via-symlink follows the symlink to the resolved path and
    #      hits the /dev/null overlay there.
    #
    # Both binds are emitted unless they collapse to the same path. Two
    # binds at the same destination are accepted by bwrap (later wins),
    # but the duplicate is needless work — skip when identical. The
    # literal bind is itself skipped when the leaf is a symlink, since
    # bwrap rejects ensure_file on S_IFLNK; the resolved bind covers
    # that case.
    local _bf_literal _bf_resolved
    for blocked in "${BLOCKED_FILES[@]}"; do
        if [[ -e "$blocked" ]]; then
            _bf_literal="$blocked"
            _bf_resolved="$(readlink -f "$blocked")"

            if [[ ! -L "$_bf_literal" ]]; then
                BWRAP_ARGS+=(--ro-bind /dev/null "$_bf_literal")
            fi
            if [[ "$_bf_resolved" != "$_bf_literal" ]]; then
                BWRAP_ARGS+=(--ro-bind /dev/null "$_bf_resolved")
            fi
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

    # Open HOME_SEEDED_FILES FDs (also after FD cleanup). bwrap reads
    # the bytes off each FD and creates a regular file at DEST inside
    # the sandbox's tmpfs HOME. We rm the staged temp file as soon as
    # the FD is open — the inode persists for the FD's lifetime, and
    # bwrap inherits the FD across exec.
    if [[ ${#_SEED_TMPFILES[@]} -gt 0 ]]; then
        local _i _seed_fd
        for ((_i=0; _i<${#_SEED_TMPFILES[@]}; _i++)); do
            exec {_seed_fd}<"${_SEED_TMPFILES[$_i]}"
            rm -f "${_SEED_TMPFILES[$_i]}"
            BWRAP_ARGS=("${BWRAP_ARGS[@]/__SEED_FD_${_i}__/$_seed_fd}")
        done
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
    # Clean up HOME_SEEDED_FILES staged temp files (dry-run doesn't exec)
    if [[ ${#_SEED_TMPFILES[@]} -gt 0 ]]; then
        local _f
        for _f in "${_SEED_TMPFILES[@]}"; do
            rm -f "$_f" 2>/dev/null || true
        done
    fi
}

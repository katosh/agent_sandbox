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
#   - Unix socket isolation: /run is replaced by a tmpfs holding only
#     the DNS resolver dir (like bwrap's --tmpfs /run)
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

# ── Read-only host filesystem (outside the writable grants) ──────
#
# Firejail starts from the host mount tree, so everything outside the
# grants has to be remounted read-only explicitly. Two firejail
# behaviours (checked in the 0.9.72 source, unchanged on master) rule
# out the obvious `--read-only=/` + `--read-write=<grant>`:
#
#   1. `--read-write=X` is refused for a directory X that is currently
#      read-only and not owned by the calling user ("you are not
#      allowed to change X to read-write", fs.c:fs_remount_simple,
#      hidden by --quiet). A project or EXTRA_WRITABLE_PATHS entry on
#      shared storage owned by root or the PI and group-writable for
#      the user (the normal HPC layout) came out READ-ONLY.
#   2. `--read-only=/` is not recursive: build_mount_array() matches
#      submounts with `dir[strlen(path)] == '/'`, which never holds for
#      path "/". Only the root filesystem became read-only; every other
#      mount (NFS/Lustre/GPFS project and scratch filesystems, /boot,
#      /run/lock, ...) stayed writable.
#
# So the launcher builds the read-only set itself (_fj_cover): every
# entry of / becomes its own recursive --read-only, except the paths
# that must stay writable. A directory that CONTAINS a grant the user
# does not own is not remounted; instead its children are covered one
# by one, down to the grant, so the grant itself is never under a
# read-only mount and needs no --read-write. The price: those
# ancestor directories themselves stay writable as far as Unix
# permissions allow (new entries can be created directly in them); the
# launcher lists the ones the user can write. Grants the user owns keep
# the stronger scheme (read-only parent + --read-write re-open).
#
# Not covered here (handled elsewhere in backend_prepare): /proc and
# /sys (firejail), /dev (--private-dev), /run (tmpfs via --whitelist),
# /tmp (--private-tmp or shared), $HOME and its ancestors (HOME_ACCESS
# rules; siblings of $HOME, i.e. other users' homes, are covered when
# the parent is small enough to enumerate).

# Upper bound for enumerating the siblings of $HOME (e.g. /home). Big
# NFS home trees would cost one mount per user; beyond this the other
# homes keep their Unix permissions (they are rarely writable anyway).
_FJ_HOME_SIBLINGS_MAX=256

# _fj_owned_by_me PATH — true when PATH (following symlinks) belongs to
# the current user. Root owns everything for firejail's check.
_fj_owned_by_me() {
    local _u
    [[ "$(id -u)" == 0 ]] && return 0
    _u="$(stat -L -c %u -- "$1" 2>/dev/null)" || return 1
    [[ "$_u" == "$(id -u)" ]]
}

# _fj_is_proper_ancestor ANC PATH
_fj_is_proper_ancestor() {
    [[ "$1" != "$2" ]] && _path_under "$2" "$1"
}

# _fj_foreign_below DIR — true when a foreign (not user-owned) grant is
# DIR or lies below it.
_fj_foreign_below() {
    local _g
    for _g in "${_FJ_FOREIGN_GRANTS[@]+"${_FJ_FOREIGN_GRANTS[@]}"}"; do
        _path_under "$_g" "$1" && return 0
    done
    return 1
}

# _fj_cover_skip PATH — paths the cover never remounts (see above).
_fj_cover_skip() {
    local _p="$1" _s _g
    for _s in /proc /sys /dev /run /tmp; do
        _path_under "$_p" "$_s" && return 0
    done
    # $HOME and everything below it: HOME_ACCESS rules.
    _path_under "$_p" "$_FJ_HOME" && return 0
    # Inside a writable grant: the grant decides (bwrap binds it rw).
    for _g in "${_FJ_GRANTS[@]+"${_FJ_GRANTS[@]}"}"; do
        _path_under "$_p" "$_g" && return 0
    done
    return 1
}

# _fj_ro PATH — make PATH read-only (protective overlays, READONLY_MOUNTS),
# or cover it piecewise when it contains a grant the user does not own.
_fj_ro() {
    local _p="$1"
    local _g
    [[ -n "$_p" ]] || return 0
    for _g in "${_FJ_FOREIGN_GRANTS[@]+"${_FJ_FOREIGN_GRANTS[@]}"}"; do
        [[ "$_p" == "$_g" ]] && return 0
    done
    if _fj_foreign_below "$_p"; then
        _fj_cover "$_p"
    else
        FIREJAIL_ARGS+=(--read-only="$_p")
    fi
}

# _fj_cover DIR — remount every child of DIR read-only, descending into
# children that are ancestors of $HOME or of a foreign grant.
_fj_cover() {
    local _d="$1" _e _n=0
    [[ -z "${_FJ_COVERED[$_d]:-}" ]] || return 0
    _FJ_COVERED[$_d]=1
    local _home_anc=false
    _fj_is_proper_ancestor "$_d" "$_FJ_HOME" && _home_anc=true
    if [[ ! -r "$_d" || ! -x "$_d" ]]; then
        _FJ_UNLISTABLE+=("$_d")
        return 0
    fi
    local -a _kids=()
    while IFS= read -r -d '' _e; do
        # Below an autofs mount point, only keys that are mounted now
        # (or lead to $HOME / a foreign grant): remounting a browsable
        # but unmounted key would trigger its automount (a mount storm
        # on /home- or lab-style maps).
        if [[ -n "${_FJ_AUTOFS[$_d]:-}" && -z "${_FJ_MOUNTED[$_e]:-}" ]] \
           && ! _fj_is_proper_ancestor "$_e" "$_FJ_HOME" && ! _fj_foreign_below "$_e"; then
            continue
        fi
        _kids+=("$_e")
    done < <(find "$_d" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)
    if $_home_anc && [[ "$_d" != / ]] && (( ${#_kids[@]} > _FJ_HOME_SIBLINGS_MAX )); then
        # Too many siblings of $HOME to remount one by one; still
        # descend towards $HOME (and foreign grants) below.
        _FJ_HOME_SIBLINGS_SKIPPED="$_d"
        for _e in "${_kids[@]}"; do
            [[ -L "$_e" ]] && continue
            _fj_cover_skip "$_e" && continue
            if _fj_is_proper_ancestor "$_e" "$_FJ_HOME" || _fj_foreign_below "$_e"; then
                _fj_cover "$_e"
            fi
        done
        return 0
    fi
    for _e in "${_kids[@]}"; do
        # A symlink is not a mount target of its own: firejail would
        # remount whatever it points to (possibly a grant).
        [[ -L "$_e" ]] && continue
        _fj_cover_skip "$_e" && continue
        if _fj_is_proper_ancestor "$_e" "$_FJ_HOME" || _fj_foreign_below "$_e"; then
            _fj_cover "$_e"
            continue
        fi
        FIREJAIL_ARGS+=(--read-only="$_e")
        _n=$((_n + 1))
    done
    # An ancestor of a foreign grant that the user can write: new
    # entries created directly in it reach the host. Reported below.
    if [[ "$_d" != / ]] && ! $_home_anc && [[ -w "$_d" ]]; then
        _FJ_OPEN_ANCESTORS+=("$_d")
    fi
}

# _fj_check_foreign_grants — after FIREJAIL_ARGS is complete: a foreign
# grant below any --read-only (or below a directory firejail itself
# always mounts read-only) cannot be made writable. Refuse to start
# instead of silently running with a read-only project.
_fj_check_foreign_grants() {
    local _g _a _p _bad=() _implicit=(/etc /usr /bin /sbin /lib /lib32 /lib64 /libx32)
    local _writable_var=false
    for _a in "${FIREJAIL_ARGS[@]}"; do
        [[ "$_a" == --writable-var ]] && _writable_var=true
    done
    $_writable_var || _implicit+=(/var)
    for _g in "${_FJ_FOREIGN_GRANTS[@]+"${_FJ_FOREIGN_GRANTS[@]}"}"; do
        for _p in "${_implicit[@]}"; do
            if _path_under "$_g" "$_p"; then
                _bad+=("$_g (firejail always mounts $_p read-only)")
                continue 2
            fi
        done
        for _a in "${FIREJAIL_ARGS[@]}"; do
            [[ "$_a" == --read-only=* ]] || continue
            _p="${_a#--read-only=}"
            if _path_under "$_g" "$_p"; then
                _bad+=("$_g (below --read-only=$_p)")
                continue 2
            fi
        done
    done
    (( ${#_bad[@]} )) || return 0
    echo "sandbox: ERROR — firejail cannot make these writable paths writable:" >&2
    for _a in "${_bad[@]}"; do echo "  $_a" >&2; done
    echo "  firejail only re-opens read-only directories that you own, and these are" >&2
    echo "  owned by another user (group-writable for you). Use --backend bwrap or" >&2
    echo "  --backend landlock, or move the path out of the read-only area." >&2
    return 1
}

backend_prepare() {
    local project_dir="$1"
    _FIREJAIL_PROJECT_DIR="$project_dir"

    # Agent config overlays are handled by prepare_agent_configs() in sandbox-lib.sh.

    # --- Network filter ---
    # Resolve mode given firejail's capability matrix (open/isolated only
    # in v1; filtered falls back per policy). May exit on strict mismatch.
    resolve_network_filter_mode firejail
    local _NETWORK_FIREJAIL_FLAG=""
    case "$_NETWORK_FILTER_RESOLVED" in
        isolated)
            _NETWORK_FIREJAIL_FLAG="--net=none"
            ;;
        filtered|open)
            : # nothing to add — share host net (filtered v1.0 is unreachable
              # here because the resolver downgrades it via fallback; left
              # as a defensive no-op for the v1.1 --netfilter integration).
            ;;
    esac

    # --- Build firejail arguments ---
    # --private-cwd target mirrors bwrap's --chdir: honor an inherited
    # $SLURM_SUBMIT_DIR when it canonicalizes under $project_dir (see
    # sandbox-lib.sh::_resolve_inherited_cwd). Keeps the two namespace
    # backends in sync.
    local _firejail_cwd
    _firejail_cwd="$(_resolve_inherited_cwd "$project_dir")"
    FIREJAIL_ARGS=(
        --noprofile
        --quiet
        --private-cwd="$_firejail_cwd"
        --caps.drop=all
        --nonewprivs
        --seccomp.drop=io_uring_setup,io_uring_enter,io_uring_register,userfaultfd,kexec_load,kexec_file_load
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

    # Network filter mode → firejail flag (resolved by backend_prepare top).
    if [[ -n "${_NETWORK_FIREJAIL_FLAG:-}" ]]; then
        FIREJAIL_ARGS+=("$_NETWORK_FIREJAIL_FLAG")
    fi

    # --- /tmp ---
    # PRIVATE_TMP=true: --private-tmp mounts a clean tmpfs on /tmp.
    # PRIVATE_TMP=false: the host /tmp is shared (MPI / NCCL rendezvous
    # files); nothing is mounted on /tmp, and the chaperon FIFO dir is
    # then NOT --whitelist'ed (a whitelist under /tmp would make
    # firejail replace /tmp with a tmpfs again; see the FIFO block).
    # /var/tmp: firejail always mounts a private tmpfs there (no
    # --keep-var-tmp); the read-only cover below then remounts /var,
    # this tmpfs included, read-only. Neither mode reaches the host's
    # /var/tmp.
    if _is_true "${PRIVATE_TMP:-true}"; then
        FIREJAIL_ARGS+=(--private-tmp)
    fi

    # IPC namespace isolation: own SysV IPC and POSIX message queues.
    # /dev/shm (POSIX shared memory) is handled with /dev below.
    # Disable via PRIVATE_IPC=false in sandbox.conf if you need
    # cross-sandbox or host-to-sandbox shared memory.
    if _is_true "${PRIVATE_IPC:-true}"; then
        FIREJAIL_ARGS+=(--ipc-namespace)
    fi

    # PID namespace is enabled by default in firejail (no flag needed).
    # --restrict-namespaces prevents the sandboxed process from creating
    # new namespaces to escape.

    # --- /dev ---
    # --private-dev: a fresh tmpfs /dev with the basic nodes (null,
    # zero, full, random, urandom, tty), a NEW devpts instance (other
    # terminals' /dev/pts/N are invisible; pty allocation, tmux and
    # script(1) work; `tty` prints "not a tty" because the inherited
    # terminal has no name inside) and an empty private /dev/shm. Host
    # nodes such as /dev/mqueue, /dev/fuse, /dev/vfio, /dev/net/tun and
    # /dev/loop* are gone. Firejail can carry only the device classes
    # of its own table into a private /dev (/dev/nvidia0-9, nvidiactl,
    # nvidia-modeset, nvidia-uvm, /dev/dri, /dev/snd, video0-9,
    # hidraw0-9, /dev/usb, /dev/input, /dev/sr0), toggled per class by
    # --no3d / --nosound / --novideo / --nou2f / --noinput / --nodvd.
    # DEVICES selects the classes; a resolved DEVICES node outside the
    # table falls back to the host /dev (loud warning), since dropping
    # it would silently break the workload (e.g. /dev/infiniband).
    _resolve_devices
    local _fj_dev _fj_3d=false _fj_snd=false _fj_video=false _fj_u2f=false _fj_input=false _fj_dvd=false
    local -a _fj_dev_unsupported=() _fj_dev_dropped=()
    for _fj_dev in "${DEVICES_RESOLVED[@]+"${DEVICES_RESOLVED[@]}"}"; do
        case "$_fj_dev" in
            /dev/dri|/dev/dri/*|/dev/nvidia[0-9]|/dev/nvidiactl|/dev/nvidia-modeset|/dev/nvidia-uvm)
                _fj_3d=true ;;
            /dev/snd|/dev/snd/*)                 _fj_snd=true ;;
            /dev/video[0-9])                     _fj_video=true ;;
            /dev/hidraw[0-9]|/dev/usb|/dev/usb/*) _fj_u2f=true ;;
            /dev/input|/dev/input/*)             _fj_input=true ;;
            /dev/sr0)                            _fj_dvd=true ;;
            # Profiling-only node matched by the default /dev/nvidia*
            # glob: not worth giving up the private /dev on GPU nodes.
            /dev/nvidia-uvm-tools)               _fj_dev_dropped+=("$_fj_dev") ;;
            *)                                   _fj_dev_unsupported+=("$_fj_dev") ;;
        esac
    done
    $_fj_3d    || FIREJAIL_ARGS+=(--no3d)
    $_fj_snd   || FIREJAIL_ARGS+=(--nosound)
    $_fj_video || FIREJAIL_ARGS+=(--novideo)
    $_fj_u2f   || FIREJAIL_ARGS+=(--nou2f)
    $_fj_input || FIREJAIL_ARGS+=(--noinput)
    $_fj_dvd   || FIREJAIL_ARGS+=(--nodvd)
    if [[ ${#_fj_dev_unsupported[@]} -eq 0 ]]; then
        _FIREJAIL_PRIVATE_DEV=true
        FIREJAIL_ARGS+=(--private-dev)
        # /dev/log is re-bound by --private-dev (journald socket); bwrap
        # has no /dev/log either.
        [[ -e /dev/log ]] && FIREJAIL_ARGS+=(--blacklist=/dev/log)
        # PRIVATE_IPC=true: the private-dev /dev/shm is an empty dir in
        # the sandbox's own /dev tmpfs, i.e. private and usable (Python
        # multiprocessing, shared_memory). false: keep the host's.
        _is_true "${PRIVATE_IPC:-true}" || FIREJAIL_ARGS+=(--keep-dev-shm)
        if [[ ${#_fj_dev_dropped[@]} -gt 0 ]] && ! _is_true "${SANDBOX_QUIET:-false}"; then
            echo "sandbox: firejail private /dev cannot carry: ${_fj_dev_dropped[*]} (not available inside; use bwrap if needed)" >&2
        fi
    else
        _FIREJAIL_PRIVATE_DEV=false
        echo "sandbox: WARNING — firejail: DEVICES lists ${_fj_dev_unsupported[*]}, which firejail's --private-dev cannot provide; using the HOST /dev instead (all device nodes, other terminals' /dev/pts). Use bwrap for a per-node DEVICES allow-list." >&2
        # Host /dev: keep POSIX mqueue files and shm off the host.
        if [[ -d /dev/mqueue ]]; then
            FIREJAIL_ARGS+=(--read-only=/dev/mqueue)
        fi
        if _is_true "${PRIVATE_IPC:-true}"; then
            # Firejail's --tmpfs is ignored on /dev paths; block it.
            FIREJAIL_ARGS+=(--blacklist=/dev/shm)
        fi
    fi

    # --- Filesystem isolation ---
    # Using --whitelist on $HOME paths automatically creates a tmpfs $HOME
    # and only exposes whitelisted entries. No --private needed.
    # --whitelist under any other top-level directory replaces that
    # directory with a tmpfs holding only the whitelisted paths.

    # Writable grants outside the HOME_ACCESS rules, canonicalised the
    # way firejail resolves them (realpath). _FJ_FOREIGN_GRANTS: those
    # the user does not own (see the read-only cover above).
    _FJ_HOME="$(_resolve_path "$HOME")"
    _FJ_GRANTS=("$project_dir")
    _FJ_FOREIGN_GRANTS=()
    _FJ_EXTRA_RW=()
    local _extra_rw _g
    while IFS= read -r _extra_rw; do
        [[ -d "$_extra_rw" ]] || continue
        _FJ_EXTRA_RW+=("$_extra_rw")
        _FJ_GRANTS+=("$(_resolve_path "$_extra_rw")")
    done < <(_effective_extra_writable_paths)
    if [[ -n "${_CHAPERON_FIFO_DIR:-}" && -d "${_CHAPERON_FIFO_DIR:-}" ]]; then
        _FJ_GRANTS+=("$(_resolve_path "$_CHAPERON_FIFO_DIR")")
    fi
    if ! _is_true "${PRIVATE_TMP:-true}" && [[ -d /tmp ]]; then
        _FJ_GRANTS+=(/tmp)
    fi
    for _g in "${_FJ_GRANTS[@]}"; do
        [[ "$_g" == /tmp ]] && continue
        _fj_owned_by_me "$_g" || _FJ_FOREIGN_GRANTS+=("$_g")
    done
    # Firejail itself mounts /var read-only (and noexec) unless
    # --writable-var; a foreign grant below /var needs it (the cover
    # then handles the rest of /var).
    for _g in "${_FJ_FOREIGN_GRANTS[@]+"${_FJ_FOREIGN_GRANTS[@]}"}"; do
        if _path_under "$_g" /var; then
            FIREJAIL_ARGS+=(--writable-var)
            break
        fi
    done

    # Host filesystem outside $HOME: read-only, see _fj_cover.
    declare -gA _FJ_COVERED=() _FJ_AUTOFS=() _FJ_MOUNTED=()
    local _mi_mp _mi_rest _mi_fs
    while read -r _ _ _ _ _mi_mp _mi_rest; do
        _mi_fs="${_mi_rest#* - }"; _mi_fs="${_mi_fs%% *}"
        [[ "$_mi_mp" == *\\* ]] && _mi_mp="$(printf '%b' "${_mi_mp//\\/\\0}")"
        _FJ_MOUNTED[$_mi_mp]=1
        [[ "$_mi_fs" == autofs ]] && _FJ_AUTOFS[$_mi_mp]=1
    done < /proc/self/mountinfo
    _FJ_OPEN_ANCESTORS=()
    _FJ_UNLISTABLE=()
    _FJ_HOME_SIBLINGS_SKIPPED=""
    _fj_cover /

    # Read-only system mounts: already covered above (a no-op inside
    # firejail for paths that are read-only by then); kept explicit so
    # the intent survives if the cover is ever relaxed.
    for mount in "${READONLY_MOUNTS[@]}"; do
        if [[ -d "$mount" || -f "$mount" ]]; then
            _fj_ro "$mount"
        fi
    done

    if [[ ${#_FJ_OPEN_ANCESTORS[@]} -gt 0 ]]; then
        echo "sandbox: WARNING — firejail: ${_FJ_FOREIGN_GRANTS[*]} is not owned by you, so its parent directories cannot be remounted read-only without making it read-only too. New files can still be created directly in: ${_FJ_OPEN_ANCESTORS[*]} (their existing contents are read-only). Use bwrap to close this." >&2
    fi
    if [[ ${#_FJ_UNLISTABLE[@]} -gt 0 ]]; then
        echo "sandbox: WARNING — firejail: cannot list ${_FJ_UNLISTABLE[*]}; entries there keep their host permissions (read-only only where Unix permissions already say so)." >&2
    fi
    if [[ -n "$_FJ_HOME_SIBLINGS_SKIPPED" ]] && ! _is_true "${SANDBOX_QUIET:-false}"; then
        echo "sandbox: firejail: more than $_FJ_HOME_SIBLINGS_MAX entries in $_FJ_HOME_SIBLINGS_SKIPPED; other users' home directories keep their host permissions." >&2
    fi

    # --- /run isolation ---
    # Like bwrap's `--tmpfs /run` + selective binds: a --whitelist under
    # /run makes firejail mount a tmpfs on /run holding only the
    # whitelisted paths, plus its own /run/firejail and /run/user/$UID
    # (masked below). The /run/systemd/resolve whitelist triggers the
    # tmpfs even where that path does not exist. Everything else under
    # /run is gone, so nothing there can be written (/run/lock,
    # /run/screen, ...) or connected to (munge, D-Bus, systemd private
    # and journal sockets, screen/tmux, LDAP ldapi, MySQL, uuidd,
    # containerd, snapd, ...). Previously only a hand-picked deny list
    # of /run paths was hidden and the rest stayed writable/reachable.
    FIREJAIL_ARGS+=(--whitelist=/run/systemd/resolve)
    # nscd: only when FILTER_PASSWD=false (as bwrap); it proxies LDAP/AD.
    if ! _is_true "${FILTER_PASSWD:-true}" && [[ -d /run/nscd ]]; then
        FIREJAIL_ARGS+=(--whitelist=/run/nscd)
    fi
    # /run/user/$UID (systemd --user, D-Bus session bus, gpg/ssh agents;
    # `systemd-run --user` escapes the sandbox): masked. When the
    # chaperon FIFO dir lives there ($TMPDIR under $XDG_RUNTIME_DIR),
    # mask every other entry instead.
    local _runuser="/run/user/$(id -u)" _ru
    if [[ -n "${_CHAPERON_FIFO_DIR:-}" ]] && _path_under "$(_resolve_path "$_CHAPERON_FIFO_DIR")" "$_runuser"; then
        local _fifo_top="${_CHAPERON_FIFO_DIR#"$_runuser"/}"
        _fifo_top="$_runuser/${_fifo_top%%/*}"
        for _ru in /run/user/* "$_runuser"/* "$_runuser"/.[!.]*; do
            [[ -e "$_ru" || -L "$_ru" ]] || continue
            [[ "$_ru" == "$_runuser" || "$_ru" == "$_fifo_top" ]] && continue
            FIREJAIL_ARGS+=(--blacklist="$_ru")
        done
    else
        FIREJAIL_ARGS+=(--blacklist=/run/user)
    fi

    # Munge socket: BLOCKED inside sandbox (chaperon handles auth outside).
    # /run/munge is hidden by the /run tmpfs above. This is intentionally
    # blocked even on compute nodes: exposing munge would allow crafting
    # arbitrary Slurm submissions that bypass the chaperon and don't
    # inherit sandbox restrictions.

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

    # --- Passwd filtering (block NSS daemon sockets) ---
    # nscd, nslcd and sssd sockets under /run are hidden by the /run
    # tmpfs above. sssd's pipes live under /var/lib. Without these
    # sockets, getent passwd returns only local users.
    if _is_true "${FILTER_PASSWD:-true}"; then
        if [[ -e /var/lib/sss/pipes ]]; then
            FIREJAIL_ARGS+=(--blacklist=/var/lib/sss/pipes)
        fi
    fi

    # Nested firejail: --nonewprivs prevents the setuid binary from
    # gaining privileges, --restrict-namespaces blocks new namespace
    # creation, and --join is blocked by --shell=none. The nested
    # instance runs with fewer privileges than the parent sandbox.

    # --- Home directory paths ---
    if [[ "${HOME_ACCESS:-restricted}" == "restricted" || "${HOME_ACCESS}" == "tmpwrite" ]]; then
        # HOME_SEEDED_FILES degrades to read-only on firejail. Producing a
        # writable per-session copy of a host dotfile inside firejail's
        # tmpfs HOME requires either --bind=src,dst (root-only) or a
        # custom entry-point wrapper — neither is in scope for an
        # unprivileged backend. Warn once, then bind read-only via the
        # existing --whitelist + --read-only path.
        local _firejail_seeded_relpaths=()
        local seedf
        for seedf in "${HOME_SEEDED_FILES[@]}"; do
            [[ -f "$HOME/$seedf" ]] || continue
            _firejail_seeded_relpaths+=("$seedf")
        done
        if [[ ${#_firejail_seeded_relpaths[@]} -gt 0 ]] && ! _is_true "${SANDBOX_QUIET:-false}"; then
            echo "sandbox: firejail backend does not support HOME_SEEDED_FILES — bound read-only:" >&2
            local _r
            for _r in "${_firejail_seeded_relpaths[@]}"; do
                echo "  ~/$_r" >&2
            done
        fi

        # Whitelist mode: tmpfs $HOME, selectively mount listed paths
        for subdir in "${HOME_READONLY[@]}"; do
            # Avoid double-mounting when the same entry is also seeded
            local _is_seeded=false
            local _s
            for _s in "${_firejail_seeded_relpaths[@]}"; do
                [[ "$subdir" == "$_s" ]] && { _is_seeded=true; break; }
            done
            $_is_seeded && continue
            local full_path="$HOME/$subdir"
            if [[ -e "$full_path" ]]; then
                FIREJAIL_ARGS+=(--whitelist="$full_path")
                FIREJAIL_ARGS+=(--read-only="$full_path")
            fi
        done

        # Seeded entries — same read-only handling, distinct loop so
        # the user-visible warning above lists exactly what's degraded.
        for subdir in "${_firejail_seeded_relpaths[@]}"; do
            local full_path="$HOME/$subdir"
            FIREJAIL_ARGS+=(--whitelist="$full_path")
            FIREJAIL_ARGS+=(--read-only="$full_path")
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
        local _blocked_sub _bp
        while IFS= read -r _blocked_sub; do
            _bp="$HOME/$_blocked_sub"
            [[ -e "$_bp" ]] && FIREJAIL_ARGS+=(--blacklist="$_bp")
        done < <(_home_blocked_paths)

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
        # write mode: full HOME writable. The read-only cover never
        # remounts $HOME; the explicit grant keeps that intent visible
        # (and re-opens $HOME should an ancestor ever be read-only).
        if [[ "${HOME_ACCESS}" == "write" ]]; then
            FIREJAIL_ARGS+=(--read-write="$HOME")
        fi
    fi

    # ── Writable grants, then protective read-only overlays ─────────
    # Firejail applies --read-only / --read-write in argv order and a
    # --read-write remount is recursive, so ANY grant emitted after a
    # protective --read-only on a descendant re-opens it. All writable
    # grants therefore come first, protective overlays last.

    # Sandbox scripts: read-only. Emitted early only when the project
    # lives inside the install dir (developing agent-sandbox itself) so
    # the project grant below still wins for the project subtree.
    local _sandbox_dir_ro_late=true
    if _path_under "$project_dir" "$SANDBOX_DIR"; then
        _fj_ro "$SANDBOX_DIR"
        _sandbox_dir_ro_late=false
    fi

    # Project directory: writable. A user-owned project below a
    # read-only tree is re-opened here; a project owned by someone else
    # was never put under a read-only mount (see _fj_cover), and an
    # explicit --read-write would only be refused.
    if _fj_owned_by_me "$project_dir"; then
        FIREJAIL_ARGS+=(--read-write="$project_dir")
    fi

    # Additional writable directories. Entries equal to or above $HOME
    # are dropped by _effective_extra_writable_paths.
    local _extra_rw
    for _extra_rw in "${_FJ_EXTRA_RW[@]+"${_FJ_EXTRA_RW[@]}"}"; do
        if [[ "${HOME_ACCESS:-restricted}" == "restricted" || "${HOME_ACCESS:-restricted}" == "tmpwrite" ]] \
           && _path_under "$_extra_rw" "$HOME"; then
            FIREJAIL_ARGS+=(--whitelist="$_extra_rw")
        fi
        if _fj_owned_by_me "$_extra_rw"; then
            FIREJAIL_ARGS+=(--read-write="$_extra_rw")
        fi
    done

    # Shared /tmp (PRIVATE_TMP=false) needs no grant: the cover never
    # remounts /tmp, so it keeps the host's permissions.

    if $_sandbox_dir_ro_late; then
        FIREJAIL_ARGS+=(--read-only="$SANDBOX_DIR")
    fi

    # .sandbox-state/ — chaperon-owned state subdir, RO-overlaid AFTER
    # every writable grant so the agent can't tamper with the
    # chaperon's slurm-log staging area or the chaperon diagnostic log.
    # Mirrors bwrap's --ro-bind; threat-model framing + the distinction
    # from reverted PR #50 documented in sandbox-lib.sh's
    # `.sandbox-state/` section. sandbox-exec.sh creates and sanitizes
    # the dir before backend_prepare, so it always exists here; fail
    # closed if that step was bypassed.
    local _state_dir="$project_dir/.sandbox-state"
    if [[ ! -d "$_state_dir" || -L "$_state_dir" ]]; then
        _prepare_sandbox_state_dir "$project_dir" firejail || exit 1
    fi
    FIREJAIL_ARGS+=(--read-only="$_state_dir")

    # Always-read-only $HOME paths (_HOME_ALWAYS_READONLY, e.g. the
    # sandbox's own ~/.config/agent-sandbox), every HOME_ACCESS mode.
    # Emitted AFTER every --read-write grant above (HOME=write,
    # HOME_WRITABLE, project dir, EXTRA_WRITABLE_PATHS): a later
    # recursive --read-write would re-open it. No --whitelist: the
    # helper only emits paths some writable grant already exposes.
    local _aro
    while IFS= read -r _aro; do
        [[ -n "$_aro" ]] && FIREJAIL_ARGS+=(--read-only="$_aro")
    done < <(_home_always_readonly_targets "$project_dir")

    # Agent-specific file hiding (e.g., CLAUDE.md, AGENTS.md) is handled
    # by BLOCKED_FILES, populated from agents/*/config.conf by _apply_agent_profiles().

    # --- Blocked files ---
    # No [[ -e ]] guard: sandbox-lib's _ensure_blocked_files_exist (called
    # from sandbox-exec.sh before backend_prepare) has already either
    # materialized a placeholder for every entry or refused to start.
    # See #73.
    for blocked in "${BLOCKED_FILES[@]}"; do
        # Resolve symlinks — firejail --blacklist may not follow them.
        # Blocking both the symlink and its target ensures coverage.
        FIREJAIL_ARGS+=(--blacklist="$blocked")
        if [[ -L "$blocked" ]]; then
            local _resolved
            _resolved="$(readlink -f "$blocked")"
            [[ "$_resolved" != "$blocked" ]] && FIREJAIL_ARGS+=(--blacklist="$_resolved")
        fi
    done

    # Agent sandbox-config directories: make visible (and, like bwrap,
    # writable — the agent needs lock files, $CLAUDE_CONFIG_DIR/.claude.json,
    # copy-on-launch configs such as codex's config.toml). The merged
    # instruction/settings files inside are made read-only individually
    # by the _AGENT_PROTECTED_FILES loop below. In restricted/tmpwrite
    # mode, --whitelist is needed to punch through the tmpfs overlay. In
    # read/write mode, HOME is already fully visible — using --whitelist
    # would trigger firejail's tmpfs HOME and break the full-HOME intent.
    for _agent_dir in "${_AGENT_SANDBOX_CONFIG_DIRS[@]:-}"; do
        if [[ -n "$_agent_dir" && -d "$_agent_dir" ]]; then
            if [[ "${HOME_ACCESS:-restricted}" == "restricted" || "${HOME_ACCESS}" == "tmpwrite" ]]; then
                FIREJAIL_ARGS+=(--whitelist="$_agent_dir")
            fi
        fi
    done

    # Individual protected agent files: the merged instruction/settings
    # copies AND the real host-executed agent config the overlays
    # register (e.g. ~/.claude/settings.json, ~/.codex/config.toml),
    # which sits inside a writable agent dir. Read-only inside so the
    # agent cannot plant hooks / MCP servers that run unsandboxed on the
    # user's next outside launch. Overlays only register regular files;
    # a symlink is skipped (marking it would protect its target instead).
    for _protected in "${_AGENT_PROTECTED_FILES[@]:-}"; do
        [[ -n "$_protected" && -f "$_protected" && ! -L "$_protected" ]] || continue
        FIREJAIL_ARGS+=(--read-only="$_protected")
    done

    # Extra blocked paths
    for blocked in "${EXTRA_BLOCKED_PATHS[@]}"; do
        if [[ -e "$blocked" ]]; then
            FIREJAIL_ARGS+=(--blacklist="$blocked")
        fi
    done

    # --- Filter environment variables ---
    # Like landlock, we filter in-shell since firejail doesn't have
    # per-variable --unsetenv.
    _warn_pattern_blocked_vars
    for var in "${BLOCKED_ENV_VARS[@]}"; do
        _is_allowed_env "$var" || unset "$var" 2>/dev/null || true
    done

    # Block credential-pattern vars (SSH_*, *_TOKEN, CI_*, etc.) from BLOCKED_ENV_PATTERNS.
    # To let a specific variable through, add it to ALLOWED_ENV_VARS.
    while IFS='=' read -r name _; do
        _is_blocked_by_pattern "$name" && { unset "$name" 2>/dev/null || true; } || true
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

    # Pass chaperon FIFO directory into the sandbox. --whitelist only
    # where firejail replaces the parent with a tmpfs: /tmp with
    # PRIVATE_TMP=true (--private-tmp), /run (always, see above), and
    # $HOME in restricted/tmpwrite. Anywhere else a --whitelist would
    # itself turn the top-level directory into a tmpfs holding only the
    # FIFO dir: with PRIVATE_TMP=false that replaced the shared host
    # /tmp by a private one, and a $TMPDIR such as /fh/scratch/... hid
    # the rest of /fh (including a project there).
    if [[ -n "${_CHAPERON_FIFO_DIR:-}" && -d "${_CHAPERON_FIFO_DIR:-}" ]]; then
        export _CHAPERON_FIFO_DIR
        local _fifo_real
        _fifo_real="$(_resolve_path "$_CHAPERON_FIFO_DIR")"
        if { _is_true "${PRIVATE_TMP:-true}" && _path_under "$_fifo_real" /tmp; } \
           || _path_under "$_fifo_real" /run \
           || { [[ "${HOME_ACCESS:-restricted}" == restricted || "${HOME_ACCESS:-restricted}" == tmpwrite ]] \
                && _path_under "$_fifo_real" "$_FJ_HOME"; }; then
            FIREJAIL_ARGS+=(--whitelist="$_CHAPERON_FIFO_DIR")
        fi
        # Stubs create per-request response FIFOs here; re-open it
        # when $TMPDIR is inside a read-only tree (user-owned: mktemp).
        FIREJAIL_ARGS+=(--read-write="$_CHAPERON_FIFO_DIR")
    fi

    # Fork bomb defense-in-depth: firejail has native rlimit support
    if [[ -n "${SANDBOX_NPROC_LIMIT:-}" ]]; then
        FIREJAIL_ARGS+=(--rlimit-nproc="$SANDBOX_NPROC_LIMIT")
    fi

    # A writable grant owned by someone else that still ended up below a
    # read-only mount would silently be read-only: refuse instead.
    _fj_check_foreign_grants || exit 1

}

# backend_mount_expectations — the path-level mounts FIREJAIL_ARGS asks
# for, one "<kind> <path>" per line, for the mount guard (sandbox-lib.sh
# §Mount guard). --read-only / --read-write / --blacklist each put a
# mount at the path inside firejail's namespace; --whitelist is left out
# (firejail rebuilds the parent dir around it). Paths firejail did not
# turn into a mount point of their own are dropped by the guard's
# baseline.
backend_mount_expectations() {
    local _o
    for _o in "${FIREJAIL_ARGS[@]}"; do
        case "$_o" in
            --read-only=/) ;;
            --read-only=/*)  printf 'ro %s\n'   "${_o#--read-only=}" ;;
            --read-write=/*) printf 'rw %s\n'   "${_o#--read-write=}" ;;
            --blacklist=/*)  printf 'mask %s\n' "${_o#--blacklist=}" ;;
        esac
    done
}

backend_exec() {
    # Hide sandbox-setting vars (HIDE_FROM_SANDBOX). Done HERE, not in
    # backend_prepare's env filter: host-side code that runs between
    # prepare and exec (chaperon spawn, banner gating) still reads
    # several of these. firejail passes our environment through, so an
    # in-process unset is the equivalent of bwrap's --unsetenv.
    local _hv
    while IFS= read -r _hv; do
        unset "$_hv" 2>/dev/null || true
    done < <(_hide_from_sandbox_names)

    # exec (via _exec_or_run_sandbox) so the launcher PID becomes
    # firejail: signals sent to the launcher reach the sandbox (firejail
    # forwards them to its child) instead of killing only this shell and
    # orphaning the sandboxed command.
    _firejail_build_argv || exit 1
    _exec_or_run_sandbox firejail "${_FJ_ARGV[@]}" -- "$@"
    exit $?
}

# ── Passing the options: profile files, not argv ─────────────────
#
# firejail refuses to start with more than 127 arguments (MAX_ARGS 128
# in firejail.h, command included): "Error: too many arguments". A
# default launch already needs ~100 options (upstream main: 92) and
# every HOME_READONLY / BLOCKED_FILES / read-only cover entry adds one,
# so FIREJAIL_ARGS goes into profile files instead. firejail turns each
# command-line option into the same profile line internally
# (`--read-only=X` -> "read-only X"), and entries keep their order, so
# the semantics are unchanged. The profile parser, however, cuts a line
# at '#', collapses runs of blanks and trims the ends: an option whose
# text contains any of those (or a newline, which would inject a line)
# stays on the command line, between the profiles, in its original
# position. The files are unlinked before the exec; firejail reads them
# through inherited descriptors (/proc/self/fd/N), so nothing is left
# behind and no other process can swap them.
_firejail_profile_safe() {
    local _a="$1" _v=""
    [[ "$_a" == --?* ]] || return 1
    case "$_a" in
        *$'\n'*|*$'\r'*|*$'\t'*|*'#'*|*'  '*) return 1 ;;
    esac
    [[ "$_a" == *=* ]] && _v="${_a#*=}"
    [[ "$_v" != ' '* && "$_v" != *' ' ]] || return 1
    (( ${#_a} < 4000 ))
}

_firejail_flush_profile() {
    (( ${#_FJ_RUN[@]} )) || return 0
    local _f="$_FJ_PROFILE_DIR/p${#_FJ_ARGV[@]}.profile" _fd _l
    : > "$_f" || return 1
    for _l in "${_FJ_RUN[@]}"; do
        printf '%s\n' "$_l" >> "$_f" || return 1
    done
    exec {_fd}<"$_f" || return 1
    _FJ_ARGV+=(--profile="/proc/self/fd/$_fd")
    _FJ_PROFILES=$((_FJ_PROFILES + 1))
    _FJ_RUN=()
}

# _firejail_build_argv — FIREJAIL_ARGS -> _FJ_ARGV (see above).
_firejail_build_argv() {
    local _a _name
    _FJ_ARGV=(--quiet)   # first: also silences "Reading profile ..."
    _FJ_RUN=()
    _FJ_PROFILES=0
    _FJ_PROFILE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/agent-sandbox-firejail-XXXXXX")" || {
        echo "sandbox: ERROR — cannot create a temporary directory for the firejail profile." >&2
        return 1
    }
    chmod 700 "$_FJ_PROFILE_DIR"
    for _a in "${FIREJAIL_ARGS[@]}"; do
        case "$_a" in --noprofile|--quiet) continue ;; esac
        if _firejail_profile_safe "$_a"; then
            _a="${_a#--}"
            if [[ "$_a" == *=* ]]; then
                _name="${_a%%=*}"
                _FJ_RUN+=("$_name ${_a#*=}")
            else
                _FJ_RUN+=("$_a")
            fi
        else
            _firejail_flush_profile || { rm -rf -- "$_FJ_PROFILE_DIR"; return 1; }
            _FJ_ARGV+=("$_a")
        fi
    done
    _firejail_flush_profile || { rm -rf -- "$_FJ_PROFILE_DIR"; return 1; }
    rm -rf -- "$_FJ_PROFILE_DIR"
    # --profile and --noprofile are mutually exclusive; without any
    # profile file, keep firejail from loading its default profile.
    (( _FJ_PROFILES )) || _FJ_ARGV=(--noprofile "${_FJ_ARGV[@]}")
    if (( ${#_FJ_ARGV[@]} > 100 )); then
        echo "sandbox: ERROR — ${#_FJ_ARGV[@]} firejail options must stay on the command line (paths containing '#', tabs or repeated spaces); firejail accepts at most 127 arguments." >&2
        return 1
    fi
}

backend_dry_run() {
    echo "# Backend: firejail"
    echo "# Binary: $(command -v firejail)"
    echo "# (options are passed as profile files at launch; see _firejail_build_argv)"
    printf 'firejail \\\n'
    for arg in "${FIREJAIL_ARGS[@]}"; do
        printf '  %s \\\n' "$arg"
    done
    printf '  -- %s\n' "$*"
}

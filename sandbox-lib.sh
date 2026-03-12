#! /bin/bash --
# sandbox-lib.sh — Core sandbox library (backend-agnostic)
#
# Sourced by sandbox-exec.sh, sbatch-sandbox.sh, srun-sandbox.sh.
# Reads configuration from sandbox.conf, detects the best available backend,
# and provides:
#
#   detect_backend            — sets SANDBOX_BACKEND (bwrap, firejail, or landlock)
#   validate_project_dir DIR  — checks DIR is allowed
#   backend_available         — can this backend work?
#   backend_prepare DIR       — set up the sandbox for DIR
#   backend_exec CMD...       — run CMD inside the sandbox (execs)
#   backend_dry_run CMD...    — print what would be run

set -euo pipefail

SANDBOX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_CONF="${SANDBOX_CONF:-$SANDBOX_DIR/sandbox.conf}"

# ── Defaults (overridden by sandbox.conf) ───────────────────────

ALLOWED_PROJECT_PARENTS=("/fh/fast" "/fh/scratch" "$HOME")

READONLY_MOUNTS=(
    "/usr" "/lib" "/lib64" "/bin" "/sbin" "/etc"
    "/app"
)

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
    ".local"
    "micromamba"
    ".condarc"
    ".mambarc"
)

HOME_WRITABLE=(
    ".claude"
    ".claude.json"
    ".local/state/claude"
    ".local/share/claude"
    ".cache"
)

BLOCKED_FILES=()

EXTRA_BLOCKED_PATHS=()

EXTRA_WRITABLE_PATHS=()

# Path to the Slurm sandbox bypass token (see ADMIN_HARDENING.md §1).
# When set, the bwrap backend automatically hides this file from the sandbox
# (overlays it with /dev/null). For the Landlock backend, use the eBPF LSM
# program instead (see slurm-enforce/token_protect.bpf.c).
# Isolate /tmp with a private tmpfs (firejail backend only).
# Default: true. Set to false if the sandboxed process needs shared /tmp
# access (e.g., MPI shared-memory transport between ranks on the same node,
# or NCCL inter-GPU communication via /tmp sockets).
PRIVATE_TMP=true

# Filter /etc/passwd inside the sandbox to prevent LDAP/AD user enumeration.
# When true, generates a minimal /etc/passwd (system UIDs < 1000 + current
# user) and overrides nsswitch.conf to use "files" only (no ldap/sss).
# bwrap: overlays /etc/passwd + /etc/nsswitch.conf via --ro-bind.
# firejail: blocks NSS daemon sockets (nscd, nslcd, sssd).
# landlock: not supported (no mount namespace).
FILTER_PASSWD=true

# Bind host /dev into the sandbox instead of bwrap's minimal devtmpfs.
# Required for tmux (pty allocation) on kernels < 5.4. Exposes host
# /dev/pts — on kernels < 6.2 a same-user process could use TIOCSTI
# to inject keystrokes into unsandboxed terminals. See sandbox.conf.
BIND_DEV_PTS=false

# Path to the Slurm bypass token file.  bwrap/firejail hide it inside
# the sandbox.  If empty and /etc/slurm/sandbox-wrapper.conf exists,
# TOKEN_FILE from that file is used automatically.
SANDBOX_BYPASS_TOKEN=""

BLOCKED_ENV_VARS=(
    "GITHUB_PAT" "GITHUB_TOKEN" "GH_TOKEN"
    "OPENAI_API_KEY" "ANTHROPIC_API_KEY" "ZENODO_TOKEN" "HF_TOKEN"
    "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "AWS_SESSION_TOKEN"
    "ST_AUTH" "SW2_URL"
    "MUTT_EMAIL_ADDRESS" "MUTT_REALNAME" "MUTT_SMTP_URL"
    "KRB5CCNAME" "SSH_CLIENT" "SSH_CONNECTION" "SSH_TTY"
    "DBUS_SESSION_BUS_ADDRESS" "OLDPWD"
    "TMUX" "TMUX_PANE"
)


# ── Helpers: boolean normalization ─────────────────────────────
# Accept true/True/TRUE/yes/1 as truthy; everything else is false.
# Used for all boolean config values to prevent silent misconfiguration.
_is_true() {
    case "${1,,}" in  # bash 4+ lowercase
        true|yes|1) return 0 ;;
        *) return 1 ;;
    esac
}

# ── Multi-level config loading ──────────────────────────────────
#
# Config hierarchy (each layer adds to the previous):
#   1. Defaults (above)
#   2. Admin config (/opt/claude-sandbox/sandbox.conf) — security baseline
#   3. User config (~/.claude/sandbox/user.conf) — additive customization
#   4. Per-project overrides (conf.d/*.conf) — project-specific additions
#
# When an admin config exists, security-critical arrays (BLOCKED_FILES,
# BLOCKED_ENV_VARS, EXTRA_BLOCKED_PATHS) are enforced: user/project
# configs can add entries but not remove admin-set ones. Items in the
# admin's HOME_READONLY cannot be moved to HOME_WRITABLE.
#
# Without an admin config, behavior is identical to a single sandbox.conf.
# See ADMIN_INSTALL.md for setup instructions.

# Preserve any SANDBOX_BACKEND set via environment or --backend flag
# so config files cannot override an explicit backend selection.
_SANDBOX_BACKEND_OVERRIDE="${SANDBOX_BACKEND:-}"

# --- Determine config files ---
_ADMIN_CONF=""
_USER_CONF=""

if [[ "${SANDBOX_CONF:-}" != "" && "$SANDBOX_CONF" != "$SANDBOX_DIR/sandbox.conf" ]]; then
    # Explicit SANDBOX_CONF override — single config, backward compat
    _USER_CONF="$SANDBOX_CONF"
elif [[ -f "/opt/claude-sandbox/sandbox.conf" ]]; then
    # Admin-installed: admin config is authoritative
    _ADMIN_CONF="/opt/claude-sandbox/sandbox.conf"
    _USER_CONF="$HOME/.claude/sandbox/user.conf"
else
    # User-only install: single config
    _USER_CONF="$SANDBOX_DIR/sandbox.conf"
fi

# --- Helper: source a config file with syntax check ---
_source_config() {
    local _conf="$1"
    if ! bash -n "$_conf" 2>/dev/null; then
        echo "Error: Syntax error in $_conf" >&2
        bash -n "$_conf" >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    source "$_conf"
}

# --- Admin enforcement: snapshot and validate ---
_snapshot_admin_config() {
    _ADMIN_BLOCKED_FILES=("${BLOCKED_FILES[@]}")
    _ADMIN_BLOCKED_ENV_VARS=("${BLOCKED_ENV_VARS[@]}")
    _ADMIN_EXTRA_BLOCKED_PATHS=("${EXTRA_BLOCKED_PATHS[@]}")
    _ADMIN_HOME_READONLY=("${HOME_READONLY[@]}")
}

_validate_admin_enforcement() {
    [[ -z "$_ADMIN_CONF" ]] && return 0

    local _violations=()

    # Check that admin-enforced entries were not removed
    local _arrays=("BLOCKED_FILES" "BLOCKED_ENV_VARS" "EXTRA_BLOCKED_PATHS")
    local _admin_arrays=("_ADMIN_BLOCKED_FILES" "_ADMIN_BLOCKED_ENV_VARS" "_ADMIN_EXTRA_BLOCKED_PATHS")

    for _i in 0 1 2; do
        local _arr_name="${_arrays[$_i]}"
        local _admin_name="${_admin_arrays[$_i]}"
        eval "local _admin_items=(\"\${${_admin_name}[@]}\")"
        eval "local _current_items=(\"\${${_arr_name}[@]}\")"

        for _admin_item in "${_admin_items[@]}"; do
            local _found=false
            for _current_item in "${_current_items[@]}"; do
                [[ "$_current_item" == "$_admin_item" ]] && { _found=true; break; }
            done
            $_found || _violations+=("$_arr_name: admin entry '$_admin_item' was removed")
        done
    done

    # Check HOME_READONLY → HOME_WRITABLE escalation
    for _admin_item in "${_ADMIN_HOME_READONLY[@]}"; do
        for _rw_item in "${HOME_WRITABLE[@]}"; do
            [[ "$_rw_item" == "$_admin_item" ]] && \
                _violations+=("HOME_READONLY→HOME_WRITABLE: admin read-only entry '$_admin_item' moved to writable")
        done
    done

    if [[ ${#_violations[@]} -gt 0 ]]; then
        echo "Error: User config violates admin-enforced security policy:" >&2
        for _v in "${_violations[@]}"; do
            echo "  - $_v" >&2
        done
        echo "" >&2
        echo "Admin config: $_ADMIN_CONF" >&2
        echo "User config:  ${_USER_CONF:-conf.d}" >&2
        exit 1
    fi
}

# --- Source configs ---
if [[ -n "$_ADMIN_CONF" && -f "$_ADMIN_CONF" ]]; then
    _source_config "$_ADMIN_CONF"
    _snapshot_admin_config
fi

if [[ -f "$_USER_CONF" ]]; then
    _source_config "$_USER_CONF"
    _validate_admin_enforcement
fi

# Restore explicit backend override (env/CLI takes precedence over config)
if [[ -n "$_SANDBOX_BACKEND_OVERRIDE" ]]; then
    SANDBOX_BACKEND="$_SANDBOX_BACKEND_OVERRIDE"
fi

# ── Validate config ──────────────────────────────────────────────

# Reject command substitution or backticks in path arrays (defense in depth).
# The config file is user-owned, but catching these prevents accidental or
# copy-paste injection of $(cmd) or `cmd` into path values.
_validate_path_array() {
    local name="$1"; shift
    for item in "$@"; do
        if [[ "$item" =~ \$\( ]] || [[ "$item" =~ \` ]]; then
            echo "Error: Command substitution in $name: $item" >&2
            exit 1
        fi
    done
}

# ── Per-project config overrides ─────────────────────────────────
#
# Source all *.conf files in conf.d/ with _PROJECT_DIR set, so each
# file can guard itself with:
#   [[ "$_PROJECT_DIR" == /some/prefix/* ]] || return 0
# and append to READONLY_MOUNTS, EXTRA_WRITABLE_PATHS, etc.
#
# Called from sandbox-exec.sh after PROJECT_DIR is resolved.

load_project_config() {
    local _PROJECT_DIR="$1"
    export _PROJECT_DIR
    local _conf_d="$SANDBOX_DIR/conf.d"
    if [[ -d "$_conf_d" ]]; then
        local _f
        for _f in "$_conf_d"/*.conf; do
            [[ -f "$_f" ]] || continue
            if ! bash -n "$_f" 2>/dev/null; then
                echo "Error: Syntax error in $_f" >&2
                bash -n "$_f" >&2
                exit 1
            fi
            # shellcheck disable=SC1090
            source "$_f"
        done
    fi
    unset _PROJECT_DIR

    # Validate all path arrays (covers sandbox.conf + conf.d/ additions)
    _validate_path_array ALLOWED_PROJECT_PARENTS "${ALLOWED_PROJECT_PARENTS[@]}"
    _validate_path_array READONLY_MOUNTS "${READONLY_MOUNTS[@]}"
    _validate_path_array HOME_READONLY "${HOME_READONLY[@]}"
    _validate_path_array HOME_WRITABLE "${HOME_WRITABLE[@]}"
    _validate_path_array BLOCKED_FILES "${BLOCKED_FILES[@]}"
    _validate_path_array EXTRA_BLOCKED_PATHS "${EXTRA_BLOCKED_PATHS[@]}"
    _validate_path_array EXTRA_WRITABLE_PATHS "${EXTRA_WRITABLE_PATHS[@]}"

    # Enforce admin policy after conf.d overrides
    _validate_admin_enforcement
}

# Fail early if HOME is unset (many paths depend on it).
if [[ -z "${HOME:-}" ]]; then
    echo "Error: \$HOME is not set." >&2
    exit 1
fi

# Warn about critical READONLY_MOUNTS that are missing from config.
# Without these, the sandbox starts but almost nothing works inside it.
for _critical_mount in /usr /lib /bin /sbin /etc; do
    _found=false
    for _m in "${READONLY_MOUNTS[@]}"; do
        if [[ "$_m" == "$_critical_mount" ]]; then _found=true; break; fi
    done
    if ! $_found && [[ -d "$_critical_mount" ]]; then
        echo "WARNING: $_critical_mount is not in READONLY_MOUNTS. The sandbox may not function correctly." >&2
    fi
done

# Warn about critical HOME_WRITABLE entries required by Claude Code.
for _critical_home in ".claude" ".claude.json"; do
    _found=false
    for _hw in "${HOME_WRITABLE[@]}"; do
        if [[ "$_hw" == "$_critical_home" ]]; then _found=true; break; fi
    done
    if ! $_found; then
        echo "WARNING: $HOME/$_critical_home is not in HOME_WRITABLE. Claude Code may not function correctly." >&2
    fi
done

# Detect paths that appear in both HOME_READONLY and HOME_WRITABLE.
# The writable mount wins (later bwrap arg overrides), which may
# silently escalate permissions beyond what the user intended.
for _ro in "${HOME_READONLY[@]}"; do
    for _rw in "${HOME_WRITABLE[@]}"; do
        if [[ "$_ro" == "$_rw" ]]; then
            echo "WARNING: $HOME/$_ro is in both HOME_READONLY and HOME_WRITABLE (writable wins)." >&2
        fi
    done
done

# Warn when backend-specific features are used with an incompatible backend.
if [[ "${SANDBOX_BACKEND:-auto}" == "landlock" ]]; then
    if _is_true "${FILTER_PASSWD:-true}"; then
        echo "WARNING: FILTER_PASSWD=true has no effect with the Landlock backend (no mount namespace)." >&2
        echo "  User enumeration prevention requires bwrap or firejail." >&2
    fi
    if [[ ${#BLOCKED_FILES[@]} -gt 0 ]]; then
        echo "WARNING: BLOCKED_FILES has no effect with the Landlock backend." >&2
        echo "  Individual file blocking requires bwrap or firejail." >&2
    fi
fi
if [[ "${SANDBOX_BACKEND:-auto}" != "bwrap" && "${SANDBOX_BACKEND:-auto}" != "auto" ]]; then
    if _is_true "${BIND_DEV_PTS:-false}"; then
        echo "WARNING: BIND_DEV_PTS only applies to the bwrap backend." >&2
    fi
fi

# Auto-discover bypass token from admin wrapper config if not set explicitly
if [[ -z "${SANDBOX_BYPASS_TOKEN:-}" && -f /etc/slurm/sandbox-wrapper.conf ]]; then
    # TOKEN_FILE is the admin-side name for the same path
    _wrapper_token=$(bash -c 'source /etc/slurm/sandbox-wrapper.conf 2>/dev/null; echo "$TOKEN_FILE"')
    if [[ -n "$_wrapper_token" ]]; then
        SANDBOX_BYPASS_TOKEN="$_wrapper_token"
    fi
    unset _wrapper_token
fi

# ── Helpers ─────────────────────────────────────────────────────

validate_project_dir() {
    local dir="$1"
    for parent in "${ALLOWED_PROJECT_PARENTS[@]}"; do
        parent="${parent/\$HOME/$HOME}"
        parent="${parent%/}"  # strip trailing slash
        # Exact match or proper subdirectory (with / boundary).
        # Without the boundary check, parent=/home/alice would
        # incorrectly match dir=/home/alicebob/project.
        if [[ "$dir" == "$parent" || "$dir" == "$parent/"* ]]; then
            return 0
        fi
    done
    echo "Error: Project directory not under an allowed parent path." >&2
    echo "  Got: $dir" >&2
    echo "  Allowed prefixes: ${ALLOWED_PROJECT_PARENTS[*]}" >&2
    echo "  Edit ALLOWED_PROJECT_PARENTS in $SANDBOX_CONF to allow more." >&2
    return 1
}

# ── Passwd filtering (LDAP/AD user enumeration prevention) ────────
#
# Generates a minimal /etc/passwd and /etc/nsswitch.conf for use inside
# the sandbox.  The filtered passwd contains only system accounts
# (UID < 1000) and the current user.  The filtered nsswitch.conf
# replaces "ldap", "sss", and "compat" with "files" for the passwd
# and group databases, so getent only returns local entries.
#
# Sets _FILTERED_PASSWD and _FILTERED_NSSWITCH to the generated paths.
# Backends that support file overlays (bwrap) use these directly.

generate_filtered_passwd() {
    _is_true "${FILTER_PASSWD:-true}" || return 0

    local tmpdir="$SANDBOX_DIR/.passwd-filter"
    mkdir -p "$tmpdir"

    local my_uid
    my_uid="$(id -u)"

    # Minimal passwd: system accounts (UID < 1000) from the local file.
    # Does NOT use getent for the base set (that would pull all LDAP users).
    awk -F: '($3 < 1000)' /etc/passwd > "$tmpdir/passwd"

    # Append specific users via getent (handles both local and LDAP).
    # Current user + service users needed by tools inside the sandbox.
    for _svc_user in "$(id -un)" slurm munge nobody; do
        if ! grep -q "^${_svc_user}:" "$tmpdir/passwd"; then
            getent passwd "$_svc_user" >> "$tmpdir/passwd" 2>/dev/null || true
        fi
    done

    # Minimal group: system groups (GID < 1000) from the local file.
    awk -F: '($3 < 1000)' /etc/group > "$tmpdir/group"

    # Append current user's groups, service groups, and well-known groups
    # by name (nogroup/nfsnobody may appear via NFS even when not in id -G).
    for _svc_group in nogroup nfsnobody; do
        if ! grep -q "^${_svc_group}:" "$tmpdir/group"; then
            getent group "$_svc_group" >> "$tmpdir/group" 2>/dev/null || true
        fi
    done
    for _svc_gid in $(id -G) $(getent passwd slurm 2>/dev/null | cut -d: -f4) $(getent passwd munge 2>/dev/null | cut -d: -f4); do
        if ! grep -q "^[^:]*:[^:]*:${_svc_gid}:" "$tmpdir/group"; then
            getent group "$_svc_gid" >> "$tmpdir/group" 2>/dev/null || true
        fi
    done

    # nsswitch.conf: replace ldap/sss/compat with files-only for passwd/group
    if [[ -f /etc/nsswitch.conf ]]; then
        sed -E \
            -e 's/^(passwd|group):.*$/\1:         files/' \
            /etc/nsswitch.conf > "$tmpdir/nsswitch.conf"
    else
        printf 'passwd:         files\ngroup:          files\nhosts:          files dns\n' \
            > "$tmpdir/nsswitch.conf"
    fi

    _FILTERED_PASSWD="$tmpdir/passwd"
    _FILTERED_GROUP="$tmpdir/group"
    _FILTERED_NSSWITCH="$tmpdir/nsswitch.conf"
}

# ── Config directory overlay ──────────────────────────────────────
#
# Creates a sandbox config directory with merged CLAUDE.md and
# settings.json, then sets CLAUDE_CONFIG_DIR so Claude Code uses it
# instead of the real config dir.  This is backend-independent and
# eliminates in-place file swapping entirely.
#
# Respects an existing CLAUDE_CONFIG_DIR (reads from it, places
# sandbox-config/ inside it).
#
# Layout:  <config-dir>/sandbox-config/
#            CLAUDE.md       — user's original + sandbox snippet
#            settings.json   — user's settings + sandbox permissions
#            *               — symlinks to everything else
#
# The directory is rebuilt on every sandbox start. Concurrent sandboxes
# all write the same merged content, so a single shared dir is fine.

prepare_config_dir() {
    # --- Determine the real config directory ---
    # Honour an existing CLAUDE_CONFIG_DIR; default to ~/.claude
    local real_claude_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

    local config_dir="$real_claude_dir/sandbox-config"
    mkdir -p "$config_dir"

    # --- Merge CLAUDE.md ---
    local sandbox_snippet="$SANDBOX_DIR/sandbox-claude.md"
    local user_claude_md="$real_claude_dir/CLAUDE.md"
    {
        if [[ -f "$user_claude_md" ]]; then
            # Strip any stale sandbox injection from a previous in-place backend
            sed '/^# __SANDBOX_INJECTED_9f3a7c__$/,/^$/d' "$user_claude_md"
        fi
        if [[ -f "$sandbox_snippet" ]]; then
            cat "$sandbox_snippet"
        fi
    } > "$config_dir/CLAUDE.md"

    # --- Merge settings.json ---
    local sandbox_settings="$SANDBOX_DIR/sandbox-settings.json"
    local user_settings="$real_claude_dir/settings.json"

    if [[ -f "$sandbox_settings" ]]; then
        [[ -f "$user_settings" ]] || echo '{}' > "$user_settings"
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
" "$user_settings" "$sandbox_settings" > "$config_dir/settings.json"
    elif [[ -f "$user_settings" ]]; then
        cp "$user_settings" "$config_dir/settings.json"
    fi

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    # Claude Code refreshes tokens via write-to-temp + rename, which
    # replaces our symlinks with real files.  Only overwrite with a
    # symlink if the outside file is newer; otherwise keep the
    # sandbox-config copy (e.g. a refreshed token from a prior session).
    for item in "$real_claude_dir"/* "$real_claude_dir"/.*; do
        local name
        name="$(basename "$item")"
        [[ "$name" == "." || "$name" == ".." ]] && continue
        case "$name" in
            CLAUDE.md|settings.json|sandbox-config) continue ;;
        esac
        [[ "$name" == *.sandbox-backup.* ]] && continue
        local target="$config_dir/$name"
        # If a real directory (not symlink) exists in sandbox-config,
        # merge its contents into the real ~/.claude/<name> and replace
        # with a symlink.  This recovers session data that was written
        # to a stale copy instead of through a symlink.
        # Skip bwrap bind-mounts (mountpoint) — can't replace those.
        if [[ -d "$target" && ! -L "$target" ]]; then
            if mountpoint -q "$target" 2>/dev/null; then
                continue
            fi
            # Merge: copy contents into the real directory, skip duplicates
            if [[ -d "$item" ]]; then
                cp -rn "$target"/. "$item"/ 2>/dev/null || true
            fi
            rm -rf "$target"
        fi
        # If target is a real file (not a symlink) and newer than the
        # outside version, keep it — it was refreshed inside the sandbox.
        if [[ -e "$target" && ! -L "$target" && "$target" -nt "$item" ]]; then
            continue
        fi
        ln -snf "$item" "$target"
    done

    export CLAUDE_CONFIG_DIR="$config_dir"
}

# ── Backend detection ───────────────────────────────────────────

# SANDBOX_BACKEND can be set in sandbox.conf or environment.
# Values: auto (picks best available), bwrap, firejail, landlock
SANDBOX_BACKEND="${SANDBOX_BACKEND:-auto}"

detect_backend() {
    if [[ "$SANDBOX_BACKEND" != "auto" ]]; then
        # User explicitly requested a backend
        if [[ ! -f "$SANDBOX_DIR/backends/${SANDBOX_BACKEND}.sh" ]]; then
            echo "Error: Unknown backend '$SANDBOX_BACKEND'" >&2
            echo "  Available: bwrap, firejail, landlock" >&2
            exit 1
        fi
        # shellcheck disable=SC1090
        source "$SANDBOX_DIR/backends/${SANDBOX_BACKEND}.sh"
        if ! backend_available; then
            echo "Error: Requested backend '$SANDBOX_BACKEND' is not available on this system." >&2
            echo "  Host:   $(hostname 2>/dev/null || echo unknown)" >&2
            echo "  Kernel: $(uname -r 2>/dev/null || echo unknown)" >&2
            echo "  LSMs:   $(cat /sys/kernel/security/lsm 2>/dev/null || echo unknown)" >&2
            exit 1
        fi
        return
    fi

    # Auto-detect: try bwrap first (mount namespace), then firejail (setuid),
    # then landlock (LSM — weakest isolation but works everywhere ≥ 5.13)
    # shellcheck disable=SC1090
    source "$SANDBOX_DIR/backends/bwrap.sh"
    if backend_available; then
        SANDBOX_BACKEND=bwrap
        return
    fi

    # shellcheck disable=SC1090
    source "$SANDBOX_DIR/backends/firejail.sh"
    if backend_available; then
        SANDBOX_BACKEND=firejail
        return
    fi

    # shellcheck disable=SC1090
    source "$SANDBOX_DIR/backends/landlock.sh"
    if backend_available; then
        SANDBOX_BACKEND=landlock
        return
    fi

    # Collect diagnostics for troubleshooting
    local _host _kernel _os _userns _lsm _bwrap_path _firejail_path
    _host="$(hostname 2>/dev/null || echo unknown)"
    _kernel="$(uname -r 2>/dev/null || echo unknown)"
    _os="$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo unknown)"
    _bwrap_path="$(command -v bwrap 2>/dev/null || echo "not found")"
    _firejail_path="$(command -v firejail 2>/dev/null || echo "not found")"
    _userns="$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo "unknown")"
    _lsm="$(cat /sys/kernel/security/lsm 2>/dev/null || echo "unknown")"

    echo "Error: No sandbox backend available." >&2
    echo "" >&2
    echo "  Host:       $_host" >&2
    echo "  OS:         $_os" >&2
    echo "  Kernel:     $_kernel" >&2
    echo "  LSMs:       $_lsm" >&2
    echo "  bwrap:      $_bwrap_path" >&2
    echo "  firejail:   $_firejail_path" >&2
    echo "  userns max: $_userns" >&2
    echo "" >&2
    echo "  Tried:" >&2
    echo "    bwrap    — $(if [[ "$_bwrap_path" == "not found" ]]; then echo "binary not found"; elif echo "$_lsm" | grep -q apparmor && sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null | grep -q 1; then echo "blocked by AppArmor userns restriction"; else echo "failed (check user namespace support)"; fi)" >&2
    echo "    firejail — $(if [[ "$_firejail_path" == "not found" ]]; then echo "binary not found"; else echo "failed (check setuid bit or seccomp support)"; fi)" >&2
    echo "    landlock — $(
        local _kmaj _kmin
        _kmaj="$(uname -r | cut -d. -f1)"
        _kmin="$(uname -r | cut -d. -f2)"
        if [[ "$_kmaj" -lt 5 ]] 2>/dev/null || { [[ "$_kmaj" -eq 5 ]] && [[ "$_kmin" -lt 13 ]]; } 2>/dev/null; then
            echo "kernel too old (need ≥ 5.13)"
        elif ! echo "$_lsm" | grep -q landlock; then
            echo "not in active LSM list"
        else
            echo "failed (check CONFIG_SECURITY_LANDLOCK)"
        fi
    )" >&2
    echo "" >&2
    echo "  Fix:" >&2
    echo "    Install bubblewrap:  brew install bubblewrap" >&2
    echo "    Install firejail:    sudo apt install firejail" >&2
    echo "    Or ensure kernel ≥ 5.13 with Landlock enabled." >&2
    exit 1
}

# ── Legacy compatibility ────────────────────────────────────────
# These functions are kept so that existing code that sources sandbox-lib.sh
# and calls build_bwrap_args() directly (e.g., srun-sandbox.sh) still works.
# New code should use detect_backend + backend_prepare + backend_exec.

# Detect on source if not already done (for scripts that source sandbox-lib.sh
# and immediately call build_bwrap_args).
_BACKEND_DETECTED=false

build_bwrap_args() {
    if [[ "$_BACKEND_DETECTED" == false ]]; then
        detect_backend
        _BACKEND_DETECTED=true
    fi
    prepare_config_dir
    backend_prepare "$1"
}

# Expose BWRAP for legacy callers (resolved by bwrap backend)
# This is a no-op if landlock backend is loaded.

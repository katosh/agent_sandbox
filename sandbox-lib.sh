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

# Require bash >= 4.4 for safe empty-array expansion under set -u.
# (In bash < 4.4, "${empty_array[@]}" is an unbound variable error.)
if [[ "${BASH_VERSINFO[0]}" -lt 4 ]] || { [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -lt 4 ]]; }; then
    echo "Error: sandbox-lib.sh requires bash >= 4.4 (found ${BASH_VERSION})." >&2
    exit 1
fi

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
# Can be set as SANDBOX_BYPASS_TOKEN or TOKEN_FILE (the Slurm wrapper name).

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

# Path to the Slurm bypass token file. bwrap/firejail hide it inside
# the sandbox. Can be set as SANDBOX_BYPASS_TOKEN or TOKEN_FILE (the
# Slurm wrapper name).
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
#   3. User config ($SANDBOX_DIR/user.conf) — additive customization
#   4. Per-project overrides ($SANDBOX_DIR/conf.d/*.conf)
#
# When an admin config exists at the hardcoded path, it is loaded first
# as a security baseline. The user's config ($SANDBOX_DIR/user.conf)
# can add entries to security-critical arrays (BLOCKED_FILES,
# BLOCKED_ENV_VARS, EXTRA_BLOCKED_PATHS) but not remove admin-set
# ones. Items in the admin's HOME_READONLY cannot be moved to
# HOME_WRITABLE. The admin path is hardcoded (not an env var) to
# prevent an agent from redirecting it to a controlled directory.
#
# Without an admin config, $SANDBOX_DIR/sandbox.conf is the only config.
# See ADMIN_INSTALL.md for setup instructions.

# Preserve any SANDBOX_BACKEND set via environment or --backend flag
# so config files cannot override an explicit backend selection.
_SANDBOX_BACKEND_OVERRIDE="${SANDBOX_BACKEND:-}"

# --- Determine config files ---
# Admin config path — set as a script variable, not from environment.
# An env var would let an agent redirect to an attacker-controlled dir.
# Change this line if the admin sandbox is installed elsewhere.
_ADMIN_CONF=""
_USER_CONF=""
_ADMIN_DIR="/opt/claude-sandbox"

if [[ "${SANDBOX_CONF:-}" != "" && "$SANDBOX_CONF" != "$SANDBOX_DIR/sandbox.conf" ]]; then
    # Explicit SANDBOX_CONF override — single config, backward compat
    _USER_CONF="$SANDBOX_CONF"
elif [[ -f "$_ADMIN_DIR/sandbox.conf" ]]; then
    # Admin-installed: admin config is authoritative, user gets user.conf
    _ADMIN_CONF="$_ADMIN_DIR/sandbox.conf"
    _USER_CONF="$SANDBOX_DIR/user.conf"
else
    # User-only install: single config
    _USER_CONF="$SANDBOX_DIR/sandbox.conf"
fi

# --- Helper: source a config file with syntax check ---
# Note: bash -n is a usability check (catches typos), not a security gate.
# Security comes from the re-apply block below. This function uses plain
# 'source' (not 'builtin .') because it runs before user config — no
# function-override concern yet.
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

# --- Admin enforcement: snapshot, re-apply, merge ---
#
# Strategy: snapshot admin values → source user config → re-source admin
# config → merge user additions on top. This makes admin values immune to
# code-execution attacks in user configs: even if user.conf redefines
# functions or manipulates variables, re-sourcing the admin config restores
# all admin-set values. User additions (+=) are preserved by diffing
# against the snapshot.
#
# Why not just validate? A validate-and-fail approach relies on functions
# (like _validate_admin_enforcement) that user config could override before
# they run. The re-apply approach doesn't depend on any functions that run
# after user config — the merge logic is inline in sandbox-lib.sh, which
# is admin-owned and not modifiable by the agent (bwrap/firejail protect it
# via mount namespace; Landlock protects the admin config but not scripts).

_snapshot_admin_config() {
    _ADMIN_BLOCKED_FILES=("${BLOCKED_FILES[@]}")
    _ADMIN_BLOCKED_ENV_VARS=("${BLOCKED_ENV_VARS[@]}")
    _ADMIN_EXTRA_BLOCKED_PATHS=("${EXTRA_BLOCKED_PATHS[@]}")
    _ADMIN_HOME_READONLY=("${HOME_READONLY[@]}")
    # Scalar values that user configs must not override
    _ADMIN_SANDBOX_BYPASS_TOKEN="${SANDBOX_BYPASS_TOKEN:-}"
    _ADMIN_TOKEN_FILE="${TOKEN_FILE:-}"
}

# ── Phase 1: Source admin config ──────────────────────────────
if [[ -n "$_ADMIN_CONF" && -f "$_ADMIN_CONF" ]]; then
    _source_config "$_ADMIN_CONF"
    _snapshot_admin_config
fi

# ── Phase 2: Source user config ──────────────────────────────
if [[ -f "$_USER_CONF" ]]; then
    _source_config "$_USER_CONF"
fi

# Reset traps that user config may have installed (e.g., DEBUG trap
# that fires on every statement and could tamper with merge variables).
trap - DEBUG RETURN ERR EXIT

# ── Phase 3: Re-apply admin enforcement ──────────────────────
# After user config may have run arbitrary code, forcefully restore
# admin-enforced values and merge user additions. This block is inline
# (not in a function) so user config cannot override it.
if [[ -n "$_ADMIN_CONF" ]]; then
    # Guard: admin config must still exist (TOCTOU defense)
    if [[ ! -f "$_ADMIN_CONF" ]]; then
        echo "FATAL: Admin config disappeared: $_ADMIN_CONF" >&2
        exit 1
    fi

    # Capture merged state (admin + user additions)
    _MERGED_BLOCKED_FILES=("${BLOCKED_FILES[@]}")
    _MERGED_BLOCKED_ENV_VARS=("${BLOCKED_ENV_VARS[@]}")
    _MERGED_EXTRA_BLOCKED_PATHS=("${EXTRA_BLOCKED_PATHS[@]}")
    _MERGED_HOME_WRITABLE=("${HOME_WRITABLE[@]}")

    # Detect removed admin entries (warn before restoring)
    for _arr in BLOCKED_FILES BLOCKED_ENV_VARS EXTRA_BLOCKED_PATHS; do
        eval "_merged=(\"\${_MERGED_${_arr}[@]}\")"
        eval "_admin=(\"\${_ADMIN_${_arr}[@]}\")"
        for _a in "${_admin[@]}"; do
            _found=false
            for _item in "${_merged[@]}"; do
                [[ "$_item" == "$_a" ]] && { _found=true; break; }
            done
            if ! $_found; then
                echo "WARNING: User config removed admin-enforced ${_arr} entry '${_a}' — restored." >&2
            fi
        done
    done

    # Detect HOME_READONLY → HOME_WRITABLE escalation (warn before undoing)
    for _aro in "${_ADMIN_HOME_READONLY[@]}"; do
        for _item in "${_MERGED_HOME_WRITABLE[@]}"; do
            if [[ "$_item" == "$_aro" ]]; then
                echo "WARNING: User config moved admin HOME_READONLY entry '${_aro}' to HOME_WRITABLE — reverted." >&2
            fi
        done
    done

    # Detect overridden admin scalar values (token path, exec path)
    if [[ -n "$_ADMIN_SANDBOX_BYPASS_TOKEN" && "${SANDBOX_BYPASS_TOKEN:-}" != "$_ADMIN_SANDBOX_BYPASS_TOKEN" ]]; then
        echo "WARNING: User config changed SANDBOX_BYPASS_TOKEN — restored to admin value." >&2
    fi
    if [[ -n "$_ADMIN_TOKEN_FILE" && "${TOKEN_FILE:-}" != "$_ADMIN_TOKEN_FILE" ]]; then
        echo "WARNING: User config changed TOKEN_FILE — restored to admin value." >&2
    fi

    # Re-source admin config to restore all admin values.
    # Uses 'builtin .' to bypass any function-override of 'source'.
    builtin . "$_ADMIN_CONF"

    # Merge: admin base + user-only additions for enforced arrays.
    # Uses eval for indirect array access — _arr is from a hardcoded list
    # (not user input), so this is safe. Cannot use namerefs here because
    # this block is intentionally not inside a function (local -n requires
    # function scope).
    for _arr in BLOCKED_FILES BLOCKED_ENV_VARS EXTRA_BLOCKED_PATHS; do
        eval "_merged=(\"\${_MERGED_${_arr}[@]}\")"
        eval "_admin=(\"\${_ADMIN_${_arr}[@]}\")"
        for _item in "${_merged[@]}"; do
            _in_admin=false
            for _a in "${_admin[@]}"; do
                [[ "$_item" == "$_a" ]] && { _in_admin=true; break; }
            done
            if ! $_in_admin; then
                eval "${_arr}+=(\"\$_item\")"
            fi
        done
    done

    # Remove any admin HOME_READONLY items that user config moved to HOME_WRITABLE
    _CLEAN_WRITABLE=()
    for _item in "${_MERGED_HOME_WRITABLE[@]}"; do
        _is_admin_ro=false
        for _aro in "${_ADMIN_HOME_READONLY[@]}"; do
            [[ "$_item" == "$_aro" ]] && { _is_admin_ro=true; break; }
        done
        $_is_admin_ro || _CLEAN_WRITABLE+=("$_item")
    done
    HOME_WRITABLE=("${_CLEAN_WRITABLE[@]}")

    # Clean up merge temporaries
    unset _MERGED_BLOCKED_FILES _MERGED_BLOCKED_ENV_VARS \
          _MERGED_EXTRA_BLOCKED_PATHS _MERGED_HOME_WRITABLE \
          _CLEAN_WRITABLE _merged _admin _item _in_admin _a \
          _is_admin_ro _aro _arr _found
fi

# Restore explicit backend override (env/CLI takes precedence over config)
if [[ -n "$_SANDBOX_BACKEND_OVERRIDE" ]]; then
    SANDBOX_BACKEND="$_SANDBOX_BACKEND_OVERRIDE"
fi
unset _SANDBOX_BACKEND_OVERRIDE

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

# ── Admin enforcement helper ─────────────────────────────────────
#
# Defined AFTER the inline enforcement block above — safe from user.conf
# function overrides (the inline block already neutralized them). Called
# by load_project_config() to enforce admin policy after conf.d overrides.
# Uses namerefs (bash 4.3+) instead of eval.

_enforce_admin_config() {
    local _label="${1:-Config}"

    if [[ ! -f "$_ADMIN_CONF" ]]; then
        echo "FATAL: Admin config disappeared: $_ADMIN_CONF" >&2
        exit 1
    fi

    # Save current state (post-user/project config)
    local _saved_bf=("${BLOCKED_FILES[@]}")
    local _saved_bev=("${BLOCKED_ENV_VARS[@]}")
    local _saved_ebp=("${EXTRA_BLOCKED_PATHS[@]}")
    local _saved_hw=("${HOME_WRITABLE[@]}")

    # Warn about removed admin entries
    local _a _item _found _aro
    for _a in "${_ADMIN_BLOCKED_FILES[@]}"; do
        _found=false
        for _item in "${_saved_bf[@]}"; do [[ "$_item" == "$_a" ]] && { _found=true; break; }; done
        $_found || echo "WARNING: ${_label} removed admin-enforced BLOCKED_FILES entry '${_a}' — restored." >&2
    done
    for _a in "${_ADMIN_BLOCKED_ENV_VARS[@]}"; do
        _found=false
        for _item in "${_saved_bev[@]}"; do [[ "$_item" == "$_a" ]] && { _found=true; break; }; done
        $_found || echo "WARNING: ${_label} removed admin-enforced BLOCKED_ENV_VARS entry '${_a}' — restored." >&2
    done
    for _a in "${_ADMIN_EXTRA_BLOCKED_PATHS[@]}"; do
        _found=false
        for _item in "${_saved_ebp[@]}"; do [[ "$_item" == "$_a" ]] && { _found=true; break; }; done
        $_found || echo "WARNING: ${_label} removed admin-enforced EXTRA_BLOCKED_PATHS entry '${_a}' — restored." >&2
    done

    # Warn about HOME_READONLY → HOME_WRITABLE escalation
    for _aro in "${_ADMIN_HOME_READONLY[@]}"; do
        for _item in "${_saved_hw[@]}"; do
            [[ "$_item" == "$_aro" ]] && echo "WARNING: ${_label} moved admin HOME_READONLY entry '${_aro}' to HOME_WRITABLE — reverted." >&2
        done
    done

    # Warn about scalar overrides
    if [[ -n "$_ADMIN_SANDBOX_BYPASS_TOKEN" && "${SANDBOX_BYPASS_TOKEN:-}" != "$_ADMIN_SANDBOX_BYPASS_TOKEN" ]]; then
        echo "WARNING: ${_label} changed SANDBOX_BYPASS_TOKEN — restored to admin value." >&2
    fi
    if [[ -n "$_ADMIN_TOKEN_FILE" && "${TOKEN_FILE:-}" != "$_ADMIN_TOKEN_FILE" ]]; then
        echo "WARNING: ${_label} changed TOKEN_FILE — restored to admin value." >&2
    fi

    # Re-source admin config
    builtin . "$_ADMIN_CONF"

    # Merge: admin base + user/project additions
    local _in_admin
    for _item in "${_saved_bf[@]}"; do
        _in_admin=false
        for _a in "${_ADMIN_BLOCKED_FILES[@]}"; do [[ "$_item" == "$_a" ]] && { _in_admin=true; break; }; done
        $_in_admin || BLOCKED_FILES+=("$_item")
    done
    for _item in "${_saved_bev[@]}"; do
        _in_admin=false
        for _a in "${_ADMIN_BLOCKED_ENV_VARS[@]}"; do [[ "$_item" == "$_a" ]] && { _in_admin=true; break; }; done
        $_in_admin || BLOCKED_ENV_VARS+=("$_item")
    done
    for _item in "${_saved_ebp[@]}"; do
        _in_admin=false
        for _a in "${_ADMIN_EXTRA_BLOCKED_PATHS[@]}"; do [[ "$_item" == "$_a" ]] && { _in_admin=true; break; }; done
        $_in_admin || EXTRA_BLOCKED_PATHS+=("$_item")
    done

    # Remove admin HOME_READONLY items from HOME_WRITABLE
    local _clean_writable=() _is_admin_ro
    for _item in "${_saved_hw[@]}"; do
        _is_admin_ro=false
        for _aro in "${_ADMIN_HOME_READONLY[@]}"; do
            [[ "$_item" == "$_aro" ]] && { _is_admin_ro=true; break; }
        done
        $_is_admin_ro || _clean_writable+=("$_item")
    done
    HOME_WRITABLE=("${_clean_writable[@]}")
}

# ── Per-project config overrides ─────────────────────────────────
#
# Source all *.conf files in conf.d/ with _PROJECT_DIR set, so each
# file can guard itself with:
#   [[ "$_PROJECT_DIR" == /some/prefix/* ]] || return 0
# and append to READONLY_MOUNTS, EXTRA_WRITABLE_PATHS, etc.
#
# Called once from sandbox-exec.sh after PROJECT_DIR is resolved.
# Not designed for multiple calls — user+project additions accumulate.

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
        # Reset traps that conf.d files may have installed
        trap - DEBUG RETURN ERR EXIT
    fi
    unset _PROJECT_DIR

    # Re-apply admin enforcement after conf.d overrides
    if [[ -n "${_ADMIN_CONF:-}" ]]; then
        _enforce_admin_config "Project config"
    fi

    # Validate all path arrays (covers sandbox.conf + conf.d/ additions)
    _validate_path_array ALLOWED_PROJECT_PARENTS "${ALLOWED_PROJECT_PARENTS[@]}"
    _validate_path_array READONLY_MOUNTS "${READONLY_MOUNTS[@]}"
    _validate_path_array HOME_READONLY "${HOME_READONLY[@]}"
    _validate_path_array HOME_WRITABLE "${HOME_WRITABLE[@]}"
    _validate_path_array BLOCKED_FILES "${BLOCKED_FILES[@]}"
    _validate_path_array EXTRA_BLOCKED_PATHS "${EXTRA_BLOCKED_PATHS[@]}"
    _validate_path_array EXTRA_WRITABLE_PATHS "${EXTRA_WRITABLE_PATHS[@]}"
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

# Auto-discover bypass token path.
# TOKEN_FILE is the Slurm wrapper name; SANDBOX_BYPASS_TOKEN is the sandbox name.
# The admin config may set either.
if [[ -z "${SANDBOX_BYPASS_TOKEN:-}" && -n "${TOKEN_FILE:-}" ]]; then
    SANDBOX_BYPASS_TOKEN="$TOKEN_FILE"
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

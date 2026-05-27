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

# Files in $HOME whose CONTENT is read from the host but seeded into
# the per-session tmpfs $HOME as a writable copy. Lets tools that
# write to dotfiles (gh auth setup-git, IDE git plugins, git config
# --global) work inside the sandbox without weakening isolation —
# writes land in the tmpfs and are discarded on sandbox exit, so the
# real host file is never modified.
#
# Conflict rule: an entry in HOME_SEEDED_FILES wins over the same
# entry in HOME_READONLY (the read-only mount is skipped).
#
# Backend support:
#   bwrap    — full support via --file FD DEST
#   firejail — full support via --private-home= (copy into tmpfs $HOME)
#   landlock — degrades to read-only with a warning (no mount namespace)
HOME_SEEDED_FILES=(
    ".gitconfig"
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

# Isolate /tmp with a private tmpfs (bwrap and firejail backends).
# Default: true. Set to false if the sandboxed process needs shared /tmp
# access (e.g., MPI shared-memory transport between ranks on the same node,
# or NCCL inter-GPU communication via /tmp sockets).
# Preserve env overrides for security booleans before setting defaults.
# Restored after config loading (but admin enforcement still wins).
_PRIVATE_TMP_OVERRIDE="${PRIVATE_TMP:-}"
_PRIVATE_IPC_OVERRIDE="${PRIVATE_IPC:-}"
_FILTER_PASSWD_OVERRIDE="${FILTER_PASSWD:-}"
_NETWORK_FILTER_MODE_OVERRIDE="${NETWORK_FILTER_MODE:-}"
_NETWORK_FILTER_FALLBACK_OVERRIDE="${NETWORK_FILTER_FALLBACK:-}"
_NETWORK_MAIL_BLOCK_OVERRIDE="${NETWORK_MAIL_BLOCK:-}"

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

# ── Network filter ──────────────────────────────────────────────
#
# Default-deny outbound network policy applied to the sandbox.
# Closes the local-MTA identity-hijack class and adjacent lateral-
# movement surface. Full rationale + per-backend matrix + the fallback
# semantics live in docs/reference/network-filter.md.
#
#   NETWORK_FILTER_MODE — open | filtered | isolated  (default: filtered)
#     open:     share the host network namespace; no isolation. Legacy
#               behaviour. Use only when the workload explicitly needs
#               host-equivalent network reach AND host-side mail policy
#               already covers identity-hijack.
#     filtered: new netns + helper (pasta or slirp4netns); applies the
#               default-deny floor below plus user/admin NETWORK_BLOCKLIST
#               additions. The agent retains general outbound TCP/UDP/DNS
#               but loses the threat-class ports.
#     isolated: new netns with no network at all. DNS / pip / git inside
#               the sandbox break; use for offline-only workloads or as
#               the strictest fallback target.
#
#   NETWORK_FILTER_FALLBACK — strict | stricter | open  (default: open)
#     strict:   the requested mode must be deliverable on this host; the
#               sandbox refuses to launch otherwise.
#     stricter: fall back ONLY to a more-restrictive mode if the requested
#               mode is unavailable. Falls back loudly. If no stricter mode
#               is possible (landlock has no netns at all), refuses to
#               launch with an explicit fix-path enumeration.
#     open:     fall back to ANY available mode, preferring stricter first.
#               Will degrade loudly to host-network if no isolated mode
#               is available.
#
# Default rationale: on kernel < 5.7 hosts (common on shared HPC login
# nodes) pasta's SO_BINDTODEVICE call requires CAP_NET_RAW; without
# admin intervention (setcap cap_net_raw+ep on the pasta binary) the
# forwarding probe trips and `filtered` is unavailable. Under
# `stricter` the resolver would fall to `isolated`, breaking DNS /
# pip / git / API inside the sandbox — i.e. the sandbox effectively
# refuses to run on those hosts. `open` keeps the sandbox usable
# (loud warning, threat-class ports re-opened) instead. Sites that
# need the stronger posture should pin `stricter`/`strict` in the
# admin baseline; that pin is non-weakening per the model below.
#
# Admin enforcement: an admin baseline can pin NETWORK_FILTER_MODE and
# NETWORK_FILTER_FALLBACK; user config can request stricter values but
# cannot weaken admin-set ones (same model as PRIVATE_TMP, FILTER_PASSWD).
NETWORK_FILTER_MODE="filtered"
NETWORK_FILTER_FALLBACK="open"

# ── Mail-block layer (NETWORK_MAIL_BLOCK) ────────────────────────
#
# Defense-in-depth above NETWORK_FILTER_MODE's port-level SMTP block.
# When active, the launcher bind-mounts a universal stub
# (tools/mail-block/mail-block-stub.sh) over every canonical mailer
# path that exists on the host and prepends a symlink farm of the same
# names to PATH. Any invocation of `sendmail`, `mail`, `mutt`, …
# prints a deterrent message and exits 77 (sysexits EX_NOPERM). The
# stub catches the syscall (execve); the network filter still catches
# application-level dialers (smtplib, curl smtp://, nc) at the netns
# edge — two reinforcing layers, evaluated CONFIG > NETWORK so the
# agent learns the policy in human-readable terms before the kernel
# drops the connection.
#
# Values: auto | on | off
#   off:  do nothing (escape hatch for sites that legitimately need
#         the canonical mailer binaries visible — rare; the v0.10.0
#         filter already breaks them at the socket layer).
#   auto: (default) on whenever the configured NETWORK_FILTER_MODE OR
#         the resolved one is anything other than `open` (strictest-
#         of-both). Disengages only when BOTH are open. Tracks user
#         intent, so a fallback that weakens the network filter from
#         `filtered` to `open` does NOT silently disable this layer.
#   on:   always on regardless of NETWORK_FILTER_MODE.
#
# Admin enforcement: admin pin uses the same "user can only request
# a stricter value" model as NETWORK_FILTER_MODE; strictness ordering
# off < auto < on.
NETWORK_MAIL_BLOCK="auto"

# Sentinel for any future "always-on, not user-removable" floor
# entries. Currently empty — the full identity-bound exfil + lateral-
# movement surface lives in `sandbox.conf::NETWORK_BLOCKLIST` so an
# operator editing their config sees the policy and can comment-out
# entries that don't apply to their deployment. See
# docs/reference/network-filter.md for the rationale + the full
# enumerated default set.
#
# Pattern syntax (when entries do live here): host[:port] | CIDR[:port]
# | port | "*.suffix" wildcard | "*" deny-all.
_NETWORK_BLOCKLIST_DEFAULTS=(
)

# User/admin block extensions. Format identical to the floor above.
# Each entry is appended; the floor cannot be removed via this list.
# Wildcard patterns (`*.example.com`, `*.example.com:443`) are supported
# under bash glob semantics. CIDR ranges (`10.0.0.0/8[:port]`) and bare
# ports (`853`) are also accepted.
NETWORK_BLOCKLIST=()

# Exception list — entries that carve a hole in the blocklist using
# the precedence model documented in docs/reference/network-filter.md.
# Format identical to NETWORK_BLOCKLIST. An exception applies when a
# more-specific entry here matches a candidate destination that an
# enclosing wildcard / CIDR / bare-port entry in NETWORK_BLOCKLIST
# would otherwise block.
#
# Examples:
#   NETWORK_BLOCKLIST+=("*.amazonaws.com")
#   NETWORK_BLOCKLIST_EXCEPT+=("s3.amazonaws.com")
#     → s3.amazonaws.com allowed; *.amazonaws.com still blocked.
#
#   NETWORK_BLOCKLIST+=("*")
#   NETWORK_BLOCKLIST_EXCEPT+=("github.com" "api.openai.com")
#     → implicit-allowlist idiom: block everything except the named
#       hosts (deny-by-default).
#
# Admin precedence: an admin-set NETWORK_BLOCKLIST entry CANNOT be
# overridden by a user NETWORK_BLOCKLIST_EXCEPT — the user's entry is
# stripped at config-load with a loud warning. The admin can carve
# their own exceptions in their own NETWORK_BLOCKLIST_EXCEPT.
NETWORK_BLOCKLIST_EXCEPT=()

# Bind host /dev into the sandbox instead of bwrap's minimal devtmpfs.
# DEPRECATED: kept as a kernel-aware shim. On kernel < 5.4 it appends
# /dev/pts to DEVICES (the historical pty workaround); on kernel >= 5.4
# it is a logged no-op (binding host /dev/pts on those kernels shadows
# bwrap's auto-mounted user-ns devpts and silently breaks tmux/script
# pty allocation). Use DEVICES (below) for targeted passthrough — that
# mechanism is admin-blacklist-aware whereas BIND_DEV_PTS=true used to
# bypass any such check. See docs/reference/device-passthrough.md for the migration.
BIND_DEV_PTS=false

# Device nodes to expose inside the sandbox (bwrap only).
#
# Each entry is bind-mounted via `bwrap --dev-bind PATH PATH` after
# `bwrap --dev /dev` has set up the minimal devtmpfs. Glob patterns are
# expanded against the host /dev at sandbox spawn time — entries that
# match nothing are silently dropped, so the NVIDIA defaults are a safe
# no-op on CPU-only nodes.
#
# DEVICES_BLACKLIST is enforced after expansion: any resolved path
# matching a blacklist glob is dropped with a stderr notice. Admins set
# the blacklist in the admin sandbox.conf; users cannot remove
# admin-set entries (same model as BLOCKED_FILES).
#
# To customize: edit DEVICES in ~/.config/agent-sandbox/sandbox.conf, or
# add `DEVICES+=(/dev/something)` from a conf.d/ overlay.
#
# Defaults expose only NVIDIA driver nodes (the recurring HPC use case).
# Extend for AMD/Intel/sound/DRI as needed.
DEVICES=(
    /dev/nvidia*
    /dev/nvidia-uvm
    /dev/nvidia-uvm-tools
    /dev/nvidia-modeset
    /dev/nvidiactl
)

# Devices that may NEVER be bind-mounted, even when listed in DEVICES.
# Admin-enforceable: when an admin sandbox.conf is present, its
# DEVICES_BLACKLIST is locked in (users add but cannot remove). Without
# an admin install these defaults are the safety baseline.
#
# Rationale per entry:
#   /dev/mem, /dev/kmem, /dev/port — direct kernel-memory access
#   /dev/pts                       — two reasons to keep it out:
#                                    (a) TIOCSTI keystroke injection
#                                    on kernel < 6.2 (Fred Hutch gizmo:
#                                    5.4, the practical risk this list
#                                    closes); (b) on kernel >= 5.4
#                                    binding host /dev/pts shadows
#                                    bwrap's auto-mounted devpts with
#                                    ptmxmode=000 and breaks tmux pty
#                                    allocation. Both reasons argue for
#                                    blacklisting by default.
#   /dev/sd*, /dev/nvme*, /dev/loop* — raw block devices: filesystem
#                                      bypass, host-data exfiltration
DEVICES_BLACKLIST=(
    /dev/mem
    /dev/kmem
    /dev/port
    /dev/pts
    /dev/sd*
    /dev/nvme*
    /dev/loop*
)

# Suppress the startup banner. Set to true to hide the one-line message
# showing backend, project dir, and home access mode.
SANDBOX_QUIET=false

# Backend selection. Empty means auto-detect (bwrap > firejail > landlock).
# Can be overridden by --backend flag, SANDBOX_BACKEND env, or config file.
# Preserve any value from env/CLI before setting the default — the override
# is restored after config loading (see _SANDBOX_BACKEND_OVERRIDE below).
SANDBOX_BACKEND="${SANDBOX_BACKEND:-}"

# Process limit (defense-in-depth against fork bombs). Empty = no limit.
# Sets RLIMIT_NPROC via ulimit -u / firejail --rlimit-nproc.
# Note: counts per-UID system-wide, not per-sandbox. Admin cgroups with
# pids.max are the primary defense; this is a supplemental safeguard.
SANDBOX_NPROC_LIMIT=""

# Landlock ABI floor (landlock backend only). Empty means "use the
# helper's defaults" — see backends/landlock-sandbox.py
# DEFAULT_REQUIRED_ABI (currently 3) and the --hard-requirement flag
# (default true). Set to a digit to override the floor; set the boolean
# to true/false to override the start/refuse behavior.
LANDLOCK_REQUIRED_ABI="${LANDLOCK_REQUIRED_ABI:-}"
LANDLOCK_HARD_REQUIREMENT="${LANDLOCK_HARD_REQUIREMENT:-}"

# Silence per-agent credential/path warnings emitted at startup. List
# agent names (matching agents/<name>/ directories) or "all" to disable
# every agent warning. Configurable via sandbox.conf.
SUPPRESS_AGENT_WARNINGS=()

BLOCKED_ENV_VARS=(
    # Specific names NOT caught by BLOCKED_ENV_PATTERNS globs.
    # Names like GITHUB_TOKEN, OPENAI_API_KEY, AWS_*, AZURE_*, SSH_*, etc.
    # are already matched by patterns — no need to list them here.
    "GITHUB_PAT"
    # Cloud & service credentials
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
    # *_PRIVATE_KEY, AWS_*, AMAZON_*, EC2_*, AZURE_*, MSAL_*, GCP_*,
    # VAULT_*, DOCKER_*, CI_*, etc.) are blocked automatically — do
    # not duplicate them here.
)

# Credential-pattern globs: block env vars matching common credential naming
# conventions. Configurable via sandbox.conf / user.conf (admin-enforced).
# To let a specific variable through, add it to ALLOWED_ENV_VARS.
#
# Cloud-provider wildcards (AWS_*, AMAZON_*, EC2_*, MSAL_*, VAULT_*) borrow
# the broad-prefix approach from bindsch/scode (scode:113-158); see
# https://github.com/bindsch/scode for the upstream policy.  Using prefixes
# instead of per-name entries closes the long tail of provider env vars
# (AWS_SECRET_ACCESS_KEY, AWS_PROFILE, AWS_DEFAULT_REGION, MSAL_CACHE_PATH,
# VAULT_ADDR, …) without requiring per-key opt-in.
BLOCKED_ENV_PATTERNS=(
    "SSH_*"
    "*_TOKEN"  "*_SECRET"  "*_PASSWORD"  "*_CREDENTIAL"
    "*_API_KEY"  "*_SECRET_KEY"  "*_PRIVATE_KEY"
    # AWS / Amazon (scode:117 — full-prefix sweep for the long tail
    # beyond AWS_ACCESS_KEY_ID and AWS_SESSION_TOKEN)
    "AWS_*"  "AMAZON_*"  "EC2_*"
    # Azure / Microsoft auth library
    "AZURE_*"  "MSAL_*"
    # Google Cloud Platform
    "GCP_*"  "GCLOUD_*"  "GOOGLE_CLOUD_*"
    # HashiCorp Vault — VAULT_TOKEN already caught by *_TOKEN; this
    # also blocks VAULT_ADDR/VAULT_NAMESPACE which leak server topology.
    "VAULT_*"
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
#
# Pattern syntax: shell-style globs, case-sensitive by default. A trailing
# `/i` flag on an entry opts that entry into case-insensitive matching —
# same convention as sed (`s/.../.../i`), Perl (`qr/.../i`), and JavaScript
# regex (`/.../i`). Env-var names are restricted to [A-Za-z0-9_] (POSIX
# IEEE Std 1003.1, Sec. 8.1) and cannot legitimately contain `/`, so the
# suffix is unambiguous. Default is case-sensitive so admin baselines
# upgrading across versions keep their existing semantics.
_is_blocked_by_pattern() {
    local _var="$1"
    _is_allowed_env "$_var" && return 1
    local _glob _pat _matched
    for _glob in "${BLOCKED_ENV_PATTERNS[@]}"; do
        _matched=false
        if [[ "$_glob" == */i ]]; then
            _pat="${_glob%/i}"
            # nocasematch is per-shell-option, restored after this entry's
            # match attempt so callers and other globs in the loop see the
            # default (case-sensitive) behaviour.
            shopt -s nocasematch
            # shellcheck disable=SC2254
            case "$_var" in $_pat) _matched=true ;; esac
            shopt -u nocasematch
        else
            # shellcheck disable=SC2254
            case "$_var" in $_glob) _matched=true ;; esac
        fi
        $_matched && return 0
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

# ── Helper: kernel version comparison ──────────────────────────
# _kernel_at_least MAJOR MINOR — returns 0 iff `uname -r` >= MAJOR.MINOR.
# Treats unparseable kernel strings as "older" (return 1) so callers default
# to the legacy code path on weird embedded/container hosts.
_kernel_at_least() {
    local _want_maj="$1" _want_min="$2"
    local _kver _kmaj _kmin
    _kver="$(uname -r 2>/dev/null)" || return 1
    _kmaj="${_kver%%.*}"
    _kmin="${_kver#*.}"
    _kmin="${_kmin%%[!0-9]*}"
    [[ "$_kmaj" =~ ^[0-9]+$ && "$_kmin" =~ ^[0-9]+$ ]] || return 1
    if (( _kmaj > _want_maj )); then
        return 0
    fi
    if (( _kmaj == _want_maj && _kmin >= _want_min )); then
        return 0
    fi
    return 1
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
# See docs/admin/install.md for setup instructions.

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
    HOME_SEEDED_FILES
    BLOCKED_FILES BLOCKED_ENV_VARS BLOCKED_ENV_PATTERNS ALLOWED_ENV_VARS
    EXTRA_BLOCKED_PATHS EXTRA_WRITABLE_PATHS DENIED_WRITABLE_PATHS
    DEVICES DEVICES_BLACKLIST
    SANDBOX_ENV SUPPRESS_AGENT_WARNINGS SANDBOX_MODULES ENABLED_AGENTS
    NETWORK_BLOCKLIST NETWORK_BLOCKLIST_EXCEPT
)
_CONFIG_SCALARS=(
    SANDBOX_BACKEND PRIVATE_TMP PRIVATE_IPC FILTER_PASSWD BIND_DEV_PTS
    NETWORK_FILTER_MODE NETWORK_FILTER_FALLBACK NETWORK_MAIL_BLOCK
    SLURM_SCOPE HOME_ACCESS SANDBOX_QUIET SANDBOX_NPROC_LIMIT
    CHAPERON_LOG_LEVEL CHAPERON_LOG_RETAIN_DAYS
    LANDLOCK_REQUIRED_ABI LANDLOCK_HARD_REQUIREMENT
)
# Enforced arrays: user cannot remove admin-set entries (only add).
_ENFORCED_ARRAYS=(BLOCKED_FILES BLOCKED_ENV_VARS BLOCKED_ENV_PATTERNS EXTRA_BLOCKED_PATHS DEVICES_BLACKLIST NETWORK_BLOCKLIST NETWORK_BLOCKLIST_EXCEPT)

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
        _src_exit=$?
        # Extract config variables.  If the config overrode declare as a
        # function, this calls the attacker'\''s code — but the parent
        # validates the output before eval'\''ing it (see below).
        # Iterate per-variable so that unset variables (which cause
        # declare -p to return 1) do not poison the exit code.
        for _v in $3; do declare -p "$_v" 2>/dev/null || true; done
        exit "$_src_exit"
    ' -- "$_parent_state" "$_conf" "$_var_names" )" || _exit_code=$?

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

# --- Path-resolution helpers (used by DENIED_WRITABLE_PATHS enforcement) ---
#
# _resolve_path: canonicalize a path, following symlinks.  readlink -f
# resolves even non-existent leaf components (GNU coreutils), so this is
# safe to call on paths that may not yet exist.  Falls back to the
# literal input if resolution fails.
_resolve_path() {
    local _p="$1"
    local _r
    _r="$(readlink -f -- "$_p" 2>/dev/null)" || _r=""
    if [[ -n "$_r" ]]; then
        echo "$_r"
    else
        echo "$_p"
    fi
}

# ── .sandbox-state/ — hidden chaperon-owned state subdir ─────────
#
# A hidden subdir of $project_dir that holds chaperon-managed state
# the sandbox needs to read but must not be able to tamper with:
#
#   .sandbox-state/slurm-logs/<transformed>   — slurmstepd writes job
#                                                logs here; the wrapper
#                                                inside the sandbox creates
#                                                relative symlinks from
#                                                user-intended paths to
#                                                here.
#   .sandbox-state/chaperon/<session-id>/log  — chaperon's diagnostic
#                                                log (bwrap/firejail
#                                                only; stderr fallback
#                                                on landlock).
#
# Threat-model framing (the load-bearing distinction from reverted
# PR #50):
#
#   "Yes, it should be considered hostile, even the now non-directly-
#   writable .sandbox-state. After all the submitted job determines
#   what is written, and we just prevent symlink injection."
#                                — operator, 2026-05-20 design discussion
#
# Content under .sandbox-state IS hostile. The submitted job decides
# what slurmstepd writes there. The bwrap/firejail RO overlay's only
# job is to prevent symlink-plant against slurmstepd's open(--output)
# — without it, an agent could `ln -sf /etc/passwd
# $project_dir/.sandbox-state/slurm-logs/<known-path>` between the
# chaperon's mkdir -p and slurmstepd's open, causing slurmstepd to
# write job output to /etc/passwd. The chaperon NEVER trusts content
# read back from .sandbox-state/ for any security decision.
#
# This is the explicit distinction from reverted PR #50 (which wanted
# to RO-protect user-owned content the agent legitimately writes to,
# e.g. .git/): .sandbox-state/ is chaperon-owned content the agent
# never wrote, so RO-protecting it costs no legitimate capability and
# adds a real security property. The "project dir is entirely hostile"
# framing from the PR #50 revert still holds for every other path
# under $project_dir.
#
# Landlock: cannot mount a RO subtree under a RW parent (rules are
# additive at the kernel level). The .sandbox-state/ overlay is
# skipped on landlock; the chaperon side detects this via
# $SANDBOX_BACKEND and disables the path-transformation feature
# entirely (no transformation, no symlink, no chaperon log file).
# See docs/reference/sandbox-state-dir.md for the full convention.
#
# The path is `$project_dir/.sandbox-state`. Backends (bwrap, firejail)
# compose this inline rather than calling a helper because the chaperon
# (which runs in a separate bash process and DOES need helpers — see
# `chaperon/handlers/_handler_lib.sh::_ensure_sandbox_state_dir`) does
# not source `sandbox-lib.sh`. Keeping the path literal here avoids the
# duplicate-function-definition smell at the cost of a string.

# _path_under: returns 0 if CHILD is identical to PARENT or is a proper
# subdirectory of PARENT.  Trailing slashes are stripped.  The "/"
# boundary check prevents false positives like /etc vs /etcetera.
_path_under() {
    # Special case: parent="/" means "everything absolute is a subdir".
    # Stripping the trailing slash from "/" produces "" which would
    # otherwise short-circuit the empty-parent guard below. Handle it
    # explicitly first.
    if [[ "$2" == "/" ]]; then
        [[ "$1" == /* ]]
        return $?
    fi
    local _child="${1%/}"
    local _parent="${2%/}"
    [[ -z "$_parent" ]] && return 1
    [[ "$_child" == "$_parent" || "$_child" == "$_parent/"* ]]
}

# _resolve_inherited_cwd: choose a backend chdir target that honors
# Slurm's inherited submission cwd when it canonicalizes under the
# project dir, falling back to $project_dir otherwise. Echoes the
# resolved path on stdout.
#
# Called from bwrap and firejail backends so a compute-node wrapper
# launched as `sandbox-exec.sh --project-dir $project_dir -- bash …`
# lands in `$SLURM_SUBMIT_DIR` instead of being snapped back to
# `$project_dir` — matching native Slurm's cwd inheritance for jobs
# submitted from a subdir. Without this, `sbatch --wrap='bash
# relpath.sh'` from `$project_dir/sub/` runs the wrap content in
# `$project_dir`, and any relative path resolves against the wrong
# directory (issue #65).
#
# Security envelope is identical to the chaperon's submission-side
# `validate_cwd` (`chaperon/handlers/_handler_lib.sh::validate_cwd`):
# the cwd must canonicalize under $project_dir. Symlink-based escapes
# are rejected by the realpath canonicalization step. When
# $SLURM_SUBMIT_DIR is unset, missing on disk, or escapes the project
# envelope, the function returns $project_dir unchanged — the
# pre-existing (safe) behavior.
_resolve_inherited_cwd() {
    local _project_dir="$1"
    local _chdir_target="$_project_dir"
    if [[ -n "${SLURM_SUBMIT_DIR:-}" ]]; then
        local _submit_canon _project_canon
        _submit_canon="$(_resolve_path "$SLURM_SUBMIT_DIR")"
        _project_canon="$(_resolve_path "$_project_dir")"
        if [[ -d "$_submit_canon" ]] && _path_under "$_submit_canon" "$_project_canon"; then
            _chdir_target="$_submit_canon"
        fi
    fi
    printf '%s' "$_chdir_target"
}

# _narrow_allowed_project_parents: filter user-requested project parents
# to those admissible under admin's allow-list.
#
# Semantics: a user entry is admissible iff its CANONICAL resolution
# (via realpath/_resolve_path, following all symlinks) is identical to
# or a path-component subdir of the CANONICAL resolution of one of
# admin's allowed parents. The canonical form is the ground truth that
# the kernel sees when bind-mounts and access checks happen, so a
# user-supplied path whose canonical escapes admin's tree (via symlink
# or ../) is rejected even if the literal string appears under an
# admin entry.
#
# Why canonical-on-canonical (not the 4-way literal/canonical OR used
# by validate_project_dir): the 4-way OR admits a literal-string match
# even when the canonical escapes. That's safe at validate_project_dir
# because $PROJECT_DIR is canonicalized via `cd && pwd -P` upstream;
# `dir` is already canonical. The merge function runs before any such
# canonicalization, so a literal-only match here would let a user
# bypass admin narrowing by symlinking a path that *looks* admissible.
#
# Path-component boundary: /foo is NOT a parent of /foobar (delegated
# to _path_under).
#
# Per-entry rejection (documented choice, not all-or-nothing): each
# non-admissible user entry is dropped with a WARNING. Consistent with
# how DENIED_WRITABLE_PATHS strips offending HOME_WRITABLE entries with
# a warning rather than aborting. Caller (_enforce_admin_policy) checks
# whether the resulting list is empty and aborts startup in that case.
#
# Args:
#   $1 — name of an indexed array containing the user-requested entries
#   $2 — label for warning messages (e.g., "User config", "Project config")
# Sets:
#   ALLOWED_PROJECT_PARENTS — narrowed effective list (in caller scope)
_narrow_allowed_project_parents() {
    local -n _user_arr=$1
    local _label="$2"

    # Canonicalize admin list once.
    local _admin_can=() _adm _adm_x
    for _adm in "${_ADMIN_ALLOWED_PROJECT_PARENTS[@]}"; do
        _adm_x="${_adm//\$\{HOME\}/$HOME}"
        _adm_x="${_adm_x/#\~\//$HOME/}"
        _adm_x="${_adm_x/\$HOME/$HOME}"
        _adm_x="${_adm_x%/}"
        [[ -z "$_adm_x" ]] && _adm_x="/"
        _admin_can+=("$(_resolve_path "$_adm_x")")
    done

    local _effective=() _u _u_lit _u_can _admissible _i
    for _u in "${_user_arr[@]}"; do
        _u_lit="${_u//\$\{HOME\}/$HOME}"
        _u_lit="${_u_lit/#\~\//$HOME/}"
        _u_lit="${_u_lit/\$HOME/$HOME}"
        _u_lit="${_u_lit%/}"
        if [[ -z "$_u_lit" ]]; then
            echo "WARNING: ${_label} ALLOWED_PROJECT_PARENTS contains an empty entry — rejected." >&2
            continue
        fi
        _u_can="$(_resolve_path "$_u_lit")"
        _admissible=false
        _i=0
        while [[ $_i -lt ${#_admin_can[@]} ]]; do
            if _path_under "$_u_can" "${_admin_can[$_i]}"; then
                _admissible=true
                break
            fi
            _i=$((_i + 1))
        done
        if $_admissible; then
            _effective+=("$_u")
        else
            if [[ "$_u_lit" != "$_u_can" ]]; then
                echo "WARNING: ${_label} ALLOWED_PROJECT_PARENTS entry '${_u}' (resolves to '${_u_can}') is not under any admin-allowed parent — rejected." >&2
            else
                echo "WARNING: ${_label} ALLOWED_PROJECT_PARENTS entry '${_u}' is not under any admin-allowed parent — rejected." >&2
            fi
            echo "  Admin-allowed: ${_ADMIN_ALLOWED_PROJECT_PARENTS[*]}" >&2
        fi
    done

    ALLOWED_PROJECT_PARENTS=("${_effective[@]}")
}

# --- Enforce admin policy: compare extracted values against admin snapshot ---
#
# After loading untrusted config (user.conf or conf.d), this function:
# 1. Warns about removed admin entries or overridden scalars
# 2. Restores admin values as the base
# 3. Merges user additions on top
# 4. Strips DENIED_WRITABLE_PATHS violations (resolves symlinks to block
#    indirection attacks — see the DENIED_WRITABLE_PATHS section below)
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
    for _a in "${_ADMIN_DEVICES_BLACKLIST[@]}"; do
        _found=false
        for _item in "${DEVICES_BLACKLIST[@]}"; do [[ "$_item" == "$_a" ]] && { _found=true; break; }; done
        $_found || echo "WARNING: ${_label} removed admin-enforced DEVICES_BLACKLIST entry '${_a}' — restored." >&2
    done
    for _a in "${_ADMIN_NETWORK_BLOCKLIST[@]+"${_ADMIN_NETWORK_BLOCKLIST[@]}"}"; do
        _found=false
        for _item in "${NETWORK_BLOCKLIST[@]+"${NETWORK_BLOCKLIST[@]}"}"; do
            [[ "$_item" == "$_a" ]] && { _found=true; break; }
        done
        $_found || echo "WARNING: ${_label} removed admin-enforced NETWORK_BLOCKLIST entry '${_a}' — restored." >&2
    done
    for _a in "${_ADMIN_NETWORK_BLOCKLIST_EXCEPT[@]+"${_ADMIN_NETWORK_BLOCKLIST_EXCEPT[@]}"}"; do
        _found=false
        for _item in "${NETWORK_BLOCKLIST_EXCEPT[@]+"${NETWORK_BLOCKLIST_EXCEPT[@]}"}"; do
            [[ "$_item" == "$_a" ]] && { _found=true; break; }
        done
        $_found || echo "WARNING: ${_label} removed admin-enforced NETWORK_BLOCKLIST_EXCEPT entry '${_a}' — restored." >&2
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

    # Network filter mode (tri-valued): user can only request a STRICTER
    # mode than the admin-pinned baseline. Ordering: open < filtered < isolated.
    if [[ -n "${_ADMIN_NETWORK_FILTER_MODE:-}" ]]; then
        local _admin_idx _user_idx
        _admin_idx="$(_network_mode_strictness_idx "$_ADMIN_NETWORK_FILTER_MODE")"
        _user_idx="$(_network_mode_strictness_idx "${NETWORK_FILTER_MODE:-filtered}")"
        if [[ "$_user_idx" -lt "$_admin_idx" ]]; then
            echo "WARNING: ${_label} weakened admin-enforced NETWORK_FILTER_MODE='${_ADMIN_NETWORK_FILTER_MODE}' to '${NETWORK_FILTER_MODE}' — restored." >&2
            NETWORK_FILTER_MODE="$_ADMIN_NETWORK_FILTER_MODE"
        fi
    fi

    # Network filter fallback (tri-valued): user can only request a STRICTER
    # policy than the admin-pinned baseline. Ordering: open < stricter < strict.
    if [[ -n "${_ADMIN_NETWORK_FILTER_FALLBACK:-}" ]]; then
        local _admin_pidx _user_pidx
        _admin_pidx="$(_network_fallback_strictness_idx "$_ADMIN_NETWORK_FILTER_FALLBACK")"
        _user_pidx="$(_network_fallback_strictness_idx "${NETWORK_FILTER_FALLBACK:-open}")"
        if [[ "$_user_pidx" -lt "$_admin_pidx" ]]; then
            echo "WARNING: ${_label} weakened admin-enforced NETWORK_FILTER_FALLBACK='${_ADMIN_NETWORK_FILTER_FALLBACK}' to '${NETWORK_FILTER_FALLBACK}' — restored." >&2
            NETWORK_FILTER_FALLBACK="$_ADMIN_NETWORK_FILTER_FALLBACK"
        fi
    fi

    # Mail-block layer (tri-valued): user can only request an EQUAL OR
    # STRICTER value than the admin pin. Ordering: off < auto < on.
    if [[ -n "${_ADMIN_NETWORK_MAIL_BLOCK:-}" ]]; then
        local _admin_midx _user_midx
        _admin_midx="$(_mail_block_strictness_idx "$_ADMIN_NETWORK_MAIL_BLOCK")"
        _user_midx="$(_mail_block_strictness_idx "${NETWORK_MAIL_BLOCK:-auto}")"
        if [[ "$_user_midx" -lt "$_admin_midx" ]]; then
            echo "WARNING: ${_label} weakened admin-enforced NETWORK_MAIL_BLOCK='${_ADMIN_NETWORK_MAIL_BLOCK}' to '${NETWORK_MAIL_BLOCK}' — restored." >&2
            NETWORK_MAIL_BLOCK="$_ADMIN_NETWORK_MAIL_BLOCK"
        fi
    fi

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
    local _user_hsf=("${HOME_SEEDED_FILES[@]}")
    local _user_app=("${ALLOWED_PROJECT_PARENTS[@]}")
    local _user_dbl=("${DEVICES_BLACKLIST[@]}")
    local _user_nbl=("${NETWORK_BLOCKLIST[@]+"${NETWORK_BLOCKLIST[@]}"}")
    local _user_nbx=("${NETWORK_BLOCKLIST_EXCEPT[@]+"${NETWORK_BLOCKLIST_EXCEPT[@]}"}")

    # --- Restore admin base values ---
    BLOCKED_FILES=("${_ADMIN_BLOCKED_FILES[@]}")
    BLOCKED_ENV_VARS=("${_ADMIN_BLOCKED_ENV_VARS[@]}")
    BLOCKED_ENV_PATTERNS=("${_ADMIN_BLOCKED_ENV_PATTERNS[@]}")
    ALLOWED_ENV_VARS=("${_ADMIN_ALLOWED_ENV_VARS[@]}")
    EXTRA_BLOCKED_PATHS=("${_ADMIN_EXTRA_BLOCKED_PATHS[@]}")
    HOME_READONLY=("${_ADMIN_HOME_READONLY[@]}")
    HOME_SEEDED_FILES=("${_ADMIN_HOME_SEEDED_FILES[@]}")
    EXTRA_WRITABLE_PATHS=("${_ADMIN_EXTRA_WRITABLE_PATHS[@]}")
    READONLY_MOUNTS=("${_ADMIN_READONLY_MOUNTS[@]}")
    # ALLOWED_PROJECT_PARENTS is computed below by
    # _narrow_allowed_project_parents (narrowing-only merge: user can
    # only restrict admin's allow-list, never expand it). No restore
    # here, no _merge_additions call; the narrow function sets the
    # final effective value from _user_app filtered against the admin
    # snapshot.
    HOME_WRITABLE=("${_ADMIN_HOME_WRITABLE[@]}")
    DENIED_WRITABLE_PATHS=("${_ADMIN_DENIED_WRITABLE_PATHS[@]}")
    DEVICES_BLACKLIST=("${_ADMIN_DEVICES_BLACKLIST[@]}")
    NETWORK_BLOCKLIST=("${_ADMIN_NETWORK_BLOCKLIST[@]+"${_ADMIN_NETWORK_BLOCKLIST[@]}"}")
    NETWORK_BLOCKLIST_EXCEPT=("${_ADMIN_NETWORK_BLOCKLIST_EXCEPT[@]+"${_ADMIN_NETWORK_BLOCKLIST_EXCEPT[@]}"}")

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
    _merge_additions _user_hsf  _ADMIN_HOME_SEEDED_FILES      HOME_SEEDED_FILES
    _narrow_allowed_project_parents _user_app "$_label"
    _merge_additions _user_dbl  _ADMIN_DEVICES_BLACKLIST       DEVICES_BLACKLIST
    _merge_additions _user_nbl  _ADMIN_NETWORK_BLOCKLIST       NETWORK_BLOCKLIST
    # NETWORK_BLOCKLIST_EXCEPT merges similarly, but with an
    # additional cover-check: user-exception entries that match (under
    # bash glob semantics) any admin-set NETWORK_BLOCKLIST entry are
    # stripped + warned. Admin entries cannot be carved out by users.
    _merge_additions _user_nbx  _ADMIN_NETWORK_BLOCKLIST_EXCEPT  NETWORK_BLOCKLIST_EXCEPT
    _strip_user_exceptions_covered_by_admin "$_label"

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
    #
    # Resolve symlinks on both sides before matching so a writable entry
    # cannot bypass the admin blocklist by pointing a symlink at a denied
    # path (e.g., EXTRA_WRITABLE_PATHS+=("/home/u/x") where /home/u/x ->
    # /etc).  bwrap/firejail follow symlinks when bind-mounting, so the
    # literal-string check alone is not sufficient.  We check BOTH the
    # literal and the resolved form: if either is under a denied path,
    # the entry is rejected.
    if [[ ${#DENIED_WRITABLE_PATHS[@]} -gt 0 ]]; then
        local _clean=() _denied _denied_resolved _full_path _full_resolved _item_resolved
        local _denied_list=() _denied_resolved_list=()

        # Precompute denied paths: literal (with $HOME expanded) + resolved form.
        for _denied in "${DENIED_WRITABLE_PATHS[@]}"; do
            _denied="${_denied/\$HOME/$HOME}"
            _denied="${_denied%/}"
            _denied_list+=("$_denied")
            _denied_resolved="$(_resolve_path "$_denied")"
            _denied_resolved_list+=("$_denied_resolved")
        done

        # Check EXTRA_WRITABLE_PATHS
        for _item in "${EXTRA_WRITABLE_PATHS[@]}"; do
            _item="${_item%/}"
            _item_resolved="$(_resolve_path "$_item")"
            _found=false
            local _i=0
            while [[ $_i -lt ${#_denied_list[@]} ]]; do
                _denied="${_denied_list[$_i]}"
                _denied_resolved="${_denied_resolved_list[$_i]}"
                if _path_under "$_item" "$_denied" \
                    || _path_under "$_item_resolved" "$_denied" \
                    || _path_under "$_item" "$_denied_resolved" \
                    || _path_under "$_item_resolved" "$_denied_resolved"; then
                    if [[ "$_item" != "$_item_resolved" ]]; then
                        echo "WARNING: ${_label} added EXTRA_WRITABLE_PATHS entry '${_item}' (resolves to '${_item_resolved}') under denied path '${_denied}' — removed." >&2
                    else
                        echo "WARNING: ${_label} added EXTRA_WRITABLE_PATHS entry '${_item}' under denied path '${_denied}' — removed." >&2
                    fi
                    _found=true; break
                fi
                _i=$((_i + 1))
            done
            $_found || _clean+=("$_item")
        done
        EXTRA_WRITABLE_PATHS=("${_clean[@]}")

        # Check HOME_WRITABLE (entries are $HOME-relative)
        _clean=()
        for _item in "${HOME_WRITABLE[@]}"; do
            _full_path="$HOME/${_item%/}"
            _full_resolved="$(_resolve_path "$_full_path")"
            _found=false
            local _j=0
            while [[ $_j -lt ${#_denied_list[@]} ]]; do
                _denied="${_denied_list[$_j]}"
                _denied_resolved="${_denied_resolved_list[$_j]}"
                if _path_under "$_full_path" "$_denied" \
                    || _path_under "$_full_resolved" "$_denied" \
                    || _path_under "$_full_path" "$_denied_resolved" \
                    || _path_under "$_full_resolved" "$_denied_resolved"; then
                    if [[ "$_full_path" != "$_full_resolved" ]]; then
                        echo "WARNING: ${_label} added HOME_WRITABLE entry '${_item}' (resolves to '${_full_resolved}') under denied path '${_denied}' — removed." >&2
                    else
                        echo "WARNING: ${_label} added HOME_WRITABLE entry '${_item}' under denied path '${_denied}' — removed." >&2
                    fi
                    _found=true; break
                fi
                _j=$((_j + 1))
            done
            $_found || _clean+=("$_item")
        done
        HOME_WRITABLE=("${_clean[@]}")
    fi

    # --- Refuse startup if narrowing emptied the project-parents list ---
    #
    # Per directive: refusing project access is not a degraded mode the
    # sandbox can fall through to. If every user-requested entry was
    # rejected as outside admin's tree (or the user explicitly cleared
    # the list), abort with a clear, actionable error rather than
    # starting the sandbox with no admissible project locations.
    if [[ ${#ALLOWED_PROJECT_PARENTS[@]} -eq 0 ]]; then
        echo "Error: ALLOWED_PROJECT_PARENTS is empty after admin/user merge — sandbox cannot start." >&2
        echo "  Admin-allowed: ${_ADMIN_ALLOWED_PROJECT_PARENTS[*]}" >&2
        echo "  User-requested: ${_user_app[*]:-(none)}" >&2
        echo "  Add at least one path under an admin-allowed parent to your user config." >&2
        exit 1
    fi
}

# --- Source a trusted config file (admin-owned, no isolation needed) ---
_source_trusted_config() {
    local _conf="$1"
    local _syntax_diag _syntax_rc=0
    # Capture diagnostic + rc atomically. The `|| _syntax_rc=$?` guard
    # is required: under `set -e` (active globally), a command
    # substitution that exits non-zero on the right-hand side of a
    # plain `var="$(...)"` assignment aborts the script in bash 4.x
    # before subsequent error-handling can run. Pinning the rc into a
    # branch of `||` keeps the compound exit zero so we always reach
    # the explicit error path below.
    _syntax_diag="$(bash -n "$_conf" 2>&1)" || _syntax_rc=$?
    if [[ $_syntax_rc -ne 0 ]]; then
        echo "Error: Syntax error in $_conf" >&2
        [[ -n "$_syntax_diag" ]] && echo "$_syntax_diag" >&2
        exit 1
    fi
    # shellcheck disable=SC1090
    source "$_conf"
}

# --- Validate admin-set ALLOWED_PROJECT_PARENTS shape ---
#
# Called from Phase 1 only when admin explicitly set the variable. Fails
# closed: any malformed value aborts startup with a clear error rather
# than falling through to a permissive default.
#
# Validates: indexed-array type (not scalar/associative), no command
# substitution (defense in depth), no empty entries, every entry is an
# absolute path (after $HOME / ~ expansion).
_validate_admin_allowed_project_parents() {
    local _decl
    _decl="$(declare -p ALLOWED_PROJECT_PARENTS 2>/dev/null || true)"
    # Must be an indexed array. Bash declare flags: 'a' = indexed array,
    # 'x' = exported (also valid). Any other shape (scalar 'declare --',
    # associative 'declare -A') is rejected.
    if [[ "$_decl" != "declare -a "* && "$_decl" != "declare -ax "* ]]; then
        echo "Error: Admin config ${_ADMIN_CONF}: ALLOWED_PROJECT_PARENTS must be an indexed array." >&2
        echo "  Got: ${_decl:-<unset>}" >&2
        exit 1
    fi
    local _entry _expanded
    for _entry in "${ALLOWED_PROJECT_PARENTS[@]}"; do
        if [[ "$_entry" =~ \$\( ]] || [[ "$_entry" =~ \` ]]; then
            echo "Error: Admin config ${_ADMIN_CONF}: ALLOWED_PROJECT_PARENTS contains command substitution: '${_entry}'" >&2
            exit 1
        fi
        _expanded="${_entry//\$\{HOME\}/$HOME}"
        _expanded="${_expanded/#\~\//$HOME/}"
        _expanded="${_expanded/\$HOME/$HOME}"
        if [[ -z "$_expanded" ]]; then
            echo "Error: Admin config ${_ADMIN_CONF}: ALLOWED_PROJECT_PARENTS contains an empty entry." >&2
            exit 1
        fi
        if [[ "${_expanded:0:1}" != "/" ]]; then
            echo "Error: Admin config ${_ADMIN_CONF}: ALLOWED_PROJECT_PARENTS entry must be an absolute path: '${_entry}'" >&2
            exit 1
        fi
    done
}

# --- Snapshot admin config values after loading ---
#
# ALLOWED_PROJECT_PARENTS: if admin explicitly set the variable
# (_admin_set_app=true), snapshot admin's value as the narrowing
# baseline. Otherwise default to ("/") so the narrowing merge admits
# every user-supplied path (admin is silent → no narrowing).
_snapshot_admin_config() {
    _ADMIN_BLOCKED_FILES=("${BLOCKED_FILES[@]}")
    _ADMIN_BLOCKED_ENV_VARS=("${BLOCKED_ENV_VARS[@]}")
    _ADMIN_BLOCKED_ENV_PATTERNS=("${BLOCKED_ENV_PATTERNS[@]}")
    _ADMIN_ALLOWED_ENV_VARS=("${ALLOWED_ENV_VARS[@]}")
    _ADMIN_EXTRA_BLOCKED_PATHS=("${EXTRA_BLOCKED_PATHS[@]}")
    _ADMIN_HOME_READONLY=("${HOME_READONLY[@]}")
    _ADMIN_HOME_WRITABLE=("${HOME_WRITABLE[@]}")
    _ADMIN_HOME_SEEDED_FILES=("${HOME_SEEDED_FILES[@]}")
    _ADMIN_DENIED_WRITABLE_PATHS=("${DENIED_WRITABLE_PATHS[@]}")
    _ADMIN_EXTRA_WRITABLE_PATHS=("${EXTRA_WRITABLE_PATHS[@]}")
    _ADMIN_READONLY_MOUNTS=("${READONLY_MOUNTS[@]}")
    if [[ "${_admin_set_app:-false}" == true ]]; then
        _ADMIN_ALLOWED_PROJECT_PARENTS=("${ALLOWED_PROJECT_PARENTS[@]}")
    else
        _ADMIN_ALLOWED_PROJECT_PARENTS=("/")
    fi
    _ADMIN_DEVICES_BLACKLIST=("${DEVICES_BLACKLIST[@]}")
    _ADMIN_NETWORK_BLOCKLIST=("${NETWORK_BLOCKLIST[@]+"${NETWORK_BLOCKLIST[@]}"}")
    _ADMIN_NETWORK_BLOCKLIST_EXCEPT=("${NETWORK_BLOCKLIST_EXCEPT[@]+"${NETWORK_BLOCKLIST_EXCEPT[@]}"}")

    # Security-critical booleans: snapshot so users cannot weaken them.
    _ADMIN_PRIVATE_TMP="${PRIVATE_TMP:-true}"
    _ADMIN_PRIVATE_IPC="${PRIVATE_IPC:-true}"
    _ADMIN_FILTER_PASSWD="${FILTER_PASSWD:-true}"
    # Network-filter scalars: snapshot only when the admin file set them
    # explicitly. Absent value → empty string → no admin enforcement (user
    # config / built-in defaults apply).
    _ADMIN_NETWORK_FILTER_MODE="${NETWORK_FILTER_MODE:-}"
    _ADMIN_NETWORK_FILTER_FALLBACK="${NETWORK_FILTER_FALLBACK:-}"
    _ADMIN_NETWORK_MAIL_BLOCK="${NETWORK_MAIL_BLOCK:-}"
}

# ── Network filter — mode resolution + helper detection ──────────
#
# Modes (ordered by strictness): open < filtered < isolated. Fallback
# policies (ordered by strictness): open < stricter < strict.
#
# The resolver picks the actual mode to apply given the requested mode,
# the fallback policy, and the backend's capability matrix. Loud warnings
# are emitted on any fallback path; explicit fix-path enumerations are
# emitted on the fail path.
#
# Backend capability matrix:
#   bwrap    — open ✓ ; filtered ✓ if helper present (pasta or
#              slirp4netns on PATH, or the shipped tools/pasta/pasta) ;
#              isolated ✓ (native --unshare-net flag)
#   firejail — open ✓ ; filtered ✓ (--netfilter, needs nft on PATH) ;
#              isolated ✓ (--net=none)
#   landlock — open ✓ ; filtered ✗ ; isolated ✗ (no mount/net namespace)
#
# See docs/reference/network-filter.md for the full design.

_network_mode_strictness_idx() {
    case "$1" in
        open) echo 0 ;;
        filtered) echo 1 ;;
        proxied) echo 2 ;;
        isolated) echo 3 ;;
        *) echo 0 ;;
    esac
}

_network_fallback_strictness_idx() {
    case "$1" in
        open) echo 0 ;;
        stricter) echo 1 ;;
        strict) echo 2 ;;
        *) echo 0 ;;
    esac
}

# Returns 0 if a network helper is available AND v1.1's bwrap backend
# can integrate it for a real filtered-mode delivery. Stdout: helper
# path.
#
# v1.1 implementation status: helper-probe is live. The
# `NETWORK_FILTER_ENABLE_HELPER_PROBE` env-toggle gate from v1.0 is
# gone — `filtered` mode is real by default whenever pasta is
# available. v1.1 enforces the blocklist at pasta's own boundary
# (via `-T ~N` outbound port exclusions); no nftables dependency.
#
# Probe order:
#   1. `command -v pasta` — distro/Homebrew install; takes precedence
#      because it's typically newer than the in-tree pin.
#   2. tools/pasta/<arch>/pasta — the shipped static binary (see
#      tools/pasta/README.md for fetch + license details).
#   3. `command -v slirp4netns` — older fallback (GPL-2.0 source-
#      offer obligation; less preferred and currently degraded).
_resolve_network_helper() {
    if command -v pasta &>/dev/null; then
        command -v pasta
        return 0
    fi
    local _arch
    _arch="$(uname -m)"
    case "$_arch" in
        x86_64|amd64) _arch=x86_64 ;;
        aarch64|arm64) _arch=aarch64 ;;
    esac
    if [[ -x "$SANDBOX_DIR/tools/pasta/$_arch/pasta" ]]; then
        echo "$SANDBOX_DIR/tools/pasta/$_arch/pasta"
        return 0
    fi
    # Legacy path retained for one release so dev trees built against
    # v1.0's tools/pasta/fetch.sh still resolve.
    if [[ -x "$SANDBOX_DIR/tools/pasta/pasta" ]]; then
        echo "$SANDBOX_DIR/tools/pasta/pasta"
        return 0
    fi
    if command -v slirp4netns &>/dev/null; then
        command -v slirp4netns
        return 0
    fi
    return 1
}

# Probe whether the resolved helper can actually forward outbound from
# an unprivileged netns on this host. Returns 0 if forwarding is healthy,
# 1 if the helper degrades to loopback-only (and so `filtered` mode would
# silently behave like `isolated`).
#
# Why this exists. pasta uses SO_BINDTODEVICE to pin host-side sockets to
# the outbound interface. On kernel < 5.7 (or any kernel without the
# 2020 relaxation backported) SO_BINDTODEVICE requires CAP_NET_RAW in
# the init userns; an unprivileged shell on a typical HPC login node has
# neither root nor a `setcap cap_net_raw+ep`-blessed pasta. pasta still
# starts under those conditions but logs `SO_BINDTODEVICE unavailable,
# forwarding only 127.0.0.1 and ::1` and silently restricts forwarding
# to loopback. Without this probe the resolver declares `filtered`
# supported, the sandbox launches with the documented filtered argv,
# and the agent gets no network at all on ports that should be allowed
# (53, 443, ...) — the worst of both worlds: not isolated (no warning),
# but no outbound. Probing catches that and lets `stricter` fallback do
# its job (filtered → isolated, loud warning).
#
# The optional override NETWORK_FILTER_SKIP_HELPER_PROBE=1 bypasses the
# probe for operators who know their pasta is healthy (e.g. setcap-
# blessed system binary) and want to spend the ms elsewhere.
#
# Side effects (set in caller's scope; this function is invoked from
# _prepare_network_helper_probe which is NOT in a subshell):
#   _NETWORK_HELPER_PROBE_RESULT   — "ok" | "degraded"
#   _NETWORK_HELPER_DEGRADED_REASON — set on degraded; consumed by
#                                     resolve_network_filter_mode's
#                                     `_why` switch.
_pasta_can_forward_outbound() {
    local _pasta="$1"
    [[ -x "$_pasta" ]] || return 1
    if [[ "${NETWORK_FILTER_SKIP_HELPER_PROBE:-0}" == "1" ]]; then
        _NETWORK_HELPER_PROBE_RESULT="ok"
        return 0
    fi
    # Run pasta with a no-op command and capture stderr. With --quiet
    # pasta still prints the SO_BINDTODEVICE degradation banner — it's
    # a critical fall-back notice, not a verbosity-gated message. Cap
    # runtime with a short timeout in case pasta hangs on an exotic
    # host config; the happy path exits in ~50ms. `|| true` is load-
    # bearing under `set -e` — we only care about the stderr text, not
    # pasta's exit code.
    local _stderr
    _stderr="$(timeout 5 "$_pasta" --foreground --quiet -- true 2>&1 1>/dev/null)" || true
    if [[ "$_stderr" == *"forwarding only 127.0.0.1"* ]]; then
        _NETWORK_HELPER_PROBE_RESULT="degraded"
        _NETWORK_HELPER_DEGRADED_REASON="pasta started but degraded to loopback-only forwarding (kernel SO_BINDTODEVICE unavailable to unprivileged users on this host); filtered mode would silently leave the agent with no outbound. Workarounds: (a) admin runs 'setcap cap_net_raw+ep $_pasta' on a system-wide pasta binary; (b) upgrade to kernel >= 5.7 with the SO_BINDTODEVICE relaxation; (c) pin NETWORK_FILTER_MODE=open or 'isolated' to make the choice explicit."
        return 1
    fi
    _NETWORK_HELPER_PROBE_RESULT="ok"
    return 0
}

# Resolve + probe the network helper in the caller's scope. Sets:
#   _NETWORK_HELPER_PROBE_RESULT   — "ok" | "degraded" | "none"
#   _NETWORK_HELPER_DEGRADED_REASON — human-readable line for `_why`
#                                     (set only on degraded)
#   _NETWORK_HELPER_RESOLVED_PATH   — helper path on resolve success
#
# Backend-agnostic at the entry point because only bwrap currently uses
# the helper, but other backends can adopt the same probe by adding a
# case below.
_prepare_network_helper_probe() {
    local _backend="$1"
    _NETWORK_HELPER_PROBE_RESULT="none"
    _NETWORK_HELPER_DEGRADED_REASON=""
    _NETWORK_HELPER_RESOLVED_PATH=""
    case "$_backend" in
        bwrap) ;;
        *) return 0 ;;
    esac
    local _helper
    _helper="$(_resolve_network_helper)" || return 0
    _NETWORK_HELPER_RESOLVED_PATH="$_helper"
    if _pasta_can_forward_outbound "$_helper"; then
        return 0
    fi
    return 0
}

# Backend-capability probe. Stdout: space-separated list of supported
# modes for the given backend.
#
# Note: this function is invoked from `resolve_network_filter_mode` via
# command substitution, so any variables it sets are confined to that
# subshell. Side effects that must reach the caller (notably
# _NETWORK_HELPER_PROBE_RESULT and _NETWORK_HELPER_DEGRADED_REASON) are
# established BEFORE this call — see `_prepare_network_helper_probe`.
_network_modes_supported_by_backend() {
    local _backend="$1"
    case "$_backend" in
        bwrap)
            # `filtered` needs pasta — it provisions the netns + tap +
            # DNS proxy AND enforces the port-level blocklist at its
            # own forwarding boundary (`-T ~N` outbound exclusions).
            # No nftables dependency.
            #
            # The helper must (a) resolve to an executable AND (b) pass
            # the forwarding probe. (b) catches the kernel-< 5.7 /
            # unprivileged-userns trap where pasta runs but silently
            # forwards only loopback — see _pasta_can_forward_outbound.
            #
            # `proxied` (v0.10.1+) needs python3 (+ ipaddress stdlib,
            # 3.6 baseline). Available on every modern Linux distro;
            # the only realistic miss is hosts with python2-only.
            # Detection: $LIBDIR/tools/proxy/agent-sandbox-proxy.py
            # plus a python3 on PATH that parses our shebang. We do
            # not exec-probe Python here — that work happens once at
            # sandbox-exec.sh::_NETWORK_PROXY launch.
            local _modes="open isolated"
            if [[ "${_NETWORK_HELPER_PROBE_RESULT:-}" == "ok" ]]; then
                _modes="open filtered isolated"
            fi
            if _proxied_supported_on_bwrap; then
                _modes="$_modes proxied"
            fi
            echo "$_modes"
            ;;
        firejail)
            # firejail delivers isolated via --net=none. `filtered` mode
            # via firejail's --netfilter requires a private netns wired
            # to a host bridge (--net=<iface>); that bridge is a site-
            # level setup we don't auto-provision in v1.1. Operators
            # using firejail get isolated-or-open until the bridge-
            # provisioning story is settled (tracked for v1.2). The
            # resolver falls back per policy.
            #
            # `proxied` is bwrap-only in 0.10.1 — wiring it for firejail
            # is mechanically straightforward (firejail also supports
            # --net=none + bind-mount) but defers to a follow-up so the
            # initial PR stays auditable.
            echo "open isolated"
            ;;
        landlock)
            # No mount/network namespace — only open.
            echo "open"
            ;;
        *)
            echo "open"
            ;;
    esac
}

# Does this host support `proxied` mode on the bwrap backend? Requires
# python3 on PATH and the agent-sandbox-proxy.py helper installed under
# $SANDBOX_DIR/tools/proxy/.
_proxied_supported_on_bwrap() {
    command -v python3 >/dev/null 2>&1 || return 1
    [[ -r "$SANDBOX_DIR/tools/proxy/agent-sandbox-proxy.py" ]] || return 1
    return 0
}

# Pretty-print the fix-path block. Used by both warn-fallback and fail
# paths. Centralizes the message text so docs and runtime stay in sync.
_network_filter_print_fixpaths() {
    local _requested="$1" _backend="$2"
    cat >&2 <<EOF
  Fix paths (pick whichever fits):
    1. Install pasta so 'filtered' mode works on bwrap:
         apt install passt         # Debian / Ubuntu 22.10+
         dnf install passt         # RHEL 9+ / Fedora
         brew install passt        # Homebrew
       Or refresh the static pasta binary shipped with agent-sandbox:
         $SANDBOX_DIR/tools/pasta/fetch.sh
       (The shipped binary lives at tools/pasta/<arch>/pasta and is
       auto-detected. No nftables / iptables dependency.)
    2. Pin NETWORK_FILTER_MODE='isolated' to accept the kill-network
       fallback intentionally (no warning, full block).
    3. Set NETWORK_FILTER_FALLBACK='open' to also accept dropping to
       host network when no isolated mode is available. ACCEPTS
       WEAKENING.
    4. Set NETWORK_FILTER_FALLBACK='strict' to refuse to launch
       instead of falling back (what 'strict' gives you).
    5. Set NETWORK_FILTER_MODE='open' to disable the layer entirely.
  See docs/reference/network-filter.md for the full mode + fallback
  matrix and per-backend support.
EOF
}

_network_filter_warn_fallback() {
    local _from="$1" _to="$2" _why="$3" _backend="$4"
    cat >&2 <<EOF
sandbox: WARNING — network filter fell back from '$_from' to '$_to'.
  Reason: $_why
  Active backend: $_backend
EOF
    _network_filter_print_fixpaths "$_from" "$_backend"
}

_network_filter_fail() {
    local _why="$1" _requested="$2" _backend="$3"
    cat >&2 <<EOF
Error: sandbox cannot deliver NETWORK_FILTER_MODE='$_requested' on backend '$_backend'.
  Reason: $_why
EOF
    _network_filter_print_fixpaths "$_requested" "$_backend"
    exit 1
}

# Resolve the actual network mode to apply. Side effects:
#   _NETWORK_FILTER_RESOLVED  — one of open|filtered|isolated
#   _NETWORK_FILTER_REASON    — human-readable rationale (for logging)
#   _NETWORK_FILTER_HELPER    — for filtered mode, the resolved network
#                               helper binary path (pasta / slirp4netns;
#                               empty otherwise)
# Exits with diagnostic on irrecoverable mismatch.
resolve_network_filter_mode() {
    local _backend="$1"
    local _requested="${NETWORK_FILTER_MODE:-filtered}"
    local _policy="${NETWORK_FILTER_FALLBACK:-open}"

    case "$_requested" in
        open|filtered|proxied|isolated) ;;
        *) echo "Error: NETWORK_FILTER_MODE='$_requested' invalid (open|filtered|proxied|isolated)." >&2; exit 1 ;;
    esac
    case "$_policy" in
        strict|stricter|open) ;;
        *) echo "Error: NETWORK_FILTER_FALLBACK='$_policy' invalid (strict|stricter|open)." >&2; exit 1 ;;
    esac

    # Run the helper-forwarding probe before evaluating supported modes.
    # _network_modes_supported_by_backend reads _NETWORK_HELPER_PROBE_RESULT
    # but cannot set it (it's invoked in a $(...) subshell below).
    _prepare_network_helper_probe "$_backend"

    local _supported
    _supported=" $(_network_modes_supported_by_backend "$_backend") "

    _NETWORK_FILTER_HELPER=""
    if [[ "$_supported" == *" $_requested "* ]]; then
        _NETWORK_FILTER_RESOLVED="$_requested"
        _NETWORK_FILTER_REASON="$_requested (requested; supported on backend '$_backend')"
        if [[ "$_requested" == "filtered" && "$_backend" == "bwrap" ]]; then
            _NETWORK_FILTER_HELPER="$(_resolve_network_helper)"
        fi
        return 0
    fi

    local _why
    case "$_requested:$_backend" in
        filtered:bwrap)
            if [[ -n "${_NETWORK_HELPER_DEGRADED_REASON:-}" ]]; then
                _why="$_NETWORK_HELPER_DEGRADED_REASON"
            else
                _why="filtered mode requires a network helper (pasta); none found on PATH and the shipped binary at tools/pasta/<arch>/pasta is missing or not executable."
            fi
            ;;
        filtered:firejail) _why="filtered mode on firejail requires a site-provisioned bridge (--net=<iface> + --netfilter); v1.1 does not auto-provision the bridge. Use bwrap for filtered mode, or accept the policy fallback." ;;
        filtered:landlock) _why="filtered mode requires a mount/network namespace; landlock has neither." ;;
        isolated:landlock) _why="isolated mode requires a network namespace; landlock has none." ;;
        *)                 _why="mode '$_requested' not supported on backend '$_backend' (supported: $_supported)." ;;
    esac

    case "$_policy" in
        strict)
            _network_filter_fail "$_why" "$_requested" "$_backend"
            ;;
        stricter)
            # Walk strict-direction modes LEAST-strict-first so we
            # strengthen as little as necessary. `proxied` (idx 2)
            # slots between `filtered` (1) and `isolated` (3): a host
            # with a degraded pasta now lands on proxied instead of
            # jumping straight to no-network. Pre-v0.10.1 the walk
            # ordered `isolated filtered` because those were the only
            # two candidates; with three candidates the load-bearing
            # invariant is "smallest step up", which means the LEAST
            # strict of the strict-direction modes wins first.
            local _req_idx _try _try_idx
            _req_idx="$(_network_mode_strictness_idx "$_requested")"
            for _try in filtered proxied isolated; do
                _try_idx="$(_network_mode_strictness_idx "$_try")"
                if [[ "$_try_idx" -gt "$_req_idx" && "$_supported" == *" $_try "* ]]; then
                    _NETWORK_FILTER_RESOLVED="$_try"
                    _NETWORK_FILTER_REASON="$_try (fallback from '$_requested'; policy=stricter)"
                    if [[ "$_try" == "filtered" && "$_backend" == "bwrap" ]]; then
                        _NETWORK_FILTER_HELPER="$(_resolve_network_helper)"
                    fi
                    _network_filter_warn_fallback "$_requested" "$_try" "$_why" "$_backend"
                    return 0
                fi
            done
            # Stricter requested but nothing strict-supported. Fall to
            # the least strict supported. (Reach: degraded-pasta + only
            # `proxied` requested + stricter — would mean isolated;
            # exposed here only for theoretical completeness.)
            _network_filter_fail "$_why (no stricter mode available on backend '$_backend'; policy=stricter)" "$_requested" "$_backend"
            ;;
        open)
            # `open` policy falls back ONLY to a LESS-restrictive mode
            # than requested — never to a stricter one. The user's
            # request named a target level of isolation; if that level
            # can't be delivered, `open` says "weaken, don't strengthen".
            # The probe order is most-strict-of-the-less-strict first so
            # we degrade as little as necessary.
            #
            # `proxied` is intentionally NOT in this fallback walk: a
            # default-config user on a degraded host got `open` in
            # v0.10.0; silently strengthening them to `proxied`
            # (different observable behaviour — ssh / raw-tcp / dig all
            # break) would violate least-surprise. Operators who want
            # the proxy chokepoint set NETWORK_FILTER_FALLBACK=stricter
            # (or NETWORK_FILTER_MODE=proxied directly).
            local _req_idx _try _try_idx
            _req_idx="$(_network_mode_strictness_idx "$_requested")"
            for _try in proxied filtered open; do
                _try_idx="$(_network_mode_strictness_idx "$_try")"
                if [[ "$_try_idx" -lt "$_req_idx" && "$_supported" == *" $_try "* ]]; then
                    _NETWORK_FILTER_RESOLVED="$_try"
                    _NETWORK_FILTER_REASON="$_try (fallback from '$_requested'; policy=open, less-restrictive)"
                    if [[ "$_try" == "filtered" && "$_backend" == "bwrap" ]]; then
                        _NETWORK_FILTER_HELPER="$(_resolve_network_helper)"
                    fi
                    _network_filter_warn_fallback "$_requested" "$_try" "$_why" "$_backend"
                    return 0
                fi
            done
            # `open` is always available — if we got here the requested
            # mode was 'open' (which means it was supported and we'd have
            # taken the happy path above). Belt-and-suspenders.
            _NETWORK_FILTER_RESOLVED="open"
            _NETWORK_FILTER_REASON="open (last-resort fallback from '$_requested'; policy=open)"
            _network_filter_warn_fallback "$_requested" "open" "$_why" "$_backend"
            return 0
            ;;
    esac
}

# ── Mail-block layer — resolution + target lists ─────────────────
#
# `NETWORK_MAIL_BLOCK` controls whether canonical mailer binaries get
# replaced inside the sandbox with `tools/mail-block/mail-block-stub.sh`.
# This is upstream of the network filter (which blocks SMTP at the
# namespace edge): the stub catches `execve` so the agent learns the
# policy in human-readable terms before the kernel drops a connection.
# Strictness ordering: off (0) < auto (1) < on (2). Admin enforcement
# uses the same "user can only request a stricter value" model as
# NETWORK_FILTER_MODE.

_mail_block_strictness_idx() {
    case "$1" in
        off) echo 0 ;;
        auto) echo 1 ;;
        on) echo 2 ;;
        *) echo 1 ;;
    esac
}

# Canonical mailer binary names. Used by `backends/bwrap.sh` to (a)
# materialise a per-launch symlink farm under $TMPDIR (bind-mounted at
# the same path on both sides of the sandbox boundary, mirroring the
# chaperon FIFO pattern) so a PATH prepend of that dir shadows
# host-PATH lookups (catches `/usr/local/bin/<name>`, Lmod-injected
# `/app/software/<pkg>/bin/<name>`, etc.) and (b) drive the bind-mount
# loop below for absolute-path invocations.
#
# Set composed from the multi-expert design review for v0.10.1:
# Sendmail family + sendmail-alternatives backing files; mail/mailx
# variants including legacy/heirloom names; mutt family; SMTP-direct
# clients; postfix admin tools; test/utility (swaks); mpack/metasend;
# exim admin; DragonFly Mail Agent (dma); qmail client utilities.
_MAIL_BLOCK_STUB_NAMES=(
    sendmail sendmail.sendmail sendmail.postfix rmail
    mail mailx Mail s-nail nail bsd-mailx heirloom-mailx
    mutt neomutt
    msmtp ssmtp nullmailer-send smtp-cli
    postsuper postdrop postqueue mailq newaliases
    swaks
    mpack metasend
    exim exim4
    dma
    qmail-inject qmail-qmqpc qmail-remote
)

# Canonical absolute paths the bind-mount loop attempts to shadow. An
# entry that doesn't exist on the host is silently skipped — there's
# no need to materialise phantom paths (the symlink farm + PATH
# prefix catches any name the loop missed). Each name is enumerated
# under `/usr/bin`, `/usr/sbin`, and known fallback locations (qmail
# under `/var/qmail/bin`, sendmail's historical `/usr/lib/sendmail`).
_mail_block_target_paths() {
    local _n
    for _n in "${_MAIL_BLOCK_STUB_NAMES[@]}"; do
        echo "/usr/bin/$_n"
        echo "/usr/sbin/$_n"
    done
    # Historical sendmail location (Debian / pre-FHS).
    echo "/usr/lib/sendmail"
    # qmail location convention.
    echo "/var/qmail/bin/qmail-inject"
    echo "/var/qmail/bin/qmail-qmqpc"
    echo "/var/qmail/bin/qmail-remote"
}

# Resolve effective mail-block mode given the network-filter mode the
# resolver picked. Side effects:
#   _MAIL_BLOCK_RESOLVED — "on" | "off"
#   _MAIL_BLOCK_REASON   — human-readable rationale (for dry-run /
#                          banner)
# Reads:
#   NETWORK_MAIL_BLOCK         — knob (auto|on|off)
#   NETWORK_FILTER_MODE        — user-configured network intent (post-
#                                admin merge); see below for why we
#                                read intent, not realised state.
#   _NETWORK_FILTER_RESOLVED   — set earlier by resolve_network_filter_mode
#
# Auto semantics — strictest-of-both intent and realised state. The
# mail-block layer disengages only when BOTH the configured network
# mode AND the resolved one are `open`; if either is anything else,
# the layer stays on.
#
# Why both, not just resolved: if a user configures
# NETWORK_FILTER_MODE=filtered with NETWORK_FILTER_FALLBACK=open and
# the host lacks pasta, the filter falls back to `open` — but their
# configured intent ("I want egress constrained") is still in force.
# `FALLBACK=open` says "accept degraded networking rather than refuse
# to launch", NOT "withdraw all egress concerns". Mail-block doesn't
# depend on the kernel features the fallback gated on (it's PATH-
# prefix + bind-mount + symlinks), so the degradation that disabled
# the primary defense does not disable this secondary one — and that
# is precisely when defense-in-depth earns its name.
#
# Why both, not just configured: under NETWORK_FILTER_FALLBACK=stricter
# the resolver can also walk UP (e.g. requested `open`, resolved to
# `filtered` because the operator pinned a stricter floor). Tracking
# the stricter of the two keeps `auto` aligned with the ambient
# strictness an outside observer would see.
resolve_network_mail_block_mode() {
    local _knob="${NETWORK_MAIL_BLOCK:-auto}"
    local _cfg="${NETWORK_FILTER_MODE:-filtered}"
    local _net="${_NETWORK_FILTER_RESOLVED:-open}"
    case "$_knob" in
        on)
            _MAIL_BLOCK_RESOLVED="on"
            _MAIL_BLOCK_REASON="on (requested)"
            ;;
        off)
            _MAIL_BLOCK_RESOLVED="off"
            _MAIL_BLOCK_REASON="off (requested)"
            ;;
        auto)
            if [[ "$_cfg" == "open" && "$_net" == "open" ]]; then
                _MAIL_BLOCK_RESOLVED="off"
                _MAIL_BLOCK_REASON="off (auto; NETWORK_FILTER_MODE=open, resolved=open)"
            else
                _MAIL_BLOCK_RESOLVED="on"
                if [[ "$_cfg" != "$_net" ]]; then
                    _MAIL_BLOCK_REASON="on (auto; NETWORK_FILTER_MODE='$_cfg', resolved to '$_net')"
                else
                    _MAIL_BLOCK_REASON="on (auto; NETWORK_FILTER_MODE='$_net')"
                fi
            fi
            ;;
        *)
            echo "Error: NETWORK_MAIL_BLOCK='$_knob' invalid (auto|on|off)." >&2
            exit 1
            ;;
    esac
}

# ── Precedence model — wildcard / exception / admin pin ──────────
#
# Policy entries (NETWORK_BLOCKLIST and NETWORK_BLOCKLIST_EXCEPT)
# support bash-glob wildcards in the host part. Examples:
#   *.amazonaws.com          # any subdomain
#   *.example.com:443        # any subdomain on port 443
#   *                        # everything (deny-all pattern)
#   10.0.0.0/8               # CIDR (string-equal match for now;
#                            #   future v1.1 enforcement parses)
#   853                      # bare port (all destinations)
#
# Matching semantics (v1.0 policy-table level):
#
#   `_network_rule_matches PATTERN CANDIDATE` returns 0 iff PATTERN
#   matches CANDIDATE under bash glob semantics. Used to detect when
#   an admin BLOCKLIST entry covers a user EXCEPT entry (and so the
#   user's exception is meaningless and must be stripped). The full
#   per-connection enforcement (CIDR + port + hostname tuple
#   evaluation) is the v1.1 helper's job — at v1.0 the resolver
#   computes and exports the policy table; this glob-cover check is
#   the only pattern-match the lib itself performs at config-load.
#
# Specificity / precedence (documented for v1.1 enforcement):
#   exact host:port  >  exact host  >  CIDR with smaller mask  >
#   CIDR with larger mask  >  wildcard host pattern  >  bare port
# Among same-specificity rules, BLOCKLIST wins over BLOCKLIST_EXCEPT
# (safer default). Admin rules always win over user rules.

_network_rule_matches() {
    # shellcheck disable=SC2053 # pattern matching is intentional
    [[ "$2" == $1 ]]
}

# Strip user-added NETWORK_BLOCKLIST_EXCEPT entries that are covered
# by any admin-set NETWORK_BLOCKLIST entry (under bash-glob semantics).
# Admin policy is absolute — users cannot carve exceptions out of
# admin blocks. Emits a loud warning per stripped entry.
_strip_user_exceptions_covered_by_admin() {
    local _label="${1:-Config}"
    # Bail when either array isn't set (test harnesses, no-admin runs).
    declare -p _ADMIN_NETWORK_BLOCKLIST &>/dev/null || return 0
    declare -p NETWORK_BLOCKLIST_EXCEPT &>/dev/null || return 0
    local _filtered=() _exc _admin _covered
    for _exc in "${NETWORK_BLOCKLIST_EXCEPT[@]+"${NETWORK_BLOCKLIST_EXCEPT[@]}"}"; do
        _covered=false
        for _admin in "${_ADMIN_NETWORK_BLOCKLIST[@]+"${_ADMIN_NETWORK_BLOCKLIST[@]}"}"; do
            if _network_rule_matches "$_admin" "$_exc"; then
                _covered=true
                echo "WARNING: ${_label} attempted to except '${_exc}' but admin NETWORK_BLOCKLIST has '${_admin}' which covers it — exception stripped (admin policy is absolute)." >&2
                break
            fi
        done
        $_covered || _filtered+=("$_exc")
    done
    NETWORK_BLOCKLIST_EXCEPT=("${_filtered[@]+"${_filtered[@]}"}")
}

# Compute the effective blocklist as the union of:
#   _NETWORK_BLOCKLIST_DEFAULTS (built-in floor; always applied)
#   NETWORK_BLOCKLIST           (admin + user merged after _enforce_admin_policy)
# Duplicates collapse; order is floor → merged-config, preserved for the
# emitted ruleset (later rules can shadow but the floor is enforced).
# Result printed one entry per line to stdout.
effective_network_blocklist() {
    local _entry
    for _entry in "${_NETWORK_BLOCKLIST_DEFAULTS[@]}"; do
        echo "$_entry"
    done
    for _entry in "${NETWORK_BLOCKLIST[@]+"${NETWORK_BLOCKLIST[@]}"}"; do
        echo "$_entry"
    done
}

# Compute the effective exception list — admin + user merged, with
# user entries covered by admin BLOCKLIST already stripped (by
# `_strip_user_exceptions_covered_by_admin` at config-load time).
# Result printed one entry per line to stdout.
effective_network_exception_list() {
    local _entry
    for _entry in "${NETWORK_BLOCKLIST_EXCEPT[@]+"${NETWORK_BLOCKLIST_EXCEPT[@]}"}"; do
        echo "$_entry"
    done
}

# ── pasta port-exclusion generator for v1.1 filtered mode ────────
#
# Generate the pasta -T (TCP) and -U (UDP) outbound port-exclusion
# SPECs from `effective_network_blocklist`. v1.1 enforces the
# blocklist at pasta's own forwarding boundary — pasta's `-T ~N`
# syntax means "forward all outbound ports except N" so the netns
# loses egress on the named ports while keeping everything else.
# No nftables dependency.
#
# Stdout: two lines —
#   TCP: ~25,~465,~587,~853,...
#   UDP: ~853,...
# Empty string in either field if no exclusions apply. Caller splits
# on first space.
#
# Honest limits — what pasta -T/-U can enforce (and what it can't):
#
#   ENFORCEABLE at pasta's boundary:
#     - bare port              ("25", "853")     → emitted as ~25
#     - host:port (universal)  ("0.0.0.0/0:25")  → port-only; ~25
#     - loopback host:port     ("127.0.0.1:25")  → ALREADY structurally
#       unreachable: pasta gives the netns its own empty loopback,
#       so host MTAs on 127.0.0.1 are unreachable regardless. We
#       also emit ~25 for defense in depth.
#
#   NOT ENFORCEABLE at pasta's boundary (skipped with stderr note;
#   tracked for v1.2 L7 proxy work):
#     - hostname entries          ("api.mailgun.net")
#     - wildcard hostnames        ("*.cloudflare-dns.com")
#     - hostname:port            ("hooks.slack.com:443")
#     - CIDR with non-universal port ("10.0.0.0/8:25" — universal
#       port portion IS enforced via the bare-port closure, so the
#       SMTP-to-CIDR threat is covered; the CIDR-specificity is what
#       gets dropped)
#     - "*" deny-all              — operators wanting deny-all should
#       pin NETWORK_FILTER_MODE=isolated directly
#
# Rationale for the pivot from a v1.1 nft-based design: pasta alone
# handles the actual identity-hijack threat (mail submission ports
# universally closed; DoT port 853 closed; loopback MTA structurally
# unreachable). Hostname-level enforcement was always best-effort
# under any L3/L4 design and properly belongs to the v1.2 L7-proxy
# scope. Eliminating the nftables runtime dependency simplifies
# deployment and reduces surface area; the threat closure remains.
generate_pasta_port_exclusions() {
    local _entry _port
    local -A _tcp_ports=() _udp_ports=()

    while IFS= read -r _entry; do
        [[ -z "$_entry" ]] && continue
        _classify_pasta_port_entry "$_entry" _tcp_ports _udp_ports
    done < <(effective_network_blocklist)

    # Exception list: the caller can lift specific ports from the
    # exclusion set. We strip any port the exception lists by
    # matching on the port-only key. Hostname-based exceptions
    # have no effect at the pasta layer (no rule was emitted for
    # the corresponding blocklist host either).
    local _exc_entry _exc_port
    while IFS= read -r _exc_entry; do
        [[ -z "$_exc_entry" ]] && continue
        if [[ "$_exc_entry" =~ ^([0-9]+)$ ]]; then
            unset "_tcp_ports[${BASH_REMATCH[1]}]" "_udp_ports[${BASH_REMATCH[1]}]"
        elif [[ "$_exc_entry" =~ :([0-9]+)$ ]]; then
            # host:port exception — only lifts if the port is
            # universally excluded (which is the common case for
            # ports we close).
            _exc_port="${BASH_REMATCH[1]}"
            # We don't auto-lift: the user asked to except a specific
            # host:port pair, but our port-level enforcement is
            # universal. Emit a stderr note that the host part can't
            # be carved at this layer.
            if [[ -n "${_tcp_ports[$_exc_port]:-}" || -n "${_udp_ports[$_exc_port]:-}" ]]; then
                [[ "${NETWORK_FILTER_VERBOSE:-0}" == "1" ]] && \
                    echo "sandbox: NOTE — host:port exception '${_exc_entry}' cannot be carved at pasta's port-level layer (port ${_exc_port} is universally blocked); use NETWORK_FILTER_MODE=open or the v1.2 L7 proxy for host-specific carve-outs." >&2
            fi
        fi
    done < <(effective_network_exception_list)

    # Emit TCP exclusion SPEC.
    local _tcp_spec="" _p
    for _p in "${!_tcp_ports[@]}"; do
        _tcp_spec="${_tcp_spec:+${_tcp_spec},}~${_p}"
    done
    local _udp_spec=""
    for _p in "${!_udp_ports[@]}"; do
        _udp_spec="${_udp_spec:+${_udp_spec},}~${_p}"
    done

    echo "TCP:${_tcp_spec}"
    echo "UDP:${_udp_spec}"
}

# Classify a blocklist entry into the pasta port-exclusion model.
# Populates the TCP/UDP associative arrays passed by name. Emits a
# stderr note for entries that are not enforceable at pasta's layer
# (hostname, CIDR-with-port, wildcards, "*").
_classify_pasta_port_entry() {
    local _entry="$1"
    local -n _tcp="$2" _udp="$3"
    local _port

    # "*" deny-all — unenforceable; operators wanting deny-all should
    # use isolated mode. Remains verbose-gated: a literal '*' in
    # NETWORK_BLOCKLIST is conventionally the "implicit-allowlist"
    # idiom (see sandbox.conf "Implicit-allowlist idiom" block),
    # where operators deliberately combine `*` with an EXCEPT list
    # and don't want a NOTE on every launch reminding them. The
    # explicit-hostname forms below (wildcard-hostname, bare
    # hostname) fire unconditionally per ASB-2026-002 because those
    # shapes are operator-error indicators ("I asked for a block,
    # the block is silently a no-op"), not deliberate idioms.
    if [[ "$_entry" == "*" ]]; then
        [[ "${NETWORK_FILTER_VERBOSE:-0}" == "1" ]] && \
            echo "sandbox: NOTE — network-filter entry '*' cannot be enforced at pasta's port-level layer (would block DNS); use NETWORK_FILTER_MODE=isolated for deny-all semantics. Skipping." >&2
        return 0
    fi

    # Wildcard hostname — needs SNI inspection (v1.2 L7 scope). NOTE
    # fires unconditionally (ASB-2026-002, vocal-by-default).
    if [[ "$_entry" == \** ]]; then
        echo "sandbox: NOTE — wildcard hostname entry '${_entry}' cannot be enforced at pasta's port-level layer (requires SNI inspection; v1.2 L7 proxy scope). Skipping." >&2
        return 0
    fi

    # Bare port → universal port exclusion.
    if [[ "$_entry" =~ ^([0-9]+)$ ]]; then
        _port="${BASH_REMATCH[1]}"
        _tcp["$_port"]=1
        _udp["$_port"]=1
        return 0
    fi

    # host:port or CIDR:port — extract the port; pasta's enforcement is
    # universal-port (we can't bind it to the host/CIDR portion). For
    # the v1.0 default blocklist this is the right answer: every
    # CIDR:port entry uses port 25 / 24 / 465 / 587 / 2525 (the SMTP
    # class) where universal closure is the desired threat model.
    if [[ "$_entry" =~ :([0-9]+)$ ]]; then
        _port="${BASH_REMATCH[1]}"
        # Note the host-specificity drop only when NETWORK_FILTER_VERBOSE=1
        # AND the host part is non-trivial (i.e., not a universal
        # loopback / any-address pattern). The "loopback + universal"
        # cases are structurally equivalent to a bare-port block here.
        local _suppress_note=false
        case "$_entry" in
            0.0.0.0/0:*|127.0.0.1:*|"[::]/0:"*|"[::1]:"*) _suppress_note=true ;;
        esac
        if [[ "${NETWORK_FILTER_VERBOSE:-0}" == "1" && "$_suppress_note" != "true" ]]; then
            echo "sandbox: NOTE — entry '${_entry}' enforced as universal port-${_port} block (pasta does not filter by host/CIDR at this layer); use the v1.2 L7 proxy for host-specific port carve-outs." >&2
        fi
        _tcp["$_port"]=1
        _udp["$_port"]=1
        return 0
    fi

    # Bare hostname, CIDR-without-port, or unrecognized form — no
    # enforcement at this layer. NOTE fires unconditionally
    # (ASB-2026-002, vocal-by-default): operators writing
    # `NETWORK_BLOCKLIST+=("evil.com")` should not silently
    # discover their configured restriction is a no-op.
    echo "sandbox: NOTE — hostname/CIDR entry '${_entry}' cannot be enforced at pasta's port-level layer (no port to exclude); use the v1.2 L7 proxy for SNI-aware filtering or isolated mode for hard deny-all. Skipping." >&2
}

# ── Test-harness early-return ────────────────────────────────────
#
# Tests can source this file as a function library by setting
# _SANDBOX_LIB_NO_INIT=1 before sourcing. Phases 1–3 (admin source,
# user source, enforcement) and downstream validation/backend
# detection are skipped, but every helper function and the admin/user
# snapshot machinery above is defined and ready to call.
#
# Production callers (sandbox-exec.sh, sbatch-sandbox.sh,
# srun-sandbox.sh) leave _SANDBOX_LIB_NO_INIT unset and get the full
# init. The variable is internal — neither config nor environment
# should set it; only the in-tree unit-test harness does.
[[ "${_SANDBOX_LIB_NO_INIT:-}" == "1" ]] && return 0

# ── Phase 1: Source admin config (trusted — admin-owned, root-protected) ──
#
# Missing-vs-malformed boundary: a missing admin config file causes
# _ADMIN_CONF to be unset above, so this block is skipped entirely and
# the sandbox runs in user-only mode. A present-but-malformed admin
# config is caught here: parse errors abort via _source_trusted_config,
# and shape errors on ALLOWED_PROJECT_PARENTS abort via
# _validate_admin_allowed_project_parents. There is no fall-through to
# a permissive default once admin has spoken.
if [[ -n "$_ADMIN_CONF" && -f "$_ADMIN_CONF" ]]; then
    # Unset before sourcing so we can detect whether admin explicitly
    # sets ALLOWED_PROJECT_PARENTS. Lib defaults at line 68 mean the
    # variable is always set before this point; unsetting lets the
    # post-source declare -p check distinguish "admin silent" (apply
    # narrowing default "/") from "admin set" (snapshot admin's value).
    unset ALLOWED_PROJECT_PARENTS
    _source_trusted_config "$_ADMIN_CONF"
    if declare -p ALLOWED_PROJECT_PARENTS &>/dev/null; then
        _admin_set_app=true
        _validate_admin_allowed_project_parents
    else
        _admin_set_app=false
        # Restore lib default so downstream code paths see a populated
        # array. The narrowing merge uses _ADMIN_ALLOWED_PROJECT_PARENTS
        # (set to ("/") by _snapshot_admin_config when admin is silent),
        # not this value, so no permissive admin policy results.
        ALLOWED_PROJECT_PARENTS=("/fh/fast" "/fh/scratch" "$HOME")
    fi
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

# Restore env overrides for network-filter scalars (env wins over config;
# admin enforcement re-applied below).
if [[ -n "${_NETWORK_FILTER_MODE_OVERRIDE:-}" ]]; then
    NETWORK_FILTER_MODE="$_NETWORK_FILTER_MODE_OVERRIDE"
fi
if [[ -n "${_NETWORK_FILTER_FALLBACK_OVERRIDE:-}" ]]; then
    NETWORK_FILTER_FALLBACK="$_NETWORK_FILTER_FALLBACK_OVERRIDE"
fi
if [[ -n "${_NETWORK_MAIL_BLOCK_OVERRIDE:-}" ]]; then
    NETWORK_MAIL_BLOCK="$_NETWORK_MAIL_BLOCK_OVERRIDE"
fi
unset _NETWORK_FILTER_MODE_OVERRIDE _NETWORK_FILTER_FALLBACK_OVERRIDE _NETWORK_MAIL_BLOCK_OVERRIDE

# Re-apply admin enforcement on network-filter scalars: env can loosen
# user config but cannot weaken admin-set values.
if [[ -n "$_ADMIN_CONF" ]]; then
    if [[ -n "${_ADMIN_NETWORK_FILTER_MODE:-}" ]]; then
        _admin_idx="$(_network_mode_strictness_idx "$_ADMIN_NETWORK_FILTER_MODE")"
        _user_idx="$(_network_mode_strictness_idx "${NETWORK_FILTER_MODE:-filtered}")"
        if [[ "$_user_idx" -lt "$_admin_idx" ]]; then
            echo "WARNING: env override NETWORK_FILTER_MODE='${NETWORK_FILTER_MODE}' weaker than admin '${_ADMIN_NETWORK_FILTER_MODE}' — restored." >&2
            NETWORK_FILTER_MODE="$_ADMIN_NETWORK_FILTER_MODE"
        fi
        unset _admin_idx _user_idx
    fi
    if [[ -n "${_ADMIN_NETWORK_FILTER_FALLBACK:-}" ]]; then
        _admin_pidx="$(_network_fallback_strictness_idx "$_ADMIN_NETWORK_FILTER_FALLBACK")"
        _user_pidx="$(_network_fallback_strictness_idx "${NETWORK_FILTER_FALLBACK:-open}")"
        if [[ "$_user_pidx" -lt "$_admin_pidx" ]]; then
            echo "WARNING: env override NETWORK_FILTER_FALLBACK='${NETWORK_FILTER_FALLBACK}' weaker than admin '${_ADMIN_NETWORK_FILTER_FALLBACK}' — restored." >&2
            NETWORK_FILTER_FALLBACK="$_ADMIN_NETWORK_FILTER_FALLBACK"
        fi
        unset _admin_pidx _user_pidx
    fi
    if [[ -n "${_ADMIN_NETWORK_MAIL_BLOCK:-}" ]]; then
        _admin_midx="$(_mail_block_strictness_idx "$_ADMIN_NETWORK_MAIL_BLOCK")"
        _user_midx="$(_mail_block_strictness_idx "${NETWORK_MAIL_BLOCK:-auto}")"
        if [[ "$_user_midx" -lt "$_admin_midx" ]]; then
            echo "WARNING: env override NETWORK_MAIL_BLOCK='${NETWORK_MAIL_BLOCK}' weaker than admin '${_ADMIN_NETWORK_MAIL_BLOCK}' — restored." >&2
            NETWORK_MAIL_BLOCK="$_ADMIN_NETWORK_MAIL_BLOCK"
        fi
        unset _admin_midx _user_midx
    fi
fi

# ── Validate config ──────────────────────────────────────────────

# Materialize each BLOCKED_FILES entry as an empty placeholder if it
# doesn't exist on host. Closes the gap (#73) where the previous
# launch-time `[[ -e $blocked ]]` guard in backends/bwrap.sh and
# backends/firejail.sh silently skipped missing entries — leaving them
# unenforced — AND avoids bwrap's own ensure_file → creat() side effect
# (which creates a host stub during mount-setup with no visibility or
# permission control by the sandbox).
#
# Why materialize rather than fail outright? The default agent configs
# (agents/*/config.conf) seed BLOCKED_FILES with canonical paths like
# $HOME/.claude/CLAUDE.md that may legitimately not exist on a fresh
# install. Pure refuse-to-start would break the out-of-the-box launch
# for every fresh user. Materializing a zero-byte placeholder where the
# user has write access preserves UX and gives the bind a clean target.
# Where the user CAN'T materialize the path (non-writable parent,
# read-only mount, parent doesn't exist and can't be created), we fail
# loud with a list of every un-materializable entry so the user knows
# exactly what to fix.
#
# Skipped under Landlock: BLOCKED_FILES has no effect there (additive-
# rules model — no per-file hiding), so the existing config-load
# warning ("BLOCKED_FILES has no effect with the Landlock backend") is
# the only signal. Creating placeholders in places the user marked for
# blocking, when blocking won't happen, would be gratuitous host
# pollution.
_ensure_blocked_files_exist() {
    [[ "${SANDBOX_BACKEND:-auto}" == "landlock" ]] && return 0
    [[ ${#BLOCKED_FILES[@]} -gt 0 ]] || return 0

    local _missing=()
    local _entry _parent
    for _entry in "${BLOCKED_FILES[@]}"; do
        [[ -e "$_entry" || -L "$_entry" ]] && continue
        _parent="$(dirname "$_entry")"
        # Try to create parents (no-op if they already exist). Failure
        # here is the most common cause of the touch failing below; we
        # let the touch error speak for itself.
        mkdir -p "$_parent" 2>/dev/null || true
        if ! touch "$_entry" 2>/dev/null; then
            _missing+=("$_entry")
        fi
    done

    if [[ ${#_missing[@]} -gt 0 ]]; then
        echo "Error: BLOCKED_FILES entries do not exist and cannot be created on host:" >&2
        local _m
        for _m in "${_missing[@]}"; do
            echo "  $_m" >&2
        done
        echo "" >&2
        echo "Each entry must either exist on host (e.g., 'touch \"$_m\"')" >&2
        echo "or be removed from BLOCKED_FILES. See docs/configure.md §BLOCKED_FILES." >&2
        exit 1
    fi
}

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
    _validate_path_array HOME_SEEDED_FILES "${HOME_SEEDED_FILES[@]}"
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

# HOME_SEEDED_FILES wins over HOME_READONLY: a file seeded into the
# tmpfs cannot also be a read-only bind to the host file. Backends
# skip the read-only mount when an entry is seeded; warn so the
# overlap is visible.
for _seed in "${HOME_SEEDED_FILES[@]}"; do
    for _ro in "${HOME_READONLY[@]}"; do
        if [[ "$_seed" == "$_ro" ]]; then
            echo "WARNING: $HOME/$_seed is in both HOME_SEEDED_FILES and HOME_READONLY (seeded wins, read-only ignored)." >&2
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
        echo "  Use bwrap/firejail, or deploy the SPANK plugin (docs/admin/hardening.md §1)." >&2
    fi
fi
if [[ "${SANDBOX_BACKEND:-auto}" != "bwrap" && "${SANDBOX_BACKEND:-auto}" != "auto" ]]; then
    if _is_true "${BIND_DEV_PTS:-false}"; then
        echo "WARNING: BIND_DEV_PTS only applies to the bwrap backend." >&2
    fi
    if [[ ${#DEVICES[@]} -gt 0 ]]; then
        echo "WARNING: DEVICES only applies to the bwrap backend." >&2
        echo "  /dev passthrough requires a mount namespace; firejail's --private-dev is coarser, landlock has no FS isolation." >&2
    fi
fi

# BIND_DEV_PTS deprecation shim. Old configs that say `BIND_DEV_PTS=true`
# used to bind the host /dev into the sandbox to give tmux a working pty.
# On kernel < 5.4 that was the only way: bwrap's user-namespace devpts
# was broken (ptmxmode=000) so tmux/script/expect could not allocate a
# pty inside the sandbox without binding the host /dev/pts on top.
#
# On kernel >= 5.4 bwrap auto-mounts a working user-ns devpts. Binding
# the host /dev/pts on top of that shadows the working mount with one
# whose ptmxmode=000 (the host devpts is configured for the privileged
# default) and silently breaks pty allocation — tmux exits with
# "create session failed", script(1) with "failed to create
# pseudo-terminal: Permission denied". The default DEVICES_BLACKLIST
# masks this for fresh installs (it lists /dev/pts), but a user who
# overrides DEVICES_BLACKLIST without copying the upstream defaults
# re-exposes the trap.
#
# So gate the shim on the kernel: on >= 5.4 the legacy toggle becomes
# a logged no-op (with a clear "drop the line" message); on < 5.4 we
# preserve the historical behaviour. The blacklist still applies on
# < 5.4 so an admin can refuse pty exposure cluster-wide.
if _is_true "${BIND_DEV_PTS:-false}"; then
    if _kernel_at_least 5 4; then
        echo "agent-sandbox: BIND_DEV_PTS=true is a no-op on kernel >= 5.4 (bwrap auto-mounts a working devpts; binding host /dev/pts would shadow it with ptmxmode=000 and break pty allocation). Drop the line from your sandbox.conf." >&2
    else
        echo "agent-sandbox: BIND_DEV_PTS is deprecated; use DEVICES+=(/dev/pts) instead. See docs/reference/device-passthrough.md." >&2
        DEVICES+=(/dev/pts)
    fi
fi

# Belt-and-suspenders for explicit /dev/pts in DEVICES on kernel >= 5.4.
# Users who wrote `DEVICES+=(/dev/pts)` directly (because the v0.6.0
# migration comment told them that was the path on < 5.4) hit the same
# devpts-shadow trap on >= 5.4. We do not silently drop the entry
# (that overrides explicit user intent), but we surface the warning at
# every spawn so the trap is at most "your tmux is broken AND you have
# a stderr line telling you why" instead of "your tmux is broken with
# no log explaining it". The DEVICES_BLACKLIST default already lists
# /dev/pts, so this branch only fires when the user has overridden the
# blacklist as well.
if _kernel_at_least 5 4 && [[ ${#DEVICES[@]} -gt 0 ]]; then
    for _dev_entry in "${DEVICES[@]}"; do
        if [[ "$_dev_entry" == "/dev/pts" ]]; then
            echo "agent-sandbox: DEVICES contains /dev/pts on kernel >= 5.4 — bwrap's auto-mounted user-ns devpts will be shadowed with ptmxmode=000 and pty allocation (tmux/script/expect) will fail with 'Permission denied'. Drop /dev/pts from DEVICES; the bind was only needed on kernel < 5.4." >&2
            break
        fi
    done
    unset _dev_entry
fi

# ── Helpers ─────────────────────────────────────────────────────

validate_project_dir() {
    local dir="$1"
    local dir_resolved
    dir_resolved="$(_resolve_path "$dir")"

    # 1. Reject if the project dir (literal or resolved) lands under any
    #    DENIED_WRITABLE_PATHS entry.  The project dir is bound writable;
    #    admin deny-lists must apply to it too, not just EXTRA_WRITABLE_PATHS.
    #    Without this, a symlink like ~/myproj -> /etc combined with an
    #    ALLOWED_PROJECT_PARENTS entry of $HOME would let the agent write
    #    to /etc despite DENIED_WRITABLE_PATHS=("/etc").
    local _denied _denied_resolved
    for _denied in "${DENIED_WRITABLE_PATHS[@]}"; do
        _denied="${_denied//\$\{HOME\}/$HOME}"
        _denied="${_denied/#\~\//$HOME/}"
        _denied="${_denied/\$HOME/$HOME}"
        _denied="${_denied%/}"
        _denied_resolved="$(_resolve_path "$_denied")"
        if _path_under "$dir" "$_denied" \
            || _path_under "$dir_resolved" "$_denied" \
            || _path_under "$dir" "$_denied_resolved" \
            || _path_under "$dir_resolved" "$_denied_resolved"; then
            echo "Error: Project directory lands under an admin-denied path." >&2
            echo "  Got: $dir" >&2
            [[ "$dir" != "$dir_resolved" ]] && echo "  Resolves to: $dir_resolved" >&2
            echo "  Denied: $_denied" >&2
            return 1
        fi
    done

    # 2. Require the project dir (literal or resolved) to be under an
    #    allowed parent.  Matching either form lets admins express the
    #    allowlist in terms of either the canonical path or a commonly
    #    used symlink alias — a bypass is impossible because (1) already
    #    rejected anything that resolves into a denied path.
    local parent parent_resolved
    for parent in "${ALLOWED_PROJECT_PARENTS[@]}"; do
        # Expand $HOME, ${HOME}, and leading ~/ consistently so config
        # authors can write any of the three forms without surprises.
        parent="${parent//\$\{HOME\}/$HOME}"
        parent="${parent/#\~\//$HOME/}"
        parent="${parent/\$HOME/$HOME}"
        parent="${parent%/}"  # strip trailing slash
        parent_resolved="$(_resolve_path "$parent")"
        # Exact match or proper subdirectory (with / boundary).
        # Without the boundary check, parent=/home/alice would
        # incorrectly match dir=/home/alicebob/project.
        if _path_under "$dir" "$parent" \
            || _path_under "$dir_resolved" "$parent" \
            || _path_under "$dir" "$parent_resolved" \
            || _path_under "$dir_resolved" "$parent_resolved"; then
            return 0
        fi
    done
    echo "Error: Project directory not under an allowed parent path." >&2
    echo "  Got: $dir" >&2
    [[ "$dir" != "$dir_resolved" ]] && echo "  Resolves to: $dir_resolved" >&2
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

# ── Device passthrough resolution ──────────────────────────────────
#
# Expand the DEVICES array against the host /dev, drop entries that match
# any DEVICES_BLACKLIST glob, and store the surviving paths in
# DEVICES_RESOLVED. Backends that support per-device binding (currently
# bwrap only) iterate DEVICES_RESOLVED and emit one --dev-bind per entry.
#
# Globs in DEVICES are expanded via `shopt -s nullglob` so patterns that
# match nothing (e.g. /dev/nvidia* on a CPU-only node) simply drop. Each
# resolved path is then case-globbed against every DEVICES_BLACKLIST
# entry — the same idiom _is_blocked_by_pattern uses for env-var globs,
# so admins can blacklist a family with one entry (`/dev/sd*` blocks
# /dev/sda, /dev/sda1, /dev/sdb, ...).
#
# Blacklist hits are logged once each to stderr so users see what was
# filtered (e.g. `BIND_DEV_PTS=true → DEVICES+=(/dev/pts)` paired with an
# admin blacklist that includes /dev/pts surfaces a clear "blacklisted,
# skipping" line).
DEVICES_RESOLVED=()

_resolve_devices() {
    DEVICES_RESOLVED=()

    [[ ${#DEVICES[@]} -eq 0 ]] && return 0

    # Snapshot + flip globbing state so DEVICES patterns expand against
    # the host /dev, even though the surrounding script runs without
    # nullglob/globstar set. `shopt -p OPT` returns non-zero when the
    # option is off, so capture exit-tolerantly under `set -e`.
    local _saved_nullglob
    _saved_nullglob="$(shopt -p nullglob 2>/dev/null || true)"
    shopt -s nullglob

    local _entry _path _bad _blacklisted _logged
    local -A _seen=()
    for _entry in "${DEVICES[@]}"; do
        # Expand glob (or pass through literal). `eval echo` would
        # be unsafe; use `compgen -G` which honours the nullglob flag
        # for patterns and falls back to literal-existence-check for
        # plain paths.
        local _matches=()
        if [[ "$_entry" == *[*?[]* ]]; then
            # Pattern entry — array-expand via globbing.
            local _expanded=( $_entry )
            _matches=( "${_expanded[@]}" )
        else
            # Literal path — keep it if the node exists. Symlinks count
            # (NVIDIA driver bundles sometimes ship /dev/nvidia0 as a
            # symlink to /dev/dri/card0 on hybrid setups).
            [[ -e "$_entry" || -L "$_entry" ]] && _matches=( "$_entry" )
        fi

        for _path in "${_matches[@]}"; do
            # Dedup — a user adding /dev/nvidia0 explicitly + the
            # /dev/nvidia* glob default would otherwise emit two
            # --dev-bind args for the same node.
            [[ -n "${_seen[$_path]:-}" ]] && continue

            _blacklisted=false
            for _bad in "${DEVICES_BLACKLIST[@]}"; do
                # shellcheck disable=SC2254
                case "$_path" in $_bad) _blacklisted=true; break ;; esac
            done

            if $_blacklisted; then
                # Log once per resolved path, not once per matching glob.
                _logged="$_path"
                echo "agent-sandbox: device $_logged is blacklisted, skipping" >&2
                _seen[$_path]=1
                continue
            fi

            _seen[$_path]=1
            DEVICES_RESOLVED+=("$_path")
        done
    done

    eval "$_saved_nullglob"
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
        echo "sandbox: warning: SANDBOX_MODULES set but 'module' command not available — skipping" >&2
        return 0
    fi

    for _mod in "${SANDBOX_MODULES[@]}"; do
        if ! module load "$_mod" 2>/dev/null; then
            echo "sandbox: warning: module '$_mod' not available — skipping" >&2
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
            # bwrap-specific: backend_available already printed the
            # probe-resolved explanation when it failed; no extra version
            # echo needed because the probe reports it inline.
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
    # Render bwrap line from the probe outcome (set by backends/bwrap.sh
    # during its backend_available() call above), falling back to
    # heuristics when the probe didn't run or didn't classify.
    local _bwrap_summary
    case "${_BWRAP_PROBE_REASON:-}" in
        not-installed)    _bwrap_summary="binary not found" ;;
        version-too-old)  _bwrap_summary="installed but too old (need ≥ 0.4.0)" ;;
        binary-broken)    _bwrap_summary="binary present but unusable (--version failed)" ;;
        apparmor-userns)  _bwrap_summary="blocked by AppArmor / LSM userns restriction" ;;
        userns-disabled)  _bwrap_summary="kernel reports No permitted_caps (userns disabled)" ;;
        clone-denied)     _bwrap_summary="clone(CLONE_NEWUSER) denied (outer seccomp / max_user_namespaces=0)" ;;
        mount-namespace-denied) _bwrap_summary="mount-namespace setup denied (running inside another sandbox?)" ;;
        unknown)          _bwrap_summary="failed with unrecognised stderr (see message below)" ;;
        "")
            # Probe never ran (e.g., backends/bwrap.sh not sourced) —
            # fall back to coarse heuristics.
            if [[ "$_bwrap_path" == "not found" ]]; then
                _bwrap_summary="binary not found"
            elif echo "$_lsm" | grep -q apparmor && sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null | grep -q 1; then
                _bwrap_summary="blocked by AppArmor userns restriction"
            else
                _bwrap_summary="failed (check user namespace support)"
            fi ;;
        *)                _bwrap_summary="failed (${_BWRAP_PROBE_REASON})" ;;
    esac
    echo "  Tried:" >&2
    echo "    bwrap    — $_bwrap_summary" >&2
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
    # Surface the bwrap probe's actionable explanation, when one was
    # captured. Skip for "not-installed" — the generic Fix block above
    # already covers that case.
    if [[ -n "${_BWRAP_PROBE_MESSAGE:-}" && "${_BWRAP_PROBE_REASON:-}" != "not-installed" ]]; then
        echo "" >&2
        echo "  bwrap details:" >&2
        echo "    ${_BWRAP_PROBE_MESSAGE}" >&2
    fi
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

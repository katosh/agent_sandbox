# shellcheck shell=bash
# Codex CLI agent overlay
#
# Merges AGENTS.md with sandbox instructions and sets CODEX_HOME
# so Codex reads from the merged directory instead of ~/.codex/ directly.
#
# Called by prepare_agent_configs() in sandbox-lib.sh. All file
# operations go through agents/overlay-lib.sh / overlay-fs.py, which
# never follow a symlink planted inside the (sandbox-writable) ~/.codex.

# _codex_host_has_landlock — true when this kernel has Landlock (ABI >= 1,
# Linux 5.13+). Codex's own Landlock sandbox needs nothing else.
_codex_host_has_landlock() {
    python3 "$SANDBOX_DIR/backends/landlock-sandbox.py" --check --required-abi 1 >/dev/null 2>&1
}

# _codex_inner_sandbox_mode — what to do about Codex's OWN sandbox
# (CODEX_INNER_SANDBOX): off | landlock | keep, on stdout.
#
# Codex wraps every command it runs in a bubblewrap sandbox. Inside
# agent-sandbox that cannot start ("bwrap: Failed to make / slave":
# seccomp denies mount(2) on bwrap, firejail blocks user namespaces;
# the landlock backend fails too), so every command Codex runs in its
# default modes fails. Measured with Codex 0.115 on each backend:
#   bwrap, firejail  Codex's bubblewrap fails; its Landlock mode works
#                    and confines (kernel 5.13+).
#   landlock         bubblewrap fails; Codex's Landlock mode cannot start
#                    commands either. Nothing nests: switch it off.
# auto therefore picks landlock where the host has it, and off otherwise.
_codex_inner_sandbox_mode() {
    local _m="${CODEX_INNER_SANDBOX:-auto}"
    case "$_m" in
        keep|off|landlock) echo "$_m"; return 0 ;;
        auto) ;;
        *) echo "sandbox: warning: codex: CODEX_INNER_SANDBOX='$_m' is not auto|landlock|off|keep; using auto" >&2 ;;
    esac
    case "${SANDBOX_BACKEND:-}" in
        bwrap|firejail) if _codex_host_has_landlock; then echo landlock; else echo off; fi ;;
        landlock)       echo off ;;
        *)              echo keep ;;
    esac
}

# _codex_inner_sandbox REAL_CODEX_DIR — edit the sandbox-private copy of
# config.toml (never the real ~/.codex/config.toml) so Codex's own
# sandbox either uses Landlock or is off. The copy is kept across
# launches while it is newer than the real file, and launches on other
# backends and hosts share it, so every run first undoes the edits of
# earlier runs (agents/codex/inner-sandbox.py marks them) and then
# applies its own mode; `keep` only undoes. Safe to repeat. The helper
# leaves a config it cannot edit safely alone and says why.
_codex_inner_sandbox() {
    local _dir="$1" _mode _helper="$SANDBOX_DIR/agents/codex/inner-sandbox.py"
    local _cur _rc _new _err
    _mode="$(_codex_inner_sandbox_mode)"
    if [[ ! -f "$_helper" ]]; then
        [[ "$_mode" == keep ]] \
            || echo "sandbox: warning: codex: $_helper missing — Codex's own sandbox left as configured" >&2
        return 0
    fi
    # The copy as it is now; an absent file counts as empty, any other
    # failure (a refused symlink, ...) means: write nothing.
    _cur="$(_overlay_fs read "$_dir" sandbox-config/config.toml 2>/dev/null; echo "__ASB_RC__=$?")"
    _rc="${_cur##*__ASB_RC__=}"; _cur="${_cur%__ASB_RC__=*}"
    case "$_rc" in 0|2) ;; *) return 0 ;; esac
    _new="$(printf '%s' "$_cur" | python3 -I "$_helper" "$_mode" 2>/dev/null; echo "__ASB_RC__=${PIPESTATUS[1]}")"
    _rc="${_new##*__ASB_RC__=}"; _new="${_new%__ASB_RC__=*}"
    if [[ "$_rc" == 3 ]]; then
        [[ "$_mode" == keep ]] && return 0
        _err="$(printf '%s' "$_cur" | python3 -I "$_helper" "$_mode" 2>&1 >/dev/null)"
        echo "sandbox: warning: codex: config.toml not adjusted for CODEX_INNER_SANDBOX=$_mode: ${_err//$'\n'/ }. Codex's own sandbox may fail to start inside agent-sandbox." >&2
        return 0
    fi
    [[ "$_rc" == 0 ]] || return 0
    [[ "$_new" == "$_cur" ]] && return 0
    printf '%s' "$_new" | _overlay_write "$_dir" sandbox-config config.toml 0600 || true
}

# agent_prepare_config PROJECT_DIR
#   Merges config files and sets up the per-session config directory.
agent_prepare_config() {
    local project_dir="$1"
    _overlay_available codex || return 0

    # --- Determine the real config directory ---
    # Always use ~/.codex as the base (not CODEX_HOME, which may
    # already point to sandbox-config from a parent sandbox invocation).
    local real_codex_dir="$HOME/.codex"
    local config_dir="$real_codex_dir/sandbox-config"
    [[ -d "$real_codex_dir" ]] || return 0

    _overlay_fs mkdir "$real_codex_dir" sandbox-config || return 0
    _overlay_read_policy "$project_dir"

    # --- Merge AGENTS.md ---
    {
        _overlay_read "$real_codex_dir" AGENTS.md && echo ""
        _overlay_snippet codex
    } | _overlay_write "$real_codex_dir" sandbox-config AGENTS.md 0444 || true

    # --- Protect host-executed config (tamper resistance) ---
    # ~/.codex/config.toml can define `notify` and `mcp_servers` commands
    # that run UNSANDBOXED the next time the user runs codex outside. The
    # real file is ro-bound (bwrap) / --read-only (firejail); Codex inside
    # gets a private copy in sandbox-config (copy-on-launch, below) that
    # it may rewrite freely (e.g. project trust decisions) without the
    # change ever reaching the host file.
    _overlay_protect_host_file "$real_codex_dir" "" config.toml ""

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    _overlay_fs sync "$real_codex_dir" sandbox-config "" \
        --skip AGENTS.md --skip sandbox-config \
        --skip .sandbox-AGENTS.md \
        --copy config.toml \
        "${_OVERLAY_POLICY[@]+"${_OVERLAY_POLICY[@]}"}" || true

    # --- Codex's own sandbox cannot start in here (CODEX_INNER_SANDBOX) ---
    _codex_inner_sandbox "$real_codex_dir" || true

    _AGENT_SANDBOX_CONFIG_DIRS+=("$config_dir")
    _AGENT_PROTECTED_FILES+=("$config_dir/AGENTS.md")

    # Export CODEX_HOME so Codex reads from merged config
    _AGENT_ENV_EXPORTS+=("CODEX_HOME=$config_dir")
}

agent_get_env_exports() {
    # CODEX_HOME is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

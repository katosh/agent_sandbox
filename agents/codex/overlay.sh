# shellcheck shell=bash
# Codex CLI agent overlay
#
# Merges AGENTS.md with sandbox instructions and sets CODEX_HOME
# so Codex reads from the merged directory instead of ~/.codex/ directly.
#
# Called by prepare_agent_configs() in sandbox-lib.sh. All file
# operations go through agents/overlay-lib.sh / overlay-fs.py, which
# never follow a symlink planted inside the (sandbox-writable) ~/.codex.

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

    _AGENT_SANDBOX_CONFIG_DIRS+=("$config_dir")
    _AGENT_PROTECTED_FILES+=("$config_dir/AGENTS.md")

    # Export CODEX_HOME so Codex reads from merged config
    _AGENT_ENV_EXPORTS+=("CODEX_HOME=$config_dir")
}

agent_get_env_exports() {
    # CODEX_HOME is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

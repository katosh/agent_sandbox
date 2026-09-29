# shellcheck shell=bash
# Gemini CLI agent overlay
#
# Merges GEMINI.md with sandbox instructions and sets GEMINI_CONFIG_DIR
# so Gemini reads from the merged directory instead of ~/.gemini/ directly.
#
# Called by prepare_agent_configs() in sandbox-lib.sh. All file
# operations go through agents/overlay-lib.sh / overlay-fs.py, which
# never follow a symlink planted inside the (sandbox-writable) ~/.gemini.

# agent_prepare_config PROJECT_DIR
#   Merges config files and sets up the per-session config directory.
agent_prepare_config() {
    local project_dir="$1"
    _overlay_available gemini || return 0

    # --- Determine the real config directory ---
    # Always use ~/.gemini as the base (not GEMINI_CONFIG_DIR, which may
    # already point to sandbox-config from a parent sandbox invocation).
    local real_gemini_dir="$HOME/.gemini"
    local config_dir="$real_gemini_dir/sandbox-config"
    [[ -d "$real_gemini_dir" ]] || return 0

    _overlay_fs mkdir "$real_gemini_dir" sandbox-config || return 0
    _overlay_read_policy "$project_dir"

    # --- Merge GEMINI.md ---
    {
        _overlay_read "$real_gemini_dir" GEMINI.md && echo ""
        _overlay_snippet gemini
    } | _overlay_write "$real_gemini_dir" sandbox-config GEMINI.md 0444 || true

    # --- settings.json (copy-on-launch, host file protected) ---
    # ~/.gemini/settings.json can define mcpServers / hooks that run
    # UNSANDBOXED the next time the user runs gemini outside. The real
    # file is ro-bound (bwrap) / --read-only (firejail); Gemini inside
    # gets a private copy in sandbox-config that it may rewrite (/settings)
    # without the change reaching the host file. A copy newer than the
    # host file is kept across launches.
    _overlay_protect_host_file "$real_gemini_dir" "" settings.json '{}'

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    _overlay_fs sync "$real_gemini_dir" sandbox-config "" \
        --skip GEMINI.md --skip sandbox-config \
        --skip .sandbox-GEMINI.md \
        --copy settings.json \
        "${_OVERLAY_POLICY[@]+"${_OVERLAY_POLICY[@]}"}" || true

    _AGENT_SANDBOX_CONFIG_DIRS+=("$config_dir")
    _AGENT_PROTECTED_FILES+=("$config_dir/GEMINI.md")

    # Export GEMINI_CONFIG_DIR so Gemini reads from merged config
    _AGENT_ENV_EXPORTS+=("GEMINI_CONFIG_DIR=$config_dir")
}

agent_get_env_exports() {
    # GEMINI_CONFIG_DIR is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

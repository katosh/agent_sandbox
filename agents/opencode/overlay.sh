# shellcheck shell=bash
# OpenCode agent overlay
#
# Merges AGENTS.md with sandbox instructions in a sandbox-config
# directory and sets OPENCODE_CONFIG_DIR so OpenCode reads from
# the merged directory instead of ~/.config/opencode/ directly.
#
# Called by prepare_agent_configs() in sandbox-lib.sh. All file
# operations go through agents/overlay-lib.sh / overlay-fs.py, which
# never follow a symlink planted inside the (sandbox-writable)
# ~/.config/opencode.

# agent_prepare_config PROJECT_DIR
#   Merges config files and sets up the per-session config directory.
agent_prepare_config() {
    local project_dir="$1"
    _overlay_available opencode || return 0

    # --- Determine the real config directory ---
    # Always use ~/.config/opencode as the base (not OPENCODE_CONFIG_DIR,
    # which may already point to sandbox-config from a parent invocation).
    local real_opencode_dir="$HOME/.config/opencode"
    local config_dir="$real_opencode_dir/sandbox-config"
    [[ -d "$real_opencode_dir" ]] || return 0

    _overlay_fs mkdir "$real_opencode_dir" sandbox-config || return 0
    _overlay_read_policy "$project_dir"

    # --- Merge AGENTS.md ---
    {
        _overlay_read "$real_opencode_dir" AGENTS.md && echo ""
        _overlay_snippet opencode
    } | _overlay_write "$real_opencode_dir" sandbox-config AGENTS.md 0444 || true

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    # Not protected here (see docs/reference/security.md): OpenCode also
    # reads ~/.config/opencode/opencode.json directly (OPENCODE_CONFIG_DIR
    # is an ADDITIONAL config dir) and rewrites it, so making it read-only
    # would break the agent.
    _overlay_fs sync "$real_opencode_dir" sandbox-config "" \
        --skip AGENTS.md --skip sandbox-config || true

    _AGENT_SANDBOX_CONFIG_DIRS+=("$config_dir")
    _AGENT_PROTECTED_FILES+=("$config_dir/AGENTS.md")

    # Export OPENCODE_CONFIG_DIR so OpenCode reads from merged config
    _AGENT_ENV_EXPORTS+=("OPENCODE_CONFIG_DIR=$config_dir")
}

agent_get_env_exports() {
    # OPENCODE_CONFIG_DIR is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

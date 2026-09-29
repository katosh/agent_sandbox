# shellcheck shell=bash
# pi (pi-mono) agent overlay
#
# Merges AGENTS.md with sandbox instructions in a sandbox-config
# directory and sets PI_CODING_AGENT_DIR so pi reads from the merged
# directory instead of ~/.pi/agent/ directly.
#
# Called by prepare_agent_configs() in sandbox-lib.sh, only when "pi"
# is listed in ENABLED_AGENTS. All file operations go through
# agents/overlay-lib.sh / overlay-fs.py, which never follow a symlink
# planted inside the (sandbox-writable) ~/.pi.

# agent_prepare_config PROJECT_DIR
#   Merges config files and sets up the per-session config directory.
agent_prepare_config() {
    local project_dir="$1"
    _overlay_available pi || return 0

    # --- Determine the real config directory ---
    # Always use ~/.pi/agent as the base (not PI_CODING_AGENT_DIR,
    # which may already point to sandbox-config from a parent
    # sandbox invocation). ~/.pi is the trusted root (the writable
    # bind); ~/.pi/agent lives INSIDE it, so it must be a real
    # directory — a symlink there may have been planted by the agent.
    local pi_root="$HOME/.pi"
    local real_pi_dir="$pi_root/agent"
    local config_dir="$real_pi_dir/sandbox-config"
    [[ -d "$pi_root" ]] || return 0

    _overlay_fs mkdir "$pi_root" agent --no-replace || return 0
    _overlay_fs mkdir "$pi_root" agent/sandbox-config || return 0
    _overlay_read_policy "$project_dir"

    # --- Merge AGENTS.md ---
    {
        _overlay_read "$pi_root" agent/AGENTS.md && echo ""
        _overlay_snippet pi
    } | _overlay_write "$pi_root" agent/sandbox-config AGENTS.md 0444 || true

    # --- settings.json (copy-on-launch, host file protected) ---
    # ~/.pi/agent/settings.json lists packages/extensions that pi loads
    # (and runs) UNSANDBOXED the next time the user runs pi outside. The
    # real file is ro-bound (bwrap) / --read-only (firejail); pi inside
    # gets a private copy it may rewrite (/model, /settings).
    _overlay_protect_host_file "$pi_root" agent settings.json '{}'

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    _overlay_fs sync "$pi_root" agent/sandbox-config agent \
        --skip AGENTS.md --skip sandbox-config \
        --copy settings.json \
        "${_OVERLAY_POLICY[@]+"${_OVERLAY_POLICY[@]}"}" || true

    _AGENT_SANDBOX_CONFIG_DIRS+=("$config_dir")
    _AGENT_PROTECTED_FILES+=("$config_dir/AGENTS.md")

    # Export PI_CODING_AGENT_DIR so pi reads from merged config
    _AGENT_ENV_EXPORTS+=("PI_CODING_AGENT_DIR=$config_dir")
}

agent_get_env_exports() {
    # PI_CODING_AGENT_DIR is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

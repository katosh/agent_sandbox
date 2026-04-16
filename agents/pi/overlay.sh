# shellcheck shell=bash
# pi (pi-mono) agent overlay
#
# Merges AGENTS.md with sandbox instructions in a sandbox-config
# directory and sets PI_CODING_AGENT_DIR so pi reads from the merged
# directory instead of ~/.pi/agent/ directly.
#
# Called by prepare_agent_configs() in sandbox-lib.sh, only when "pi"
# is listed in ENABLED_AGENTS.

# agent_prepare_config PROJECT_DIR
#   Merges config files and sets up the per-session config directory.
agent_prepare_config() {
    local project_dir="$1"

    # --- Determine the real config directory ---
    # Always use ~/.pi/agent as the base (not PI_CODING_AGENT_DIR,
    # which may already point to sandbox-config from a parent
    # sandbox invocation).
    local real_pi_dir="$HOME/.pi/agent"
    mkdir -p "$real_pi_dir" 2>/dev/null || true

    local config_dir="$real_pi_dir/sandbox-config"
    chmod u+w "$config_dir" 2>/dev/null || true
    mkdir -p "$config_dir"

    # --- Merge AGENTS.md ---
    local sandbox_snippet="$(_agent_file pi agent.md)"
    local user_agents_md="$real_pi_dir/AGENTS.md"
    {
        if [[ -f "$user_agents_md" ]]; then
            cat "$user_agents_md"
        fi
        if [[ -f "$sandbox_snippet" ]]; then
            echo ""
            sed "s|__SANDBOX_DIR__|$SANDBOX_DIR|g" "$sandbox_snippet"
        fi
    } > "$config_dir/AGENTS.md.tmp.$$"
    chmod a-w "$config_dir/AGENTS.md.tmp.$$" 2>/dev/null || true
    if ! mv -f "$config_dir/AGENTS.md.tmp.$$" "$config_dir/AGENTS.md" 2>/dev/null; then
        rm -f "$config_dir/AGENTS.md.tmp.$$" 2>/dev/null || true
    fi

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    for item in "$real_pi_dir"/* "$real_pi_dir"/.*; do
        local name
        name="$(basename "$item")"
        [[ "$name" == "." || "$name" == ".." ]] && continue
        case "$name" in
            AGENTS.md|sandbox-config) continue ;;
        esac
        local target="$config_dir/$name"
        if [[ -e "$target" && ! -L "$target" && "$target" -nt "$item" ]]; then
            continue
        fi
        if [[ -L "$target" && "$(readlink "$target")" == "$item" ]]; then
            continue
        fi
        ln -snf "$item" "$target" 2>/dev/null || true
    done

    _AGENT_SANDBOX_CONFIG_DIRS+=("$config_dir")
    _AGENT_PROTECTED_FILES+=("$config_dir/AGENTS.md")

    # Export PI_CODING_AGENT_DIR so pi reads from merged config
    _AGENT_ENV_EXPORTS+=("PI_CODING_AGENT_DIR=$config_dir")
}

agent_get_env_exports() {
    # PI_CODING_AGENT_DIR is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

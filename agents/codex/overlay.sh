# Codex CLI agent overlay
#
# Merges AGENTS.md with sandbox instructions and sets CODEX_HOME
# so Codex reads from the merged directory instead of ~/.codex/ directly.
#
# Called by prepare_agent_configs() in sandbox-lib.sh.

# agent_prepare_config PROJECT_DIR
#   Merges config files and sets up the per-session config directory.
agent_prepare_config() {
    local project_dir="$1"

    # --- Determine the real config directory ---
    # Honour an existing CODEX_HOME; default to ~/.codex
    local real_codex_dir="${CODEX_HOME:-$HOME/.codex}"

    local config_dir="$real_codex_dir/sandbox-config"
    chmod u+w "$config_dir" 2>/dev/null || true
    mkdir -p "$config_dir"

    # --- Merge AGENTS.md ---
    local sandbox_snippet="$SANDBOX_DIR/agents/codex/agent.md"
    local user_agents_md="$real_codex_dir/AGENTS.md"
    {
        if [[ -f "$user_agents_md" ]]; then
            cat "$user_agents_md"
        fi
        if [[ -f "$sandbox_snippet" ]]; then
            echo ""
            cat "$sandbox_snippet"
        fi
    } > "$config_dir/AGENTS.md.tmp.$$"
    chmod a-w "$config_dir/AGENTS.md.tmp.$$" 2>/dev/null || true
    mv -f "$config_dir/AGENTS.md.tmp.$$" "$config_dir/AGENTS.md"

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    for item in "$real_codex_dir"/* "$real_codex_dir"/.*; do
        local name
        name="$(basename "$item")"
        [[ "$name" == "." || "$name" == ".." ]] && continue
        case "$name" in
            AGENTS.md|sandbox-config) continue ;;
            .sandbox-AGENTS.md) continue ;;   # stale merged file from old overlay
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

    chmod a-w "$config_dir" 2>/dev/null || true

    _AGENT_SANDBOX_CONFIG_DIRS+=("$config_dir")

    # Export CODEX_HOME so Codex reads from merged config
    _AGENT_ENV_EXPORTS+=("CODEX_HOME=$config_dir")
}

agent_get_env_exports() {
    # CODEX_HOME is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

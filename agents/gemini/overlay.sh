# Gemini CLI agent overlay
#
# Merges GEMINI.md with sandbox instructions and sets GEMINI_CONFIG_DIR
# so Gemini reads from the merged directory instead of ~/.gemini/ directly.
#
# Called by prepare_agent_configs() in sandbox-lib.sh.

# agent_prepare_config PROJECT_DIR
#   Merges config files and sets up the per-session config directory.
agent_prepare_config() {
    local project_dir="$1"

    # --- Determine the real config directory ---
    # Honour an existing GEMINI_CONFIG_DIR; default to ~/.gemini
    local real_gemini_dir="${GEMINI_CONFIG_DIR:-$HOME/.gemini}"

    local config_dir="$real_gemini_dir/sandbox-config"
    chmod u+w "$config_dir" 2>/dev/null || true
    mkdir -p "$config_dir"

    # --- Merge GEMINI.md ---
    local sandbox_snippet="$SANDBOX_DIR/agents/gemini/agent.md"
    local user_gemini_md="$real_gemini_dir/GEMINI.md"
    {
        if [[ -f "$user_gemini_md" ]]; then
            cat "$user_gemini_md"
        fi
        if [[ -f "$sandbox_snippet" ]]; then
            echo ""
            cat "$sandbox_snippet"
        fi
    } > "$config_dir/GEMINI.md.tmp.$$"
    chmod a-w "$config_dir/GEMINI.md.tmp.$$" 2>/dev/null || true
    mv -f "$config_dir/GEMINI.md.tmp.$$" "$config_dir/GEMINI.md"

    # --- Merge settings.json ---
    # Gemini CLI uses ~/.gemini/settings.json for user-level settings.
    # Symlink it into the sandbox-config so the agent inherits user prefs.
    local user_settings="$real_gemini_dir/settings.json"
    if [[ -f "$user_settings" && ! -e "$config_dir/settings.json" ]]; then
        ln -snf "$user_settings" "$config_dir/settings.json" 2>/dev/null || true
    fi

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    for item in "$real_gemini_dir"/* "$real_gemini_dir"/.*; do
        local name
        name="$(basename "$item")"
        [[ "$name" == "." || "$name" == ".." ]] && continue
        case "$name" in
            GEMINI.md|sandbox-config) continue ;;
            .sandbox-GEMINI.md) continue ;;   # stale merged file from old overlay
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

    # Export GEMINI_CONFIG_DIR so Gemini reads from merged config
    _AGENT_ENV_EXPORTS+=("GEMINI_CONFIG_DIR=$config_dir")
}

agent_get_env_exports() {
    # GEMINI_CONFIG_DIR is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

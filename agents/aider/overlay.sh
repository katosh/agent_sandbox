# shellcheck shell=bash
# Aider agent overlay
#
# Aider has no instruction file to merge, but supports loading
# read-only context files via AIDER_READ. We use this to inject
# sandbox instructions as a conventions-style read-only file.
#
# Called by prepare_agent_configs() in sandbox-lib.sh.

agent_prepare_config() {
    local project_dir="$1"

    # Inject sandbox instructions via AIDER_READ env var.
    # If the user already has AIDER_READ set, append our snippet.
    local sandbox_snippet="$SANDBOX_DIR/agents/aider/agent.md"
    if [[ -f "$sandbox_snippet" ]]; then
        if [[ -n "${AIDER_READ:-}" ]]; then
            _AGENT_ENV_EXPORTS+=("AIDER_READ=${AIDER_READ} ${sandbox_snippet}")
        else
            _AGENT_ENV_EXPORTS+=("AIDER_READ=${sandbox_snippet}")
        fi
    fi
}

agent_get_env_exports() {
    # AIDER_READ is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

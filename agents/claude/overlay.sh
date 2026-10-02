# shellcheck shell=bash
# Claude Code agent overlay
#
# Merges CLAUDE.md with sandbox instructions, merges settings.json
# with sandbox permissions, and sets CLAUDE_CONFIG_DIR so Claude Code
# reads from the merged directory instead of ~/.claude/ directly.
#
# Called by prepare_agent_configs() in sandbox-lib.sh.

# agent_prepare_config PROJECT_DIR
#   Merges config files and sets up the per-session config directory.
agent_prepare_config() {
    local project_dir="$1"
    _overlay_available claude || return 0

    # --- Determine the real config directory ---
    # Always use ~/.claude as the base (not CLAUDE_CONFIG_DIR, which may
    # already point to sandbox-config from a parent sandbox invocation —
    # e.g., compute-node re-entry via sbatch wrapping).
    #
    # ~/.claude itself is trusted (it is the writable bind / Landlock rule
    # root, so the sandbox cannot replace it). Everything BELOW it is
    # agent-writable, so every read, write and link goes through
    # overlay-fs.py (agents/overlay-lib.sh), which never follows a
    # symlink the agent may have planted there.
    local real_claude_dir="$HOME/.claude"
    local config_dir="$real_claude_dir/sandbox-config"
    [[ -d "$real_claude_dir" ]] || return 0

    # Create sandbox-config (or replace a planted symlink / file at that
    # name) and unlock it for regeneration.
    _overlay_fs mkdir "$real_claude_dir" sandbox-config || return 0
    _overlay_read_policy "$project_dir"

    # --- Merge CLAUDE.md ---
    # User's CLAUDE.md (stale in-place injection from an old backend
    # stripped), then the sandbox snippet. Read-only for everyone (0444)
    # and additionally ro-bound inside the sandbox.
    {
        { _overlay_read "$real_claude_dir" CLAUDE.md || true; } \
            | sed '/^# __SANDBOX_INJECTED_9f3a7c__$/,/^$/d'
        _overlay_snippet claude
    } | _overlay_write "$real_claude_dir" sandbox-config CLAUDE.md 0444 || true

    # --- Merge settings.json ---
    # User settings + sandbox permissions/hooks. The merged copy is what
    # Claude reads inside (CLAUDE_CONFIG_DIR); it is 0444 and ro-bound so
    # the agent cannot escalate its own permissions mid-session.
    local sandbox_settings
    sandbox_settings="$(_agent_file claude settings.json)"
    if [[ -f "$sandbox_settings" ]]; then
        { _overlay_read "$real_claude_dir" settings.json || true; } \
            | python3 -c "
import json, sys
try:
    user = json.loads(sys.stdin.read() or '{}')
    if not isinstance(user, dict):
        user = {}
except ValueError:
    user = {}
with open(sys.argv[1]) as f:
    sandbox = json.load(f)
# Merge permissions.allow
user.setdefault('permissions', {})
existing = user['permissions'].get('allow', [])
for rule in sandbox.get('permissions', {}).get('allow', []):
    if rule not in existing:
        existing.append(rule)
user['permissions']['allow'] = existing
# Merge hooks: for each event type, append sandbox hooks to user hooks
# (skip duplicates by comparing the command string).
sandbox_hooks = sandbox.get('hooks', {})
if sandbox_hooks:
    user.setdefault('hooks', {})
    for event, sandbox_groups in sandbox_hooks.items():
        user_groups = user['hooks'].get(event, [])
        # Collect existing command strings to avoid duplicates
        existing_cmds = set()
        for g in user_groups:
            for h in g.get('hooks', []):
                if h.get('type') == 'command':
                    existing_cmds.add(h.get('command', ''))
        for g in sandbox_groups:
            new_hooks = [h for h in g.get('hooks', [])
                         if h.get('command', '') not in existing_cmds]
            if new_hooks:
                user_groups.append({**g, 'hooks': new_hooks})
        user['hooks'][event] = user_groups
json.dump(user, sys.stdout, indent=2)
" "$sandbox_settings" \
            | _overlay_write "$real_claude_dir" sandbox-config settings.json 0444 || true
    else
        { _overlay_read "$real_claude_dir" settings.json || true; } \
            | _overlay_write "$real_claude_dir" sandbox-config settings.json 0444 || true
    fi

    # --- Protect host-executed config (tamper resistance) ---
    # Inside the sandbox Claude reads only $CLAUDE_CONFIG_DIR, so the REAL
    # ~/.claude/settings.json (hooks, statusLine, apiKeyHelper, env) and
    # ~/.claude.json (mcpServers) are never needed writable there. Both
    # are executed UNSANDBOXED the next time the user runs `claude`
    # outside, so they are ro-bound (bwrap) / --read-only (firejail).
    # ~/.claude.json is also HOME_READONLY via agents/claude/config.conf,
    # which covers Landlock. The placeholder '{}' is only created when
    # nothing exists, so the file can be protected from the first launch.
    _overlay_protect_host_file "$real_claude_dir" "" settings.json '{}'
    if [[ -f "$HOME/.claude.json" && ! -L "$HOME/.claude.json" ]]; then
        _AGENT_PROTECTED_FILES+=("$HOME/.claude.json")
    fi

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    # Claude Code refreshes tokens via write-to-temp + rename, which
    # replaces our symlinks with real files. A real file newer than the
    # outside version is kept (e.g. a refreshed token); a real directory
    # (session data written to a stale copy) is merged no-clobber into
    # the real ~/.claude/<name> and replaced by a symlink. The merge never
    # follows a symlink on either side.
    _overlay_fs sync "$real_claude_dir" sandbox-config "" \
        --skip CLAUDE.md --skip settings.json --skip sandbox-config \
        --skip-glob '*.sandbox-backup.*' --merge-dirs || true

    # Register the config dir for writable bind-mount, and mark the
    # merged files as protected (individual ro-bind inside the sandbox).
    # The directory must be writable so claude can create lock files,
    # session data, MCP caches, etc.
    _AGENT_SANDBOX_CONFIG_DIRS+=("$config_dir")
    _AGENT_PROTECTED_FILES+=("$config_dir/CLAUDE.md")
    [[ -f "$config_dir/settings.json" ]] && _AGENT_PROTECTED_FILES+=("$config_dir/settings.json")

    # Export CLAUDE_CONFIG_DIR so Claude reads from merged config
    _AGENT_ENV_EXPORTS+=("CLAUDE_CONFIG_DIR=$config_dir")
    # The native installer's version store (~/.local/share/claude) is
    # read-only inside (a planted binary there would run unsandboxed on
    # the next outside launch), so an in-sandbox self-update can only
    # fail. Turn it off; update from outside the sandbox (`claude update`).
    _AGENT_ENV_EXPORTS+=("DISABLE_AUTOUPDATER=1")
}

# agent_get_env_exports
#   Returns env var assignments to be exported into the sandbox.
agent_get_env_exports() {
    # CLAUDE_CONFIG_DIR is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

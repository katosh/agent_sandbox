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

    # --- Determine the real config directory ---
    # Honour an existing CLAUDE_CONFIG_DIR; default to ~/.claude
    local real_claude_dir="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

    local config_dir="$real_claude_dir/sandbox-config"
    # Unlock for regeneration (may have been locked by a prior run).
    # The overlay runs outside the sandbox, so we have ownership.
    chmod u+w "$config_dir" 2>/dev/null || true
    mkdir -p "$config_dir"

    # --- Merge CLAUDE.md ---
    local sandbox_snippet="$SANDBOX_DIR/agents/claude/agent.md"
    local user_claude_md="$real_claude_dir/CLAUDE.md"
    {
        if [[ -f "$user_claude_md" ]]; then
            # Strip any stale sandbox injection from a previous in-place backend
            sed '/^# __SANDBOX_INJECTED_9f3a7c__$/,/^$/d' "$user_claude_md"
        fi
        if [[ -f "$sandbox_snippet" ]]; then
            cat "$sandbox_snippet"
        fi
    } > "$config_dir/CLAUDE.md.tmp.$$"
    chmod a-w "$config_dir/CLAUDE.md.tmp.$$" 2>/dev/null || true
    mv -f "$config_dir/CLAUDE.md.tmp.$$" "$config_dir/CLAUDE.md"

    # --- Merge settings.json ---
    local sandbox_settings="$SANDBOX_DIR/agents/claude/settings.json"
    local user_settings="$real_claude_dir/settings.json"

    if [[ -f "$sandbox_settings" ]]; then
        [[ -f "$user_settings" ]] || echo '{}' > "$user_settings"
        python3 -c "
import json, sys
try:
    with open(sys.argv[1]) as f:
        user = json.load(f)
except (ValueError, IOError):
    user = {}
with open(sys.argv[2]) as f:
    sandbox = json.load(f)
user.setdefault('permissions', {})
existing = user['permissions'].get('allow', [])
for rule in sandbox.get('permissions', {}).get('allow', []):
    if rule not in existing:
        existing.append(rule)
user['permissions']['allow'] = existing
json.dump(user, sys.stdout, indent=2)
" "$user_settings" "$sandbox_settings" > "$config_dir/settings.json.tmp.$$"
        mv -f "$config_dir/settings.json.tmp.$$" "$config_dir/settings.json"
    elif [[ -f "$user_settings" ]]; then
        cp "$user_settings" "$config_dir/settings.json"
    fi
    # Make merged settings read-only to prevent mid-session permission escalation
    if [[ -f "$config_dir/settings.json" ]]; then
        chmod a-w "$config_dir/settings.json" 2>/dev/null || true
    fi

    # --- Symlink everything else (preserve fresher sandbox copies) ---
    # Claude Code refreshes tokens via write-to-temp + rename, which
    # replaces our symlinks with real files.  Only overwrite with a
    # symlink if the outside file is newer; otherwise keep the
    # sandbox-config copy (e.g. a refreshed token from a prior session).
    for item in "$real_claude_dir"/* "$real_claude_dir"/.*; do
        local name
        name="$(basename "$item")"
        [[ "$name" == "." || "$name" == ".." ]] && continue
        case "$name" in
            CLAUDE.md|settings.json|sandbox-config) continue ;;
        esac
        [[ "$name" == *.sandbox-backup.* ]] && continue
        local target="$config_dir/$name"
        # If a real directory (not symlink) exists in sandbox-config,
        # merge its contents into the real ~/.claude/<name> and replace
        # with a symlink.  This recovers session data that was written
        # to a stale copy instead of through a symlink.
        # Skip bwrap bind-mounts (mountpoint) — can't replace those.
        if [[ -d "$target" && ! -L "$target" ]]; then
            if mountpoint -q "$target" 2>/dev/null; then
                continue
            fi
            # Merge: copy contents into the real directory, skip duplicates
            if [[ -d "$item" ]]; then
                cp -rn "$target"/. "$item"/ 2>/dev/null || true
            fi
            rm -rf "$target"
        fi
        # If target is a real file (not a symlink) and newer than the
        # outside version, keep it — it was refreshed inside the sandbox.
        if [[ -e "$target" && ! -L "$target" && "$target" -nt "$item" ]]; then
            continue
        fi
        # Skip if symlink already points to the correct target — avoids
        # NFS write contention when concurrent SLURM tasks run this.
        if [[ -L "$target" && "$(readlink "$target")" == "$item" ]]; then
            continue
        fi
        ln -snf "$item" "$target" 2>/dev/null || true
    done

    # Lock the sandbox-config directory to prevent sandboxed agents from
    # deleting or replacing the read-only merged files (rm requires dir write).
    chmod a-w "$config_dir" 2>/dev/null || true

    # Register for bwrap ro-bind (prevents rm/chmod bypass inside sandbox)
    _AGENT_SANDBOX_CONFIG_DIRS+=("$config_dir")

    # Export CLAUDE_CONFIG_DIR so Claude reads from merged config
    _AGENT_ENV_EXPORTS+=("CLAUDE_CONFIG_DIR=$config_dir")
}

# agent_get_env_exports
#   Returns env var assignments to be exported into the sandbox.
agent_get_env_exports() {
    # CLAUDE_CONFIG_DIR is set by agent_prepare_config via _AGENT_ENV_EXPORTS
    :
}

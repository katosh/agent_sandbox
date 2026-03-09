#!/usr/bin/env bash
# backends/landlock.sh — Landlock LSM sandbox backend
#
# Provides: backend_available, backend_name, backend_prepare, backend_exec
# Sourced by sandbox-lib.sh — has access to all config arrays.
#
# Landlock restricts filesystem access at the kernel level without needing
# user namespaces. This makes it work on Ubuntu 24.04 where AppArmor blocks
# unprivileged user namespace creation (which bwrap requires).
#
# Key differences from bwrap:
#   - Blocked paths return EACCES (not ENOENT) — functionally equivalent
#   - No mount namespace — cannot overlay files or relocate binaries.
#     This means:
#       * Slurm wrapping relies on PATH shadowing only — the real
#         /usr/bin/sbatch and /usr/bin/srun remain directly callable.
#       * Sandbox self-protection not possible — Landlock rules are
#         additive, so can't make a subdir read-only when parent is
#         writable. An agent could modify sandbox scripts to weaken
#         future sessions or submitted Slurm jobs.
#     See ADMIN_HARDENING.md §2 for mitigations.
#   - CLAUDE.md/settings.json merging uses in-place swap with backup/restore
#   - Environment filtering done in shell (not via bwrap --unsetenv/--setenv)

LANDLOCK_SANDBOX="$SANDBOX_DIR/backends/landlock-sandbox.py"

# ── Backend interface ────────────────────────────────────────────

backend_available() {
    [[ "$(uname -s)" == "Linux" ]] || return 1
    command -v python3 &>/dev/null || return 1
    python3 "$LANDLOCK_SANDBOX" --check &>/dev/null
}

backend_name() {
    echo "landlock"
}

# Track files we need to restore on exit
_LANDLOCK_BACKUPS=()

_landlock_restore() {
    for entry in "${_LANDLOCK_BACKUPS[@]}"; do
        local backup="${entry%%|*}"
        local original="${entry##*|}"
        if [[ -f "$backup" ]]; then
            mv -f "$backup" "$original" 2>/dev/null || true
        fi
    done
    _LANDLOCK_BACKUPS=()
}

_landlock_swap_file() {
    local original="$1"
    local new_content="$2"

    local resolved="$original"
    if [[ -L "$original" ]]; then
        resolved="$(readlink -f "$original")"
    fi

    if [[ -f "$resolved" ]]; then
        local backup="${resolved}.sandbox-backup"
        cp -f "$resolved" "$backup"
        _LANDLOCK_BACKUPS+=("${backup}|${resolved}")
        cat > "$resolved" <<< "$new_content"
    elif [[ -n "$new_content" ]]; then
        local dir
        dir="$(dirname "$resolved")"
        mkdir -p "$dir"
        cat > "$resolved" <<< "$new_content"
        _LANDLOCK_BACKUPS+=("/dev/null|${resolved}")
    fi
}

backend_prepare() {
    local project_dir="$1"
    _LANDLOCK_PROJECT_DIR="$project_dir"

    # Set up restore trap
    trap '_landlock_restore' EXIT INT TERM

    # --- Restore stale backups from a previous crash FIRST ---
    for f in "$HOME/.claude/CLAUDE.md.sandbox-backup" "$HOME/.claude/settings.json.sandbox-backup"; do
        if [[ -f "$f" ]]; then
            local target="${f%.sandbox-backup}"
            echo "Warning: Restoring stale backup from previous crash" >&2
            mv -f "$f" "$target"
        fi
    done

    # --- CLAUDE.md overlay (in-place swap) ---
    local sandbox_snippet="$SANDBOX_DIR/sandbox-claude.md"
    local claude_md_path="$HOME/.claude/CLAUDE.md"

    if [[ -f "$sandbox_snippet" ]]; then
        local claude_md_resolved="$claude_md_path"
        [[ -L "$claude_md_path" ]] && claude_md_resolved="$(readlink -f "$claude_md_path")"

        local merged=""
        if [[ -f "$claude_md_resolved" ]]; then
            merged="$(cat "$claude_md_resolved")"
        fi
        merged="${merged}
$(cat "$sandbox_snippet")"
        _landlock_swap_file "$claude_md_path" "$merged"
    fi

    # --- Settings overlay (in-place swap) ---
    local sandbox_settings="$SANDBOX_DIR/sandbox-settings.json"
    local user_settings="$HOME/.claude/settings.json"

    if [[ -f "$sandbox_settings" ]]; then
        local user_settings_resolved="$user_settings"
        [[ -L "$user_settings" ]] && user_settings_resolved="$(readlink -f "$user_settings")"

        [[ -f "$user_settings_resolved" ]] || echo '{}' > "$user_settings_resolved"

        local merged_settings
        merged_settings=$(python3 -c "
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
" "$user_settings_resolved" "$sandbox_settings")
        _landlock_swap_file "$user_settings" "$merged_settings"
    fi

    # --- Build landlock-sandbox.py arguments ---
    LANDLOCK_ARGS=()

    # Read-only system mounts
    for mount in "${READONLY_MOUNTS[@]}"; do
        if [[ -d "$mount" ]]; then
            LANDLOCK_ARGS+=(--ro "$mount")
        fi
    done

    # Kernel/virtual filesystems
    for vfs in /proc /dev /tmp /run; do
        [[ -d "$vfs" ]] && LANDLOCK_ARGS+=(--rw "$vfs")
    done
    [[ -d /var/run && ! -L /var/run ]] && LANDLOCK_ARGS+=(--rw /var/run)

    # Read-only home subdirectories (directories only — Landlock rules
    # apply to directory trees, not individual files)
    for subdir in "${HOME_READONLY[@]}"; do
        local full_path="$HOME/$subdir"
        if [[ -d "$full_path" ]]; then
            LANDLOCK_ARGS+=(--ro "$full_path")
        fi
        # Individual files are handled by their parent directory's rule.
        # Since $HOME is not in any allowed list, individual dotfiles
        # like .bashrc are blocked by default. To allow them, users
        # should ensure they're inside an allowed directory.
    done

    # Writable home subdirectories
    for subdir in "${HOME_WRITABLE[@]}"; do
        local full_path="$HOME/$subdir"
        if [[ -d "$full_path" ]]; then
            LANDLOCK_ARGS+=(--rw "$full_path")
        fi
    done

    # Scratch filesystems (read-only)
    for scratch in "${SCRATCH_MOUNTS[@]}"; do
        [[ -d "$scratch" ]] && LANDLOCK_ARGS+=(--ro "$scratch")
    done

    # Project directory: writable
    LANDLOCK_ARGS+=(--rw "$project_dir")

    # --- Filter environment variables ---
    declare -A _saved_creds
    for var in "${ALLOWED_CREDENTIALS[@]}"; do
        if [[ -n "${!var:-}" ]]; then
            _saved_creds[$var]="${!var}"
        fi
    done

    for var in "${BLOCKED_ENV_VARS[@]}"; do
        unset "$var" 2>/dev/null || true
    done

    for var in "${!_saved_creds[@]}"; do
        export "$var=${_saved_creds[$var]}"
    done

    # Set sandbox env vars
    export SANDBOX_ACTIVE=1
    export SANDBOX_BACKEND=landlock
    export SANDBOX_PROJECT_DIR="$project_dir"
    export PATH="$SANDBOX_DIR/bin:${PATH}"
}

backend_exec() {
    python3 "$LANDLOCK_SANDBOX" "${LANDLOCK_ARGS[@]}" -- "$@"
    local rc=$?
    _landlock_restore
    trap - EXIT INT TERM
    exit $rc
}

backend_dry_run() {
    echo "# Backend: landlock"
    echo "# Helper: $LANDLOCK_SANDBOX"
    printf 'python3 %s \\\n' "$LANDLOCK_SANDBOX"
    for arg in "${LANDLOCK_ARGS[@]}"; do
        printf '  %s \\\n' "$arg"
    done
    printf '  -- %s\n' "$*"
}

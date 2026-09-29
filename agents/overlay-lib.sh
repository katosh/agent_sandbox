# shellcheck shell=bash
# agents/overlay-lib.sh — helpers shared by agents/*/overlay.sh
#
# Sourced by prepare_agent_configs() (sandbox-lib.sh) inside the same
# subshell as each overlay, right before the overlay itself.
#
# Overlays run on the HOST, outside the sandbox, but they write into
# directories the sandboxed agent can write too (~/.claude,
# ~/.codex, ...). Every file operation therefore goes through
# agents/overlay-fs.py, which never follows a symlink below the
# agent's config root, creates files with O_EXCL and verifies renames
# by inode. Do NOT reintroduce `cp`, `>`, `mv`, `ln -sf` or `rm -rf`
# on paths inside an agent config dir: each of those follows a symlink
# the agent may have planted and turns a host-side write into a write
# anywhere in $HOME (see docs/reference/security.md, "Agent config
# overlays").

_OVERLAY_FS_PY="${SANDBOX_DIR:-}/agents/overlay-fs.py"

# _overlay_fs SUBCOMMAND ARGS... — run the no-follow filesystem helper.
_overlay_fs() {
    python3 "$_OVERLAY_FS_PY" "$@"
}

# _overlay_available AGENT — 0 if the helper can run; warns otherwise.
# Without it an overlay does nothing (no merged config, no *_CONFIG_DIR
# export) rather than falling back to symlink-following shell.
_overlay_available() {
    if command -v python3 >/dev/null 2>&1 && [[ -f "$_OVERLAY_FS_PY" ]]; then
        return 0
    fi
    echo "sandbox: warning: $1: python3 or $_OVERLAY_FS_PY missing — agent config overlay skipped" >&2
    return 1
}

# _overlay_read_policy PROJECT_DIR — fill _OVERLAY_POLICY with
# --allow/--deny arguments for `overlay-fs.py read|sync`.
#
# When a source file an overlay copies into sandbox-config (CLAUDE.md,
# AGENTS.md, config.toml, ...) is a symlink, the copy may only follow it
# to a file the sandbox can ALREADY read. Otherwise a symlink planted
# from inside (e.g. ~/.codex/AGENTS.md -> ~/.ssh/id_ed25519 on landlock,
# where per-file protection is impossible) would make the host copy a
# secret into a file the agent reads. The allow list approximates what
# the active HOME_ACCESS mode exposes; the deny list is every masked
# path. It is deliberately conservative: a user whose CLAUDE.md is a
# symlink into an unexposed dotfiles directory gets a warning telling
# them to add that directory to HOME_READONLY.
_OVERLAY_POLICY=()
_overlay_read_policy() {
    local project_dir="${1:-}" _e _r
    _OVERLAY_POLICY=()
    case "${HOME_ACCESS:-restricted}" in
        read|write)
            _OVERLAY_POLICY+=(--allow "$HOME")
            ;;
        *)
            for _e in "${HOME_READONLY[@]+"${HOME_READONLY[@]}"}" \
                      "${HOME_WRITABLE[@]+"${HOME_WRITABLE[@]}"}"; do
                [[ -n "$_e" ]] || continue
                _OVERLAY_POLICY+=(--allow "$HOME/$_e")
                _r="$(realpath -m -- "$HOME/$_e" 2>/dev/null)" || continue
                [[ "$_r" != "$HOME/$_e" ]] && _OVERLAY_POLICY+=(--allow "$_r")
            done
            ;;
    esac
    # Outside $HOME. Skip mounts that contain $HOME itself (e.g. "/"):
    # $HOME is masked by a tmpfs in restricted/tmpwrite mode.
    for _e in "${READONLY_MOUNTS[@]+"${READONLY_MOUNTS[@]}"}" \
              "${EXTRA_WRITABLE_PATHS[@]+"${EXTRA_WRITABLE_PATHS[@]}"}" \
              "$project_dir" "${SANDBOX_DIR:-}"; do
        [[ -n "$_e" && "$_e" == /* ]] || continue
        [[ "$HOME/" == "${_e%/}/"* ]] && continue
        _OVERLAY_POLICY+=(--allow "$_e")
    done
    for _e in "${_HOME_ALWAYS_BLOCKED[@]+"${_HOME_ALWAYS_BLOCKED[@]}"}"; do
        [[ -n "$_e" ]] && _OVERLAY_POLICY+=(--deny "$HOME/$_e")
    done
    for _e in "${BLOCKED_FILES[@]+"${BLOCKED_FILES[@]}"}" \
              "${EXTRA_BLOCKED_PATHS[@]+"${EXTRA_BLOCKED_PATHS[@]}"}"; do
        [[ -n "$_e" ]] || continue
        _OVERLAY_POLICY+=(--deny "$_e")
        _r="$(readlink -f -- "$_e" 2>/dev/null)" || continue
        [[ -n "$_r" && "$_r" != "$_e" ]] && _OVERLAY_POLICY+=(--deny "$_r")
    done
}

# _overlay_read ROOT REL — print ROOT/REL (policy-checked if a symlink).
# Returns 2 if absent, 3 if refused (a warning is printed).
#
# The agent's own instruction file (~/.claude/CLAUDE.md, ...) is in
# BLOCKED_FILES only so the agent reads the merged copy; if the user
# keeps it as a symlink into a dotfiles repo, its resolved target is
# masked too. That one --deny is dropped for the file being read — the
# allow list still has to cover the target, so a planted symlink to an
# unexposed file is refused all the same.
_overlay_read() {
    local _src="$1/$2" _self="" _i
    local -a _args=()
    if [[ -L "$_src" ]] && _array_contains_ "$_src" "${BLOCKED_FILES[@]+"${BLOCKED_FILES[@]}"}"; then
        _self="$(readlink -f -- "$_src" 2>/dev/null)" || _self=""
    fi
    for (( _i = 0; _i < ${#_OVERLAY_POLICY[@]}; _i += 2 )); do
        if [[ -n "$_self" && "${_OVERLAY_POLICY[_i]}" == --deny \
              && "${_OVERLAY_POLICY[_i+1]}" == "$_self" ]]; then
            continue
        fi
        _args+=("${_OVERLAY_POLICY[_i]}" "${_OVERLAY_POLICY[_i+1]}")
    done
    _overlay_fs read "$1" "$2" "${_args[@]+"${_args[@]}"}"
}

_array_contains_() {
    local _needle="$1" _e; shift
    for _e in "$@"; do [[ "$_e" == "$_needle" ]] && return 0; done
    return 1
}

# _overlay_write ROOT REL NAME MODE — atomically install stdin at
# ROOT/REL/NAME with octal MODE. Never follows a symlink.
_overlay_write() {
    _overlay_fs write "$1" "$2" "$3" "$4"
}

# _overlay_snippet AGENT — the agent's sandbox instruction snippet with
# __SANDBOX_DIR__ substituted, on stdout (nothing if it does not exist).
_overlay_snippet() {
    local _snippet
    _snippet="$(_agent_file "$1" agent.md)"
    [[ -f "$_snippet" ]] || return 0
    sed "s|__SANDBOX_DIR__|$SANDBOX_DIR|g" "$_snippet"
}

# _overlay_protect_host_file ROOT REL NAME CONTENT — make sure the REAL
# host-executed config file ROOT/REL/NAME exists (created with CONTENT
# via O_EXCL if absent, so a planted dangling symlink is never followed)
# and register it as protected: bwrap ro-binds it and firejail marks it
# --read-only inside the sandbox, so an agent cannot plant hooks / MCP
# servers / notify commands that run UNSANDBOXED the next time the user
# starts the agent outside. Landlock cannot carve a read-only file out of
# a writable directory; see docs/reference/security.md.
_overlay_protect_host_file() {
    local _root="$1" _rel="$2" _name="$3" _content="$4" _path
    _overlay_fs ensure-file "$_root" "$_rel" "$_name" "$_content" || true
    _path="$_root${_rel:+/$_rel}/$_name"
    # Only a regular, non-symlink file is registered: binding a planted
    # symlink would mount its target instead.
    if [[ -f "$_path" && ! -L "$_path" ]]; then
        _AGENT_PROTECTED_FILES+=("$_path")
    else
        echo "sandbox: warning: $_path is not a regular file — not protected read-only" >&2
    fi
}

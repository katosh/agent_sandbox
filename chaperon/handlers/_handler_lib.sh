#! /bin/bash --
# chaperon/handlers/_handler_lib.sh — Shared handler utilities
#
# Argument whitelisting, CWD validation, and job wrapping for sbatch.

# ── Sandbox warning messages ───────────────────────────────────
#
# When the chaperon blocks an action, the error message doubles as a
# prompt-injection recovery signal.  If a compromised agent is being
# steered to exfiltrate data or escape the sandbox, these messages
# interrupt the injected context and re-anchor the agent to its real
# instructions (CLAUDE.md / AGENTS.md / agent.md).
#
# Two tiers:
#   _sandbox_warn  — normal denial (unrecognized flag, usage error)
#   _sandbox_deny  — security-critical denial (bypass attempt, scope violation)

_sandbox_warn() {
    echo "sandbox: $1" >&2
    echo "  ↳ Review your instructions and the user's original request before retrying." >&2
}

_sandbox_deny() {
    echo "sandbox: $1" >&2
    echo "  ⚠ This action was blocked for security. Re-read your instructions (CLAUDE.md / AGENTS.md) and the user's original request. Do not retry." >&2
}

# ── .sandbox-state/ helpers (chaperon-side) ──────────────────────
#
# The chaperon process is spawned by sandbox-exec.sh as a separate
# bash process; it does NOT source sandbox-lib.sh. These helpers
# duplicate the path convention defined under the `.sandbox-state/`
# section of sandbox-lib.sh. The path is `$project_dir/.sandbox-state`
# in BOTH places — keep them in sync if the convention ever changes.
#
# Threat-model framing for content under this dir (load-bearing, do
# not revert this without re-reading the design discussion):
#
#   "Yes, it should be considered hostile, even the now non-directly-
#   writable .sandbox-state. After all the submitted job determines
#   what is written, and we just prevent symlink injection."
#                                 — operator, 2026-05-20 design discussion
#
# The chaperon NEVER trusts content read back from `.sandbox-state/`
# for any security decision. The RO overlay on bwrap/firejail only
# prevents in-sandbox symlink-plant against slurmstepd's
# `open(--output)` — the bug being fixed by the convention.

_sandbox_state_dir() {
    printf '%s/.sandbox-state' "$1"
}

# _sandbox_state_safe_mkdir <project_dir> <relpath>
#
# Create (if missing) and validate `<project_dir>/<relpath>` one
# component at a time, e.g. relpath `.sandbox-state/slurm-logs`. The
# chaperon writes here as the host user, so a symlink planted at any
# component (by an earlier job, a landlock session, or a pre-existing
# tree) would redirect its writes outside the project. Refuses (returns
# 1 with a message on stderr) if any component:
#   - is a symlink, or
#   - is not a directory owned by the current user, or
#   - does not canonicalise to <realpath(project_dir)>/<relpath>
#     (catches a component swapped between the checks).
# New components are created with mode 0700. The project dir itself is
# not checked (it was validated by the launcher).
_sandbox_state_safe_mkdir() {
    local _proj="$1" _rel="$2"
    local _proj_real
    _proj_real="$(realpath -e -- "$_proj" 2>/dev/null)" || {
        echo "sandbox: refusing to use '$_proj/$_rel': project dir does not resolve." >&2
        return 1
    }
    local _cur="$_proj" _cur_rel="" _comp _saved_ifs="$IFS"
    local -a _comps
    IFS='/'
    # shellcheck disable=SC2206  # split on / is intentional
    _comps=( $_rel )
    IFS="$_saved_ifs"
    for _comp in "${_comps[@]}"; do
        [[ -z "$_comp" || "$_comp" == "." ]] && continue
        if [[ "$_comp" == ".." ]]; then
            echo "sandbox: refusing to use '$_proj/$_rel': '..' component." >&2
            return 1
        fi
        _cur="$_cur/$_comp"
        _cur_rel="$_cur_rel/$_comp"
        if [[ ! -L "$_cur" && ! -e "$_cur" ]]; then
            mkdir -m 700 -- "$_cur" 2>/dev/null || true
        fi
        if [[ -L "$_cur" ]]; then
            echo "sandbox: refusing to use '$_cur': it is a symlink (possible symlink-plant). Remove it to re-enable Slurm log staging." >&2
            return 1
        fi
        if [[ ! -d "$_cur" || ! -O "$_cur" ]]; then
            echo "sandbox: refusing to use '$_cur': not a directory owned by $(id -un 2>/dev/null || echo you)." >&2
            return 1
        fi
        local _real
        _real="$(realpath -e -- "$_cur" 2>/dev/null)" || _real=""
        if [[ "$_real" != "$_proj_real$_cur_rel" ]]; then
            echo "sandbox: refusing to use '$_cur': resolves to '$_real', not '$_proj_real$_cur_rel'." >&2
            return 1
        fi
    done
    return 0
}

_sandbox_state_slurm_logs_dir() {
    printf '%s/.sandbox-state/slurm-logs' "$1"
}

# _slurm_output_feature_enabled
#
# Returns 0 if the Slurm --output / --error path-transformation
# feature should be active for this chaperon process. Disabled on
# landlock (no RO-overlay mechanism — symlink-plant defense
# unavailable, see backends/landlock.sh's note). $SANDBOX_BACKEND
# is exported by sandbox-exec.sh after detect_backend specifically
# so the chaperon can branch on it here.
_slurm_output_feature_enabled() {
    case "${SANDBOX_BACKEND:-}" in
        bwrap|firejail) return 0 ;;
        *) return 1 ;;
    esac
}

# _ensure_sandbox_state_dir <project_dir>
#
# Idempotent mkdir of `.sandbox-state/{slurm-logs,chaperon}` with a
# README.md marker so operators encountering the dir for the first
# time can decode it without grepping. Called from sbatch.sh before
# computing the staging path. Owner-only perms — these dirs hold log
# content that may carry user data.
_ensure_sandbox_state_dir() {
    local _project_dir="$1"
    local _state_dir="$_project_dir/.sandbox-state"

    # Do NOT short-circuit on `[[ -d $_state_dir ]]`: chaperon/logging.sh
    # mkdir's `.sandbox-state/chaperon/` early in chaperon startup, which
    # creates `.sandbox-state/` itself. Short-circuiting then would skip
    # mkdir'ing `slurm-logs/` and slurmstepd's open(--output) would fail
    # with ENOENT. `mkdir -p` is already idempotent — re-run is cheap.
    # Component-wise, symlink-refusing creation (C6): never mkdir -p
    # through a planted symlink.
    _sandbox_state_safe_mkdir "$_project_dir" ".sandbox-state/slurm-logs" || return 1
    _sandbox_state_safe_mkdir "$_project_dir" ".sandbox-state/chaperon" || return 1
    chmod 700 "$_state_dir" "$_state_dir/slurm-logs" "$_state_dir/chaperon" 2>/dev/null || true

    # README marker: noclobber makes bash open with O_CREAT|O_EXCL, which
    # fails on ANY existing path including a dangling symlink, so the
    # write can never follow a planted link.
    local _marker="$_state_dir/README.md"
    if [[ ! -e "$_marker" && ! -L "$_marker" ]]; then
        ( set -C; cat > "$_marker" ) <<'_SANDBOX_STATE_README' 2>/dev/null || true
# .sandbox-state/

Hidden chaperon-owned state directory created by `agent-sandbox`.
Do not modify by hand — content is managed by the chaperon process
running outside the sandbox.

## Contents

- `slurm-logs/<path>` — `sbatch --output` / `--error` are redirected
  here so slurmstepd writes inside the project tree (cross-node
  accessible via NFS) while the bwrap/firejail bind-mount layer
  prevents in-sandbox symlink-plant against slurmstepd's `open()`.
  The wrapper inside the sandbox creates relative symlinks from the
  user's intended output paths to files here.

- `chaperon/<session-id>/log` — chaperon diagnostic log (one
  subdirectory per chaperon process; disambiguates concurrent
  sandboxes in the same project).

## Writability matrix

| Principal | Permission | Why |
|---|---|---|
| host (chaperon, slurmstepd) | read+write | chaperon mkdir's; slurmstepd writes |
| sandbox (bwrap/firejail)    | read-only  | bind-mount overlay; prevents symlink-plant |
| sandbox (landlock)          | writable   | landlock can't make subdir RO under RW parent; the slurm-output feature is disabled there |

## Lifecycle

Keep forever (sandbox artifact). To reclaim: `rm -rf .sandbox-state/`.

See `docs/reference/sandbox-state-dir.md` in the agent-sandbox source
tree for the full convention and the threat-model framing.
_SANDBOX_STATE_README
        chmod 644 "$_marker" 2>/dev/null || true
    fi
    return 0
}

# _prepare_staging_output_path <project_dir> <staging_path>
#
# Materialise the parent directory of a transformed --output/--error
# staging path (slurmstepd does not mkdir -p) using the symlink-refusing
# component walk, and refuse if the staging file itself already exists
# as a symlink (slurmstepd would follow it when opening the log).
# %-patterns in the leaf are left alone (resolved by slurmstepd at open
# time; the literal pattern path is what gets checked).
_prepare_staging_output_path() {
    local _proj="$1" _staging="$2"
    local _logs="$_proj/.sandbox-state/slurm-logs"
    if [[ "$_staging" != "$_logs/"* ]]; then
        _sandbox_deny "staging path '$_staging' is outside '$_logs'."
        return 1
    fi
    local _parent_rel
    _parent_rel="$(dirname -- "${_staging#"$_proj"/}")"
    if ! _sandbox_state_safe_mkdir "$_proj" "$_parent_rel"; then
        _sandbox_deny "refusing to stage Slurm output under '$_proj/$_parent_rel' (see message above)."
        return 1
    fi
    if [[ -L "$_staging" ]]; then
        _sandbox_deny "refusing to stage Slurm output: '$_staging' already exists as a symlink."
        return 1
    fi
    return 0
}

# ── Slurm --output / --error / --input path validation ───────────
#
# slurmstepd opens --output / --error / --input OUTSIDE the sandbox, as
# the host user, and follows symlinks. Where the chaperon does not
# redirect them into the RO staging dir (sbatch on landlock; srun on
# every backend) the path itself must be safe:
#   - no backslash (Slurm strips `\` and disables % expansion, so `.\.`
#     would become `..`) and no `..` component (the kernel resolves `..`
#     after following symlinks, so lexical checks would not hold);
#   - only % patterns whose expansion cannot contain `/` (%A %a %J %j %N
#     %n %s %t %u %%, optional zero-pad digits), and only in the file
#     name; %x (job name, agent controlled) and unknown ones are refused;
#   - the directory part, resolved against the submission cwd, must be
#     inside the project dir with no symlink component;
#   - the target must not already exist as a symlink (for a patterned
#     file name: no symlink in the directory may match the pattern).
# `/dev/null` is always accepted. Returns 1 with a _sandbox_deny message
# otherwise. Residual: the directory is agent-writable on landlock, so a
# symlink planted AFTER this check can still race slurmstepd's open().

_slurm_io_deny() {
    _sandbox_deny "Slurm '$1 $2' refused: $3. slurmstepd opens this file outside the sandbox, so it must be a plain path inside the project directory ($4)."
}

# _validate_slurm_io_path <flag> <value> <project_dir> [cwd]
_validate_slurm_io_path() {
    local _flag="$1" _val="$2" _proj="$3" _cwd="${4:-$3}"
    [[ -z "$_val" || "$_val" == /dev/null ]] && return 0

    if [[ "$_val" == *\\* ]]; then
        _slurm_io_deny "$_flag" "$_val" "backslashes are not allowed" "$_proj"; return 1
    fi
    if [[ "/$_val/" == */../* ]]; then
        _slurm_io_deny "$_flag" "$_val" "'..' components are not allowed" "$_proj"; return 1
    fi
    if [[ "$_val" == */ ]]; then
        _slurm_io_deny "$_flag" "$_val" "the path names a directory" "$_proj"; return 1
    fi

    local _dirpart="" _leaf="$_val"
    if [[ "$_val" == */* ]]; then
        _dirpart="${_val%/*}"
        _leaf="${_val##*/}"
        [[ -z "$_dirpart" ]] && _dirpart="/"
    fi

    # Directory part: no % at all (patterns there cannot be checked now).
    if [[ "$_dirpart" == *%* ]]; then
        _slurm_io_deny "$_flag" "$_val" "% patterns are only allowed in the file name" "$_proj"; return 1
    fi

    # File name: allowed patterns only; build a [[ == ]] glob (patterns →
    # *, glob metacharacters escaped).
    local _glob="" _i=0 _n=${#_leaf} _c _j _spec _patterned=false
    while (( _i < _n )); do
        _c="${_leaf:_i:1}"
        if [[ "$_c" == "%" ]]; then
            _j=$((_i + 1))
            while (( _j < _n )) && [[ "${_leaf:_j:1}" == [0-9] ]]; do _j=$((_j + 1)); done
            _spec="${_leaf:_j:1}"
            case "$_spec" in
                %) _glob+="%" ;;
                A|a|J|j|N|n|s|t|u) _glob+="*"; _patterned=true ;;
                x) _slurm_io_deny "$_flag" "$_val" "'%x' (job name) could change the directory" "$_proj"; return 1 ;;
                *) _slurm_io_deny "$_flag" "$_val" "unsupported '%${_leaf:_i+1:_j-_i}' pattern" "$_proj"; return 1 ;;
            esac
            _i=$((_j + 1))
            continue
        fi
        case "$_c" in
            '*'|'?'|'['|']') _glob+="\\$_c" ;;
            *) _glob+="$_c" ;;
        esac
        _i=$((_i + 1))
    done

    # Resolve the directory against the physical cwd; map to the
    # project's real path (it may be spelled via its literal path).
    local _proj_real _cwd_phys _dir _rel
    _proj_real="$(realpath -e -- "$_proj" 2>/dev/null)" || {
        _slurm_io_deny "$_flag" "$_val" "the project dir does not resolve" "$_proj"; return 1; }
    _cwd_phys="$(cd "$_cwd" 2>/dev/null && pwd -P)" || _cwd_phys="$_proj_real"
    if [[ -z "$_dirpart" ]]; then
        _dir="$_cwd_phys"
    elif [[ "$_dirpart" == /* ]]; then
        _dir="$_dirpart"
    else
        _dir="$_cwd_phys/$_dirpart"
    fi
    while [[ "$_dir" == *//* ]]; do _dir="${_dir//\/\//\/}"; done
    while [[ "$_dir" == */./* ]]; do _dir="${_dir//\/.\//\/}"; done
    _dir="${_dir%/.}"; _dir="${_dir%/}"
    if [[ "$_dir" == "$_proj_real" || "$_dir" == "$_proj_real"/* ]]; then
        _rel="${_dir#"$_proj_real"}"
    elif [[ "$_dir" == "${_proj%/}" || "$_dir" == "${_proj%/}"/* ]]; then
        _rel="${_dir#"${_proj%/}"}"
    else
        _slurm_io_deny "$_flag" "$_val" "directory '${_dir:-/}' is outside the project" "$_proj"; return 1
    fi

    # No symlink component between the project root and the directory.
    local _cur="$_proj_real" _comp _saved_ifs="$IFS"
    local -a _rcomps
    IFS='/'
    # shellcheck disable=SC2206  # split on / is intentional
    _rcomps=( $_rel )
    IFS="$_saved_ifs"
    for _comp in "${_rcomps[@]}"; do
        [[ -z "$_comp" ]] && continue
        _cur="$_cur/$_comp"
        if [[ -L "$_cur" ]]; then
            _slurm_io_deny "$_flag" "$_val" "'$_cur' is a symlink" "$_proj"; return 1
        fi
        [[ -e "$_cur" ]] || break      # Slurm won't create it; nothing to follow
        if [[ ! -d "$_cur" ]]; then
            _slurm_io_deny "$_flag" "$_val" "'$_cur' is not a directory" "$_proj"; return 1
        fi
    done

    # Target must not already be a symlink.
    local _tdir="$_proj_real$_rel"
    if ! $_patterned; then
        if [[ -L "$_tdir/$_leaf" ]]; then
            _slurm_io_deny "$_flag" "$_val" "'$_tdir/$_leaf' is a symlink" "$_proj"; return 1
        fi
    elif [[ -d "$_tdir" ]]; then
        local _f
        for _f in "$_tdir"/* "$_tdir"/.*; do
            [[ -L "$_f" ]] || continue
            # shellcheck disable=SC2053  # pattern match intended
            if [[ "${_f##*/}" == $_glob ]]; then
                _slurm_io_deny "$_flag" "$_val" "existing symlink '$_f' matches the file pattern" "$_proj"; return 1
            fi
        done
    fi
    return 0
}

# ── Slurm --output / --error path transformation ─────────────────
#
# Transform a user-supplied --output / --error value into an absolute
# path under `$project_dir/.sandbox-state/slurm-logs/` such that:
#
#   - Absolute paths are encoded under `__abs__/` (escape encoded so
#     the wrapper can reverse the transform and re-prepend `/`).
#   - `..` path components are renamed to `__updir__` (escape
#     contained — `__updir__` is a literal directory name, can't
#     traverse out of the staging subtree).
#   - `.` and empty components are dropped (path normalisation).
#   - `%`-patterns (`%j`, `%A`, `%a`, `%N`, `%u`, `%t`, ...) survive
#     intact; slurmstepd substitutes them at file-open time, so the
#     resolved on-disk staging path becomes the runtime location.
#     Callers MUST first run _check_staged_slurm_io_value: `%x` (job
#     name) and a backslash (stripped by Slurm, `.\.` → `..`) could
#     otherwise leave the staging subtree at open time.
#
# Why transform rather than validate-and-reject: the staging dir is
# bind-mounted read-only inside the sandbox (bwrap/firejail), so an
# agent can't symlink-plant against slurmstepd's `open(--output)` —
# the actual escape vector this closes. Validation would still be
# brittle for `%`-patterns and produces a UX cliff when the user
# innocently submits `--output=/scratch/foo` (rejected vs. silently
# redirected, with a symlink at the intended path resolving to the
# staging file for the cases the agent CAN write to).
#
# Echoes the transformed absolute path on stdout. Pure function;
# table-testable via test.sh.
_transform_slurm_output_path() {
    local _value="$1"
    local _project_dir="$2"

    # Trim ambient whitespace (defensive).
    _value="${_value#"${_value%%[![:space:]]*}"}"
    _value="${_value%"${_value##*[![:space:]]}"}"

    local _state_logs="$_project_dir/.sandbox-state/slurm-logs"

    # Empty input: caller is expected to skip the transform; defensive
    # return of the staging root keeps the function total.
    [[ -z "$_value" ]] && { printf '%s' "$_state_logs"; return; }

    # Detect absolute → encode original-was-absolute as `__abs__/`
    # prefix so the wrapper can re-prepend `/` on the way out.
    local _is_abs=false
    if [[ "$_value" == /* ]]; then
        _is_abs=true
        while [[ "$_value" == /* ]]; do _value="${_value#/}"; done
    fi

    # Split on / and process each component. `..` → `__updir__` only
    # at exact-component match; `..foo` is left alone (legitimate
    # filename).
    local _out_components=()
    if $_is_abs; then
        _out_components+=("__abs__")
    fi
    local _saved_ifs="$IFS"
    IFS='/'
    # shellcheck disable=SC2206  # split on / is intentional
    local _parts=( $_value )
    IFS="$_saved_ifs"
    local _p
    for _p in "${_parts[@]}"; do
        case "$_p" in
            "")  ;;                                  # collapse //
            ".") ;;                                  # drop no-op
            "..") _out_components+=("__updir__") ;;  # contain escape
            *)   _out_components+=("$_p") ;;
        esac
    done

    local _saved_ifs2="$IFS"
    IFS='/'
    local _transformed="${_out_components[*]}"
    IFS="$_saved_ifs2"

    if [[ -z "$_transformed" ]]; then
        printf '%s' "$_state_logs"
    else
        printf '%s/%s' "$_state_logs" "$_transformed"
    fi
}

# ── Whitelisted sbatch flags ────────────────────────────────────
# Only these flags are forwarded to the real sbatch. This is a security
# boundary: flags that could bypass sandboxing are excluded.
#
# Handled by stub/protocol (not denied — intercepted before reaching here):
#   --wrap        — stub converts to SCRIPT in protocol
#
# Denied (security-critical):
#   --chdir / -D  — CWD comes from stub's pwd, validated against project dir
#   --uid / --gid — must not impersonate other users
#   --get-user-env — can leak host environment
#   --propagate   — can propagate unsafe rlimits
#   --export      — allowed, but REWRITTEN (see _sanitize_export_value):
#   the generated job wrapper runs on the compute node OUTSIDE the
#   sandbox, before sandbox-exec.sh re-enters it, so any value that
#   reaches the job environment is interpreted by host-side code first
#   (BASH_ENV/ENV by bash itself, LD_PRELOAD by the loader, SANDBOX_CONF /
#   HOME_ACCESS / BWRAP / ... by the compute-node sandbox-exec.sh). Only
#   ALL / NONE / NIL or bare variable NAMES reach Slurm (their values come
#   from the chaperon's own host environment, as with the default ALL);
#   agent-supplied NAME=VALUE pairs are applied INSIDE the sandbox via
#   `/usr/bin/env NAME=VALUE <interpreter>`.
#   --prolog / --epilog / --task-prolog / --task-epilog — run arbitrary scripts
#   --burst-buffer-file / --bbf — arbitrary file access
#   --bcast       — copy binary to nodes (bypass wrapping)
#   --container   — OCI containers bypass sandbox
#
# Format: space-delimited, both short and long forms.
# Flags that take a value are marked with "=" suffix in _SBATCH_VALUE_FLAGS.

_SBATCH_ALLOWED_FLAGS=" \
  -A --account \
  -c --cpus-per-task \
  -d --dependency \
  -e --error \
  -H --hold \
  -J --job-name \
  -n --ntasks \
  -N --nodes \
  -o --output \
  -p --partition \
  -q --qos \
  -t --time \
  -G --gpus \
  -w --nodelist \
  -x --exclude \
  --begin \
  --comment \
  --constraint \
  --contiguous \
  --cpu-freq \
  --deadline \
  --exclusive \
  --export \
  --gres \
  --gpus-per-node \
  --gpus-per-task \
  --mail-type \
  --mail-user \
  --mem \
  --mem-per-cpu \
  --mem-per-gpu \
  --nice \
  --ntasks-per-node \
  --cpus-per-gpu \
  --overcommit \
  --oversubscribe \
  --priority \
  --requeue \
  --no-requeue \
  --reservation \
  --signal \
  --switches \
  --threads-per-core \
  --tmp \
  --verbose \
  --wait \
  --wait-all-nodes \
  --wckey \
  --array \
  --parsable \
  --test-only \
  --help \
  --usage \
  --version \
"

# Slurm option classes (see "Slurm option-argument classes" below):
#   _SBATCH_VALUE_FLAGS  — REQUIRED argument: `--flag value`,
#                          `--flag=value`, `-f value`. Consumes the next
#                          token when given without `=`.
#   _SBATCH_OPTARG_FLAGS — OPTIONAL argument (`--flag[=value]`): a value
#                          binds ONLY with `=`; a following token is never
#                          consumed (Slurm's getopt treats it as the batch
#                          script).
#   every other allowed flag takes NO argument.
# Classified against sbatch 23.11 (`sbatch --flag` / `--flag=x` probes).
# Keep _STUB_VALUE_FLAGS in stubs/sbatch in sync.
_SBATCH_VALUE_FLAGS=" \
  -A --account \
  -c --cpus-per-task \
  -d --dependency \
  -e --error \
  -J --job-name \
  -n --ntasks \
  -N --nodes \
  -o --output \
  -p --partition \
  -q --qos \
  -t --time \
  -G --gpus \
  -w --nodelist \
  -x --exclude \
  --begin \
  --comment \
  --constraint \
  --cpu-freq \
  --deadline \
  --export \
  --gres \
  --gpus-per-node \
  --gpus-per-task \
  --mail-type \
  --mail-user \
  --mem \
  --mem-per-cpu \
  --mem-per-gpu \
  --ntasks-per-node \
  --cpus-per-gpu \
  --priority \
  --reservation \
  --signal \
  --switches \
  --threads-per-core \
  --tmp \
  --wait-all-nodes \
  --wckey \
  --array \
"

# Check if a flag is in the allowed list.
_is_allowed_flag() {
    local flag="$1"
    # Strip =value for --flag=value forms
    local base="${flag%%=*}"
    [[ "$_SBATCH_ALLOWED_FLAGS" == *" $base "* ]]
}

# Security-critical deny-list (ASB-2026-001). Shared between
# validate_sbatch_args (CLI) and create_wrapped_script (#SBATCH
# directive filter) so both entry points reject identically. An
# attacker who can put `--task-prolog` on the CLI is blocked by
# validate_sbatch_args; an attacker who hides `--task-prolog`
# inside a #SBATCH directive body must be blocked here too.
_is_denied_flag() {
    local base="${1%%=*}"
    case "$base" in
        --prolog|--epilog|--task-prolog|--task-epilog) return 0 ;;
        --get-user-env)                                return 0 ;;
        --bcast)                                       return 0 ;;
        --container)                                   return 0 ;;
        --uid|--gid)                                   return 0 ;;
        --propagate)                                   return 0 ;;
        --burst-buffer-file|--bbf)                     return 0 ;;
        --wrap)                                        return 0 ;;
        --chdir|-D)                                    return 0 ;;
    esac
    return 1
}

_SBATCH_OPTARG_FLAGS=" --exclusive --nice "

# Check if a flag consumes a value argument.
_is_value_flag() {
    [[ "$_SBATCH_VALUE_FLAGS" == *" $1 "* ]]
}

# ── Slurm option-argument classes ────────────────────────────────
#
# Slurm parses its command line with getopt_long, where every option is
# one of: no argument, REQUIRED argument (`--flag value`, `--flag=value`,
# `-f value`, `-fvalue`) or OPTIONAL argument (`--flag[=value]`, e.g.
# srun `--kill-on-bad-exit[=0|1]`, `--nice[=adj]`, `--exclusive[=user]`):
# an optional argument binds ONLY with `=`, the following token is never
# consumed. If the chaperon treated an optional-argument flag as taking a
# separate value, it would swallow the next token (`srun
# --kill-on-bad-exit ./evil true`), while real Slurm would run that token
# as the command / batch script, outside the sandbox-exec.sh wrapping.
#
# Two layers keep the chaperon's parse identical to Slurm's:
#   1. per-tool lists: *_VALUE_FLAGS (required) and *_OPTARG_FLAGS
#      (optional, never consume); everything else takes no argument;
#   2. every validated flag is re-emitted as ONE self-contained token
#      (`--long=value` for required-argument flags, the bare flag
#      otherwise) and the user command / batch script is passed after an
#      explicit `--` inserted by the chaperon. _assert_slurm_flag_argv
#      checks that no bare word precedes that `--`, so even a
#      misclassified flag cannot move a user token into Slurm's command
#      slot.

# _slurm_long_flag <flag> — print the long form of a (short) flag.
# Only short flags whose meaning is the same for sbatch and srun.
_slurm_long_flag() {
    case "$1" in
        --*) printf '%s' "$1" ;;
        -A) printf -- '--account' ;;
        -c) printf -- '--cpus-per-task' ;;
        -d) printf -- '--dependency' ;;
        -e) printf -- '--error' ;;
        -G) printf -- '--gpus' ;;
        -i) printf -- '--input' ;;
        -J) printf -- '--job-name' ;;
        -n) printf -- '--ntasks' ;;
        -N) printf -- '--nodes' ;;
        -o) printf -- '--output' ;;
        -p) printf -- '--partition' ;;
        -q) printf -- '--qos' ;;
        -t) printf -- '--time' ;;
        -w) printf -- '--nodelist' ;;
        -x) printf -- '--exclude' ;;
        *)  return 1 ;;
    esac
}

# _slurm_normalize_flag <tool> <arg> <value_flags> <optarg_flags> <has_next> [next]
#
# Classifies an ALREADY ALLOW-LISTED flag token and produces the single
# token to forward to Slurm. Sets in the caller's scope (do NOT call in
# $(...)):
#   _SLURM_FLAG_TOKEN    — `--long=value` or the bare flag
#   _SLURM_FLAG_CONSUMED — 1 if <next> was consumed as the value, else 0
# Returns 1 (with a message) for a value on a no-argument flag, a
# short flag written with `=`, or a required value that is missing.
_slurm_normalize_flag() {
    local _tool="$1" _arg="$2" _req="$3" _opt="$4" _has_next="$5" _next="${6-}"
    local _base _long
    _SLURM_FLAG_TOKEN=""
    _SLURM_FLAG_CONSUMED=0
    case "$_arg" in
        --*=*)
            _base="${_arg%%=*}"
            if [[ "$_req" == *" $_base "* || "$_opt" == *" $_base "* ]]; then
                _SLURM_FLAG_TOKEN="$_arg"
                return 0
            fi
            _sandbox_warn "$_tool flag '$_base' does not take a value."
            return 1
            ;;
        --?*|-?)
            if [[ "$_req" == *" $_arg "* ]]; then
                if [[ "$_has_next" != 1 ]]; then
                    _sandbox_warn "$_tool flag '$_arg' requires a value."
                    return 1
                fi
                if ! _long="$(_slurm_long_flag "$_arg")"; then
                    _sandbox_warn "internal error: no long form known for $_tool flag '$_arg'."
                    return 1
                fi
                _SLURM_FLAG_TOKEN="$_long=$_next"
                _SLURM_FLAG_CONSUMED=1
                return 0
            fi
            # No-argument or optional-argument flag: never consumes.
            _SLURM_FLAG_TOKEN="$_arg"
            return 0
            ;;
    esac
    _sandbox_warn "$_tool flag '$_arg' is not recognized (write '-X value' or '--long-name=value')."
    return 1
}

# _assert_slurm_flag_argv <tool> <value_flags> <flag tokens...>
#
# Final check before exec'ing the real binary: every token that will
# precede the chaperon's `--` must be a single self-contained flag. A
# bare word, a lone `-`/`--`, or a required-argument flag without its
# attached `=value` (which would make Slurm consume the NEXT token) is an
# internal error: refuse rather than let Slurm pick a different command.
_assert_slurm_flag_argv() {
    local _tool="$1" _req="$2" _t
    shift 2
    for _t in "$@"; do
        case "$_t" in
            -|--|[!-]*|"")
                _sandbox_warn "internal error: refusing to run $_tool: non-flag token '$_t' before the command separator."
                return 1
                ;;
            --*=*) ;;
            *)
                if [[ "$_req" == *" $_t "* ]]; then
                    _sandbox_warn "internal error: refusing to run $_tool: '$_t' would consume the next argument."
                    return 1
                fi
                ;;
        esac
    done
    return 0
}

# _validate_slurm_job_name <origin> <value>
#
# The job name is agent-controlled and expands into `%x` in Slurm file
# name patterns (opened by slurmstepd outside the sandbox). `%x` is
# refused in --output/--error/--input anyway; as defense in depth the
# name itself may not contain `/` or `\` and may not be `.` or `..`.
# <value> may carry one pair of surrounding quotes (#SBATCH form).
_validate_slurm_job_name() {
    local _origin="$1" _v="$2"
    if [[ "$_v" == */* || "$_v" == *\\* ]]; then
        _sandbox_deny "$_origin '$_v' refused: a job name may not contain '/' or '\\' (it expands into Slurm's %x file name pattern)."
        return 1
    fi
    _v="${_v#"${_v%%[![:space:]]*}"}"
    _v="${_v%"${_v##*[![:space:]]}"}"
    if [[ ${#_v} -ge 2 && ( "$_v" == \"*\" || "$_v" == \'*\' ) ]]; then
        _v="${_v:1:${#_v}-2}"
    fi
    if [[ "$_v" == "." || "$_v" == ".." ]]; then
        _sandbox_deny "$_origin '$_v' refused: a job name may not be '.' or '..'."
        return 1
    fi
    return 0
}

# _check_staged_slurm_io_value <flag> <value>
#
# --output/--error values that go through the bwrap/firejail staging
# transform keep their % patterns for slurmstepd to expand OUTSIDE the
# sandbox. Only patterns whose expansion cannot contain `/` are allowed
# (%A %a %J %j %N %n %s %t %u %%, optional zero-pad digits); `%x` (job
# name, agent controlled) and unknown patterns are refused. A backslash
# is refused too: Slurm strips backslashes (and skips pattern expansion)
# at open time, so `.\./` would become `../` after the transform.
# Same pattern policy as _validate_slurm_io_path (C9).
_check_staged_slurm_io_value() {
    local _flag="$1" _val="$2" _i=0 _j _n _spec
    _n=${#_val}
    if [[ "$_val" == *\\* ]]; then
        _sandbox_deny "Slurm '$_flag $_val' refused: backslashes are not allowed (slurmstepd strips them at open time)."
        return 1
    fi
    while (( _i < _n )); do
        if [[ "${_val:_i:1}" == "%" ]]; then
            _j=$((_i + 1))
            while (( _j < _n )) && [[ "${_val:_j:1}" == [0-9] ]]; do _j=$((_j + 1)); done
            _spec="${_val:_j:1}"
            case "$_spec" in
                %|A|a|J|j|N|n|s|t|u) ;;
                x)
                    _sandbox_deny "Slurm '$_flag $_val' refused: '%x' (job name) is agent-controlled and could change the directory slurmstepd writes to."
                    return 1
                    ;;
                *)
                    _sandbox_deny "Slurm '$_flag $_val' refused: unsupported '%${_val:_i+1:_j-_i}' pattern."
                    return 1
                    ;;
            esac
            _i=$((_j + 1))
            continue
        fi
        _i=$((_i + 1))
    done
    return 0
}

# ── --export sanitisation ────────────────────────────────────────
#
# Why: the job wrapper generated by create_wrapped_script executes on
# the compute node OUTSIDE the sandbox (it is what launches
# sandbox-exec.sh). Whatever `--export=NAME=VALUE` puts into the job
# environment is therefore seen first by host-side code: bash honours
# BASH_ENV/ENV, the dynamic loader honours LD_PRELOAD/LD_AUDIT, and the
# compute-node sandbox-exec.sh honours SANDBOX_CONF, HOME_ACCESS, BWRAP,
# PRIVATE_TMP, _PASSWD_SRC_FILE, ... So agent-chosen VALUES must never
# reach Slurm. We forward only ALL / NONE / NIL and bare NAMES (Slurm
# fills those from the chaperon's own host environment, the same source
# the default `--export=ALL` uses) and apply NAME=VALUE pairs inside the
# sandbox via `/usr/bin/env NAME=VALUE <interpreter>`.

# Mirror of sandbox-lib.sh's _CONFIG_SCALARS + _CONFIG_ARRAYS. The
# chaperon does not source sandbox-lib.sh (heavy, side effects), so the
# list is duplicated here; test.sh asserts it stays a superset of the
# launcher's lists. Used by the --export deny-list and by the wrapper's
# pre-exec `unset`.
_CHAPERON_LAUNCHER_CONFIG_VARS=(
    ALLOWED_PROJECT_PARENTS READONLY_MOUNTS HOME_READONLY HOME_WRITABLE
    HOME_SEEDED_FILES
    BLOCKED_FILES BLOCKED_ENV_VARS BLOCKED_ENV_PATTERNS ALLOWED_ENV_VARS
    HIDE_FROM_SANDBOX
    EXTRA_BLOCKED_PATHS EXTRA_WRITABLE_PATHS DENIED_WRITABLE_PATHS
    DEVICES DEVICES_BLACKLIST
    SANDBOX_ENV SUPPRESS_AGENT_WARNINGS SANDBOX_MODULES ENABLED_AGENTS
    NETWORK_BLOCKLIST NETWORK_BLOCKLIST_EXCEPT
    SANDBOX_BACKEND PRIVATE_TMP PRIVATE_IPC FILTER_PASSWD BIND_DEV_PTS
    NETWORK_FILTER_MODE NETWORK_FILTER_FALLBACK NETWORK_MAIL_BLOCK
    SLURM_SCOPE HOME_ACCESS SANDBOX_QUIET SANDBOX_NPROC_LIMIT
    CHAPERON_LOG_LEVEL CHAPERON_LOG_RETAIN_DAYS
    LANDLOCK_REQUIRED_ABI LANDLOCK_HARD_REQUIREMENT
    MOUNT_GUARD MOUNT_GUARD_INTERVAL
    CLEANUP_MATERIALIZED_BLOCKED_FILES
)

# _is_denied_export_name <name>
# Returns 0 if <name> must not be set via --export.
_is_denied_export_name() {
    local _n="$1" _c
    case "$_n" in
        BASH_ENV|ENV|SHELLOPTS|BASHOPTS|PS4|GCONV_PATH|PATH) return 0 ;;
        BASH_FUNC_*|LD_*)                                    return 0 ;;
        SANDBOX_*|_SANDBOX*|_CHAPERON*|CHAPERON_*)           return 0 ;;
        REAL_*|SLURM_*)                                      return 0 ;;
        _PASSWD_SRC_FILE|_GROUP_SRC_FILE|BWRAP)              return 0 ;;
    esac
    for _c in "${_CHAPERON_LAUNCHER_CONFIG_VARS[@]}"; do
        [[ "$_n" == "$_c" ]] && return 0
    done
    return 1
}

# _sanitize_export_value <value> <origin>
#
# Parses an sbatch --export value. On success (return 0) sets, in the
# caller's scope (do NOT call inside $(...)):
#   _EXPORT_SLURM_VALUE      — the rewritten value to hand to Slurm
#                              (ALL | NONE | NIL | NAME[,NAME...] |
#                              ALL,NAME[,NAME...])
#   _EXPORT_ENV_ASSIGNMENTS  — array of NAME=VALUE pairs to apply inside
#                              the sandbox
# <origin> is used in messages only ("--export" or "#SBATCH --export").
# Returns 1 (with a _sandbox_deny / _sandbox_warn message) on a denied
# or malformed entry.
_sanitize_export_value() {
    local _val="$1" _origin="${2:---export}"
    _EXPORT_SLURM_VALUE=""
    _EXPORT_ENV_ASSIGNMENTS=()
    if [[ -z "$_val" ]]; then
        _sandbox_warn "sbatch '$_origin' requires a value (ALL, NONE, or a comma list of variables)."
        return 1
    fi
    local _mode="" _names=() _tok _name _saved_ifs="$IFS"
    local -a _toks
    IFS=','
    # shellcheck disable=SC2206  # split on , is intentional
    _toks=( $_val )
    IFS="$_saved_ifs"
    local _first=true
    for _tok in "${_toks[@]}"; do
        [[ -z "$_tok" ]] && continue
        if $_first; then
            _first=false
            case "${_tok^^}" in
                ALL|NONE|NIL) _mode="${_tok^^}"; continue ;;
            esac
        fi
        case "${_tok^^}" in
            ALL|NONE|NIL)
                _sandbox_warn "sbatch '$_origin=$_val': '$_tok' must be the first entry."
                return 1
                ;;
        esac
        _name="${_tok%%=*}"
        if [[ ! "$_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            _sandbox_deny "sbatch '$_origin': '$_name' is not a valid environment variable name."
            return 1
        fi
        if _is_denied_export_name "$_name"; then
            _sandbox_deny "sbatch '$_origin' may not set '$_name' — the job wrapper runs outside the sandbox and this variable controls the shell, the dynamic loader, Slurm or the sandbox itself."
            return 1
        fi
        if [[ "$_tok" == *=* ]]; then
            _EXPORT_ENV_ASSIGNMENTS+=("$_tok")
        fi
        # Both bare names and NAME=VALUE contribute the NAME to Slurm's
        # list: this keeps Slurm's "only these variables" semantics for
        # a list without ALL (the value Slurm propagates, if any, is the
        # chaperon's host value; the in-sandbox `env` overrides it).
        _names+=("$_name")
    done
    if [[ "$_mode" == NONE || "$_mode" == NIL ]] && (( ${#_names[@]} > 0 )); then
        _sandbox_warn "sbatch '$_origin=$_val': Slurm does not allow explicit variables with $_mode."
        return 1
    fi
    if [[ "$_mode" == ALL ]]; then
        _EXPORT_SLURM_VALUE="ALL"
    elif [[ -n "$_mode" ]]; then
        _EXPORT_SLURM_VALUE="$_mode"
    elif (( ${#_names[@]} > 0 )); then
        IFS=','
        _EXPORT_SLURM_VALUE="${_names[*]}"
        IFS="$_saved_ifs"
    else
        _sandbox_warn "sbatch '$_origin' requires a value (ALL, NONE, or a comma list of variables)."
        return 1
    fi
    return 0
}

# ── Argument validation ─────────────────────────────────────────

# _maybe_transform_slurm_output_arg <flag> <value> <project_dir>
#
# Pure-stdout helper for validate_sbatch_args and the #SBATCH-directive
# filter in create_wrapped_script. Given an --output / --error flag-name
# and raw value, returns the value-to-forward-to-sbatch on stdout.
#
# Deliberately side-effect-free: callers invoke via $(...) command
# substitution, which would lose any global-variable side-effects to a
# subshell. The (user, staging) pair is recorded by the caller via
# `_capture_slurm_output_pair` in the caller's own scope.
#
# If the feature is disabled (landlock) or value is empty, returns the
# value unchanged — the user's path flows verbatim to real sbatch.
_maybe_transform_slurm_output_arg() {
    local _flag="$1" _value="$2" _project_dir="$3"
    if ! _slurm_output_feature_enabled || [[ -z "$_value" ]]; then
        printf '%s' "$_value"
        return
    fi
    case "$_flag" in
        -o|--output|-e|--error) ;;
        *) printf '%s' "$_value"; return ;;
    esac
    _transform_slurm_output_path "$_value" "$_project_dir"
}

# _capture_slurm_output_pair <flag> <user_value> <staging_value>
#
# Caller-scope companion to _maybe_transform_slurm_output_arg. Records
# the (user-template, staging-template) pair into the per-stream capture
# vars that `create_wrapped_script` reads to emit the in-sandbox symlink
# prelude. Multiple occurrences: later wins (matches Slurm's
# last-occurrence semantics).
#
# Must be called in the caller's scope (NOT inside `$(...)`), since the
# whole point is to mutate variables visible to the wrapper-building code.
# Silently no-ops when the feature is disabled or the user value is empty
# — same gates as the transform helper.
_capture_slurm_output_pair() {
    local _flag="$1" _user="$2" _staging="$3"
    _slurm_output_feature_enabled || return 0
    [[ -z "$_user" ]] && return 0
    case "$_flag" in
        -o|--output) _USER_SLURM_OUTPUT="$_user"; _STAGING_SLURM_OUTPUT="$_staging" ;;
        -e|--error)  _USER_SLURM_ERROR="$_user";  _STAGING_SLURM_ERROR="$_staging"  ;;
    esac
}

# Validate and filter sbatch arguments.
# Input:  REQ_ARGS array (from protocol), PROJECT_DIR (caller scope)
# Output: VALIDATED_ARGS array (safe to pass to real sbatch)
#         _USER_SLURM_OUTPUT / _STAGING_SLURM_OUTPUT (and ERROR
#         counterparts) — populated when --output / --error are
#         present AND the feature is enabled (bwrap/firejail).
# Returns 1 if a denied flag is found.
validate_sbatch_args() {
    VALIDATED_ARGS=()
    _USER_COMMENT=""   # Captured here, injected by sbatch handler with chaperon tag
    _USER_SLURM_OUTPUT=""
    _USER_SLURM_ERROR=""
    _STAGING_SLURM_OUTPUT=""
    _STAGING_SLURM_ERROR=""
    # --export state: consumed by create_wrapped_script. CLI wins over
    # any #SBATCH --export directive (matching Slurm's precedence).
    _EXPORT_FROM_CLI=false
    _EXPORT_ENV_ASSIGNMENTS=()
    local _cli_export_assignments=()
    local _project_dir="${PROJECT_DIR:-}"
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            --export=*|--export)
                local _ev
                if [[ "$arg" == --export=* ]]; then
                    _ev="${arg#--export=}"
                elif (( i + 1 < ${#REQ_ARGS[@]} )); then
                    (( i++ ))
                    _ev="${REQ_ARGS[$i]}"
                else
                    _sandbox_warn "sbatch '--export' requires a value."
                    return 1
                fi
                _sanitize_export_value "$_ev" "--export" || return 1
                # Last occurrence wins (Slurm semantics): drop any
                # earlier rewritten --export from VALIDATED_ARGS.
                local _kept=() _va
                for _va in "${VALIDATED_ARGS[@]+"${VALIDATED_ARGS[@]}"}"; do
                    [[ "$_va" == --export=* ]] || _kept+=("$_va")
                done
                VALIDATED_ARGS=("${_kept[@]+"${_kept[@]}"}")
                VALIDATED_ARGS+=("--export=$_EXPORT_SLURM_VALUE")
                _cli_export_assignments=("${_EXPORT_ENV_ASSIGNMENTS[@]+"${_EXPORT_ENV_ASSIGNMENTS[@]}"}")
                _EXPORT_FROM_CLI=true
                ;;
            --wrap|--wrap=*)
                _sandbox_warn "sbatch '--wrap' is handled automatically. Pass your script as a file argument or use --wrap normally."
                return 1
                ;;
            --chdir|--chdir=*|-D)
                _sandbox_warn "sbatch '--chdir' is not allowed — the working directory is set automatically to your current directory."
                return 1
                ;;
            --output=*|-o=*|--error=*|-e=*|--output|-o|--error|-e)
                # `=` form or space form (--output <value>): extract the
                # value, validate / transform, capture, and re-emit as a
                # single `--output=<value>` token.
                local _flag _v _t
                if [[ "$arg" == *=* ]]; then
                    _flag="${arg%%=*}"
                    _v="${arg#*=}"
                elif (( i + 1 < ${#REQ_ARGS[@]} )); then
                    _flag="$arg"
                    (( i++ ))
                    _v="${REQ_ARGS[$i]}"
                else
                    _sandbox_warn "sbatch '$arg' requires a value."
                    return 1
                fi
                if _slurm_output_feature_enabled; then
                    # Staged (bwrap/firejail): % patterns survive the
                    # transform, so only directory-neutral ones may.
                    _check_staged_slurm_io_value "$_flag" "$_v" || return 1
                elif ! _validate_slurm_io_path "$_flag" "$_v" "$_project_dir" "${REQ_CWD:-$_project_dir}"; then
                    # Without the staging transform (landlock) the path
                    # goes to slurmstepd verbatim: validate it instead.
                    return 1
                fi
                _t="$(_maybe_transform_slurm_output_arg "$_flag" "$_v" "$_project_dir")"
                _capture_slurm_output_pair "$_flag" "$_v" "$_t"
                VALIDATED_ARGS+=("$(_slurm_long_flag "$_flag")=$_t")
                ;;
            --uid|--uid=*|--gid|--gid=*)
                _sandbox_deny "sbatch '--uid/--gid' is not allowed — jobs must run as your own user."
                return 1
                ;;
            --get-user-env|--get-user-env=*)
                _sandbox_deny "sbatch '--get-user-env' is not allowed — it can leak environment variables from outside the sandbox."
                return 1
                ;;
            --propagate|--propagate=*)
                _sandbox_deny "sbatch '--propagate' is not allowed — resource limit propagation is restricted for security."
                return 1
                ;;
            --prolog|--prolog=*|--epilog|--epilog=*|--task-prolog|--task-prolog=*|--task-epilog|--task-epilog=*)
                _sandbox_deny "sbatch '--prolog/--epilog' is not allowed — custom prolog/epilog scripts could run outside sandbox control."
                return 1
                ;;
            --burst-buffer-file|--burst-buffer-file=*|--bbf|--bbf=*)
                _sandbox_deny "sbatch '--burst-buffer-file' is not allowed — arbitrary file access is restricted."
                return 1
                ;;
            --bcast|--bcast=*)
                _sandbox_deny "sbatch '--bcast' is not allowed — binary broadcasting could bypass sandbox wrapping."
                return 1
                ;;
            --container|--container=*)
                _sandbox_deny "sbatch '--container' is not allowed — OCI containers would bypass sandbox restrictions."
                return 1
                ;;
            --comment=*)
                # Intercept --comment: chaperon will inject its own tag.
                # Save the user's value to append later.
                _USER_COMMENT="${arg#--comment=}"
                ;;
            --comment)
                # --comment <value> form
                if (( i + 1 < ${#REQ_ARGS[@]} )); then
                    (( i++ ))
                    _USER_COMMENT="${REQ_ARGS[$i]}"
                fi
                ;;
            -*)
                # Allow-listed flag: classify (no / required / optional
                # argument) and re-emit as one token (`--long=value` or
                # the bare flag). Optional-argument flags (--nice,
                # --exclusive) never consume the next token.
                if ! _is_allowed_flag "$arg"; then
                    _sandbox_warn "sbatch flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                local _has_next=0
                (( i + 1 < ${#REQ_ARGS[@]} )) && _has_next=1
                _slurm_normalize_flag sbatch "$arg" "$_SBATCH_VALUE_FLAGS" "$_SBATCH_OPTARG_FLAGS" \
                    "$_has_next" "${REQ_ARGS[$((i + 1))]-}" || return 1
                if (( _SLURM_FLAG_CONSUMED )); then i=$((i + 1)); fi
                VALIDATED_ARGS+=("$_SLURM_FLAG_TOKEN")
                ;;
            *)
                _sandbox_warn "sbatch unexpected positional argument. Script files are handled by the stub — this should not happen."
                return 1
                ;;
        esac
        (( i++ ))
    done
    # The job name expands into %x (see _validate_slurm_job_name).
    local _va
    for _va in "${VALIDATED_ARGS[@]+"${VALIDATED_ARGS[@]}"}"; do
        if [[ "$_va" == --job-name=* ]]; then
            _validate_slurm_job_name "sbatch --job-name" "${_va#--job-name=}" || return 1
        fi
    done
    _EXPORT_ENV_ASSIGNMENTS=("${_cli_export_assignments[@]+"${_cli_export_assignments[@]}"}")
    return 0
}

# ── CWD validation ──────────────────────────────────────────────

# Validate that the requested CWD is under the project directory.
# Usage: validate_cwd <cwd> <project_dir>
validate_cwd() {
    local cwd="$1" project_dir="$2"

    # Resolve to physical path (no symlink tricks)
    local resolved
    resolved="$(cd "$cwd" 2>/dev/null && pwd -P)" || {
        _sandbox_warn "working directory does not exist: $cwd"
        return 1
    }

    local resolved_project
    resolved_project="$(cd "$project_dir" 2>/dev/null && pwd -P)" || {
        _sandbox_warn "project directory does not exist: $project_dir"
        return 1
    }

    if [[ "$resolved" != "$resolved_project" && "$resolved" != "$resolved_project"/* ]]; then
        _sandbox_deny "working directory '$resolved' is outside the project directory '$resolved_project'. Jobs must run within the project."
        return 1
    fi
    return 0
}

# ── Job wrapping ────────────────────────────────────────────────

# Detect whether an interpreter line is a POSIX-ish shell that supports
# `-s --` (read script from stdin, treat following args as positionals).
# Handles plain `/bin/bash`, `/bin/bash -e -u`, and `/usr/bin/env bash`.
# Returns 0 for shell, 1 for non-shell or unrecognized.
_is_shell_interpreter() {
    local line="$1"
    # shellcheck disable=SC2206  # word-splitting on the shebang is intentional
    local tokens=($line)
    local first="${tokens[0]:-}"
    [[ -z "$first" ]] && return 1
    local first_base
    first_base="$(basename -- "$first")"
    case "$first_base" in
        bash|sh|zsh|dash|ksh|ash) return 0 ;;
        env)
            # Walk past env's own flags / VAR=val assignments to find the
            # real interpreter token. Conservative: any flag we don't
            # explicitly recognize as boolean is treated as taking a value.
            local i=1
            while (( i < ${#tokens[@]} )); do
                local t="${tokens[$i]}"
                case "$t" in
                    --) (( i++ )); break ;;
                    -i|--ignore-environment|-0|--null|-v|--debug|-S*|--split-string=*)
                        (( i++ )) ;;
                    -u|--unset|-C|--chdir)
                        (( i += 2 )) ;;
                    -*)
                        (( i += 2 )) ;;
                    *=*)
                        (( i++ )) ;;
                    *)
                        break ;;
                esac
            done
            local env_target="${tokens[$i]:-}"
            [[ -z "$env_target" ]] && return 1
            local env_base
            env_base="$(basename -- "$env_target")"
            case "$env_base" in
                bash|sh|zsh|dash|ksh|ash) return 0 ;;
            esac
            return 1
            ;;
    esac
    return 1
}

# Create a wrapped sbatch script that runs the user's command inside
# the sandbox on the compute node.
# Usage: create_wrapped_script <sandbox_exec> <project_dir> <script_content> <output_file> [script_arg ...]
#
# The trailing positional script_args are forwarded so that $1/$@/$# work
# inside the user's wrapped script. For shell shebangs the script is piped
# via stdin and `-s -- arg1 arg2 ...` carries the positionals; for other
# interpreters (python, perl, R, …) the script is materialised to a tmpfile
# inside the sandbox at runtime and exec'd directly so its argv is correct.
create_wrapped_script() {
    local sandbox_exec="$1" project_dir="$2" script_content="$3" output_file="$4"
    shift 4
    local script_args=("$@")

    # The wrapper must not depend on PATH (it runs in the untrusted job
    # environment), so sandbox-exec.sh has to be an absolute path.
    if [[ "$sandbox_exec" != /* ]]; then
        _sandbox_warn "internal error: sandbox-exec path '$sandbox_exec' is not absolute."
        return 1
    fi

    # Filter #SBATCH directives: keep safe ones, strip dangerous ones.
    # This prevents bypassing the flag whitelist (e.g. #SBATCH --uid=0,
    # #SBATCH --prolog=/evil.sh) while preserving
    # legitimate resource directives (--mem, --partition, --time, etc.).
    local safe_directives=""
    local stripped_count=0
    local _export_directive_failed=false _dir_export_value="" _io_directive_failed=false
    local -a _dir_export_assign=()
    # Agent-supplied NAME=VALUE pairs from a CLI --export (set by
    # validate_sbatch_args); replaced below by the last #SBATCH --export
    # directive's pairs when there was no CLI --export.
    local -a _env_assign=()
    if [[ "${_EXPORT_FROM_CLI:-false}" == true ]]; then
        _env_assign=("${_EXPORT_ENV_ASSIGNMENTS[@]+"${_EXPORT_ENV_ASSIGNMENTS[@]}"}")
    fi
    while IFS= read -r line; do
        # Normalize: strip leading whitespace/tabs before checking.
        # Slurm accepts leading whitespace before #SBATCH directives.
        local trimmed="${line#"${line%%[! 	]*}"}"
        if [[ "$trimmed" == "#SBATCH"* ]]; then
            # Extract the flag from the directive
            local directive_body="${trimmed#\#SBATCH}"
            directive_body="${directive_body# }"  # strip leading space
            # Get the flag name (before = or space)
            local flag_name
            case "$directive_body" in
                --*=*) flag_name="${directive_body%%=*}" ;;
                --*)   flag_name="${directive_body%% *}" ;;
                -*)    flag_name="${directive_body:0:2}" ;;
                *)     flag_name="" ;;
            esac

            # ── ASB-2026-001 defense-in-depth ──────────────────────
            # Slurm's #SBATCH directive parser whitespace-tokenizes
            # the body, so `#SBATCH --time=01 --task-prolog=/evil.sh`
            # would apply BOTH flags despite our flag-name extraction
            # stopping at the first `=`. Refuse any directive whose
            # body contains `[[:space:]]--` — the smuggling-shape
            # signature. Single-flag-per-directive is the Slurm
            # convention; multi-flag lines are rare in practice and
            # always recoverable by splitting onto separate lines.
            # A single dash smuggles just as well (`#SBATCH --hold
            # -e/path` sets --error), so any whitespace-then-`-` counts.
            if [[ "$directive_body" == *[[:space:]]-* ]]; then
                _sandbox_deny "#SBATCH directive '${directive_body}' contains multiple flag tokens; only one flag per #SBATCH line is allowed (whitespace-smuggling defense, ASB-2026-001)."
                stripped_count=$((stripped_count + 1))
                continue
            fi

            # A short no-argument flag followed by more characters is a
            # getopt option cluster: `#SBATCH -He/path` is `-H -e /path`.
            # Only required-argument short flags may carry an attached
            # value (`-Jname`, `-o file`).
            if [[ "$flag_name" == -[!-] ]] && ! _is_value_flag "$flag_name"; then
                local _rest="${directive_body:2}"
                _rest="${_rest%"${_rest##*[![:space:]]}"}"
                if [[ -n "$_rest" ]]; then
                    _sandbox_deny "#SBATCH directive '${directive_body}' attaches characters to the no-argument flag '$flag_name' (getopt would read them as further options)."
                    stripped_count=$((stripped_count + 1))
                    continue
                fi
            fi

            # Explicit security-critical deny-list parity with the
            # CLI surface (validate_sbatch_args). Without this a
            # bare `#SBATCH --task-prolog=/x` would be silently
            # stripped via the allow-list miss below — operators
            # deserve a specific message, and a future allow-list
            # expansion must not silently re-admit a denied flag.
            if [[ -n "$flag_name" ]] && _is_denied_flag "$flag_name"; then
                _sandbox_deny "#SBATCH '${flag_name}' is not allowed — denied by the chaperon's security flag list."
                stripped_count=$((stripped_count + 1))
                continue
            fi

            # --export directive: never forwarded verbatim (see
            # _sanitize_export_value). A CLI --export overrides every
            # directive (Slurm precedence), so drop them; otherwise the
            # LAST directive wins and is re-emitted, rewritten, below.
            if [[ "$flag_name" == "--export" ]]; then
                if [[ "${_EXPORT_FROM_CLI:-false}" == true ]]; then
                    continue
                fi
                local _xval
                case "$directive_body" in
                    --export=*) _xval="${directive_body#--export=}" ;;
                    *)          _xval="${directive_body#--export}"
                                _xval="${_xval#"${_xval%%[![:space:]]*}"}" ;;
                esac
                _xval="${_xval%"${_xval##*[![:space:]]}"}"
                if [[ "$_xval" == \"*\" && ${#_xval} -ge 2 ]]; then
                    _xval="${_xval:1:${#_xval}-2}"
                fi
                if [[ "$_xval" == *[[:space:]\"\'\\#]* ]]; then
                    _sandbox_deny "#SBATCH --export value '${_xval}' contains whitespace, quotes, '#' or backslashes; pass such values with --export on the sbatch command line instead."
                    _export_directive_failed=true
                    continue
                fi
                if _sanitize_export_value "$_xval" "#SBATCH --export"; then
                    _dir_export_value="$_EXPORT_SLURM_VALUE"
                    _dir_export_assign=("${_EXPORT_ENV_ASSIGNMENTS[@]+"${_EXPORT_ENV_ASSIGNMENTS[@]}"}")
                else
                    _export_directive_failed=true
                fi
                continue
            fi

            # Job name: expands into %x (see _validate_slurm_job_name).
            if [[ "$flag_name" == "-J" || "$flag_name" == "--job-name" ]]; then
                local _jval
                case "$directive_body" in
                    --*=*) _jval="${directive_body#*=}" ;;
                    --*)   _jval="${directive_body#--job-name}" ;;
                    *)     _jval="${directive_body:2}" ;;
                esac
                _jval="${_jval%%#*}"
                if ! _validate_slurm_job_name "#SBATCH $flag_name" "$_jval"; then
                    _io_directive_failed=true
                    continue
                fi
            fi

            if [[ -n "$flag_name" ]] && _is_allowed_flag "$flag_name"; then
                # Transform --output / --error values inside #SBATCH
                # directives so the redirect-to-staging contract applies
                # to BOTH command-line flags AND in-script directives.
                # Otherwise the user could bypass via
                # `#SBATCH --output=/etc/foo` (which validate_sbatch_args
                # never sees). Only transforms when the feature is
                # enabled (bwrap/firejail) — landlock passes through.
                case "$flag_name" in
                    --output|--error|-o|-e)
                        if _slurm_output_feature_enabled; then
                            local _dval _new_val _new_line
                            case "$directive_body" in
                                --*=*) _dval="${directive_body#*=}" ;;
                                --*)   _dval="${directive_body#* }" ;;
                                *)     _dval="${directive_body:2}"  ;;  # -o val / -oval
                            esac
                            # Trim surrounding whitespace / comments — defensive.
                            _dval="${_dval%%#*}"
                            _dval="${_dval#"${_dval%%[![:space:]]*}"}"
                            _dval="${_dval%"${_dval##*[![:space:]]}"}"
                            # % patterns survive the transform: only
                            # directory-neutral ones (no %x), no backslash.
                            if ! _check_staged_slurm_io_value "#SBATCH $flag_name" "$_dval"; then
                                _io_directive_failed=true
                                continue
                            fi
                            _new_val="$(_transform_slurm_output_path "$_dval" "$project_dir")"
                            # Reconstruct as `#SBATCH <flag>=<new_val>` (canonical
                            # form). Quote the value via printf %q so a path with
                            # special characters cannot be interpreted by Slurm's
                            # directive tokenizer as a flag boundary (ASB-2026-001
                            # belt-and-braces — the whitespace-smuggling defense
                            # above already rejects the attack at the body level).
                            local _new_val_quoted
                            printf -v _new_val_quoted '%q' "$_new_val"
                            # Short flags take the value as a separate
                            # token (`-o=x` would make the value "=x").
                            if [[ "$flag_name" == --* ]]; then
                                _new_line="#SBATCH $flag_name=$_new_val_quoted"
                            else
                                _new_line="#SBATCH $flag_name $_new_val_quoted"
                            fi
                            # Capture for env-var passing — last directive wins,
                            # matching command-line `validate_sbatch_args` semantics.
                            _capture_slurm_output_pair "$flag_name" "$_dval" "$_new_val"
                            safe_directives+="$_new_line"$'\n'
                        else
                            # No staging (landlock): slurmstepd opens the
                            # path verbatim, so validate it and re-emit
                            # canonically. Values Slurm's tokenizer could
                            # read differently (quotes, whitespace, #) are
                            # refused; a refused directive fails the job.
                            local _lval
                            case "$directive_body" in
                                --*=*) _lval="${directive_body#*=}" ;;
                                --*)   _lval="${directive_body#* }" ;;
                                *)     _lval="${directive_body:2}" ;;
                            esac
                            _lval="${_lval#"${_lval%%[![:space:]]*}"}"
                            _lval="${_lval%"${_lval##*[![:space:]]}"}"
                            if [[ -z "$_lval" || "$_lval" == *[[:space:]\"\'#]* ]]; then
                                _sandbox_deny "#SBATCH $flag_name value '${_lval}' must be a single unquoted path (no whitespace, quotes or '#'); pass it on the sbatch command line instead."
                                _io_directive_failed=true
                            elif _validate_slurm_io_path "$flag_name" "$_lval" "$project_dir" "${REQ_CWD:-$project_dir}"; then
                                if [[ "$flag_name" == --* ]]; then
                                    safe_directives+="#SBATCH $flag_name=$_lval"$'\n'
                                else
                                    safe_directives+="#SBATCH $flag_name $_lval"$'\n'
                                fi
                            else
                                _io_directive_failed=true
                            fi
                        fi
                        ;;
                    *)
                        safe_directives+="$line"$'\n'
                        ;;
                esac
            else
                stripped_count=$((stripped_count + 1))
            fi
        fi
    done <<< "$script_content"

    if [[ "$stripped_count" -gt 0 ]]; then
        _sandbox_deny "stripped $stripped_count unsafe #SBATCH directive(s) from script (denied flags are not allowed in directives either)"
    fi

    # A rejected --export directive fails the whole submission: silently
    # dropping it would change the job's environment semantics.
    if $_export_directive_failed || $_io_directive_failed; then
        return 1
    fi
    if [[ -n "$_dir_export_value" ]]; then
        safe_directives+="#SBATCH --export=$_dir_export_value"$'\n'
        _env_assign=("${_dir_export_assign[@]+"${_dir_export_assign[@]}"}")
    fi

    # Default --output injection: extend the staging + symlink contract to
    # the implicit `slurm-<jobid>.out` path. Without this, an in-sandbox
    # agent could symlink-plant `<cwd>/slurm-<next-jobid>.out` before
    # slurmstepd opens it (cwd is sandbox-writable; the staging dir is not).
    #
    # Fires only when:
    #   - the feature is on (bwrap/firejail; landlock has no RO-overlay)
    #   - AND neither validate_sbatch_args (CLI -o/--output) nor the
    #     directive loop above (#SBATCH --output=) populated the capture.
    #
    # Pattern matches stock sbatch: `slurm-%A_%a.out` for arrays (detected
    # by --array in VALIDATED_ARGS), `slurm-%j.out` otherwise. Stderr is
    # untouched — stock Slurm merges stderr into stdout when only --output
    # is set, and the prelude's stderr-symlink branch no-ops on empty
    # capture, so no `--error` injection is needed.
    #
    # Injected as a #SBATCH directive (not a CLI flag) so the precedence
    # ordering stays correct: an explicit CLI flag on a future submission
    # would still win. Goes through `_capture_slurm_output_pair` so the
    # prelude built below picks up the same values it would for any other
    # captured path.
    if _slurm_output_feature_enabled && [[ -z "${_USER_SLURM_OUTPUT:-}" ]]; then
        local _default_pat _default_staging _is_array=false _va
        for _va in "${VALIDATED_ARGS[@]}"; do
            case "$_va" in
                -a|--array|--array=*) _is_array=true; break ;;
            esac
        done
        if $_is_array; then
            _default_pat="slurm-%A_%a.out"
        else
            _default_pat="slurm-%j.out"
        fi
        _default_staging="$(_transform_slurm_output_path "$_default_pat" "$project_dir")"
        _capture_slurm_output_pair "--output" "$_default_pat" "$_default_staging"
        safe_directives+="#SBATCH --output=$_default_staging"$'\n'
    fi

    # Strip #SBATCH directives from script body — they're in the wrapper header.
    local script_body
    script_body="$(printf '%s\n' "$script_content" | grep -vE '^[[:space:]]*#SBATCH' || true)"

    # Extract the interpreter from the shebang (default: sh, matching Slurm).
    # The wrapper pipes the script to the interpreter via stdin instead of
    # using `sh -c`, so the user's shebang is honored.  The #! line is a
    # comment in all common interpreters (sh, bash, python, perl, R, ruby),
    # so leaving it in the script content is harmless.
    local first_line interpreter
    first_line="$(head -1 <<< "$script_body")"
    if [[ "$first_line" == "#!"* ]]; then
        interpreter="${first_line#\#!}"
        interpreter="${interpreter# }"  # strip optional leading space
    else
        interpreter="/bin/sh"
    fi

    # Generate a unique EOF marker and verify it doesn't collide with
    # the script content.  This lets us inline the entire script via
    # heredoc — no temp files, no NFS issues, no cleanup needed.
    local eof_marker="_CHAPERON_EOF_${RANDOM}_${RANDOM}_$$"
    if printf '%s' "$script_body" | grep -qF "$eof_marker"; then
        _sandbox_warn "script contains the internal heredoc marker '$eof_marker'. This is astronomically unlikely — please resubmit."
        return 1
    fi

    # Build a self-contained wrapper:
    #   1. #SBATCH directives (validated)
    #   2. Inline script via heredoc
    #   3. Either pipe to an interpreter (shells) or materialise to a
    #      tmpfile inside the sandbox and exec it (non-shells) so the
    #      user's shebang is honored AND $1/$@/$# survive.
    #
    # Why two paths? Shells support `-s --` (read script from stdin, treat
    # following tokens as positional args), so for #!/bin/bash etc. we keep
    # the original pipe-through-stdin form and append `-s -- arg1 arg2 …`.
    # Non-shell interpreters (python, perl, R, …) either don't read stdin
    # the same way or set argv[0] to '-' / '-c' when they do, breaking
    # `sys.argv` for the user's script. For those we write the script to
    # a private tmpfs file inside the sandbox at runtime and exec it
    # directly with the positionals — argv ends up exactly as if the
    # script had been launched as a normal file.
    #
    # Pre-quote the script positional args once: bash printf %q produces
    # safe shell-quoted tokens that survive embedding in either generated
    # wrapper form below.
    local quoted_script_args=""
    if (( ${#script_args[@]} > 0 )); then
        local _sa
        for _sa in "${script_args[@]}"; do
            quoted_script_args+=" $(printf '%q' "$_sa")"
        done
    fi

    # Compose the in-sandbox prelude that creates relative symlinks
    # from the user's intended --output/--error paths to the
    # chaperon-managed staging files. The prelude runs INSIDE the
    # sandbox so its filesystem writes are governed by the bind-mount
    # envelope — that's what makes the user's path the permission
    # check (if intended is not sandbox-writable, the symlink fails
    # and the log only lives at the staging path, which is always
    # reachable for reading).
    #
    # Only emitted when the feature captured something (validate_sbatch_args
    # or the #SBATCH directive filter populated _STAGING_SLURM_*). Empty on
    # landlock because _slurm_output_feature_enabled gates the chaperon-side
    # transform — no captures, no prelude.
    local _slurm_link_prelude=""
    if [[ -n "${_STAGING_SLURM_OUTPUT:-}" || -n "${_STAGING_SLURM_ERROR:-}" ]]; then
        local _q_user_out _q_stage_out _q_user_err _q_stage_err
        printf -v _q_user_out  '%q' "${_USER_SLURM_OUTPUT:-}"
        printf -v _q_stage_out '%q' "${_STAGING_SLURM_OUTPUT:-}"
        printf -v _q_user_err  '%q' "${_USER_SLURM_ERROR:-}"
        printf -v _q_stage_err '%q' "${_STAGING_SLURM_ERROR:-}"
        # heredoc-style assembly — values pre-quoted via printf %q so they
        # survive embedding regardless of special chars. The prelude is
        # bash syntax; emitted only into bash contexts (see embedding
        # below — non-bash shell scripts skip it). `%x` is not resolved:
        # the chaperon refuses it in both templates
        # (_check_staged_slurm_io_value), so it can never reach here.
        _slurm_link_prelude="$(cat <<EOF
# --- agent-sandbox: link intended slurm output paths to staging ---
_sandbox_slurm_resolve_pat() {
    local _p="\$1"
    local _array_id="\${SLURM_ARRAY_JOB_ID:-\${SLURM_JOB_ID:-}}"
    _p="\${_p//%j/\${SLURM_JOB_ID:-}}"
    _p="\${_p//%A/\$_array_id}"
    _p="\${_p//%a/\${SLURM_ARRAY_TASK_ID:-}}"
    _p="\${_p//%N/\${SLURMD_NODENAME:-\${HOSTNAME:-}}}"
    _p="\${_p//%n/\${SLURM_NODEID:-0}}"
    _p="\${_p//%t/\${SLURM_PROCID:-0}}"
    _p="\${_p//%u/\${USER:-}}"
    printf '%s' "\$_p"
}
_sandbox_link_slurm_output() {
    local _stream="\$1" _intended_template="\$2" _staging_template="\$3"
    [[ -z "\$_intended_template" || -z "\$_staging_template" ]] && return 0
    local _intended _staging
    _intended="\$(_sandbox_slurm_resolve_pat "\$_intended_template")"
    _staging="\$(_sandbox_slurm_resolve_pat "\$_staging_template")"
    [[ "\$_intended" != /* ]] && _intended="\$PWD/\$_intended"
    [[ "\$_intended" == "\$_staging" ]] && return 0
    if ! mkdir -p -- "\$(dirname -- "\$_intended")" 2>/dev/null; then
        echo "sandbox: \$_stream-symlink: parent dir of '\$_intended' not sandbox-writable; log lives at \$_staging" >&2
        return 0
    fi
    local _rel
    _rel="\$(realpath --relative-to="\$(dirname -- "\$_intended")" "\$_staging" 2>/dev/null)" \\
        || _rel="\$_staging"
    rm -f -- "\$_intended" 2>/dev/null
    if ! ln -s -- "\$_rel" "\$_intended" 2>/dev/null; then
        echo "sandbox: \$_stream-symlink to '\$_intended' failed; log lives at \$_staging" >&2
    fi
}
_sandbox_link_slurm_output stdout $_q_user_out $_q_stage_out
_sandbox_link_slurm_output stderr $_q_user_err $_q_stage_err
unset -f _sandbox_link_slurm_output _sandbox_slurm_resolve_pat
# --- end agent-sandbox prelude ---
EOF
)"
    fi

    # In-sandbox environment assignments from --export NAME=VALUE. They
    # become arguments of `/usr/bin/env` in the command handed to
    # sandbox-exec.sh, i.e. they are applied INSIDE the sandbox only and
    # never exist in the host-side job environment. printf %q makes each
    # pair a single inert word in the wrapper.
    local _env_prefix=""
    if (( ${#_env_assign[@]} > 0 )); then
        local _ea _ea_q
        _env_prefix="/usr/bin/env"
        for _ea in "${_env_assign[@]}"; do
            printf -v _ea_q '%q' "$_ea"
            _env_prefix+=" $_ea_q"
        done
        _env_prefix+=" "
    fi

    # Pre-exec scrub list. Explicit names for everything not covered by
    # the prefix loops emitted below (SANDBOX_*, _SANDBOX*, _CHAPERON*,
    # CHAPERON_*, REAL_*).
    local _unset_names="BASH_ENV ENV BWRAP _PASSWD_SRC_FILE _GROUP_SRC_FILE LANDLOCK_SANDBOX"
    local _cv
    for _cv in "${_CHAPERON_LAUNCHER_CONFIG_VARS[@]}"; do
        case "$_cv" in SANDBOX_*|CHAPERON_*) continue ;; esac
        _unset_names+=" $_cv"
    done

    {
        # The wrapper runs on the compute node OUTSIDE the sandbox, in
        # whatever environment Slurm hands it; it must not trust that
        # environment:
        #   - `bash -p` skips BASH_ENV / ENV and does not import shell
        #     functions or SHELLOPTS / BASHOPTS from the environment;
        #   - only builtins run before sandbox-exec.sh (no PATH lookup:
        #     the script is captured with `read`, not `cat`), and
        #     sandbox-exec.sh is invoked by absolute path;
        #   - launcher-config and loader-hook variables are unset before
        #     the exec so the compute-node sandbox-exec.sh resolves its
        #     settings from the config files, not from the job env.
        printf '#!/bin/bash -p\n'
        if [[ -n "$safe_directives" ]]; then
            printf '%s' "$safe_directives"
        fi
        printf '\n# --- Chaperon wrapper (auto-generated) ---\n'
        printf 'unset -v %s\n' "$_unset_names"
        printf 'for _v in "${!SANDBOX_@}" "${!_SANDBOX@}" "${!_CHAPERON@}" "${!CHAPERON_@}" "${!REAL_@}"; do unset -v "$_v"; done; unset -v _v\n'
        # Restore Slurm's submission cwd on the compute node before
        # exec'ing into the sandbox. Pairs with each backend's
        # `_resolve_inherited_cwd` chdir target: backends that *can*
        # enforce cwd via --chdir (bwrap, firejail) read $SLURM_SUBMIT_DIR
        # directly, so this `cd` is redundant for them. Backends that
        # cannot (landlock has no --chdir surface — it inherits cwd from
        # the parent) rely on this line to land in the submission dir on
        # clusters whose prolog drops cwd to $HOME. `:-.` no-ops cleanly
        # when SLURM_SUBMIT_DIR is unset; `|| true` swallows a stale dir.
        printf 'cd "${SLURM_SUBMIT_DIR:-.}" 2>/dev/null || true\n'
        # Retain the submitting session's quiet decision on the compute
        # node. SANDBOX_QUIET is exported (canonicalized to true/false) to
        # the chaperon by sandbox-exec.sh; bake it LITERALLY into the
        # wrapper here so the compute-node sandbox-exec.sh re-entry stays
        # quiet even when `--export=NONE` drops it from the job env or an
        # in-sandbox agent unset it. Only forced when quiet is active — a
        # non-quiet session lets the compute node resolve normally. This
        # runs OUTSIDE the sandbox (before the agent's script), so the
        # agent cannot suppress it. Security: prevents recovering the
        # suppressed banner via a submitted job's log.
        case "${SANDBOX_QUIET:-false}" in
            [Tt]rue|[Yy]es|1) printf 'export SANDBOX_QUIET=true\n' ;;
        esac
        # `read -d ''` returns 1 at end of input by design; `|| true`
        # keeps that from being mistaken for a failure. The heredoc adds
        # one trailing newline, stripped again to match the old
        # `$(cat <<EOF)` capture.
        printf 'IFS= read -r -d '"''"' _SCRIPT <<'"'"'%s'"'"' || true\n' "$eof_marker"
        printf '%s\n' "$script_body"
        printf '%s\n' "$eof_marker"
        printf '_SCRIPT="${_SCRIPT%%$'"'"'\\n'"'"'}"\n'

        if _is_shell_interpreter "$interpreter"; then
            # Shell path: pipe script to `<interp> -s -- <args>` so the
            # shell reads the body from stdin and assigns positionals.
            #
            # Strip any standalone `--` tokens from the interpreter line —
            # `--` ends option processing, so a shebang like
            # `#!/bin/bash --` (or the stub's `--wrap` synthesis) would
            # produce `bash -- -s ...` and bash would treat `-s` as a
            # filename. We append our own `-s --` below, so a leading
            # `--` from the user is redundant anyway.
            local interp_clean=""
            local _interp_tokens _it
            # shellcheck disable=SC2206  # word-splitting on the shebang is intentional
            _interp_tokens=($interpreter)
            for _it in "${_interp_tokens[@]}"; do
                [[ "$_it" == "--" ]] && continue
                interp_clean+="${interp_clean:+ }$_it"
            done
            local sep=""
            if (( ${#script_args[@]} > 0 )); then
                sep=" --"
            fi
            # When the slurm-output prelude is non-empty (bwrap/firejail
            # + at least one --output/--error captured), wrap the
            # inside-sandbox invocation in `bash -c '<prelude>; exec
            # <interp> -s ...'`. The outer bash runs the prelude (which
            # creates the relative symlinks under sandbox bind-mount
            # control), then exec's the user's chosen shell with the
            # script piped to stdin still intact. Without the prelude
            # (landlock or no --output/--error), keep the original
            # direct-exec form.
            if [[ -n "$_slurm_link_prelude" ]]; then
                local _inside="$_slurm_link_prelude"$'\n'"exec $interp_clean -s$sep \"\$@\""
                local _inside_q="${_inside//\'/\'\\\'\'}"
                printf 'printf '"'"'%%s\\n'"'"' "$_SCRIPT" | exec %q --project-dir %q -- %sbash -c '"'"'%s'"'"' _chaperon%s\n' \
                    "$sandbox_exec" "$project_dir" "$_env_prefix" "$_inside_q" "$quoted_script_args"
            else
                printf 'printf '"'"'%%s\\n'"'"' "$_SCRIPT" | exec %q --project-dir %q -- %s%s -s%s%s\n' \
                    "$sandbox_exec" "$project_dir" "$_env_prefix" "$interp_clean" "$sep" "$quoted_script_args"
            fi
        else
            # Non-shell path: inside the sandbox, materialise the script to
            # a private tmpfs file, chmod +x, exec it with the positionals.
            # The sandbox's /tmp is per-invocation private (bwrap/firejail)
            # or at minimum user-owned (landlock) — the file is gone the
            # moment the sandbox tears down, and the rm -f is
            # belt-and-suspenders for landlock's shared-tmp case.
            #
            # The runner-script body uses double-quoted single-quotes-by-
            # concatenation so we don't have to fight nested quoting:
            # everything between '...' is literal except for double-quote
            # boundaries we open to embed a literal single quote ('"'"').
            #
            # The slurm-output prelude (when non-empty) goes BEFORE
            # `set -e` so a prelude failure doesn't abort the user's
            # script — graceful degradation: no symlink, log only at
            # the staging path.
            local runner=""
            [[ -n "$_slurm_link_prelude" ]] && runner="$_slurm_link_prelude"$'\n'
            runner+='set -e
_t=$(mktemp /tmp/.chaperon-script-XXXXXX) || exit 1
trap '"'"'rm -f "$_t"'"'"' EXIT
printf '"'"'%s\n'"'"' "$1" > "$_t"
chmod +x "$_t"
shift
"$_t" "$@"'
            # Wrap the runner in single quotes for the bash -c argument
            # by escaping any embedded single quotes ('\'').
            local runner_q="${runner//\'/\'\\\'\'}"
            printf 'exec %q --project-dir %q -- %sbash -c '"'"'%s'"'"' _chaperon_runner "$_SCRIPT"%s\n' \
                "$sandbox_exec" "$project_dir" "$_env_prefix" "$runner_q" "$quoted_script_args"
        fi
    } > "$output_file"
    chmod +x "$output_file"
}

# Create a --wrap style wrapped command.
# Usage: create_wrapped_command <sandbox_exec> <project_dir> <wrap_cmd>
# Prints the --wrap argument value to stdout.
create_wrapped_command() {
    local sandbox_exec="$1" project_dir="$2" wrap_cmd="$3"
    # Retain the session's quiet decision (see create_wrapped_script). When
    # the chaperon was launched quiet, prefix an env assignment so the
    # compute-node sandbox-exec.sh re-entry stays quiet regardless of
    # --export. Only when active; otherwise the compute node resolves
    # normally.
    local _quiet_prefix=""
    case "${SANDBOX_QUIET:-false}" in
        [Tt]rue|[Yy]es|1) _quiet_prefix="SANDBOX_QUIET=true " ;;
    esac
    printf '%s%q --project-dir %q -- sh -c %q' \
        "$_quiet_prefix" "$sandbox_exec" "$project_dir" "$wrap_cmd"
}

# ── Job tagging via --comment (for scancel/squeue scoping) ───────
#
# Every job submitted through the chaperon gets a structured --comment
# tag that encodes the session and project identity.  This is queried
# by scancel/squeue to scope operations — no file-based tracking needed.
#
# Tag format:  chaperon:sid=<SESSION_ID>,proj=<PROJECT_HASH>[,user=<comment>]:END
#
#   sid  = unique per-chaperon-instance (PID + epoch, set once at startup)
#   proj = first 12 hex chars of md5(project_dir)
#   user = the user-supplied --comment value, if any (url-encoded to avoid commas)
#
# Query examples:
#   squeue --me -h -o "%i %k" | grep "chaperon:sid=$SID"   → session scope
#   squeue --me -h -o "%i %k" | grep "chaperon:.*proj=$H"  → project scope
#   squeue --me -h -o "%i %k" | grep "^chaperon:"          → user scope

# Session ID: unique per chaperon process.  Combine PID and epoch
# so that recycled PIDs from a later boot don't collide.
# Guard: only set once per chaperon process — _handler_lib.sh is
# sourced by every handler file (all loaded once at chaperon startup),
# and the session ID must remain stable across all requests within the
# same chaperon instance.
if [[ -z "${_CHAPERON_SESSION_ID:-}" ]]; then
    _CHAPERON_SESSION_ID="${BASHPID:-$$}.$(date +%s)"
fi

# Build the --comment value for sbatch.
# Usage: _build_chaperon_comment <project_dir>
# Reads _USER_COMMENT (set by validate_sbatch_args).
_build_chaperon_comment() {
    local project_dir="$1"
    local proj_hash
    proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"

    local tag="chaperon:sid=${_CHAPERON_SESSION_ID},proj=${proj_hash}"

    # Append user's original comment with encoding to prevent scope pollution.
    # Encode commas (tag delimiter), colons (tag prefix), and equals signs
    # (key=value separator) to prevent crafted comments from injecting
    # fake chaperon:, sid=, or proj= patterns into the tag.
    if [[ -n "${_USER_COMMENT:-}" ]]; then
        local safe_comment="${_USER_COMMENT//,/%2C}"
        safe_comment="${safe_comment//:/%3A}"
        safe_comment="${safe_comment//=/%3D}"
        tag+=",user=${safe_comment}"
    fi

    # End marker — colons are percent-encoded in user values, so :END
    # is an unambiguous boundary for _strip_chaperon_tags().
    tag+=":END"

    printf '%s' "$tag"
}

# Query squeue (+ sacct fallback) for job IDs matching a chaperon tag pattern.
# Usage: _query_chaperon_jobs <grep_pattern>
# Prints matching job IDs (one per line).
_query_chaperon_jobs() {
    local pattern="$1"
    local _real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
    local _real_sacct="${REAL_SACCT:-/usr/bin/sacct}"
    local _results _raw _rc=0

    # squeue: pending/running jobs.  A failed or timed-out squeue is an
    # ERROR, not "no jobs": returning an empty set here made callers
    # (scancel, scontrol) report "nothing in scope" at rc 0 (nexus-code#1744).
    _raw="$(timeout 10 "$_real_squeue" --me -h -o "%i %k")" || _rc=$?
    if (( _rc != 0 )); then
        _sandbox_warn "could not list jobs from Slurm (squeue exit $_rc); refusing to treat this as an empty scope."
        return "$_rc"
    fi
    _results="$(printf '%s\n' "$_raw" | grep -E "$pattern" | awk '{print $1}')" || true

    # sacct fallback: recently completed jobs (if slurmdbd is available)
    if [[ -x "$_real_sacct" ]]; then
        local _sacct_results
        _sacct_results="$(timeout 10 "$_real_sacct" -u "$(id -un)" \
            -n -o "JobID%20,Comment%200" -X --starttime=now-7days 2>/dev/null \
            | grep -E "$pattern" \
            | awk '{print $1}')" || true
        if [[ -n "$_sacct_results" ]]; then
            _results="$(printf '%s\n%s' "${_results:-}" "$_sacct_results" | sort -u)"
        fi
    fi

    [[ -n "${_results:-}" ]] && printf '%s\n' "$_results"
}

# Get the set of job IDs that this scope allows.
# Prints job IDs one per line.
# Usage: _get_scoped_jobs <scope> <project_dir>
_get_scoped_jobs() {
    local scope="$1" project_dir="$2"

    case "$scope" in
        session)
            _query_chaperon_jobs "chaperon:sid=${_CHAPERON_SESSION_ID}[,.]"
            ;;
        project)
            local proj_hash
            proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"
            _query_chaperon_jobs "chaperon:.*proj=${proj_hash}"
            ;;
        user|none)
            # Both "user" and "none" return ALL jobs of the current user
            local _real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
            local _real_sacct="${REAL_SACCT:-/usr/bin/sacct}"
            local _user_jobs
            local _urc=0
            _user_jobs="$(timeout 10 "$_real_squeue" --me -h -o "%i")" || _urc=$?
            if (( _urc != 0 )); then
                _sandbox_warn "could not list jobs from Slurm (squeue exit $_urc); refusing to treat this as an empty scope."
                return "$_urc"
            fi
            # sacct fallback for completed jobs
            if [[ -x "$_real_sacct" ]]; then
                local _sacct_jobs
                _sacct_jobs="$(timeout 10 "$_real_sacct" -u "$(id -un)" \
                    -n -o "JobID%20" -X --starttime=now-7days 2>/dev/null \
                    | awk '{print $1}')" || true
                [[ -n "$_sacct_jobs" ]] && _user_jobs="$(printf '%s\n%s' "${_user_jobs:-}" "$_sacct_jobs" | sort -u)"
            fi
            [[ -n "${_user_jobs:-}" ]] && printf '%s\n' "$_user_jobs"
            ;;
        *)
            _sandbox_warn "unknown SLURM_SCOPE value: '$scope'. Valid values: session, project, user, none"
            return 1
            ;;
    esac
}

# ── Query a job's comment (squeue → sacct fallback) ──────────────
# squeue only shows pending/running jobs. For recently completed jobs,
# fall back to sacct (which queries the persistent accounting database).
# Returns the comment string, or empty if the job is not found.
_get_job_comment() {
    local base_id="$1"
    local _real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
    local _real_sacct="${REAL_SACCT:-/usr/bin/sacct}"
    local comment

    # Try squeue first (fast, no database dependency).  "Invalid job id"
    # means the job is gone (fall through to sacct); any other failure
    # (timeout, controller unreachable) is a lookup ERROR (return 2) so
    # callers can tell it apart from "job not found".
    local _sq_err _sq_rc=0
    _sq_err="$(mktemp)" || return 2
    comment="$(timeout 10 "$_real_squeue" -j "$base_id" --me -h -o "%k" 2>"$_sq_err")" || _sq_rc=$?
    if [[ -n "$comment" ]]; then
        rm -f "$_sq_err"
        printf '%s' "$comment"
        return 0
    fi
    if (( _sq_rc != 0 )) && ! grep -qi "invalid job id" "$_sq_err"; then
        rm -f "$_sq_err"
        return 2
    fi
    rm -f "$_sq_err"

    # Fall back to sacct (persistent, survives job completion)
    if [[ -x "$_real_sacct" ]]; then
        comment="$(timeout 10 "$_real_sacct" -j "$base_id" -u "$(id -un)" \
            -n -o "Comment%200" -X --starttime=now-7days 2>/dev/null \
            | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
            | head -1)" || true
        if [[ -n "$comment" ]]; then
            printf '%s' "$comment"
            return 0
        fi
    fi

    return 1
}

# ── Validate that a single job ID is in scope ────────────────────
# Uses a targeted squeue query (with sacct fallback) instead of
# fetching all scoped jobs.
# Shared by scontrol, sstat, and any handler that needs per-job validation.
_validate_job_in_scope() {
    local job_id="$1" scope="$2" project_dir="$3"

    local base_id="${job_id%%_*}"
    if [[ ! "$base_id" =~ ^[0-9]+$ ]]; then
        _sandbox_warn "'$job_id' is not a valid job ID."
        return 1
    fi

    # Query the job's comment (squeue first, sacct fallback)
    local comment
    local _crc=0
    comment="$(_get_job_comment "$base_id")" || _crc=$?
    if (( _crc == 2 )); then
        _sandbox_warn "could not query Slurm for job $job_id (controller unreachable or timed out); try again."
        return 1
    fi

    if [[ -z "$comment" ]]; then
        _sandbox_warn "job $job_id not found in queue or not owned by you."
        return 1
    fi

    # Check if the comment matches the scope.
    # Strip :END marker, then match only in the tag prefix (before ,user=)
    # to prevent injection via crafted user comments. Require delimiter
    # after session ID to prevent prefix collisions (sid=123.100 vs
    # sid=123.1000000).
    local match=false
    local stripped="${comment%:END}"
    local tag_prefix="${stripped%%,user=*}"
    case "$scope" in
        session)
            [[ "$tag_prefix" == "chaperon:sid=${_CHAPERON_SESSION_ID},"* || \
               "$tag_prefix" == "chaperon:sid=${_CHAPERON_SESSION_ID}" ]] && match=true
            ;;
        project)
            local proj_hash
            proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"
            [[ "$tag_prefix" == *"proj=${proj_hash}"* ]] && match=true
            ;;
        user)
            # "user" allows any job owned by this user (squeue --me already filters by uid)
            match=true
            ;;
        none)
            # No scope restriction
            match=true
            ;;
    esac

    if ! "$match"; then
        _sandbox_deny "job $job_id was not submitted by this $scope — cannot modify."
        return 1
    fi
    return 0
}

# ── Strip chaperon tags from Slurm output ──────────────────────────
#
# Pipe Slurm command output through this to replace chaperon tags with
# the user's original comment (or empty string if none was set).
#
# Tag format: chaperon:sid=...,proj=...[,user=<percent-encoded>]:END
# The :END marker is an unambiguous boundary because colons are
# percent-encoded (%3A) in the user value, so ":END" cannot appear
# inside it.  The user= value also has commas (%2C) and equals (%3D)
# percent-encoded.  We decode these after extracting.
#
# Usage: "$real_squeue" ... | _strip_chaperon_tags
_strip_chaperon_tags() {
    # Step 1: Replace full tag with just the user comment value (or empty).
    #   - With user comment:  chaperon:sid=X,proj=Y,user=VALUE:END → VALUE
    #   - Without:            chaperon:sid=X,proj=Y:END             → (empty)
    #   The :END marker provides an unambiguous boundary regardless of
    #   output format (tabular, JSON, YAML, scontrol key=value).
    # Step 2: Decode the three percent-encoded characters.
    sed -E 's/chaperon:sid=[^,]*,proj=[^,]*(,user=([^:]*))?\:END/\2/g' \
    | sed \
        -e 's/%2C/,/g' \
        -e 's/%3A/:/g' \
        -e 's/%3D/=/g'
}

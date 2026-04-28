#! /bin/bash --
# chaperon/handlers/squeue.sh — Handle squeue requests from sandbox
#
# Filters squeue output to only show jobs within scope (project by default).
# Uses the same --comment tag set by the sbatch handler for scoping.
#
# Scope levels (configured via SLURM_SCOPE in sandbox.conf):
#   "project"  — jobs from any sandbox session with same project dir (default)
#   "session"  — only jobs submitted by THIS sandbox session
#   "user"     — all jobs of the current user
#   "none"     — no scope restriction

source "$(dirname "${BASH_SOURCE[0]}")/_handler_lib.sh"

# ── Allowed squeue flags ─────────────────────────────────────────
_SQUEUE_ALLOWED_FLAGS=" \
  -h --noheader \
  -l --long \
  -o --format \
  -O --Format \
  -S --sort \
  -t --states \
  -p --partition \
  -n --name \
  -j --jobs \
  -w --nodelist \
  --start \
  --array \
  -r --array-unique \
  -v --verbose \
  -Q --quiet \
  --help \
  --usage \
  --version \
  --json \
  --yaml \
"

_SQUEUE_VALUE_FLAGS=" \
  -o --format \
  -O --Format \
  -S --sort \
  -t --states \
  -p --partition \
  -n --name \
  -j --jobs \
  -w --nodelist \
"

_is_squeue_allowed() {
    local base="${1%%=*}"
    [[ "$_SQUEUE_ALLOWED_FLAGS" == *" $base "* ]]
}

_is_squeue_value_flag() {
    [[ "$_SQUEUE_VALUE_FLAGS" == *" $1 "* ]]
}

handle_squeue() {
    local project_dir="$1"
    local sandbox_exec="$2"

    local real_squeue="${REAL_SQUEUE:-/usr/bin/squeue}"
    if [[ ! -x "$real_squeue" ]]; then
        _sandbox_warn "squeue binary not found at $real_squeue — is Slurm installed?"
        return 1
    fi

    local scope="${SLURM_SCOPE:-project}"

    # Parse and validate arguments.
    # Track whether the user explicitly passed -j/--jobs so we don't
    # inject a duplicate -j (Slurm chokes on duplicate -j flags).
    local validated_flags=()
    local user_job_ids=""
    local i=0
    while (( i < ${#REQ_ARGS[@]} )); do
        local arg="${REQ_ARGS[$i]}"
        case "$arg" in
            # Silently accept scope-widening flags — the sandbox already
            # scopes output, so these are no-ops.  Skip any attached value.
            -u|--user|--account)
                # These take a value argument — skip it
                if (( i + 1 < ${#REQ_ARGS[@]} )) && [[ "${REQ_ARGS[$((i+1))]}" != -* ]]; then
                    (( i++ )) || true
                fi
                ;;
            --user=*|--account=*|--me)
                # Self-contained — just skip
                ;;
            # Capture -j/--jobs value separately to avoid duplicate -j
            -j|--jobs)
                if (( i + 1 < ${#REQ_ARGS[@]} )); then
                    (( i++ )) || true
                    user_job_ids="${REQ_ARGS[$i]}"
                fi
                ;;
            --jobs=*)
                user_job_ids="${arg#--jobs=}"
                ;;
            --*=*)
                if _is_squeue_allowed "$arg"; then
                    validated_flags+=("$arg")
                else
                    _sandbox_warn "squeue flag '${arg%%=*}' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            -*)
                if _is_squeue_allowed "$arg"; then
                    validated_flags+=("$arg")
                    if _is_squeue_value_flag "$arg" && (( i + 1 < ${#REQ_ARGS[@]} )); then
                        (( i++ )) || true
                        validated_flags+=("${REQ_ARGS[$i]}")
                    fi
                else
                    _sandbox_warn "squeue flag '$arg' is not recognized. Only whitelisted flags are allowed inside the sandbox."
                    return 1
                fi
                ;;
            *)
                _sandbox_warn "unexpected squeue argument: '$arg'"
                return 1
                ;;
        esac
        (( i++ )) || true
    done

    # Handle --help/--version/--usage
    for f in "${validated_flags[@]}"; do
        case "$f" in --help|--usage|--version)
            local rc=0
            "$real_squeue" "${validated_flags[@]}" || rc=$?
            return "$rc"
            ;;
        esac
    done

    # For "user" and "none" scopes, just show all user jobs directly
    if [[ "$scope" == "user" || "$scope" == "none" ]]; then
        local rc=0
        local job_args=()
        [[ -n "$user_job_ids" ]] && job_args=(-j "$user_job_ids")
        "$real_squeue" --me "${job_args[@]}" "${validated_flags[@]}" | _strip_chaperon_tags || rc=$?
        return "$rc"
    fi

    # For session/project scopes, filter by chaperon tag.
    # If the user explicitly requested specific job IDs (-j), validate
    # each one against the scope instead of injecting a scoped job list.
    if [[ -n "$user_job_ids" ]]; then
        # User asked for specific jobs — validate each is in scope
        local scoped_job_ids
        scoped_job_ids="$(_get_scoped_jobs "$scope" "$project_dir")"

        # Check each requested job against scoped set
        local requested_ids validated_ids=""
        IFS=',' read -ra requested_ids <<< "$user_job_ids"
        for _req_id in "${requested_ids[@]}"; do
            local _base_id="${_req_id%%_*}"  # strip array suffix
            if echo "$scoped_job_ids" | grep -qE "^${_base_id}(_|$)"; then
                [[ -n "$validated_ids" ]] && validated_ids+=","
                validated_ids+="$_req_id"
            fi
        done

        if [[ -z "$validated_ids" ]]; then
            # None of the requested jobs are in scope
            return 0
        fi

        local rc=0
        "$real_squeue" --me -j "$validated_ids" "${validated_flags[@]}" | _strip_chaperon_tags || rc=$?
        return "$rc"
    fi

    # No explicit -j: show all jobs in scope.
    #
    # Instead of collecting scoped job IDs and passing them via -j (which
    # hits ARG_MAX with many jobs and costs an extra squeue call), we make
    # a SINGLE squeue --me call with the comment field injected into the
    # output, filter lines by the chaperon scope tag, then strip the
    # injected comment before returning.  The chaperon tag format
    # (chaperon:sid=...,proj=...:END) is designed for exactly this:
    # greppable, strippable, and injection-safe via percent-encoding.

    # Build scope-matching pattern (same patterns used by _query_chaperon_jobs)
    local scope_pattern
    case "$scope" in
        session)
            scope_pattern="chaperon:sid=${_CHAPERON_SESSION_ID}[,.]"
            ;;
        project)
            local proj_hash
            proj_hash="$(printf '%s' "$project_dir" | md5sum | cut -c1-12)"
            scope_pattern="chaperon:.*proj=${proj_hash}"
            ;;
    esac

    # Detect output mode and format type from validated flags
    local _out_json=false _out_yaml=false
    local _fmt_type="default"  # default | long | custom_o | custom_O
    local _fmt_idx=-1
    for ((_i=0; _i<${#validated_flags[@]}; _i++)); do
        case "${validated_flags[$_i]}" in
            --json)              _out_json=true ;;
            --yaml)              _out_yaml=true ;;
            -l|--long)           _fmt_type="long" ;;
            -o|--format)         _fmt_type="custom_o"; _fmt_idx=$_i ;;
            --format=*)          _fmt_type="custom_o"; _fmt_idx=$_i ;;
            -O|--Format)         _fmt_type="custom_O"; _fmt_idx=$_i ;;
            --Format=*)          _fmt_type="custom_O"; _fmt_idx=$_i ;;
        esac
    done

    local rc=0

    if $_out_json && command -v jq >/dev/null 2>&1; then
        # JSON: comment is already in the output — filter with jq.
        "$real_squeue" --me "${validated_flags[@]}" \
            | jq --arg pat "$scope_pattern" \
                '.jobs |= map(select(.comment // "" | test($pat)))' \
            | _strip_chaperon_tags || rc=$?

    elif [[ "$_fmt_type" != "custom_O" ]] && ! $_out_yaml; then
        # Tabular output (-o based): inject comment field at the end of
        # the format string, separated by \x1f (Unit Separator).  This
        # byte won't appear in normal squeue output and gives awk an
        # unambiguous split point for filtering and stripping.
        local _sep=$'\x1f'
        local _modified_flags=("${validated_flags[@]}")

        # Detect -h/--noheader so the awk filter knows whether the first
        # output line is a header (pass-through) or already a data row
        # (must be scope-filtered).  Pre-fix, awk used a "first column
        # starts with a digit" heuristic which leaked every data row when
        # the user-supplied -o format put a non-numeric column first
        # (e.g. -o "%j %i" — job name first).
        local _noheader=0
        for _f in "${validated_flags[@]}"; do
            [[ "$_f" == "-h" || "$_f" == "--noheader" ]] && _noheader=1
        done

        case "$_fmt_type" in
            default)
                # Replace default with an explicit format + comment.
                # Widths approximate the common Slurm default; the exact
                # site default (slurm.conf/SQUEUE_FORMAT) may differ in
                # column widths but the data is identical.
                _modified_flags+=(-o "%.18i %.9P %.8j %.8u %.2t %.10M %.6D %R${_sep}%.400k")
                ;;
            long)
                # Remove -l, replace with the long-format equivalent + comment
                local _new=()
                for _f in "${_modified_flags[@]}"; do
                    [[ "$_f" == "-l" || "$_f" == "--long" ]] && continue
                    _new+=("$_f")
                done
                _modified_flags=("${_new[@]}")
                _modified_flags+=(-o "%.18i %.9P %.8j %.8u %.8T %.10M %.10l %.6D %R${_sep}%.400k")
                ;;
            custom_o)
                # Append separator + comment to the user's format string.
                # This preserves their layout exactly.
                if [[ "${validated_flags[$_fmt_idx]}" == --format=* ]]; then
                    local _user_fmt="${validated_flags[$_fmt_idx]#--format=}"
                    _modified_flags[$_fmt_idx]="--format=${_user_fmt}${_sep}%.400k"
                else
                    # -o FORMAT or --format FORMAT (next element is the value)
                    local _val_idx=$((_fmt_idx + 1))
                    _modified_flags[$_val_idx]="${validated_flags[$_val_idx]}${_sep}%.400k"
                fi
                ;;
        esac

        # Single squeue call → scope filter → strip chaperon tags.
        "$real_squeue" --me "${_modified_flags[@]}" \
            | _squeue_filter_scope "$scope_pattern" "$_noheader" \
            | _strip_chaperon_tags || rc=$?

    else
        # -O/--Format or YAML: separator injection is not feasible.
        # Fall back to batched -j calls (two squeue calls, but these
        # format modes are rare).
        local scoped_job_ids
        scoped_job_ids="$(_get_scoped_jobs "$scope" "$project_dir")"
        [[ -z "$scoped_job_ids" ]] && return 0
        _squeue_batched "$real_squeue" "$scoped_job_ids" \
            "${validated_flags[@]}" \
            | _strip_chaperon_tags || rc=$?
    fi

    return "$rc"
}

# Filter chaperon-tagged squeue tabular output by scope pattern.
#
# The handler injects the chaperon comment field after a \x1f Unit-Separator
# byte at the end of every line, then this filter splits on it: left side is
# what the user sees, right side is the comment we match against. Pre-fix,
# this used a "first column starts with a digit" heuristic to discriminate
# header lines from data rows — which leaked every data row when the user-
# supplied -o format put a non-numeric column first (e.g. "%j %i").
#
# stdin:  squeue output with \x1f-separated comment field
# stdout: lines with comment trimmed; data rows filtered by scope pattern
#         (header line, if expected, passes through unfiltered)
# Args:   $1 = scope pattern (awk regex)
#         $2 = noheader flag — "1" if -h/--noheader, else "0"
_squeue_filter_scope() {
    local pat="$1" noheader="$2"
    local sep=$'\x1f'
    awk -v pat="$pat" -v sep="$sep" -v noheader="$noheader" '
        BEGIN { skip_header = (noheader == "0") ? 1 : 0 }
        {
            p = index($0, sep)
            if (p == 0) { print; next }
            display = substr($0, 1, p - 1)
            comment = substr($0, p + 1)
            if (skip_header) { print display; skip_header = 0; next }
            if (comment ~ pat) print display
        }
    '
}

# Run squeue with -j in batches to stay within ARG_MAX.
# Usage: _squeue_batched <real_squeue> <scoped_ids_newline_sep> [flags...]
_squeue_batched() {
    local _real_sq="$1" _scoped_ids="$2"
    shift 2

    local _job_csv
    _job_csv="$(printf '%s\n' "$_scoped_ids" | paste -sd,)"

    # Conservative per-argument limit (well under typical 2 MB ARG_MAX)
    local _max_len=100000
    if (( ${#_job_csv} <= _max_len )); then
        "$_real_sq" --me -j "$_job_csv" "$@"
        return $?
    fi

    # Check whether user already suppressed the header
    local _noheader=false
    for _a in "$@"; do
        [[ "$_a" == "-h" || "$_a" == "--noheader" ]] && _noheader=true
    done

    local _first=true _batch=""
    while IFS= read -r _id; do
        [[ -z "$_id" ]] && continue
        if [[ -n "$_batch" ]] && (( ${#_batch} + ${#_id} + 1 > _max_len )); then
            # Flush current batch
            if $_first; then
                "$_real_sq" --me -j "$_batch" "$@"
                _first=false
            elif $_noheader; then
                "$_real_sq" --me -j "$_batch" "$@"
            else
                "$_real_sq" --me -j "$_batch" -h "$@"
            fi
            _batch="$_id"
        else
            [[ -n "$_batch" ]] && _batch+=","
            _batch+="$_id"
        fi
    done <<< "$_scoped_ids"

    # Flush last batch
    if [[ -n "$_batch" ]]; then
        if $_first; then
            "$_real_sq" --me -j "$_batch" "$@"
        elif $_noheader; then
            "$_real_sq" --me -j "$_batch" "$@"
        else
            "$_real_sq" --me -j "$_batch" -h "$@"
        fi
    fi
}

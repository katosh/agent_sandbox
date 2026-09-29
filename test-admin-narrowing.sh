#!/usr/bin/env bash
# test-admin-narrowing.sh — Unit tests for the narrowing-only admin/user
# merge of ALLOWED_PROJECT_PARENTS and the fail-closed admin-config
# error path.
#
# Sources sandbox-lib.sh with _SANDBOX_LIB_NO_INIT=1 so all helper
# functions are loaded without running the configuration phases. Tests
# then invoke the merge logic directly with prepared admin/user state
# and assert the effective list, exit codes, and stderr messages.
#
# Why a separate file rather than test-admin.sh? The existing
# test-admin.sh requires a real admin install at
# /app/lib/agent-sandbox/sandbox.conf and tests end-to-end via
# sandbox-exec.sh. Validating the narrowing-merge function with a
# variety of admin configurations would require root access to write
# alternative admin configs, which the test harness cannot do. The
# unit-test approach here exercises the same code with deterministic
# inputs and runs anywhere bash is available.
#
# Usage: bash test-admin-narrowing.sh [--verbose]

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$SCRIPT_DIR/sandbox-lib.sh"

VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

PASS=0; FAIL=0
pass() { ((PASS++)); echo "  ✓ $1"; }
fail() { ((FAIL++)); echo "  ✗ $1"; [[ "$VERBOSE" == true && -n "${2:-}" ]] && echo "    $2"; }

# Run a snippet in a fresh subprocess that sources sandbox-lib.sh in
# function-only mode. Captures combined stdout+stderr and exit code in
# OUT and RC respectively. The subprocess gets an isolated $HOME under
# /tmp to avoid touching the real user data dir during template-deploy.
run_isolated() {
    local _snippet="$1"
    local _tmp_home
    _tmp_home="$(mktemp -d)"
    OUT="$(HOME="$_tmp_home" _SANDBOX_LIB_NO_INIT=1 bash -c '
        set -uo pipefail
        source "'"$LIB"'"
        '"$_snippet"'
    ' 2>&1)"
    RC=$?
    rm -rf "$_tmp_home"
}

# Run a snippet that sources sandbox-lib.sh in FULL mode (no test
# seam) with a synthesized admin config at $tmpdir/admin/sandbox.conf.
# Used for fail-closed tests that exercise the validation in Phase 1.
# The lib's _ADMIN_DIR is hardcoded to /app/lib/agent-sandbox so we
# instead drive Phase 1 manually after sourcing in function-only mode.
run_admin_phase1() {
    local _admin_content="$1"
    local _user_content="${2:-}"
    local _tmp_home _admin _user
    _tmp_home="$(mktemp -d)"
    _admin="$_tmp_home/admin.conf"
    _user="$_tmp_home/user.conf"
    printf '%s' "$_admin_content" > "$_admin"
    printf '%s' "$_user_content"  > "$_user"
    OUT="$(HOME="$_tmp_home" _SANDBOX_LIB_NO_INIT=1 bash -c '
        set -uo pipefail
        source "'"$LIB"'"
        # Drive Phase 1 against the synthesized admin config exactly as
        # the production code path does, so validation and snapshot run.
        _ADMIN_CONF="'"$_admin"'"
        _USER_CONF="'"$_user"'"
        unset ALLOWED_PROJECT_PARENTS
        _source_trusted_config "$_ADMIN_CONF"
        if declare -p ALLOWED_PROJECT_PARENTS &>/dev/null; then
            _admin_set_app=true
            _validate_admin_allowed_project_parents
        else
            _admin_set_app=false
            ALLOWED_PROJECT_PARENTS=("/fh/fast" "/fh/scratch" "$HOME")
        fi
        _snapshot_admin_config
        # Drive the rest of the merge manually for the snippet to
        # consume the resulting state.
        _load_untrusted_config "$_USER_CONF" "User config"
        _enforce_admin_policy "User config"
        # Echo the effective list for the test to assert on.
        printf "EFFECTIVE: %s\n" "${ALLOWED_PROJECT_PARENTS[*]:-(empty)}"
    ' 2>&1)"
    RC=$?
    rm -rf "$_tmp_home"
}

echo "╔═══════════════════════════════════════════════╗"
echo "║  ALLOWED_PROJECT_PARENTS Narrowing Tests      ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# ──────────────────────────────────────────────────────────────────
#  (a) Default admin (missing file) + user request → admissible
# ──────────────────────────────────────────────────────────────────
echo "(a) Missing admin config → narrowing default '/'"

# When admin config is missing entirely, _ADMIN_CONF is empty and
# Phase 1 is skipped. _ADMIN_ALLOWED_PROJECT_PARENTS is never
# populated. Simulate the effective state directly: admin baseline is
# the narrowing default ("/") and user requests an arbitrary path.
run_isolated '
    _ADMIN_ALLOWED_PROJECT_PARENTS=("/")
    _user_app=("/home/dotto/nexus" "/var/tmp/whatever")
    _narrow_allowed_project_parents _user_app "User config"
    printf "EFFECTIVE: %s\n" "${ALLOWED_PROJECT_PARENTS[*]}"
'
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -q "EFFECTIVE: /home/dotto/nexus /var/tmp/whatever"; then
    pass "(a) all user paths admissible when admin baseline is '/'"
else
    fail "(a) user paths rejected against '/' baseline" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  (b) Admin narrows + user request inside the narrowing → admissible
# ──────────────────────────────────────────────────────────────────
echo "(b) Admin narrows; user inside narrowing → admissible"
run_isolated '
    _ADMIN_ALLOWED_PROJECT_PARENTS=("/home/dotto")
    _user_app=("/home/dotto/nexus")
    _narrow_allowed_project_parents _user_app "User config"
    printf "EFFECTIVE: %s\n" "${ALLOWED_PROJECT_PARENTS[*]}"
'
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -q "EFFECTIVE: /home/dotto/nexus$"; then
    pass "(b) user path under admin narrowing is kept"
else
    fail "(b) user path rejected despite being under admin narrowing" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  (c) Admin narrows + user request outside → rejected; effective empty
# ──────────────────────────────────────────────────────────────────
echo "(c) Admin narrows; user outside narrowing → rejected"
run_isolated '
    _ADMIN_ALLOWED_PROJECT_PARENTS=("/home/dotto")
    _user_app=("/tmp/foo")
    _narrow_allowed_project_parents _user_app "User config"
    printf "EFFECTIVE: %s\n" "${ALLOWED_PROJECT_PARENTS[*]:-(empty)}"
'
if [[ $RC -eq 0 ]] \
    && echo "$OUT" | grep -qE "WARNING:.*ALLOWED_PROJECT_PARENTS entry .*/tmp/foo.*not under any admin-allowed parent" \
    && echo "$OUT" | grep -q "EFFECTIVE: (empty)"; then
    pass "(c) user path outside admin tree rejected with warning, effective list empty"
else
    fail "(c) rejection or empty-list signal missing" "rc=$RC out=$OUT"
fi

# Now test the empty-list refuses-to-start path via _enforce_admin_policy.
# We need the full admin/user policy machinery to run, so use run_admin_phase1.
echo "(c2) Empty effective list → sandbox refuses to start"
run_admin_phase1 'ALLOWED_PROJECT_PARENTS=("/home/dotto")' 'ALLOWED_PROJECT_PARENTS=("/tmp/foo")'
if [[ $RC -ne 0 ]] \
    && echo "$OUT" | grep -qE "Error:.*ALLOWED_PROJECT_PARENTS is empty after admin/user merge"; then
    pass "(c2) empty effective list triggers exit non-zero with clear error"
else
    fail "(c2) empty effective list did not refuse startup" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  (d) Admin narrows + user request via symlink that escapes → rejected
# ──────────────────────────────────────────────────────────────────
echo "(d) Symlink escape from admin narrowing → rejected"
# Create a real symlink whose canonical resolution lands outside admin's
# tree. Admin allows /home/dotto. We make /home/dotto/escape -> /tmp.
# (Actually we use a tmp scratch dir as 'admin' to avoid polluting
# /home/dotto; the test is structurally identical.)
_d_tmp="$(mktemp -d)"
mkdir -p "$_d_tmp/admin_tree" "$_d_tmp/outside"
ln -s "$_d_tmp/outside" "$_d_tmp/admin_tree/escape"
# Admin tree: $_d_tmp/admin_tree. User requests $_d_tmp/admin_tree/escape
# whose realpath is $_d_tmp/outside (escapes admin tree).
run_isolated "
    _ADMIN_ALLOWED_PROJECT_PARENTS=(\"$_d_tmp/admin_tree\")
    _user_app=(\"$_d_tmp/admin_tree/escape\")
    _narrow_allowed_project_parents _user_app \"User config\"
    printf \"EFFECTIVE: %s\n\" \"\${ALLOWED_PROJECT_PARENTS[*]:-(empty)}\"
"
if [[ $RC -eq 0 ]] \
    && echo "$OUT" | grep -qE "WARNING:.*resolves to .*outside.*not under any admin-allowed parent" \
    && echo "$OUT" | grep -q "EFFECTIVE: (empty)"; then
    pass "(d) symlink escape rejected with resolves-to message"
else
    fail "(d) symlink escape was accepted or message wrong" "rc=$RC out=$OUT"
fi
rm -rf "$_d_tmp"

# ──────────────────────────────────────────────────────────────────
#  (e) /foo vs /foobar boundary → rejected (string-prefix is insufficient)
# ──────────────────────────────────────────────────────────────────
echo "(e) /foo vs /foobar path-component boundary → rejected"
run_isolated '
    _ADMIN_ALLOWED_PROJECT_PARENTS=("/foo")
    _user_app=("/foobar")
    _narrow_allowed_project_parents _user_app "User config"
    printf "EFFECTIVE: %s\n" "${ALLOWED_PROJECT_PARENTS[*]:-(empty)}"
'
if [[ $RC -eq 0 ]] \
    && echo "$OUT" | grep -qE "WARNING:.*ALLOWED_PROJECT_PARENTS entry .*/foobar.*not under any admin-allowed parent" \
    && echo "$OUT" | grep -q "EFFECTIVE: (empty)"; then
    pass "(e) /foobar correctly rejected as not-a-subdir of /foo"
else
    fail "(e) string-prefix match accepted /foobar under /foo" "rc=$RC out=$OUT"
fi

# Sanity counter-check: /foo/bar IS admissible under /foo.
echo "(e2) /foo/bar under /foo → admissible (counter-check)"
run_isolated '
    _ADMIN_ALLOWED_PROJECT_PARENTS=("/foo")
    _user_app=("/foo/bar")
    _narrow_allowed_project_parents _user_app "User config"
    printf "EFFECTIVE: %s\n" "${ALLOWED_PROJECT_PARENTS[*]:-(empty)}"
'
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -q "EFFECTIVE: /foo/bar$"; then
    pass "(e2) /foo/bar correctly admitted as subdir of /foo"
else
    fail "(e2) /foo/bar rejected despite being a true subdir" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  (f) Admin config malformed → fail-closed (no fall-through)
# ──────────────────────────────────────────────────────────────────
echo "(f1) Admin sets ALLOWED_PROJECT_PARENTS as scalar → refuse to start"
run_admin_phase1 'ALLOWED_PROJECT_PARENTS="not_an_array"' ''
if [[ $RC -ne 0 ]] \
    && echo "$OUT" | grep -qE "Error: Admin config .*: ALLOWED_PROJECT_PARENTS must be an indexed array" \
    && ! echo "$OUT" | grep -q "EFFECTIVE:"; then
    pass "(f1) scalar ALLOWED_PROJECT_PARENTS aborts startup, no fall-through"
else
    fail "(f1) scalar value did not fail-closed" "rc=$RC out=$OUT"
fi

echo "(f2) Admin entry is a relative path → refuse to start"
run_admin_phase1 'ALLOWED_PROJECT_PARENTS=("relative/path")' ''
if [[ $RC -ne 0 ]] \
    && echo "$OUT" | grep -qE "Error: Admin config .*: ALLOWED_PROJECT_PARENTS entry must be an absolute path" \
    && ! echo "$OUT" | grep -q "EFFECTIVE:"; then
    pass "(f2) non-absolute admin entry aborts startup"
else
    fail "(f2) non-absolute entry did not fail-closed" "rc=$RC out=$OUT"
fi

echo "(f3) Admin syntax error → refuse to start"
# A truly malformed bash file. Note: `bash -n` has a quirk where some
# parser errors (e.g. unbalanced `(`) only print a diagnostic without
# returning non-zero. Use a `if foo` style that bash -n unambiguously
# rejects with rc=2 ("syntax error: unexpected end of file").
run_admin_phase1 $'if foo\n' ''
if [[ $RC -ne 0 ]] \
    && echo "$OUT" | grep -qE "Error: Syntax error in" \
    && ! echo "$OUT" | grep -q "EFFECTIVE:"; then
    pass "(f3) syntax error in admin config aborts startup"
else
    fail "(f3) admin syntax error did not fail-closed" "rc=$RC out=$OUT"
fi

echo "(f3b) Admin runtime error during source → refuse to start"
# Even if bash -n passes, a runtime error during source aborts under
# set -e. This guards against admins shipping configs that look valid
# at parse-time but fail at evaluation (e.g. unset-var with set -u).
run_admin_phase1 'echo "deliberate" >&2; false' ''
if [[ $RC -ne 0 ]]; then
    pass "(f3b) runtime error during admin source aborts startup"
else
    fail "(f3b) runtime error in admin config did not abort" "rc=$RC out=$OUT"
fi

echo "(f4) Admin entry contains command substitution → refuse to start"
# Use single-quotes inside the admin config so the dollar is literal and
# the validator catches it via regex (defense in depth even though bash
# expands most cases at source-time).
_f4_admin=$'ALLOWED_PROJECT_PARENTS=(\'$(echo /home/dotto)\')'
run_admin_phase1 "$_f4_admin" ''
if [[ $RC -ne 0 ]] \
    && echo "$OUT" | grep -qE "Error: Admin config .*: ALLOWED_PROJECT_PARENTS contains command substitution"; then
    pass "(f4) command-substitution entry rejected"
else
    fail "(f4) command-substitution entry accepted" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  (g) Mixed user list with one rejected entry → per-entry filter
# ──────────────────────────────────────────────────────────────────
echo "(g) Mixed user list: keep admissible, reject inadmissible"
# Documented choice: per-entry filtering with WARNING (not all-or-nothing).
# Consistent with how DENIED_WRITABLE_PATHS strips offending entries with
# a warning rather than aborting.
run_admin_phase1 'ALLOWED_PROJECT_PARENTS=("/home/dotto")' \
                 'ALLOWED_PROJECT_PARENTS=("/home/dotto/nexus" "/tmp/foo")'
if [[ $RC -eq 0 ]] \
    && echo "$OUT" | grep -qE "WARNING:.*ALLOWED_PROJECT_PARENTS entry .*/tmp/foo.*not under any admin-allowed parent" \
    && echo "$OUT" | grep -qE "EFFECTIVE:.*/home/dotto/nexus" \
    && ! echo "$OUT" | grep -qE "EFFECTIVE:.*/tmp/foo"; then
    pass "(g) admissible kept, inadmissible rejected with warning, sandbox starts"
else
    fail "(g) per-entry filtering did not behave as documented" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  Bonus: admin set ("/") explicitly → all user paths admissible
# ──────────────────────────────────────────────────────────────────
echo "(h) Admin sets ('/') explicitly → no narrowing"
run_isolated '
    _ADMIN_ALLOWED_PROJECT_PARENTS=("/")
    _user_app=("/some/random/path")
    _narrow_allowed_project_parents _user_app "User config"
    printf "EFFECTIVE: %s\n" "${ALLOWED_PROJECT_PARENTS[*]:-(empty)}"
'
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -q "EFFECTIVE: /some/random/path$"; then
    pass "(h) admin '/' baseline admits any absolute path"
else
    fail "(h) admin '/' did not admit arbitrary path" "rc=$RC out=$OUT"
fi

# ══════════════════════════════════════════════════════════════════
#  Admin enforcement through the REAL layer loader
# ══════════════════════════════════════════════════════════════════
#
# run_layers drives the production functions (_select_config_files →
# _load_config_layers → optional snippet) against a scratch admin dir,
# instead of re-implementing Phase 1–3 like run_admin_phase1 does.
# HOME is faked via a `getent` shell function (sandbox-lib.sh resolves
# HOME from the passwd database, not $HOME), so the real
# ~/.config/agent-sandbox is never read or written.
#
#   $1 — admin sandbox.conf content ("" = no admin baseline)
#   $2 — user-layer content, written to $SCRATCH/alt.conf
#   $3 — "sandbox_conf" to point SANDBOX_CONF at alt.conf, else the
#        content goes to the fake ~/.config/agent-sandbox/user.conf
#        (admin) or sandbox.conf (no admin)
#   $4 — bash snippet run after the layers are loaded
#   $5 — extra env assignments (e.g. "PRIVATE_TMP=false"), optional
# Exposes SCRATCH (fake HOME is $SCRATCH/home) to $4 via the env.
run_layers() {
    local _admin_content="$1" _user_content="$2" _mode="$3" _snippet="$4" _extra_env="${5:-}"
    SCRATCH="$(mktemp -d)"
    mkdir -p "$SCRATCH/home/.config/agent-sandbox" "$SCRATCH/admin"
    [[ -n "$_admin_content" ]] && printf '%s\n' "$_admin_content" > "$SCRATCH/admin/sandbox.conf"
    local _sc=""
    if [[ "$_mode" == "sandbox_conf" ]]; then
        printf '%s\n' "$_user_content" > "$SCRATCH/alt.conf"
        _sc="$SCRATCH/alt.conf"
    elif [[ -n "$_admin_content" ]]; then
        printf '%s\n' "$_user_content" > "$SCRATCH/home/.config/agent-sandbox/user.conf"
    else
        printf '%s\n' "$_user_content" > "$SCRATCH/home/.config/agent-sandbox/sandbox.conf"
    fi
    OUT="$(env -u SANDBOX_CONF $_extra_env SCRATCH="$SCRATCH" ${_sc:+SANDBOX_CONF="$_sc"} \
        _SANDBOX_LIB_NO_INIT=1 SANDBOX_QUIET=true bash -c '
        set -uo pipefail
        getent() {
            if [[ "$1" == passwd && "$2" == "$(id -un)" ]]; then
                echo "$(id -un):x:$(id -u):$(id -g)::$SCRATCH/home:/bin/bash"
            else command getent "$@"; fi
        }
        source "'"$LIB"'"
        _select_config_files "$SCRATCH/admin"
        echo "ADMIN_CONF=${_ADMIN_CONF:-none}"
        echo "USER_CONF=${_USER_CONF}"
        _load_config_layers
        '"$_snippet"'
    ' 2>&1)"
    RC=$?
    rm -rf "$SCRATCH"
}

# ──────────────────────────────────────────────────────────────────
#  (i) SANDBOX_CONF swaps only the user layer — admin still applies (F3)
# ──────────────────────────────────────────────────────────────────
echo "(i) SANDBOX_CONF cannot bypass the admin baseline"
run_layers $'PRIVATE_TMP=true\nNETWORK_FILTER_MODE=isolated\nBLOCKED_ENV_VARS+=("ADMIN_SECRET_X")' \
           $'PRIVATE_TMP=false\nNETWORK_FILTER_MODE=open\nBLOCKED_ENV_VARS=()' \
           sandbox_conf \
           'echo "EFF PRIVATE_TMP=$PRIVATE_TMP NETWORK_FILTER_MODE=$NETWORK_FILTER_MODE BEV=${BLOCKED_ENV_VARS[*]}"'
if [[ $RC -eq 0 ]] \
    && echo "$OUT" | grep -q "ADMIN_CONF=.*/admin/sandbox.conf" \
    && echo "$OUT" | grep -q "USER_CONF=.*/alt.conf" \
    && echo "$OUT" | grep -q "EFF PRIVATE_TMP=true NETWORK_FILTER_MODE=isolated BEV=.*ADMIN_SECRET_X"; then
    pass "(i) SANDBOX_CONF replaces the user layer; admin pins still enforced"
else
    fail "(i) SANDBOX_CONF skipped or weakened the admin baseline" "rc=$RC out=$OUT"
fi

echo "(i2) SANDBOX_CONF without an admin baseline is the only config"
run_layers '' 'PRIVATE_TMP=false' sandbox_conf 'echo "EFF PRIVATE_TMP=$PRIVATE_TMP"'
if [[ $RC -eq 0 ]] && echo "$OUT" | grep -q "ADMIN_CONF=none" \
    && echo "$OUT" | grep -q "EFF PRIVATE_TMP=false"; then
    pass "(i2) no admin baseline: SANDBOX_CONF file is the effective user config"
else
    fail "(i2) SANDBOX_CONF user-only mode broken" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  (j) HOME_WRITABLE / EXTRA_WRITABLE_PATHS vs admin HOME_READONLY (F2)
# ──────────────────────────────────────────────────────────────────
echo "(j) Writable entries equal/below/above admin read-only are reverted"
run_layers 'HOME_READONLY+=(".ssh" ".config/git")' \
           $'HOME_WRITABLE+=(".ssh/" "./.ssh" ".ssh//" ".ssh/authorized_keys" ".config" "sshlink" ".cache/uv" "myproj-data")\nEXTRA_WRITABLE_PATHS+=("$HOME/.ssh/" "$HOME/./.config/git/sub" "/var/tmp/ok-extra")' \
           user \
           'printf "HW:%s\n" "${HOME_WRITABLE[@]}"; printf "EWP:%s\n" "${EXTRA_WRITABLE_PATHS[@]}"' \
           ''
_j_out="$OUT"; _j_rc=$RC
_j_ok=true
for _bad in '.ssh/' './.ssh' '.ssh//' '.ssh/authorized_keys' '.config'; do
    echo "$_j_out" | grep -qxF "HW:$_bad" && { _j_ok=false; echo "    kept bad HW: $_bad"; }
    echo "$_j_out" | grep -qF "HOME_WRITABLE entry '$_bad' overlaps admin HOME_READONLY" \
        || echo "$_j_out" | grep -qF "moved admin HOME_READONLY entry" || { _j_ok=false; echo "    no warning for $_bad"; }
done
for _good in '.cache/uv' 'myproj-data'; do
    echo "$_j_out" | grep -qxF "HW:$_good" || { _j_ok=false; echo "    dropped good HW: $_good"; }
done
echo "$_j_out" | grep -qE '^EWP:.*/\.ssh/?$' && { _j_ok=false; echo "    kept EXTRA_WRITABLE_PATHS ~/.ssh"; }
echo "$_j_out" | grep -q '^EWP:.*config/git/sub' && { _j_ok=false; echo "    kept EXTRA_WRITABLE_PATHS under .config/git"; }
echo "$_j_out" | grep -qxF 'EWP:/var/tmp/ok-extra' || { _j_ok=false; echo "    dropped unrelated EXTRA_WRITABLE_PATHS"; }
if [[ $_j_rc -eq 0 ]] && $_j_ok; then
    pass "(j) non-canonical / parent / child spellings of admin RO entries rejected; unrelated kept"
else
    fail "(j) admin HOME_READONLY escalation via path spelling" "rc=$_j_rc out=$_j_out"
fi

echo "(j2) Symlink to an admin read-only dir is rejected"
# The link must exist before the check runs, so create it in the
# snippet and re-run enforcement on a fresh HOME_WRITABLE.
run_layers 'HOME_READONLY+=(".ssh")' 'HOME_WRITABLE+=("sshlink")' user '
    mkdir -p "$HOME/.ssh"; ln -s "$HOME/.ssh" "$HOME/sshlink"
    HOME_WRITABLE=("${_ADMIN_HOME_WRITABLE[@]}" "sshlink")
    _enforce_admin_policy "Recheck"
    printf "HW:%s\n" "${HOME_WRITABLE[@]}"'
if [[ $RC -eq 0 ]] && ! echo "$OUT" | grep -qxF "HW:sshlink" \
    && echo "$OUT" | grep -qF "HOME_WRITABLE entry 'sshlink' overlaps admin HOME_READONLY entry '.ssh'"; then
    pass "(j2) symlinked alias of an admin read-only dir rejected"
else
    fail "(j2) symlink alias escaped the HOME_READONLY check" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  (k) _ENFORCED_ARRAYS drives enforcement; HIDE_FROM_SANDBOX floor (F5)
# ──────────────────────────────────────────────────────────────────
echo "(k) Every _ENFORCED_ARRAYS name restores admin entries after '=()'"
# Admin adds a sentinel to every enforced array; the user empties them
# all. Each sentinel must come back (with a warning). Iterating the
# declared list makes the list itself load-bearing: an array listed
# there but not enforced (or vice versa) fails here.
run_layers '
for _n in "${_ENFORCED_ARRAYS[@]}"; do eval "$_n+=(\"ADMIN_SENTINEL_$_n\")"; done' \
    'BLOCKED_FILES=(); BLOCKED_ENV_VARS=(); BLOCKED_ENV_PATTERNS=(); EXTRA_BLOCKED_PATHS=(); DEVICES_BLACKLIST=(); NETWORK_BLOCKLIST=(); NETWORK_BLOCKLIST_EXCEPT=(); HIDE_FROM_SANDBOX=()' \
    user '
    for _n in "${_ENFORCED_ARRAYS[@]}"; do
        declare -n _arr="$_n"
        _hit=false
        for _v in "${_arr[@]}"; do [[ "$_v" == "ADMIN_SENTINEL_$_n" ]] && _hit=true; done
        $_hit && echo "RESTORED:$_n" || echo "LOST:$_n"
        unset -n _arr
    done
    echo "COUNT:${#_ENFORCED_ARRAYS[@]}"'
_k_expected="$(echo "$OUT" | sed -n 's/^COUNT://p')"
if [[ $RC -eq 0 ]] && ! echo "$OUT" | grep -q '^LOST:' \
    && [[ -n "$_k_expected" && "$(echo "$OUT" | grep -c '^RESTORED:')" -eq "$_k_expected" ]] \
    && echo "$OUT" | grep -q "removed admin-enforced HIDE_FROM_SANDBOX entry 'ADMIN_SENTINEL_HIDE_FROM_SANDBOX' — restored"; then
    pass "(k) all $_k_expected _ENFORCED_ARRAYS restored admin entries (with warnings)"
else
    fail "(k) an enforced array lost its admin entries" "rc=$RC out=$OUT"
fi

echo "(k2) Built-in HIDE_FROM_SANDBOX defaults survive HIDE_FROM_SANDBOX=() without admin"
run_layers '' 'HIDE_FROM_SANDBOX=("MY_EXTRA_HIDE")' user '_hide_from_sandbox_names'
_k2_ok=true
for _d in SLURM_SCOPE CHAPERON_LOG_LEVEL CHAPERON_LOG_RETAIN_DAYS SANDBOX_QUIET HOME_ACCESS SANDBOX_NPROC_LIMIT SANDBOX_CONF MY_EXTRA_HIDE; do
    echo "$OUT" | grep -qx "$_d" || { _k2_ok=false; echo "    missing $_d"; }
done
if [[ $RC -eq 0 ]] && $_k2_ok; then
    pass "(k2) defaults + user additions emitted after user replaced the array"
else
    fail "(k2) built-in HIDE_FROM_SANDBOX defaults removable by user config" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  (l) Launch overrides: env beats config, admin beats env (F4)
# ──────────────────────────────────────────────────────────────────
echo "(l) Env override beats user config; admin pin beats env override"
run_layers '' 'PRIVATE_TMP=true' user '_apply_launch_overrides; echo "EFF PRIVATE_TMP=$PRIVATE_TMP"' 'PRIVATE_TMP=false'
_l1="$OUT"; _l1_rc=$RC
run_layers 'PRIVATE_TMP=true' '' user '_apply_launch_overrides; echo "EFF PRIVATE_TMP=$PRIVATE_TMP"' 'PRIVATE_TMP=false'
if [[ $_l1_rc -eq 0 && $RC -eq 0 ]] && echo "$_l1" | grep -q "EFF PRIVATE_TMP=false" \
    && echo "$OUT" | grep -q "EFF PRIVATE_TMP=true" \
    && echo "$OUT" | grep -q "Launch override (env/CLI) weakened admin-enforced PRIVATE_TMP=true"; then
    pass "(l) env override wins over config, loses to admin pin (with warning)"
else
    fail "(l) launch override precedence wrong" "no-admin: $_l1 | admin: $OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  (m) SANDBOX_ENV cannot carry settings (F1)
# ──────────────────────────────────────────────────────────────────
echo "(m) SANDBOX_ENV rejects config/launcher/hidden/blocked names"
run_layers 'NETWORK_FILTER_MODE=isolated' \
    'SANDBOX_ENV+=("NETWORK_FILTER_MODE=open" "PRIVATE_TMP=false" "HOME_ACCESS=write" "_PASSWD_SRC_FILE=/x" "SANDBOX_CONF=/x" "CHAPERON_LOG_LEVEL=debug" "GITHUB_TOKEN=t" "BAD-NAME=1" "noequals" "PATH=/opt/x:/usr/bin" "MY_TOOL_HOME=/opt/tool")' \
    user '_prepare_sandbox_env; echo "PATHV=$_SANDBOX_ENV_PATH"; printf "CHILD:%s\n" "${_SANDBOX_CHILD_ENV[@]}"; echo "EFF NFM=$NETWORK_FILTER_MODE"'
_m_ok=true
for _n in NETWORK_FILTER_MODE PRIVATE_TMP HOME_ACCESS _PASSWD_SRC_FILE SANDBOX_CONF CHAPERON_LOG_LEVEL GITHUB_TOKEN BAD-NAME; do
    echo "$OUT" | grep -q "^CHILD:$_n=" && { _m_ok=false; echo "    accepted $_n"; }
    echo "$OUT" | grep -qF "SANDBOX_ENV entry '$_n' ignored" || { _m_ok=false; echo "    no warning for $_n"; }
done
echo "$OUT" | grep -qxF "CHILD:MY_TOOL_HOME=/opt/tool" || { _m_ok=false; echo "    dropped MY_TOOL_HOME"; }
echo "$OUT" | grep -qxF "PATHV=/opt/x:/usr/bin" || { _m_ok=false; echo "    PATH not split out"; }
echo "$OUT" | grep -qxF "EFF NFM=isolated" || { _m_ok=false; echo "    NETWORK_FILTER_MODE changed"; }
if [[ $RC -eq 0 ]] && $_m_ok; then
    pass "(m) SANDBOX_ENV: settings/internal/hidden/blocked names rejected, plain vars + PATH kept"
else
    fail "(m) SANDBOX_ENV validation" "rc=$RC out=$OUT"
fi

# ──────────────────────────────────────────────────────────────────
#  Summary
# ──────────────────────────────────────────────────────────────────
echo ""
echo "Passed: $PASS · Failed: $FAIL"
[[ $FAIL -eq 0 ]]

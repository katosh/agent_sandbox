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

# ──────────────────────────────────────────────────────────────────
#  Summary
# ──────────────────────────────────────────────────────────────────
echo ""
echo "Passed: $PASS · Failed: $FAIL"
[[ $FAIL -eq 0 ]]

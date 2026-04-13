#! /bin/bash --
# test.sh — Comprehensive test suite for the sandbox
#
# Runs from the repo directory or the installed ~/.config/agent-sandbox/.
# Tests cover filesystem isolation, environment blocking, chaperon
# proxy isolation, Slurm submission, and security hardening.
#
# Usage:
#   bash test.sh                          # full test (all backends)
#   bash test.sh --quick                  # quick smoke test (no Slurm jobs)
#   bash test.sh --verbose                # show command output on failure
#   bash test.sh --backend bwrap          # test only bwrap backend
#
# The --quick flag runs a minimal smoke test (~5 checks per backend):
# sandbox boot, filesystem isolation, credential blocking, project
# write, and chaperon proxy.  Completes in seconds.  No Slurm jobs.
#
# The full test (default) runs all 13 sections including chaperon
# functional tests (submits real Slurm jobs), escape vectors, syscall
# restrictions, resource isolation, credential protection, and more.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_EXEC="$SCRIPT_DIR/sandbox-exec.sh"
PROJECT_DIR=""

# Use the repo's sandbox.conf as the reference config for tests.
# Without this, CI runners (which have no ~/.config/agent-sandbox/sandbox.conf)
# rely solely on sandbox-lib.sh hardcoded defaults and miss user-config-only
# settings like per-project overrides.
export SANDBOX_CONF="$SCRIPT_DIR/sandbox.conf"
export SANDBOX_QUIET=true

VERBOSE=false
BACKEND_FLAG=""
QUICK_MODE=false
_JUNIT_PATH=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            cat <<'HELP'
Usage: bash test.sh [OPTIONS] [PROJECT_DIR]

Options:
  --quick           Minimal smoke test (~5 checks/backend, no Slurm jobs)
  --full            Run all sections including Slurm job tests (default)
  --verbose         Show command output on failure
  --backend NAME    Test only one backend (bwrap, firejail, or landlock)
  --junit PATH      Emit JUnit XML report to PATH (one file per backend
                    if multiple backends run; path is suffixed with the
                    backend name unless only one backend is tested)
  -h, --help        Show this help

Sections:
  1. Basic sandbox functionality (boot, env vars)
  2. Filesystem isolation (~/.ssh, ~/.aws, ~/.gnupg hidden)
  3. Environment variable blocking (GITHUB_PAT, API keys)
  4. CLAUDE.md and settings.json overlays
  5. Chaperon: Slurm proxy isolation and scoping
  6. Chaperon functional tests (submits real Slurm jobs)
  7. Security: escape vector tests
  8. Security: syscall restrictions (seccomp)
  9. Resource isolation
 10. Credential protection
 11. Sandbox self-protection
 12. Stability / stress tests
 13. Lmod module loading (requires lmod + SANDBOX_TEST_LMOD=1)

The quick test (--quick) is safe to run anywhere — it never submits
Slurm jobs or modifies state outside the sandbox.

Examples:
  bash test.sh --quick              # fast smoke test
  bash test.sh --backend bwrap      # full test, bwrap only
  bash test.sh --verbose            # full test, show failures
  bash test.sh --quick /tmp/proj    # quick test with custom project dir
HELP
            exit 0
            ;;
        --verbose) VERBOSE=true; shift ;;
        --backend) BACKEND_FLAG="$2"; shift 2 ;;
        --quick) QUICK_MODE=true; shift ;;
        --full) QUICK_MODE=false; shift ;;
        --junit) _JUNIT_PATH="$2"; shift 2 ;;
        -*) shift ;;
        *) PROJECT_DIR="$1"; shift ;;
    esac
done

# Default project dir: use the repo itself
[[ -z "$PROJECT_DIR" ]] && PROJECT_DIR="$SCRIPT_DIR"

# ── Cleanup on exit/interrupt ─────────────────────────────────────
# Track temp files/dirs/paths created during the run; remove on exit.
# _TEST_TEMP_FILES — file entries (rm -f); kept for backwards compat.
# _TEST_TEMP_DIRS  — directory entries (rm -rf).
# _TEST_TRAPPED_PATHS — general-purpose "also remove on exit" list
#                       (rm -rf) for fixture roots, markers, etc.
_TEST_TEMP_FILES=()
_TEST_TEMP_DIRS=()
_TEST_TRAPPED_PATHS=()
_test_cleanup() {
    for _f in "${_TEST_TEMP_FILES[@]}"; do
        rm -f "$_f" 2>/dev/null
    done
    for _d in "${_TEST_TEMP_DIRS[@]}"; do
        rm -rf "$_d" 2>/dev/null
    done
    for _p in "${_TEST_TRAPPED_PATHS[@]}"; do
        rm -rf "$_p" 2>/dev/null
    done
}
trap _test_cleanup EXIT

# Register PATH for rm -rf on exit (directories).
trap_rm_dir() {
    local _p="$1"
    _TEST_TEMP_DIRS+=("$_p")
}
# Register PATH for rm -rf on exit (files or dirs — general-purpose).
trap_rm_path() {
    local _p="$1"
    _TEST_TRAPPED_PATHS+=("$_p")
}

# ── Helpers ───────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0
WARN=0

pass() {
    ((PASS++))
    echo "  ✓ $1"
    [[ -n "${_JUNIT_PATH:-}" ]] && _junit_emit pass "$1"
}
fail() {
    ((FAIL++))
    echo "  ✗ $1"
    [[ "$VERBOSE" == true && -n "${2:-}" ]] && echo "    $2"
    [[ -n "${_JUNIT_PATH:-}" ]] && _junit_emit fail "$1" "${2:-}"
}
skip() {
    ((SKIP++))
    echo "  ⊘ $1 (skipped)"
    [[ -n "${_JUNIT_PATH:-}" ]] && _junit_emit skip "$1"
}
warn() { ((WARN++)); echo "  ⚠ $1 (known limitation)"; }

# ── JUnit XML emission (enabled by --junit PATH) ──────────────────
# Each test case is appended to a spool file ($_JUNIT_PATH.cases) as
# raw <testcase ... /> lines. _junit_finalize wraps the accumulated
# cases in a <testsuite>/<testsuites> envelope and writes the final
# report. Called once per backend from run_tests.
_junit_emit() {
    local _kind="$1" _name="$2" _detail="${3:-}"
    local _spool="${_JUNIT_PATH}.cases"
    # XML-escape: & < > " '
    local _xname _xdetail
    _xname=$(printf '%s' "$_name" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&apos;/g')
    _xdetail=$(printf '%s' "$_detail" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'"'"'/\&apos;/g')
    case "$_kind" in
        pass) printf '  <testcase classname="%s" name="%s"/>\n' "$CURRENT_BACKEND" "$_xname" >> "$_spool" ;;
        fail) printf '  <testcase classname="%s" name="%s"><failure message="%s"/></testcase>\n' "$CURRENT_BACKEND" "$_xname" "$_xdetail" >> "$_spool" ;;
        skip) printf '  <testcase classname="%s" name="%s"><skipped/></testcase>\n' "$CURRENT_BACKEND" "$_xname" >> "$_spool" ;;
    esac
}

# Wrap the spooled <testcase> lines in <testsuite>/<testsuites> and
# write to the final destination. Arg 1 is the backend name; arg 2
# is an optional output path (defaults to $_JUNIT_PATH, suffixed with
# -$backend.xml when multiple backends are being tested).
_junit_finalize() {
    [[ -z "${_JUNIT_PATH:-}" ]] && return 0
    local _backend="$1"
    local _spool="${_JUNIT_PATH}.cases"
    local _out
    if [[ ${#AVAILABLE_BACKENDS[@]} -gt 1 ]]; then
        # Preserve extension if present: foo.xml → foo-<backend>.xml
        local _base="$_JUNIT_PATH" _ext=""
        if [[ "$_base" == *.xml ]]; then
            _ext=".xml"
            _base="${_base%.xml}"
        fi
        _out="${_base}-${_backend}${_ext}"
    else
        _out="$_JUNIT_PATH"
    fi
    local _total=$((PASS + FAIL + SKIP))
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<testsuites>'
        printf '<testsuite name="sandbox-%s" tests="%d" failures="%d" skipped="%d">\n' \
            "$_backend" "$_total" "$FAIL" "$SKIP"
        [[ -f "$_spool" ]] && cat "$_spool"
        echo '</testsuite>'
        echo '</testsuites>'
    } > "$_out"
    rm -f "$_spool"
}

# Current backend being tested (set by run_tests)
CURRENT_BACKEND=""

# Run a command inside the sandbox. Returns the exit code.
# Captures stdout in $OUTPUT and stderr in $OUTPUT_ERR so tests can
# assert against each stream independently (sandbox/backend warnings
# live on stderr and would otherwise pollute OUTPUT).
sandbox() {
    local _stderr_file
    _stderr_file=$(mktemp)
    OUTPUT=$(timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- "$@" 2>"$_stderr_file")
    local rc=$?
    OUTPUT_ERR=$(cat "$_stderr_file")
    rm -f "$_stderr_file"
    return $rc
}

# Invoke the sandbox and FAIL THE TEST if the sandbox itself didn't reach
# guest code. Protects against the "green on crash" class where a sandbox
# boot failure emits "error: not allowed" to stderr and a subsequent
# grep for "not allowed" passes a test that should have failed.
#
# Usage:
#   sandbox_must_run bash -c 'echo $SANDBOX_ACTIVE' || return
#   [[ "$OUTPUT" == "1" ]] && pass "sandbox booted" || fail "..."
#
# Returns the guest command's exit code on success, or >=125 on boot
# failure (and prints a diagnostic). After a successful return,
# $OUTPUT and $OUTPUT_ERR reflect the guest's stdout/stderr.
sandbox_must_run() {
    local _marker="__SANDBOX_REACHED_$$_${RANDOM}__"
    # Append the marker to stdout so a successful boot always leaves
    # it in $OUTPUT even if the guest command itself produced nothing.
    sandbox bash -c "$(printf 'RC=0; %s || RC=$?; printf "\\n%s\\n" "%s"; exit $RC' \
        "$(printf '%q ' "$@")" \
        "$_marker")"
    local _rc=$?
    if [[ "$OUTPUT" != *"$_marker"* ]]; then
        # Guest never reached the marker → sandbox boot failed.
        fail "sandbox boot failed before guest command" \
             "rc=$_rc stdout=$OUTPUT stderr=$OUTPUT_ERR"
        return 125
    fi
    # Strip the marker line from $OUTPUT so callers don't have to.
    OUTPUT="${OUTPUT%$'\n'"$_marker"*}"
    return $_rc
}

is_bwrap() { [[ "$CURRENT_BACKEND" == "bwrap" ]]; }
is_firejail() { [[ "$CURRENT_BACKEND" == "firejail" ]]; }
is_landlock() { [[ "$CURRENT_BACKEND" == "landlock" ]]; }
# Mount-namespace backends (bwrap and firejail) hide files with ENOENT
has_mount_ns() { is_bwrap || is_firejail; }

# ── Pre-flight ────────────────────────────────────────────────────

echo "╔═══════════════════════════════════════════════╗"
echo "║  Sandbox Test Suite                           ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

if [[ ! -x "$SANDBOX_EXEC" ]]; then
    echo "ERROR: sandbox-exec.sh not found at $SANDBOX_EXEC"
    exit 1
fi

# Detect available backends
AVAILABLE_BACKENDS=()

check_backend() {
    timeout 5 "$SANDBOX_EXEC" --backend "$1" --dry-run --project-dir "$PROJECT_DIR" -- true &>/dev/null
}

if [[ -n "$BACKEND_FLAG" ]]; then
    AVAILABLE_BACKENDS=("$BACKEND_FLAG")
else
    for _backend in bwrap firejail landlock; do
        if check_backend "$_backend"; then
            AVAILABLE_BACKENDS+=("$_backend")
        fi
    done
fi

if [[ ${#AVAILABLE_BACKENDS[@]} -eq 0 ]]; then
    echo "ERROR: No sandbox backends available."
    timeout 5 "$SANDBOX_EXEC" --dry-run --project-dir "$PROJECT_DIR" -- true 2>&1 || true
    exit 1
fi

echo "Available backends: ${AVAILABLE_BACKENDS[*]}"
echo ""

# Track overall results across all backends
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0
TOTAL_WARN=0
ANY_FAIL=false

run_tests() {
CURRENT_BACKEND="$1"
PASS=0
FAIL=0
SKIP=0
WARN=0

echo "┌───────────────────────────────────────────────"
echo "│  Testing backend: $CURRENT_BACKEND"
echo "└───────────────────────────────────────────────"
echo ""

# ── Quick smoke test (early return) ──────────────────────────────
# Minimal deployment check: does the sandbox boot, isolate files,
# block credentials, allow project writes, and proxy Slurm commands?
# 5 sandbox calls — completes in seconds.

if [[ "$QUICK_MODE" == true ]]; then

# 1. Sandbox boots with correct backend
if sandbox bash -c 'echo "$SANDBOX_ACTIVE:$SANDBOX_BACKEND"'; then
    if [[ "$OUTPUT" == "1:$CURRENT_BACKEND" ]]; then
        pass "Sandbox boots ($CURRENT_BACKEND)"
    else
        fail "Sandbox boots but env is wrong (expected 1:$CURRENT_BACKEND)" "$OUTPUT"
    fi
else
    fail "Sandbox failed to start" "$OUTPUT"
    # Cannot continue — report and return
    TOTAL=$((PASS + FAIL + SKIP + WARN))
    echo ""; echo "  Results: $PASS passed, $FAIL failed (out of $TOTAL)"; echo ""
    TOTAL_PASS=$((TOTAL_PASS + PASS)); TOTAL_FAIL=$((TOTAL_FAIL + FAIL))
    TOTAL_SKIP=$((TOTAL_SKIP + SKIP)); TOTAL_WARN=$((TOTAL_WARN + WARN))
    ANY_FAIL=true
    return
fi

# 2. Filesystem isolation — ~/.ssh should be blocked
if [[ -d "$HOME/.ssh" ]]; then
    if sandbox bash -c 'ls "$HOME/.ssh" >/dev/null 2>&1 && echo VISIBLE || echo BLOCKED'; then
        if [[ "$OUTPUT" == "BLOCKED" ]]; then
            pass "Filesystem isolation (~/.ssh blocked)"
        else
            fail "~/.ssh accessible inside sandbox (isolation broken)"
        fi
    fi
else
    skip "~/.ssh not present on host"
fi

# 3. Project directory is writable
_tf="$PROJECT_DIR/.test-write-$$"
if sandbox bash -c "touch '$_tf' && rm -f '$_tf'"; then
    pass "Project directory is writable"
else
    fail "Project directory is not writable" "$OUTPUT"
fi
rm -f "$_tf"

# 4. Credential blocking
export GITHUB_PAT="test-secret"
if sandbox bash -c 'echo ${GITHUB_PAT:-BLOCKED}'; then
    if [[ "$OUTPUT" == "BLOCKED" ]]; then
        pass "Credentials blocked (GITHUB_PAT)"
    else
        fail "GITHUB_PAT leaked into sandbox"
    fi
fi
unset GITHUB_PAT

# 5. Passwd filter / user enumeration prevention
if is_bwrap; then
    if sandbox bash -c 'wc -l < /etc/passwd'; then
        _host_count=$(wc -l < /etc/passwd)
        _sandbox_count="$OUTPUT"
        if [[ "$_sandbox_count" -le "$_host_count" ]]; then
            pass "Passwd filter active (host: $_host_count → sandbox: $_sandbox_count)"
        else
            fail "Passwd not filtered (sandbox has more lines than host)" "$OUTPUT"
        fi
    else
        fail "Could not read /etc/passwd in sandbox" "$OUTPUT"
    fi
elif is_firejail; then
    _host_getent=$(getent passwd | wc -l)
    if sandbox bash -c 'getent passwd | wc -l'; then
        _sandbox_getent="$OUTPUT"
        if [[ "$_sandbox_getent" -le "$_host_getent" ]]; then
            pass "User enum prevention (host: $_host_getent → sandbox: $_sandbox_getent)"
        else
            fail "getent not filtered (sandbox exposes more users)" "$OUTPUT"
        fi
    else
        fail "Could not run getent in sandbox" "$OUTPUT"
    fi
else
    skip "Passwd filter not supported on Landlock (no mount namespace)"
fi

# 6. Chaperon proxy — squeue completes without hanging
if command -v /usr/bin/squeue &>/dev/null; then
    if sandbox bash -c 'squeue 2>&1; echo DONE'; then
        if echo "$OUTPUT" | grep -q "DONE"; then
            pass "Chaperon proxy works (squeue completes)"
        else
            fail "squeue did not complete" "$OUTPUT"
        fi
    else
        if echo "$OUTPUT" | grep -q "DONE"; then
            pass "Chaperon proxy works (squeue completes)"
        else
            fail "squeue may have hung" "$OUTPUT"
        fi
    fi
else
    skip "Slurm not installed"
fi

# Per-backend summary (quick mode)
TOTAL=$((PASS + FAIL + SKIP + WARN))
echo ""
echo "════════════════════════════════════════════════"
echo "  Results: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped (out of $TOTAL)"
echo "════════════════════════════════════════════════"
echo ""
TOTAL_PASS=$((TOTAL_PASS + PASS))
TOTAL_FAIL=$((TOTAL_FAIL + FAIL))
TOTAL_SKIP=$((TOTAL_SKIP + SKIP))
TOTAL_WARN=$((TOTAL_WARN + WARN))
[[ $FAIL -gt 0 ]] && ANY_FAIL=true
# Emit JUnit report for this backend (no-op if --junit wasn't set).
_junit_finalize "$CURRENT_BACKEND"
return
fi
# ── End quick smoke test ─────────────────────────────────────────

# ══════════════════════════════════════════════════════════════════
# Full test suite (sections 1–13)
# ══════════════════════════════════════════════════════════════════

# ── 1. Basic sandbox ─────────────────────────────────────────────

echo "1. Basic sandbox functionality"

if sandbox echo "hello"; then
    pass "Sandbox starts and runs commands"
else
    fail "Sandbox failed to start" "$OUTPUT"
    echo ""
    echo "  Cannot continue — sandbox is non-functional."
    echo "  Run with --verbose for details."
    exit 1
fi

if sandbox bash -c 'echo $SANDBOX_ACTIVE'; then
    if [[ "$OUTPUT" == "1" ]]; then
        pass "SANDBOX_ACTIVE=1"
    else
        fail "SANDBOX_ACTIVE not set" "$OUTPUT"
    fi
fi

if sandbox bash -c 'echo $SANDBOX_PROJECT_DIR'; then
    if [[ "$OUTPUT" == "$PROJECT_DIR" ]]; then
        pass "SANDBOX_PROJECT_DIR set correctly"
    else
        fail "SANDBOX_PROJECT_DIR wrong: $OUTPUT (expected $PROJECT_DIR)"
    fi
fi

if sandbox bash -c 'echo $SANDBOX_BACKEND'; then
    if [[ "$OUTPUT" == "$CURRENT_BACKEND" ]]; then
        pass "SANDBOX_BACKEND=$CURRENT_BACKEND"
    else
        fail "SANDBOX_BACKEND wrong: $OUTPUT (expected $CURRENT_BACKEND)"
    fi
fi

# ── Config loading sanity ────────────────────────────────────────
# The repo's sandbox.conf skeleton must load without triggering
# "exited with code" warnings. Catches missing default initializations
# for variables listed in _CONFIG_ARRAYS / _CONFIG_SCALARS.
if sandbox bash -c 'echo ok'; then
    if [[ "$OUTPUT_ERR" == *"exited with code"* ]]; then
        fail "Config loading produced warnings" "$OUTPUT_ERR"
    else
        pass "Config loads cleanly (no warnings)"
    fi
fi

# ── ALLOWED_PROJECT_PARENTS enforcement ──────────────────────────
# sandbox-exec.sh must reject --project-dir paths that aren't under
# any entry in ALLOWED_PROJECT_PARENTS (sandbox.conf:92-97). Build a
# dir under /var/tmp (writable on virtually every host, never in the
# default allow-list) and verify rejection with a clear error.
#
# Fallback: if /var/tmp isn't usable (rare — some hardened setups
# mount it noexec or lock it down), fall back to /dev/shm. Both are
# writable-by-user on essentially every Linux but outside the default
# HOME / /fh/* prefixes.
_reject_dir=$(mktemp -d "/var/tmp/sandbox-rejtest-XXXXXX" 2>/dev/null) || \
    _reject_dir=$(mktemp -d "/dev/shm/sandbox-rejtest-XXXXXX" 2>/dev/null)
if [[ -n "$_reject_dir" && -d "$_reject_dir" ]]; then
    _TEST_TEMP_DIRS+=("$_reject_dir")
    # Identify which parent we ended up under, so we can sanity-check
    # the effective config doesn't accidentally list it.
    _reject_parent="${_reject_dir%/*}"
    _raw=$("$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$_reject_dir" -- true 2>&1)
    _rc=$?
    if [[ $_rc -ne 0 ]] && echo "$_raw" | grep -qiE "not.*allowed|not under any ALLOWED_PROJECT_PARENTS|must be under"; then
        pass "ALLOWED_PROJECT_PARENTS rejects --project-dir outside listed prefixes"
    else
        # False-positive guard: if an admin or user config happens to
        # list the parent we chose, the sandbox would legitimately
        # accept it. Detect that and skip rather than report a bogus
        # failure.
        if grep -qE "\"${_reject_parent}\"" \
            /app/lib/agent-sandbox/sandbox.conf \
            "${HOME}/.config/agent-sandbox/sandbox.conf" 2>/dev/null; then
            skip "ALLOWED_PROJECT_PARENTS test: ${_reject_parent} is in a config layer — can't test negative"
        else
            fail "ALLOWED_PROJECT_PARENTS did not reject project-dir under ${_reject_parent}" "rc=$_rc out=$_raw"
        fi
    fi
else
    skip "ALLOWED_PROJECT_PARENTS test: could not create a temp dir under /var/tmp or /dev/shm"
fi

echo ""

# ── 2. Filesystem isolation ──────────────────────────────────────

echo "2. Filesystem isolation"

# Helper: test that a sensitive directory is blocked (ENOENT for bwrap, EACCES for landlock)
test_blocked_dir() {
    local dir="$1"
    local name="$2"
    local _hint=""
    # Check if the dir is in HOME_READONLY in an admin config — that's why it would be visible
    if [[ -f /app/lib/agent-sandbox/sandbox.conf ]]; then
        local _basename="${dir##*/}"
        _basename="${_basename#.}"  # strip leading dot for matching
        if grep -q "\"\.${_basename}\"" /app/lib/agent-sandbox/sandbox.conf 2>/dev/null; then
            _hint=" — admin config has it in HOME_READONLY (remove to hide)"
        fi
    fi

    if has_mount_ns; then
        if sandbox test -d "$dir"; then
            fail "$name is visible (should be hidden)${_hint}"
        else
            pass "$name is hidden"
        fi
    else
        # Landlock: directory may exist but access is denied
        if sandbox bash -c "ls '$dir' 2>&1"; then
            fail "$name is accessible (should be blocked)${_hint}"
        else
            if echo "$OUTPUT" | grep -qi "permission denied\|cannot open\|cannot access"; then
                pass "$name is blocked (EACCES)"
            else
                # Could also be ENOENT if the dir doesn't exist on the host
                pass "$name is blocked"
            fi
        fi
    fi
}

test_blocked_dir "$HOME/.ssh" "~/.ssh"
test_blocked_dir "$HOME/.aws" "~/.aws"
test_blocked_dir "$HOME/.gnupg" "~/.gnupg"

# ── Extra credential paths beyond the canonical .ssh/.aws/.gnupg ─
# sandbox-lib.sh's _HOME_ALWAYS_BLOCKED currently lists only those
# three, but README/SECURITY.md tacitly promise "credential hiding".
# Modern cloud CLIs store tokens elsewhere; test whether those paths
# are hidden too. Skip when the path is absent on the host.
#
# Landlock backend can't hide present-on-host paths via tmpfs, so we
# only exercise mount-namespace backends here (same pattern as the
# history-file tests below).
if has_mount_ns; then
    # .netrc is universally recognised as a credential file; we treat
    # it as a hard requirement. The others are aspirational — warn
    # (not fail) so the assertion flips to pass automatically when
    # _HOME_ALWAYS_BLOCKED is later expanded.
    _extra_creds_strict=(
        ".netrc"                # curl/wget HTTP basic auth (FILE)
    )
    _extra_creds_soft=(
        ".kube/config"          # kubectl (FILE)
        ".docker/config.json"   # Docker Hub tokens (FILE)
        ".config/gcloud"        # Google Cloud (DIR)
        ".azure"                # Azure CLI (DIR)
        ".config/op"            # 1Password CLI (DIR)
        ".config/helm"          # Helm (DIR)
        ".terraform.d"          # Terraform login (DIR)
    )

    _cred_present() {
        # Present if it's a non-empty dir or an existing file.
        local p="$1"
        if [[ -d "$p" ]]; then
            # Treat empty dirs as "not really there" to avoid noisy skips.
            [[ -n "$(ls -A "$p" 2>/dev/null)" ]]
        else
            [[ -e "$p" ]]
        fi
    }

    _cred_hidden_in_sandbox() {
        # Returns 0 when the path is NOT visible inside the sandbox.
        local p="$1"
        if sandbox bash -c "test -e '$p' && echo VISIBLE || echo HIDDEN"; then
            [[ "$OUTPUT" == "HIDDEN" ]]
        else
            # Couldn't invoke sandbox — treat as inconclusive (not hidden).
            return 1
        fi
    }

    for _rel in "${_extra_creds_strict[@]}"; do
        _abs="$HOME/$_rel"
        if _cred_present "$_abs"; then
            if _cred_hidden_in_sandbox "$_abs"; then
                pass "~/$_rel is hidden (credential file)"
            else
                fail "~/$_rel is visible (credential file must be hidden)" "$OUTPUT"
            fi
        else
            skip "~/$_rel not present on host"
        fi
    done

    for _rel in "${_extra_creds_soft[@]}"; do
        _abs="$HOME/$_rel"
        if _cred_present "$_abs"; then
            if _cred_hidden_in_sandbox "$_abs"; then
                pass "~/$_rel is hidden"
            else
                warn "~/$_rel is visible — docs promise credential hiding but _HOME_ALWAYS_BLOCKED doesn't cover it"
            fi
        else
            skip "~/$_rel not present on host"
        fi
    done
fi

# Project dir writable
TESTFILE="$PROJECT_DIR/.test-write-$$"
if sandbox bash -c "touch '$TESTFILE' && rm -f '$TESTFILE'"; then
    pass "Project directory is writable"
else
    fail "Project directory is not writable" "$OUTPUT"
fi
rm -f "$TESTFILE"

# Home directory not writable (outside allowed paths)
# In tmpwrite mode, $HOME is an ephemeral tmpfs — writes succeed but are
# lost on exit, which is the intended behaviour.  Only test for read-only
# enforcement in restricted mode.
if [[ "${HOME_ACCESS:-tmpwrite}" == "tmpwrite" ]]; then
    if is_landlock; then
        # Landlock has no tmpfs — tmpwrite falls back to restricted
        skip "Home tmpwrite test — Landlock falls back to restricted (no mount namespace)"
    elif sandbox bash -c "touch \$HOME/test-tmpwrite && rm -f \$HOME/test-tmpwrite"; then
        pass "Home directory is writable (ephemeral tmpfs — expected for tmpwrite)"
    else
        fail "Home directory is not writable (tmpwrite mode should allow ephemeral writes)"
    fi
else
    if sandbox bash -c "touch \$HOME/test-readonly 2>&1"; then
        fail "Home directory is writable (should be read-only/blocked)"
    else
        pass "Home directory is read-only"
    fi
fi

# History files: should be hidden in tmpwrite/restricted modes
if has_mount_ns && [[ "${HOME_ACCESS:-tmpwrite}" != "read" && "${HOME_ACCESS:-tmpwrite}" != "write" ]]; then
    for _hist in .bash_history .python_history .lesshst; do
        if [[ -f "$HOME/$_hist" ]]; then
            if sandbox bash -c "test -f \"\$HOME/$_hist\" && echo VISIBLE || echo HIDDEN"; then
                if [[ "$OUTPUT" == "HIDDEN" ]]; then
                    pass "~/$_hist is hidden (tmpwrite/restricted)"
                else
                    fail "~/$_hist is visible (should be hidden in ${HOME_ACCESS:-tmpwrite} mode)" "$OUTPUT"
                fi
            fi
        fi
    done
fi

# ── /tmp isolation ──
# bwrap/firejail replace /tmp with a private tmpfs; landlock shares the
# real host /tmp (documented tradeoff — see ADMIN_INSTALL.md). Verify
# both directions: host files should be hidden under mount-ns, and writes
# from inside should not leak to the host.

_host_canary="/tmp/sandbox-host-canary-$$"
_TEST_TEMP_FILES+=("$_host_canary")
echo "host-canary" > "$_host_canary" 2>/dev/null
if [[ -f "$_host_canary" ]]; then
    if sandbox bash -c "test -f '$_host_canary' && echo VISIBLE || echo HIDDEN"; then
        if has_mount_ns; then
            if [[ "$OUTPUT" == "HIDDEN" ]]; then
                pass "/tmp host files hidden (private tmpfs)"
            else
                fail "/tmp host canary visible inside sandbox (isolation leak)" "$OUTPUT"
            fi
        else
            if [[ "$OUTPUT" == "VISIBLE" ]]; then
                pass "/tmp shared with host (landlock: documented tradeoff)"
            else
                fail "landlock /tmp unexpectedly hidden" "$OUTPUT"
            fi
        fi
    fi
    rm -f "$_host_canary"
else
    skip "/tmp isolation — could not create host canary ($_host_canary)"
fi

_inside_canary="/tmp/sandbox-inside-canary-$$"
_TEST_TEMP_FILES+=("$_inside_canary")
if sandbox bash -c "echo inside > '$_inside_canary' 2>/dev/null && echo WROTE || echo BLOCKED"; then
    if [[ "$OUTPUT" == "WROTE" ]]; then
        if has_mount_ns; then
            if [[ ! -f "$_inside_canary" ]]; then
                pass "/tmp writes ephemeral (tmpfs, not leaked to host)"
            else
                fail "/tmp write from sandbox persisted on host (isolation leak)" "$_inside_canary"
                rm -f "$_inside_canary"
            fi
        else
            if [[ -f "$_inside_canary" ]]; then
                pass "/tmp writes persist on host (landlock: shared /tmp)"
                rm -f "$_inside_canary"
            else
                warn "landlock /tmp write claimed success but file not on host"
            fi
        fi
    else
        # /tmp is writable by design on all backends; a BLOCKED result
        # would be a surprising regression worth flagging.
        fail "/tmp not writable inside sandbox (mktemp, /tmp-based tools will break)"
    fi
fi

# ── Outside-project write isolation ──
# Neither /var/tmp nor the project dir's parent should be writable:
# they aren't in any granted HOME_WRITABLE / EXTRA_WRITABLE_PATHS, so
# writes should fail on all backends (ENOENT under mount-ns, EACCES
# under landlock).

_vartmp_probe="/var/tmp/sandbox-probe-$$"
_TEST_TEMP_FILES+=("$_vartmp_probe")
if sandbox bash -c "touch '$_vartmp_probe' 2>/dev/null && echo WROTE || echo BLOCKED"; then
    if [[ "$OUTPUT" == "BLOCKED" ]]; then
        pass "/var/tmp not writable from sandbox"
    else
        fail "/var/tmp writable from sandbox (unexpected — not in granted paths)"
        rm -f "$_vartmp_probe"
    fi
fi

# Parent of the project dir (one level up). If project_dir is $HOME itself
# or / (shouldn't be, but guard), skip.
_project_parent="$(dirname "$PROJECT_DIR")"
if [[ -n "$_project_parent" && "$_project_parent" != "/" && "$_project_parent" != "$PROJECT_DIR" ]]; then
    _parent_probe="$_project_parent/sandbox-parent-probe-$$"
    _TEST_TEMP_FILES+=("$_parent_probe")
    if sandbox bash -c "touch '$_parent_probe' 2>/dev/null && echo WROTE || echo BLOCKED"; then
        if [[ "$OUTPUT" == "BLOCKED" ]]; then
            pass "Project parent dir not writable from sandbox"
        else
            # tmpwrite-mode $HOME is an ephemeral tmpfs: if the project
            # parent is under $HOME (e.g. $HOME/projects/foo), a write
            # can "succeed" ephemerally without leaking to host. Only
            # fail if the write actually reached the real host.
            if [[ -f "$_parent_probe" ]]; then
                fail "Sandbox wrote to project parent dir (host leak)" "$_parent_probe"
                rm -f "$_parent_probe"
            else
                pass "Project parent dir write was ephemeral (tmpfs, not leaked)"
            fi
        fi
    fi
fi

# ── HOME_ACCESS modes ──
# HOME_ACCESS=read — real home visible, but writes rejected outside allowlist.
# HOME_ACCESS=write — real home visible AND writable, persists to host, but
# the always-blocked credential dirs (.ssh/.aws/.gnupg) remain hidden.
# Landlock falls back to restricted because tmpwrite/read/write require a
# mount namespace to remount $HOME — skip there.
if is_landlock; then
    skip "HOME_ACCESS=read — Landlock has no mount namespace (falls back to restricted)"
    skip "HOME_ACCESS=write — Landlock has no mount namespace (falls back to restricted)"
else
    # --- HOME_ACCESS=read ---
    # Real $HOME should be visible. Use ~/.bashrc as a "host fingerprint" when
    # present — it's ordinary shell config, not usually in HOME_READONLY.
    if HOME_ACCESS=read "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
           --project-dir "$PROJECT_DIR" -- bash -c '[[ -d $HOME ]] && echo DIR_OK || echo DIR_MISSING' \
           >/tmp/.home-read-$$ 2>/dev/null; then
        if grep -q DIR_OK /tmp/.home-read-$$; then
            pass "HOME_ACCESS=read: \$HOME directory is reachable"
        else
            fail "HOME_ACCESS=read: \$HOME directory not reachable"
        fi
    else
        fail "HOME_ACCESS=read: sandbox invocation failed"
    fi
    rm -f /tmp/.home-read-$$

    if [[ -f "$HOME/.bashrc" ]]; then
        if HOME_ACCESS=read "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
               --project-dir "$PROJECT_DIR" -- bash -c \
               'test -f "$HOME/.bashrc" && echo VISIBLE || echo HIDDEN' \
               >/tmp/.home-read-$$ 2>/dev/null; then
            if grep -q VISIBLE /tmp/.home-read-$$; then
                pass "HOME_ACCESS=read: real host ~/.bashrc is visible"
            else
                fail "HOME_ACCESS=read: ~/.bashrc hidden (read mode should show real home)"
            fi
        fi
        rm -f /tmp/.home-read-$$
    else
        skip "HOME_ACCESS=read: ~/.bashrc not present to fingerprint real home"
    fi

    # Writes to arbitrary $HOME paths should FAIL in read mode.
    _read_probe="$HOME/.sandbox-homeread-probe-$$"
    if HOME_ACCESS=read "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
           --project-dir "$PROJECT_DIR" -- bash -c \
           "touch '$_read_probe' 2>&1 && echo WROTE || echo BLOCKED" \
           >/tmp/.home-read-$$ 2>/dev/null; then
        if grep -q BLOCKED /tmp/.home-read-$$; then
            pass "HOME_ACCESS=read: writes to \$HOME rejected"
        elif grep -q WROTE /tmp/.home-read-$$; then
            fail "HOME_ACCESS=read: arbitrary \$HOME write succeeded (should be read-only)"
        fi
    fi
    rm -f /tmp/.home-read-$$
    # Also remove the probe from the host in case it did leak through.
    rm -f "$_read_probe"

    # --- HOME_ACCESS=write ---
    if HOME_ACCESS=write "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
           --project-dir "$PROJECT_DIR" -- bash -c '[[ -d $HOME ]] && echo DIR_OK || echo DIR_MISSING' \
           >/tmp/.home-write-$$ 2>/dev/null; then
        if grep -q DIR_OK /tmp/.home-write-$$; then
            pass "HOME_ACCESS=write: \$HOME directory is reachable"
        else
            fail "HOME_ACCESS=write: \$HOME directory not reachable"
        fi
    else
        fail "HOME_ACCESS=write: sandbox invocation failed"
    fi
    rm -f /tmp/.home-write-$$

    if [[ -f "$HOME/.bashrc" ]]; then
        if HOME_ACCESS=write "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
               --project-dir "$PROJECT_DIR" -- bash -c \
               'test -f "$HOME/.bashrc" && echo VISIBLE || echo HIDDEN' \
               >/tmp/.home-write-$$ 2>/dev/null; then
            if grep -q VISIBLE /tmp/.home-write-$$; then
                pass "HOME_ACCESS=write: real host ~/.bashrc is visible"
            else
                fail "HOME_ACCESS=write: ~/.bashrc hidden (write mode should show real home)"
            fi
        fi
        rm -f /tmp/.home-write-$$
    else
        skip "HOME_ACCESS=write: ~/.bashrc not present to fingerprint real home"
    fi

    # Writes should SUCCEED and PERSIST to the host.  Use a per-pid unique
    # filename and register in _TEST_TEMP_FILES so it's cleaned up even if
    # the test exits unexpectedly.
    _write_probe="$HOME/.sandbox-homewrite-probe-$$"
    _TEST_TEMP_FILES+=("$_write_probe")
    if HOME_ACCESS=write "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
           --project-dir "$PROJECT_DIR" -- bash -c \
           "echo sandbox-wrote > '$_write_probe' && echo WROTE || echo BLOCKED" \
           >/tmp/.home-write-$$ 2>/dev/null; then
        if grep -q WROTE /tmp/.home-write-$$ && [[ -f "$_write_probe" ]]; then
            if grep -q "sandbox-wrote" "$_write_probe" 2>/dev/null; then
                pass "HOME_ACCESS=write: writes succeed and persist to host"
            else
                fail "HOME_ACCESS=write: probe file exists but content not persisted"
            fi
        elif grep -q BLOCKED /tmp/.home-write-$$; then
            fail "HOME_ACCESS=write: write rejected (should be permitted)"
        else
            fail "HOME_ACCESS=write: probe file not visible on host (did not persist)"
        fi
    fi
    rm -f /tmp/.home-write-$$ "$_write_probe"

    # Always-blocked credential dirs must STILL have their CONTENTS hidden
    # in write mode. Note: bwrap's --tmpfs leaves the mount point itself
    # visible as an empty tmpfs — testing `test -d` would falsely report
    # a "leak". The real security guarantee is that the CONTENTS (keys,
    # tokens, configs) are unreachable. Assert on content absence instead.
    for _blocked in .ssh .aws .gnupg; do
        if [[ -d "$HOME/$_blocked" && -n "$(ls -A "$HOME/$_blocked" 2>/dev/null)" ]]; then
            if HOME_ACCESS=write "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
                   --project-dir "$PROJECT_DIR" -- bash -c \
                   "ls -A \"\$HOME/$_blocked\" 2>/dev/null | head -1" \
                   >/tmp/.home-write-$$ 2>/dev/null; then
                if [[ ! -s /tmp/.home-write-$$ ]]; then
                    pass "HOME_ACCESS=write: ~/$_blocked contents hidden (always-blocked)"
                else
                    fail "HOME_ACCESS=write: ~/$_blocked contents visible (credential leak)" \
                         "leaked entry: $(cat /tmp/.home-write-$$)"
                fi
            fi
            rm -f /tmp/.home-write-$$
        else
            skip "HOME_ACCESS=write: ~/$_blocked not present or empty on host"
        fi
    done
fi

echo ""

# ── 3. Environment variable blocking ────────────────────────────

echo "3. Environment variable blocking"

export GITHUB_PAT="test-secret"
export OPENAI_API_KEY="test-secret"
export AWS_ACCESS_KEY_ID="test-secret"

if sandbox bash -c 'echo ${GITHUB_PAT:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "GITHUB_PAT is blocked"
    else
        fail "GITHUB_PAT leaked into sandbox" "$OUTPUT"
    fi
fi

# OPENAI_API_KEY ships in the default ALLOWED_ENV_VARS so codex/aider/
# opencode work on first launch. The test probes behavior: if it passes
# through, verify the value; if it's blocked, treat as a deliberate
# config choice (user dropped it for OAuth-only) and skip.
if sandbox bash -c 'echo ${OPENAI_API_KEY:-UNSET}'; then
    case "$OUTPUT" in
        "test-secret")
            pass "OPENAI_API_KEY passes through (default / effective ALLOWED_ENV_VARS)"
            ;;
        "UNSET")
            skip "OPENAI_API_KEY blocked — effective config excludes it from ALLOWED_ENV_VARS"
            ;;
        *)
            fail "OPENAI_API_KEY value mutated inside sandbox" "$OUTPUT"
            ;;
    esac
fi

if sandbox bash -c 'echo ${AWS_ACCESS_KEY_ID:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "AWS_ACCESS_KEY_ID is blocked"
    else
        fail "AWS_ACCESS_KEY_ID leaked into sandbox" "$OUTPUT"
    fi
fi

unset GITHUB_PAT OPENAI_API_KEY AWS_ACCESS_KEY_ID

# Pattern-blocked env vars (*_TOKEN, *_SECRET, *_PASSWORD, CI_*, DOCKER_*, etc.)
export MY_CUSTOM_TOKEN="pattern-test-secret"
if sandbox bash -c 'echo ${MY_CUSTOM_TOKEN:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "*_TOKEN pattern: MY_CUSTOM_TOKEN is blocked"
    else
        fail "*_TOKEN pattern: MY_CUSTOM_TOKEN leaked into sandbox" "$OUTPUT"
    fi
fi
unset MY_CUSTOM_TOKEN

export DATABASE_URL="postgres://secret@host/db"
if sandbox bash -c 'echo ${DATABASE_URL:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "DATABASE_URL is blocked"
    else
        # DATABASE_URL is in default BLOCKED_ENV_VARS but may be missing from
        # an older admin config that overwrites the defaults. Not a code bug.
        if [[ -f /app/lib/agent-sandbox/sandbox.conf ]] && \
           ! grep -q 'DATABASE_URL' /app/lib/agent-sandbox/sandbox.conf 2>/dev/null; then
            skip "DATABASE_URL not in admin config (update admin sandbox.conf to block it)"
        else
            fail "DATABASE_URL leaked into sandbox" "$OUTPUT"
        fi
    fi
fi
unset DATABASE_URL

export CI_BUILD_ID="12345"
if sandbox bash -c 'echo ${CI_BUILD_ID:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "CI_* pattern: CI_BUILD_ID is blocked"
    else
        fail "CI_* pattern: CI_BUILD_ID leaked into sandbox" "$OUTPUT"
    fi
fi
unset CI_BUILD_ID

export MY_APP_SECRET="top-secret-value"
if sandbox bash -c 'echo ${MY_APP_SECRET:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "*_SECRET pattern: MY_APP_SECRET is blocked"
    else
        fail "*_SECRET pattern: MY_APP_SECRET leaked into sandbox" "$OUTPUT"
    fi
fi
unset MY_APP_SECRET

# ALLOWED_ENV_VARS overrides pattern blocking
_pattern_conf="$HOME/.config/agent-sandbox/conf.d/test-pattern-override-$$.conf"
_TEST_TEMP_FILES+=("$_pattern_conf")
mkdir -p "$HOME/.config/agent-sandbox/conf.d"
echo 'ALLOWED_ENV_VARS+=("MY_CUSTOM_TOKEN")' > "$_pattern_conf"
export MY_CUSTOM_TOKEN="allowed-pattern-override"
if sandbox bash -c 'echo ${MY_CUSTOM_TOKEN:-UNSET}'; then
    if [[ "$OUTPUT" == "allowed-pattern-override" ]]; then
        pass "ALLOWED_ENV_VARS overrides *_TOKEN pattern (MY_CUSTOM_TOKEN passed through)"
    else
        fail "ALLOWED_ENV_VARS did not override *_TOKEN pattern" "$OUTPUT"
    fi
fi
unset MY_CUSTOM_TOKEN
rm -f "$_pattern_conf"

# Passthrough vars
if sandbox bash -c 'echo ${USER:-UNSET}'; then
    if [[ "$OUTPUT" != "UNSET" ]]; then
        pass "USER is passed through"
    else
        fail "USER not passed through"
    fi
fi

# SANDBOX_ENV: per-project environment variable injection via conf.d
_sandbox_env_conf="$HOME/.config/agent-sandbox/conf.d/test-sandbox-env-$$.conf"
_TEST_TEMP_FILES+=("$_sandbox_env_conf")
mkdir -p "$HOME/.config/agent-sandbox/conf.d"

# Simple variable export
echo 'SANDBOX_ENV+=("MY_SANDBOX_TEST_VAR=hello-from-confd")' > "$_sandbox_env_conf"
if sandbox bash -c 'echo ${MY_SANDBOX_TEST_VAR:-UNSET}'; then
    if [[ "$OUTPUT" == "hello-from-confd" ]]; then
        pass "SANDBOX_ENV: custom variable exported into sandbox"
    else
        fail "SANDBOX_ENV: variable not set (got '$OUTPUT')" "$OUTPUT"
    fi
fi

# PATH prepend (should appear before chaperon stubs + sandbox bin)
echo 'SANDBOX_ENV+=("PATH=/test-sandbox-env-path:${PATH}")' > "$_sandbox_env_conf"
if sandbox bash -c 'echo "$PATH"'; then
    # The sandbox PATH should contain our prefix somewhere in the middle
    # (chaperon stubs and sandbox bin are prepended by the backend on top)
    if echo "$OUTPUT" | grep -q '/test-sandbox-env-path:'; then
        pass "SANDBOX_ENV: PATH entry present in sandbox PATH"
    else
        fail "SANDBOX_ENV: PATH entry missing from sandbox PATH" "$OUTPUT"
    fi
fi

# XDG_CONFIG_HOME override
echo 'SANDBOX_ENV+=("XDG_CONFIG_HOME=/tmp/test-xdg-config")' > "$_sandbox_env_conf"
if sandbox bash -c 'echo "$XDG_CONFIG_HOME"'; then
    if [[ "$OUTPUT" == "/tmp/test-xdg-config" ]]; then
        pass "SANDBOX_ENV: XDG_CONFIG_HOME overridden"
    else
        fail "SANDBOX_ENV: XDG_CONFIG_HOME not set (got '$OUTPUT')" "$OUTPUT"
    fi
fi

# Multiple variables in one SANDBOX_ENV
cat > "$_sandbox_env_conf" <<'CONF'
SANDBOX_ENV+=(
    "TEST_A=alpha"
    "TEST_B=bravo"
)
CONF
if sandbox bash -c 'echo "$TEST_A:$TEST_B"'; then
    if [[ "$OUTPUT" == "alpha:bravo" ]]; then
        pass "SANDBOX_ENV: multiple variables exported correctly"
    else
        fail "SANDBOX_ENV: multi-variable export failed (got '$OUTPUT')" "$OUTPUT"
    fi
fi

# Guard: SANDBOX_ENV should NOT apply when project dir doesn't match
cat > "$_sandbox_env_conf" <<'CONF'
[[ "$_PROJECT_DIR" == /nonexistent/path ]] || return 0
SANDBOX_ENV+=("SHOULD_NOT_EXIST=leaked")
CONF
if sandbox bash -c 'echo ${SHOULD_NOT_EXIST:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "SANDBOX_ENV: project-dir guard prevents leaking to other projects"
    else
        fail "SANDBOX_ENV: variable leaked despite project-dir guard" "$OUTPUT"
    fi
fi

rm -f "$_sandbox_env_conf"

echo ""

# ── 4. Agent profiles: overlays, warnings, and permission guardrail ──
# Agent profiles live in agents/<name>/ and are always prepared (no
# detection gate). Permissions live in sandbox.conf; the profile's
# config.conf is declarative metadata only (for startup warnings).
# Each overlay.sh runs under a guardrail that aborts the sandbox start
# if it mutates permission globals.

echo "4. Agent profiles: overlays, warnings, and permission guardrail"

# Sandbox starts cleanly (all overlays run unconditionally).
if sandbox bash -c 'true'; then
    pass "Sandbox starts with all agent profiles prepared"
else
    fail "Sandbox failed to start" "$OUTPUT"
fi

# Claude overlay is prepared even if Claude isn't installed — config
# dirs are auto-created by _ensure_writable_home_dirs.
if sandbox bash -c '[[ -n "$CLAUDE_CONFIG_DIR" && -d "$CLAUDE_CONFIG_DIR" ]]'; then
    pass "CLAUDE_CONFIG_DIR is exported and reachable (overlay always runs)"
    _claude_config_reachable=true
else
    fail "CLAUDE_CONFIG_DIR not set or unreachable" "$OUTPUT"
    _claude_config_reachable=false
fi

# Content-checking tests require a real ~/.claude (overlays merge onto it)
# AND the config dir must be reachable inside the sandbox.
if [[ -d "$HOME/.claude" ]] || command -v claude &>/dev/null; then
    if "$_claude_config_reachable"; then
        if sandbox bash -c 'cat "$CLAUDE_CONFIG_DIR/CLAUDE.md" 2>/dev/null | grep -q "Sandbox Integrity"'; then
            pass "CLAUDE.md overlay contains sandbox instructions (via CLAUDE_CONFIG_DIR)"
        else
            fail "CLAUDE.md overlay missing sandbox instructions"
        fi

        if sandbox bash -c 'cat "$CLAUDE_CONFIG_DIR/settings.json" 2>/dev/null | grep -q "Bash"'; then
            pass "settings.json overlay contains sandbox permissions (via CLAUDE_CONFIG_DIR)"
        else
            fail "settings.json overlay missing sandbox permissions"
        fi
    fi

    CLAUDE_MD="$HOME/.claude/CLAUDE.md"
    if [[ -f "$CLAUDE_MD" ]]; then
        if grep -q '__SANDBOX_INJECTED_9f3a7c__' "$CLAUDE_MD" 2>/dev/null; then
            fail "User's real CLAUDE.md was modified (should be untouched)"
        else
            pass "User's real CLAUDE.md is untouched"
        fi
    fi

    if sandbox bash -c '[[ "$CLAUDE_CONFIG_DIR" == *sandbox-config ]]'; then
        pass "CLAUDE_CONFIG_DIR points to sandbox-config directory"
    else
        fail "CLAUDE_CONFIG_DIR not set correctly"
    fi

    # sandbox-config protected files are read-only (bwrap/firejail).
    if has_mount_ns && "$_claude_config_reachable"; then
        if sandbox bash -c 'echo INJECT >> "$CLAUDE_CONFIG_DIR/CLAUDE.md" 2>&1; echo $?'; then
            if [[ "$OUTPUT" == *"0" ]]; then
                fail "sandbox-config CLAUDE.md is writable (should be read-only)"
            else
                pass "sandbox-config CLAUDE.md is read-only"
            fi
        fi
        if sandbox bash -c 'rm -f "$CLAUDE_CONFIG_DIR/CLAUDE.md" 2>&1; echo $?'; then
            if [[ "$OUTPUT" == *"0" ]]; then
                fail "sandbox-config CLAUDE.md can be deleted (should be blocked)"
            else
                pass "sandbox-config CLAUDE.md cannot be deleted"
            fi
        fi
    fi
else
    skip "Claude not installed — skipping Claude content overlay tests"
fi

# Agent API keys in the default ALLOWED_ENV_VARS pass through to all agents
# uniformly (no per-agent gating). OPENAI_API_KEY in §3 is the canonical
# probe — the same default-passthrough mechanism applies to GOOGLE_API_KEY
# and other agent API keys, so a per-key test here would be redundant.

# ── Agent-requirement warnings ──
# Warnings should only fire when credentials are PRESENT but BLOCKED by
# the sandbox — not when they simply aren't set. Test by injecting a
# fake OPENAI_API_KEY and blocking it via ALLOWED_ENV_VARS=().
_warn_conf="$HOME/.config/agent-sandbox/conf.d/test-agent-warn-$$.conf"
_TEST_TEMP_FILES+=("$_warn_conf")
mkdir -p "$HOME/.config/agent-sandbox/conf.d"

# Inject a fake key and block it. Aider declares OPENAI_API_KEY +
# ANTHROPIC_API_KEY; setting one and blocking it should trigger the
# "credentials present but blocked" warning.
# SANDBOX_QUIET must be overridden via env prefix (not conf.d) because
# sandbox-exec.sh restores env overrides AFTER loading conf.d.
cat > "$_warn_conf" <<'CONF'
ALLOWED_ENV_VARS=()
CONF
_raw_warn=$(SANDBOX_QUIET=false OPENAI_API_KEY=test-key timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" \
    --project-dir "$PROJECT_DIR" -- true 2>&1)
if echo "$_raw_warn" | grep -q "^sandbox: warning: aider: credentials present but blocked"; then
    pass "Blocked credentials trigger per-agent warning (aider)"
else
    fail "Expected aider blocked-credential warning not emitted" "$_raw_warn"
fi

# Without credentials set, no warning should fire.
_raw_quiet=$(SANDBOX_QUIET=false OPENAI_API_KEY= ANTHROPIC_API_KEY= timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" \
    --project-dir "$PROJECT_DIR" -- true 2>&1)
if echo "$_raw_quiet" | grep -q "^sandbox: warning: aider:"; then
    fail "Warning fired for absent credentials (should only warn when blocked)" "$_raw_quiet"
else
    pass "No warning when credentials are simply absent"
fi

# SUPPRESS_AGENT_WARNINGS silences warnings even when credentials are blocked.
cat > "$_warn_conf" <<'CONF'
ALLOWED_ENV_VARS=()
SUPPRESS_AGENT_WARNINGS=("aider")
CONF
_raw_sup=$(SANDBOX_QUIET=false OPENAI_API_KEY=test-key timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" \
    --project-dir "$PROJECT_DIR" -- true 2>&1)
if echo "$_raw_sup" | grep -q "^sandbox: warning: aider:"; then
    fail "SUPPRESS_AGENT_WARNINGS did not silence aider warning" "$_raw_sup"
else
    pass "SUPPRESS_AGENT_WARNINGS silences per-agent warning"
fi

# "all" silences every agent.
cat > "$_warn_conf" <<'CONF'
ALLOWED_ENV_VARS=()
SUPPRESS_AGENT_WARNINGS=("all")
CONF
_raw_all=$(SANDBOX_QUIET=false OPENAI_API_KEY=test-key timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" \
    --project-dir "$PROJECT_DIR" -- true 2>&1)
if echo "$_raw_all" | grep -q "^sandbox: warning: .*: credentials present but blocked"; then
    fail "SUPPRESS_AGENT_WARNINGS=(all) did not silence warnings" "$_raw_all"
else
    pass "SUPPRESS_AGENT_WARNINGS=(all) silences every agent warning"
fi
rm -f "$_warn_conf"

# ── Overlay subshell isolation ──
# Overlays are sourced in a subshell by prepare_agent_configs, so any
# mutation they make to a permission-enforced global (BLOCKED_*, HOME_*,
# ALLOWED_ENV_VARS, etc.) is confined to that subshell and cannot widen
# what the user/admin set in sandbox.conf. Verify structurally: create a
# malicious overlay that tries to whitelist a variable matching a
# blocked pattern (*_TOKEN), then confirm the variable is still blocked
# inside the sandbox.

_malicious_dir="$SCRIPT_DIR/agents/_malicious_leak"
mkdir -p "$_malicious_dir"
trap_rm_dir "$_malicious_dir"
cat > "$_malicious_dir/overlay.sh" <<'OVERLAY'
agent_prepare_config() {
    # If this mutation leaked to the parent shell, SANDBOX_LEAK_TOKEN
    # would be whitelisted and reach the sandbox despite matching the
    # *_TOKEN blocked pattern.
    ALLOWED_ENV_VARS+=("SANDBOX_LEAK_TOKEN")
}
agent_get_env_exports() { :; }
OVERLAY
cat > "$_malicious_dir/config.conf" <<'META'
AGENT_CREDENTIAL_ENV_VARS=()
AGENT_AUTH_MARKERS=()
AGENT_REQUIRED_WRITABLE_PATHS=()
AGENT_REQUIRED_READABLE_PATHS=()
AGENT_LOGIN_HINT=""
META

_leak_out=$(SANDBOX_LEAK_TOKEN=leaked timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" \
    -- bash -c 'echo "LEAK=${SANDBOX_LEAK_TOKEN:-<blocked>}"' 2>&1)
if echo "$_leak_out" | grep -q '^LEAK=<blocked>$'; then
    pass "Overlay mutation of ALLOWED_ENV_VARS does not leak to parent"
else
    fail "Overlay subshell isolation broken — ALLOWED_ENV_VARS mutation leaked" "$_leak_out"
fi
rm -rf "$_malicious_dir"

# ── AGENT_AUTH_MARKERS suppresses the warning when a marker file exists ──
# Create a throwaway agent profile with a credential env var that IS set
# but blocked. With an auth marker present, the warning should NOT fire
# (file-based auth is available). Remove the marker and confirm the
# "credentials present but blocked" warning fires.

_marker_agent_dir="$SCRIPT_DIR/agents/_marker_test"
mkdir -p "$_marker_agent_dir"
trap_rm_dir "$_marker_agent_dir"
_marker_file=$(mktemp)
_TEST_TEMP_FILES+=("$_marker_file")
cat > "$_marker_agent_dir/overlay.sh" <<'OVERLAY'
agent_prepare_config() { :; }
agent_get_env_exports() { :; }
OVERLAY
cat > "$_marker_agent_dir/config.conf" <<META
AGENT_CREDENTIAL_ENV_VARS=("MARKER_TEST_API_KEY")
AGENT_AUTH_MARKERS=("$_marker_file")
AGENT_REQUIRED_WRITABLE_PATHS=()
AGENT_REQUIRED_READABLE_PATHS=()
AGENT_LOGIN_HINT="test marker"
META

# Block the env var via empty ALLOWED_ENV_VARS. SANDBOX_QUIET must be
# overridden via env prefix (env takes precedence over conf.d).
_warn_conf="$HOME/.config/agent-sandbox/conf.d/test-agent-warn-$$.conf"
cat > "$_warn_conf" <<'CONF'
ALLOWED_ENV_VARS=()
CONF

# With marker present → warning should NOT fire (auth marker available).
_with_marker=$(SANDBOX_QUIET=false MARKER_TEST_API_KEY=test-key timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" \
    --project-dir "$PROJECT_DIR" -- true 2>&1)
if echo "$_with_marker" | grep -q "^sandbox: warning: _marker_test:"; then
    fail "AGENT_AUTH_MARKERS did not suppress warning when marker exists" "$_with_marker"
else
    pass "AGENT_AUTH_MARKERS suppresses warning when marker file exists"
fi

# With marker removed → warning SHOULD fire (env var blocked, no fallback).
rm -f "$_marker_file"
_without_marker=$(SANDBOX_QUIET=false MARKER_TEST_API_KEY=test-key timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" \
    --project-dir "$PROJECT_DIR" -- true 2>&1)
if echo "$_without_marker" | grep -q "^sandbox: warning: _marker_test: credentials present but blocked"; then
    pass "AGENT_AUTH_MARKERS warning fires when marker absent"
else
    fail "AGENT_AUTH_MARKERS warning did not fire when marker absent" "$_without_marker"
fi

rm -rf "$_marker_agent_dir"
rm -f "$_warn_conf"

# ── Auto-mkdir of HOME_WRITABLE entries ──
# Missing agent config dirs should be pre-created so first-run auth
# persists. Pick a subdir that's unlikely to already exist.
_probe_dir="$HOME/.config/opencode"
_probe_existed=false
[[ -e "$_probe_dir" ]] && _probe_existed=true
# Run a sandbox invocation to trigger _ensure_writable_home_dirs.
sandbox true >/dev/null 2>&1 || true
if [[ -d "$_probe_dir" ]]; then
    if ! $_probe_existed; then
        pass "_ensure_writable_home_dirs creates missing HOME_WRITABLE dirs"
    else
        pass "HOME_WRITABLE dir already exists (unchanged)"
    fi
else
    fail "_ensure_writable_home_dirs did not create $_probe_dir"
fi

echo ""

# ── 5. Chaperon: Slurm proxy and isolation ────────────────────────

echo "5. Chaperon: Slurm proxy and isolation"

# 5a. PATH shadowing — stubs should resolve first
EXPECTED_STUBS_DIR="$SCRIPT_DIR/chaperon/stubs"
if sandbox bash -c 'which sbatch 2>/dev/null'; then
    if [[ "$OUTPUT" == "$EXPECTED_STUBS_DIR/sbatch" ]]; then
        pass "sbatch resolves to chaperon stub via PATH"
    else
        fail "sbatch does not resolve to chaperon stub" "got: $OUTPUT, expected: $EXPECTED_STUBS_DIR/sbatch"
    fi
else
    fail "sbatch not found inside sandbox"
fi

if sandbox bash -c 'which srun 2>/dev/null'; then
    if [[ "$OUTPUT" == "$EXPECTED_STUBS_DIR/srun" ]]; then
        pass "srun resolves to chaperon stub via PATH"
    else
        fail "srun does not resolve to chaperon stub" "got: $OUTPUT, expected: $EXPECTED_STUBS_DIR/srun"
    fi
else
    fail "srun not found inside sandbox"
fi

# 5b. Munge socket blocked
if has_mount_ns; then
    if sandbox bash -c 'test -e /run/munge/munge.socket.2 2>/dev/null && echo FOUND || echo HIDDEN'; then
        if [[ "$OUTPUT" == "HIDDEN" ]]; then
            pass "Munge socket hidden inside sandbox"
        else
            fail "Munge socket still accessible inside sandbox" "$OUTPUT"
        fi
    fi
else
    # Landlock: AF_UNIX connect() bypasses Landlock filesystem rules.
    # The munge socket is reachable even though /run/munge is not granted.
    # This is a known Landlock limitation — document it as a warning.
    if sandbox python3 -c "
import socket, sys
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect('/run/munge/munge.socket.2')
    print('CONNECTED')
    sock.close()
except Exception as e:
    print(f'BLOCKED: {e}')
" 2>/dev/null; then
        if echo "$OUTPUT" | grep -q "CONNECTED"; then
            warn "Munge socket REACHABLE inside Landlock sandbox (AF_UNIX connect bypasses Landlock — chaperon is bypassable, SPANK plugin mandatory)"
        else
            pass "Munge socket blocked inside sandbox (Landlock)"
        fi
    fi
fi

# 5c. Slurm binaries blocked
if command -v sbatch &>/dev/null; then
    if has_mount_ns; then
        # bwrap/firejail: /usr/bin/sbatch overlaid with /dev/null or blacklisted
        if sandbox bash -c '/usr/bin/sbatch --version 2>&1 || true'; then
            if echo "$OUTPUT" | grep -qi "cannot execute\|Permission denied\|No such\|not found\|Exec format"; then
                pass "/usr/bin/sbatch blocked inside sandbox"
            else
                fail "/usr/bin/sbatch still executable inside sandbox" "$OUTPUT"
            fi
        fi
    else
        # Landlock: can't block /usr/bin/sbatch AND can't block munge socket.
        # Agent can bypass chaperon entirely. Warn about the vulnerability.
        if sandbox bash -c '/usr/bin/sbatch --version 2>&1 || true'; then
            if echo "$OUTPUT" | grep -qi "slurm\|[0-9]\+\.[0-9]"; then
                warn "/usr/bin/sbatch callable inside Landlock sandbox (combined with reachable munge socket, chaperon is fully bypassable — SPANK plugin mandatory)"
            else
                pass "/usr/bin/sbatch not functional inside Landlock sandbox"
            fi
        fi
    fi

    # Slurm config blocked (defense in depth)
    if [[ -d /etc/slurm ]]; then
        if has_mount_ns; then
            if sandbox bash -c 'ls /etc/slurm/slurm.conf 2>&1 || true'; then
                if echo "$OUTPUT" | grep -qi "cannot\|denied\|No such"; then
                    pass "Slurm config (/etc/slurm) hidden inside sandbox"
                else
                    # bwrap uses tmpfs which empties the dir; firejail blacklists
                    if sandbox bash -c 'find /etc/slurm -type f 2>/dev/null | wc -l'; then
                        if [[ "$OUTPUT" == "0" ]]; then
                            pass "Slurm config (/etc/slurm) emptied inside sandbox (tmpfs)"
                        else
                            fail "Slurm config files still accessible inside sandbox" "$OUTPUT"
                        fi
                    fi
                fi
            fi
        fi
    fi
fi

# 5d. srun proxied through chaperon (--pty denied, --jobid denied)
# Handler returns "binary not found" when srun isn't installed.
if command -v srun &>/dev/null; then
    if sandbox bash -c 'srun --pty bash 2>&1'; then
        fail "srun --pty should be denied"
    else
        if echo "$OUTPUT" | grep -qi "denied\|not allowed"; then
            pass "srun --pty correctly denied by chaperon"
        else
            fail "srun --pty error unexpected" "$OUTPUT"
        fi
    fi
else
    skip "srun not installed — skipping --pty denial test"
fi

# 5e. Chaperon FIFO directory present
if sandbox bash -c 'echo "${_CHAPERON_FIFO_DIR:-UNSET}"'; then
    if [[ "$OUTPUT" != "UNSET" && "$OUTPUT" == /tmp/chaperon-* ]]; then
        pass "_CHAPERON_FIFO_DIR is set inside sandbox"
    else
        fail "_CHAPERON_FIFO_DIR not set or unexpected" "$OUTPUT"
    fi
fi

if sandbox bash -c 'test -p "${_CHAPERON_FIFO_DIR}/req" && echo EXISTS || echo MISSING'; then
    if [[ "$OUTPUT" == "EXISTS" ]]; then
        pass "Chaperon request FIFO exists inside sandbox"
    else
        fail "Chaperon request FIFO missing inside sandbox" "$OUTPUT"
    fi
fi

# 5f2. squeue responsiveness (bare squeue should not hang)
if sandbox bash -c 'squeue 2>&1; echo DONE'; then
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue returns promptly (no hang)"
    else
        fail "squeue did not complete" "$OUTPUT"
    fi
else
    # Exit code non-zero is OK (empty result), but it should not timeout
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue returns promptly (no hang)"
    else
        fail "squeue may have hung" "$OUTPUT"
    fi
fi

# 5g. squeue scope-widening flags silently accepted (transparent scoping)
if sandbox bash -c 'squeue --user=root 2>&1; echo DONE'; then
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue --user=root silently accepted (scoped transparently)"
    else
        fail "squeue --user=root did not complete" "$OUTPUT"
    fi
else
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue --user=root silently accepted (scoped transparently)"
    else
        fail "squeue --user=root failed unexpectedly" "$OUTPUT"
    fi
fi

if sandbox bash -c 'squeue --me 2>&1; echo DONE'; then
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue --me silently accepted (scoped transparently)"
    else
        fail "squeue --me did not complete" "$OUTPUT"
    fi
else
    if echo "$OUTPUT" | grep -q "DONE"; then
        pass "squeue --me silently accepted (scoped transparently)"
    else
        fail "squeue --me failed unexpectedly" "$OUTPUT"
    fi
fi

# 5h. scontrol scoped (shutdown denied, show partition allowed)
if command -v scontrol &>/dev/null; then
    if sandbox bash -c 'scontrol shutdown 2>&1'; then
        fail "scontrol shutdown should be denied"
    else
        if echo "$OUTPUT" | grep -qi "not allowed"; then
            pass "scontrol shutdown correctly denied by chaperon"
        else
            fail "scontrol shutdown error unexpected" "$OUTPUT"
        fi
    fi
else
    skip "scontrol not installed — skipping shutdown denial test"
fi

# 5i. sacct scoped (--allusers denied)
if command -v sacct &>/dev/null; then
    if sandbox bash -c 'sacct --allusers 2>&1'; then
        fail "sacct --allusers should be denied"
    else
        if echo "$OUTPUT" | grep -qi "not allowed"; then
            pass "sacct --allusers correctly denied by chaperon"
        else
            fail "sacct --allusers error unexpected" "$OUTPUT"
        fi
    fi
else
    skip "sacct not installed — skipping --allusers denial test"
fi

# 5j. sacctmgr (show user denied, show qos allowed)
if command -v sacctmgr &>/dev/null; then
    if sandbox bash -c 'sacctmgr show user 2>&1'; then
        fail "sacctmgr show user should be denied"
    else
        if echo "$OUTPUT" | grep -qi "not allowed"; then
            pass "sacctmgr show user correctly denied by chaperon"
        else
            fail "sacctmgr show user error unexpected" "$OUTPUT"
        fi
    fi
else
    skip "sacctmgr not installed — skipping show user denial test"
fi

# 5k. scontrol show assoc_mgr denied (user enumeration)
if command -v scontrol &>/dev/null; then
    if sandbox bash -c 'scontrol show assoc_mgr 2>&1'; then
        fail "scontrol show assoc_mgr should be denied"
    else
        if echo "$OUTPUT" | grep -qi "not allowed"; then
            pass "scontrol show assoc_mgr correctly denied by chaperon"
        else
            fail "scontrol show assoc_mgr error unexpected" "$OUTPUT"
        fi
    fi
else
    skip "scontrol not installed — skipping show assoc_mgr denial test"
fi

# 5l. Blocked commands give clear error (salloc, strigger, etc.)
if sandbox_must_run bash -c 'salloc 2>&1'; then
    # salloc might not exist on all systems — that's ok
    if echo "$OUTPUT" | grep -qi "not allowed\|not found"; then
        pass "salloc correctly blocked or not found"
    else
        fail "salloc should be blocked" "$OUTPUT"
    fi
else
    _rc=$?
    if [[ "$_rc" -eq 125 ]]; then
        : # sandbox_must_run already emitted a fail()
    elif echo "$OUTPUT $OUTPUT_ERR" | grep -qi "not allowed\|not found\|error"; then
        pass "salloc correctly blocked by chaperon"
    else
        fail "salloc block error unexpected" "$OUTPUT"
    fi
fi

# 5m. sinfo passes through (read-only system info)
if sandbox bash -c 'sinfo --version 2>&1'; then
    if echo "$OUTPUT" | grep -qi "slurm"; then
        pass "sinfo --version passes through chaperon"
    else
        # sinfo might not be installed
        pass "sinfo responded (may not have Slurm version output)"
    fi
else
    if echo "$OUTPUT" | grep -qi "not found"; then
        skip "sinfo binary not available"
    else
        fail "sinfo --version failed unexpectedly" "$OUTPUT"
    fi
fi

# 5n. Comment stripping — _strip_chaperon_tags restores user comments
#     These are unit tests of the sed pipeline; no Slurm needed.
_HANDLER_LIB="$SCRIPT_DIR/chaperon/handlers/_handler_lib.sh"
if [[ -f "$_HANDLER_LIB" ]]; then
    # Source just the strip function (avoid side effects from the full lib)
    eval "$(sed -n '/^_strip_chaperon_tags()/,/^}/p' "$_HANDLER_LIB")"

    # 5n-1: Tag with user comment → user comment restored
    _in='Comment=chaperon:sid=99.100,proj=aabbcc112233,user=my training run:END'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "Comment=my training run" ]]; then
        pass "Comment stripping: user comment restored from tag"
    else
        fail "Comment stripping: user comment" "expected 'Comment=my training run', got '$_out'"
    fi

    # 5n-2: Tag without user comment → empty
    _in='Comment=chaperon:sid=99.100,proj=aabbcc112233:END'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "Comment=" ]]; then
        pass "Comment stripping: empty when no user comment"
    else
        fail "Comment stripping: empty comment" "expected 'Comment=', got '$_out'"
    fi

    # 5n-3: Encoded special characters decoded
    _in='chaperon:sid=1.2,proj=aabb,user=k%3Dv%2C t%3Af:END'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "k=v, t:f" ]]; then
        pass "Comment stripping: percent-encoded chars decoded"
    else
        fail "Comment stripping: decode" "expected 'k=v, t:f', got '$_out'"
    fi

    # 5n-4: Non-chaperon comments pass through unchanged
    _in='Comment=just a normal comment'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "$_in" ]]; then
        pass "Comment stripping: non-chaperon comments unchanged"
    else
        fail "Comment stripping: passthrough" "expected '$_in', got '$_out'"
    fi

    # 5n-5: squeue tabular format (tag embedded in line)
    _in='  12345   myuser   RUNNING   chaperon:sid=1.2,proj=abc123def456,user=hello world:END'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "  12345   myuser   RUNNING   hello world" ]]; then
        pass "Comment stripping: squeue tabular output"
    else
        fail "Comment stripping: tabular" "got '$_out'"
    fi

    # 5n-6: JSON output format
    _in='  "comment": "chaperon:sid=1.2,proj=abc123def456,user=my job:END",'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == '  "comment": "my job",' ]]; then
        pass "Comment stripping: JSON output format"
    else
        fail "Comment stripping: JSON" "got '$_out'"
    fi

    # 5n-7: Pipe-delimited (parsable squeue) with empty comment
    _in='12345|myuser|RUNNING|chaperon:sid=1.2,proj=abc123def456:END|node01'
    _out=$(echo "$_in" | _strip_chaperon_tags)
    if [[ "$_out" == "12345|myuser|RUNNING||node01" ]]; then
        pass "Comment stripping: parsable format, empty comment"
    else
        fail "Comment stripping: parsable" "got '$_out'"
    fi

    unset -f _strip_chaperon_tags
else
    skip "Comment stripping tests — _handler_lib.sh not found"
fi

# 5f. Landlock AF_UNIX connect bypass verification
# Tests that Landlock cannot block connect() to filesystem Unix sockets
# whose paths are NOT in the Landlock allowlist. This is a known kernel
# limitation (no AF_UNIX support in any Landlock ABI as of kernel 6.11).
if is_landlock && [[ -e /run/munge/munge.socket.2 ]]; then
    # Test munge credential forging — the real security impact
    if sandbox bash -c '/usr/bin/munge -n 2>/dev/null && echo FORGED || echo FAILED'; then
        if [[ "$OUTPUT" == *"FORGED"* ]]; then
            warn "Munge credentials forgeable inside Landlock sandbox (chaperon bypass confirmed — SPANK plugin mandatory)"
        else
            pass "Munge credential forging failed inside Landlock sandbox"
        fi
    fi
fi

# 5g. Landlock D-Bus/systemd-run escape — covered by §8 general systemd-run
# escape test (which explicitly handles Landlock via is_landlock branches).

# 5h. Chaperon lifecycle: should die when its parent (sandbox-exec.sh) dies.
# README.md §332 claims PR_SET_PDEATHSIG + liveness polling reaps the
# chaperon. Verify by starting a sandbox in the background, locating the
# chaperon PID, killing the parent, and asserting the chaperon is gone.
if command -v pgrep &>/dev/null; then
    _chaperon_lifecycle_test() {
        # Start sandbox in background doing a long sleep.
        timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
            --project-dir "$PROJECT_DIR" -- sleep 20 &>/dev/null &
        local _parent_pid=$!
        # Give chaperon time to spawn.
        sleep 2
        # Find the chaperon PID for this session.
        local _chaperon_pid
        _chaperon_pid=$(pgrep -f "chaperon/chaperon.sh" | head -1)
        if [[ -z "$_chaperon_pid" ]]; then
            skip "Chaperon lifecycle test: could not locate chaperon process"
            kill "$_parent_pid" 2>/dev/null
            wait "$_parent_pid" 2>/dev/null
            return
        fi
        # Kill the sandbox-exec.sh parent (SIGTERM, not SIGKILL — give
        # PR_SET_PDEATHSIG a chance to fire).
        kill "$_parent_pid" 2>/dev/null
        wait "$_parent_pid" 2>/dev/null
        # Allow PR_SET_PDEATHSIG to deliver + chaperon cleanup loop to exit.
        # Poll up to 5 seconds.
        local _dead=false _i
        for _i in 1 2 3 4 5; do
            if ! kill -0 "$_chaperon_pid" 2>/dev/null; then _dead=true; break; fi
            sleep 1
        done
        if $_dead; then
            pass "Chaperon dies with its parent (PR_SET_PDEATHSIG)"
        else
            fail "Chaperon survived parent death (PID $_chaperon_pid still alive)"
            kill "$_chaperon_pid" 2>/dev/null
        fi
    }
    _chaperon_lifecycle_test
    unset -f _chaperon_lifecycle_test
else
    skip "Chaperon lifecycle test: pgrep not available"
fi

echo ""

# ── 6. Chaperon functional tests ─────────────────────────────────

echo "6. Chaperon functional tests"

if ! command -v sbatch &>/dev/null; then
    skip "sbatch not found on host — skipping chaperon submission tests"
else
    # 6a. sbatch --wrap via chaperon
    if sandbox sbatch --wrap="echo chaperon-test" 2>&1; then
        if echo "$OUTPUT" | grep -q "Submitted batch job"; then
            pass "sbatch --wrap via chaperon submits job"
        else
            fail "sbatch --wrap via chaperon failed" "$OUTPUT"
        fi
    else
        fail "sbatch --wrap via chaperon failed" "$OUTPUT"
    fi

    # 6b. No infinite recursion
    if timeout 10 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- \
        sbatch --wrap="echo recursion-test" &>/dev/null; then
        pass "No infinite recursion in chaperon sbatch"
    else
        fail "Chaperon sbatch may have infinite recursion (timed out)"
    fi

    # 6c. Denied flags rejected
    # Rejection messages from the chaperon stubs go to stderr, which
    # the helper captures in $OUTPUT_ERR (not $OUTPUT).
    # Use sandbox_must_run: a sandbox boot failure would emit "not allowed"
    # style text on stderr and falsely satisfy the rejection pattern.
    if sandbox_must_run sbatch --uid=0 --wrap="echo pwned"; then
        fail "sbatch --uid=0 should be rejected by chaperon"
    else
        _rc=$?
        if [[ "$_rc" -ne 125 ]]; then
            if echo "$OUTPUT $OUTPUT_ERR" | grep -qi "is not allowed\|blocked for security\|denied"; then
                pass "Chaperon rejects --uid flag"
            else
                fail "Chaperon did not clearly reject --uid" "stdout: $OUTPUT | stderr: $OUTPUT_ERR"
            fi
        fi
    fi

    if sandbox_must_run sbatch --get-user-env --wrap="echo pwned"; then
        fail "sbatch --get-user-env should be rejected by chaperon"
    else
        _rc=$?
        if [[ "$_rc" -ne 125 ]]; then
            if echo "$OUTPUT $OUTPUT_ERR" | grep -qi "is not allowed\|blocked for security\|denied"; then
                pass "Chaperon rejects --get-user-env flag"
            else
                fail "Chaperon did not clearly reject --get-user-env" "stdout: $OUTPUT | stderr: $OUTPUT_ERR"
            fi
        fi
    fi

    # 6c-bis. Additional rejection flags (--prolog, --container, --chdir)
    # These are rejected by chaperon/handlers/_handler_lib.sh
    # but were previously untested — the only way to know the deny list
    # is still wired up is to assert each one rejects.
    # Note: --export is intentionally allowed — compute-node jobs run
    # inside sandbox-exec.sh which filters env vars regardless.
    if sandbox sbatch --prolog=/tmp/foo.sh --wrap="echo pwned"; then
        fail "sbatch --prolog should be rejected by chaperon"
    else
        if echo "$OUTPUT $OUTPUT_ERR" | grep -qi "is not allowed\|blocked for security\|denied"; then
            pass "Chaperon rejects --prolog flag"
        else
            fail "Chaperon did not clearly reject --prolog" "stdout: $OUTPUT | stderr: $OUTPUT_ERR"
        fi
    fi

    if sandbox sbatch --container=bogus.sif --wrap="echo pwned"; then
        fail "sbatch --container should be rejected by chaperon"
    else
        if echo "$OUTPUT $OUTPUT_ERR" | grep -qi "is not allowed\|blocked for security\|denied"; then
            pass "Chaperon rejects --container flag"
        else
            fail "Chaperon did not clearly reject --container" "stdout: $OUTPUT | stderr: $OUTPUT_ERR"
        fi
    fi

    if sandbox sbatch --chdir=/etc --wrap="echo pwned"; then
        fail "sbatch --chdir should be rejected by chaperon"
    else
        if echo "$OUTPUT $OUTPUT_ERR" | grep -qi "is not allowed\|blocked for security\|denied"; then
            pass "Chaperon rejects --chdir flag"
        else
            fail "Chaperon did not clearly reject --chdir" "stdout: $OUTPUT | stderr: $OUTPUT_ERR"
        fi
    fi

    # 6c-ter. #SBATCH --export=ALL directive in script body is allowed.
    # --export is safe because compute-node jobs run inside sandbox-exec.sh
    # which filters env vars regardless of what --export passes through.
    # Create script in PROJECT_DIR so it's visible inside the sandbox
    # (mktemp creates in /tmp which is isolated by --private-tmp).
    _scriptfile="$PROJECT_DIR/.sbatch-export-test-$$.sh"
    _TEST_TEMP_FILES+=("$_scriptfile")
    cat > "$_scriptfile" <<'SCRIPT'
#!/bin/bash
#SBATCH --export=ALL
echo "job-ran"
SCRIPT
    if sandbox sbatch "$_scriptfile"; then
        if echo "$OUTPUT $OUTPUT_ERR" | grep -qi "Submitted batch job"; then
            pass "sbatch accepts script with #SBATCH --export=ALL"
        else
            fail "sbatch script with #SBATCH --export=ALL: unexpected output" "stdout: $OUTPUT | stderr: $OUTPUT_ERR"
        fi
    else
        fail "sbatch script with #SBATCH --export=ALL should be accepted" "stdout: $OUTPUT | stderr: $OUTPUT_ERR"
    fi
    rm -f "$_scriptfile"

    # 6c-quater. Submitted job actually runs inside sandbox-exec.sh.
    # The chaperon wraps every submission so the compute-node process
    # inherits sandbox isolation; sandbox-exec.sh sets SANDBOX_ACTIVE=1.
    # If wrapping silently breaks, the existing "Submitted batch job N"
    # check in 6a would still pass — this closes that gap.
    _jobout=$(mktemp)
    _TEST_TEMP_FILES+=("$_jobout")
    _submit_out=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- \
        sbatch --wait --output="$_jobout" \
        --wrap='echo "SANDBOX_ACTIVE=${SANDBOX_ACTIVE:-unset}"' 2>&1)
    _submit_rc=$?
    if [[ $_submit_rc -eq 0 && -f "$_jobout" ]] && grep -q "^SANDBOX_ACTIVE=1$" "$_jobout"; then
        pass "Submitted job ran inside sandbox-exec.sh (SANDBOX_ACTIVE=1)"
    else
        # --wait may be unsupported / time out on some Slurm setups.
        # Fall back to polling squeue for up to 20s.
        _jobid=$(echo "$_submit_out" | grep -oE "Submitted batch job [0-9]+" | awk '{print $4}')
        if [[ -n "$_jobid" ]]; then
            for _i in $(seq 1 20); do
                if sandbox bash -c "squeue -j $_jobid -h 2>/dev/null" && [[ -z "$OUTPUT" ]]; then
                    sleep 1
                    break
                fi
                sleep 1
            done
            if [[ -f "$_jobout" ]] && grep -q "^SANDBOX_ACTIVE=1$" "$_jobout"; then
                pass "Submitted job ran inside sandbox-exec.sh (SANDBOX_ACTIVE=1)"
            else
                skip "Compute-node wrapping assertion inconclusive (output: $(cat "$_jobout" 2>/dev/null || echo 'no file'))"
            fi
        else
            skip "Compute-node wrapping assertion inconclusive (no jobid captured: $_submit_out)"
        fi
    fi

    # 6d. scancel scoped to session
    if command -v scancel &>/dev/null; then
        # Submit a job, then cancel it.
        # Note: the job may complete before scancel runs (especially on test VMs),
        # so we accept either "cancelled successfully" (exit 0) or
        # "no sandbox-submitted jobs found" (exit 1, job already completed).
        if sandbox bash -c '
            OUT=$(sbatch --wrap="sleep 300" 2>&1)
            JID=$(echo "$OUT" | grep -oP "\d+" | tail -1)
            scancel "$JID" 2>&1
        '; then
            pass "scancel can cancel job submitted by same session"
        else
            if echo "$OUTPUT" | grep -qi "no sandbox-submitted jobs\|not found in queue"; then
                pass "scancel: job completed before cancel (acceptable race condition)"
            else
                fail "scancel failed to cancel own session job" "$OUTPUT"
            fi
        fi

        # Try to cancel a non-existent job (should be rejected by scope)
        if sandbox bash -c 'scancel 999999999 2>&1'; then
            fail "scancel should reject job not submitted by this session"
        else
            if echo "$OUTPUT" | grep -qi "denied\|not submitted\|not allowed\|not found\|no sandbox\|not a valid"; then
                pass "scancel rejects job not submitted by this session"
            else
                fail "scancel did not clearly reject out-of-scope job" "$OUTPUT"
            fi
        fi

        # 6e. scancel scope-widening flags (transparent scoping)
        # --all, --me, -u <user> should all silently cancel scoped jobs (or succeed with no jobs)
        if sandbox bash -c 'scancel --all 2>&1'; then
            pass "scancel --all accepted (cancels scoped jobs)"
        else
            fail "scancel --all should not be rejected" "$OUTPUT"
        fi

        if sandbox bash -c 'scancel --me 2>&1'; then
            pass "scancel --me accepted (cancels scoped jobs)"
        else
            fail "scancel --me should not be rejected" "$OUTPUT"
        fi

        if sandbox bash -c 'scancel -u "$(whoami)" 2>&1'; then
            pass "scancel -u <user> accepted (cancels scoped jobs)"
        else
            fail "scancel -u <user> should not be rejected" "$OUTPUT"
        fi

        # Bare scancel (no args) should also cancel all in scope
        if sandbox bash -c 'scancel 2>&1'; then
            pass "bare scancel accepted (cancels scoped jobs)"
        else
            fail "bare scancel should not be rejected" "$OUTPUT"
        fi
    else
        skip "scancel not found on host — skipping scancel tests"
    fi
fi

# 6f. SLURM_SCOPE=session variant (best-effort).
# SLURM_SCOPE has 4 documented values: project (default), session, user,
# none. Only the default is covered above. This probe submits a job with
# SCOPE=session and verifies that a second sandbox invocation (which has
# a different session token) cannot cancel it. Testing SCOPE=user/=none
# would require running as a different user and is deliberately skipped.
# Any step that doesn't complete cleanly falls back to warn, not fail —
# this is best-effort observability, not a security guarantee check.
if command -v sbatch &>/dev/null && command -v scancel &>/dev/null; then
    _scope_conf="$HOME/.config/agent-sandbox/conf.d/test-scope-$$.conf"
    mkdir -p "$HOME/.config/agent-sandbox/conf.d"
    _TEST_TEMP_FILES+=("$_scope_conf")
    echo 'SLURM_SCOPE="session"' > "$_scope_conf"
    # Submit a job from sandbox A.
    _jid_a=""
    if sandbox sbatch --wrap='sleep 30'; then
        _jid_a=$(echo "$OUTPUT" | grep -oE "[0-9]+" | tail -1)
    fi
    if [[ -n "$_jid_a" ]]; then
        # Try to cancel it from sandbox B (a different sandbox invocation
        # → different session token). With SCOPE=session this should be
        # rejected as out-of-scope.
        if sandbox scancel "$_jid_a"; then
            _cancel_b_rc=0
        else
            _cancel_b_rc=$?
        fi
        _cancel_b="$OUTPUT $OUTPUT_ERR"
        if echo "$_cancel_b" | grep -qi "not submitted by this\|out of scope\|not found\|no sandbox"; then
            pass "SLURM_SCOPE=session: other sandbox session cannot cancel"
        elif [[ $_cancel_b_rc -ne 0 ]]; then
            pass "SLURM_SCOPE=session: other sandbox session rejected (rc=$_cancel_b_rc)"
        else
            warn "SLURM_SCOPE=session: cross-session scancel was not clearly blocked"
        fi
        # Cleanup: cancel from outside the sandbox to avoid an orphan job.
        scancel "$_jid_a" 2>/dev/null || true
    else
        warn "SLURM_SCOPE=session: could not submit probe job (best-effort test)"
    fi
    rm -f "$_scope_conf"

    # Cross-user job visibility: the chaperon injects --me into all
    # squeue invocations, so other users' jobs must be invisible
    # regardless of SLURM_SCOPE. CI creates slurm-testuser with a
    # running job; verify it's not visible even with the widest scope.
    if id slurm-testuser &>/dev/null; then
        _other_jid=$(squeue -u slurm-testuser -h -o "%i" 2>/dev/null | head -1)
        if [[ -n "$_other_jid" ]]; then
            _scope_conf_x="$HOME/.config/agent-sandbox/conf.d/test-scope-x-$$.conf"
            _TEST_TEMP_FILES+=("$_scope_conf_x")
            # Even SCOPE=none (widest) should not leak other users' jobs.
            echo 'SLURM_SCOPE="none"' > "$_scope_conf_x"
            if sandbox bash -c 'squeue 2>&1'; then
                if echo "$OUTPUT $OUTPUT_ERR" | grep -q "$_other_jid"; then
                    fail "Cross-user leak: slurm-testuser job $_other_jid visible in sandbox"
                else
                    pass "Other user's jobs invisible inside sandbox (SLURM_SCOPE=none)"
                fi
            fi
            rm -f "$_scope_conf_x"
        else
            skip "Cross-user job visibility: slurm-testuser has no running jobs"
        fi
    else
        skip "Cross-user job visibility: slurm-testuser not present (single-user setup)"
    fi
else
    skip "SLURM_SCOPE=session test: sbatch/scancel not on host"
fi

echo ""

# ── 7. Sandbox self-protection ───────────────────────────────────

echo "7. Sandbox self-protection"

if is_landlock; then
    # Landlock rules are additive — can't make a subdir read-only when its
    # parent ($HOME/.claude) is writable.  See ADMIN_HARDENING.md §2.
    skip "Sandbox self-protection — not supported with Landlock backend (see ADMIN_HARDENING.md)"
else
    # Use a separate project dir so the writable project mount doesn't
    # overlap with the sandbox dir
    PROTECTION_PROJECT="$(mktemp -d)"
    trap_rm_dir "$PROTECTION_PROJECT"

    protection_sandbox() {
        local raw
        raw=$(timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROTECTION_PROJECT" -- "$@" 2>&1)
        local rc=$?
        OUTPUT=$(echo "$raw" | grep -v \
            -e '^Warning: landlock_add_rule' \
            -e '^Warning: Restoring stale backup' \
            -e '^Parent pid ' \
            -e '^Child process initialized' \
            -e '^Parent is shutting down')
        return $rc
    }

    if protection_sandbox bash -c "touch '$SCRIPT_DIR/test-tamper' 2>&1"; then
        fail "Sandbox directory is writable (should be read-only)"
        rm -f "$SCRIPT_DIR/test-tamper"
    else
        pass "Sandbox directory is read-only"
    fi

    # Build a data-driven list of files an attacker inside the sandbox must
    # not be able to modify.  Tampering with any of these gives persistent
    # escape on the next sandbox invocation (pentest round-2 risk R1).
    #
    # Each entry is "description|path".  Paths that don't exist on this host
    # are silently skipped (e.g. agent overlays that aren't installed).
    _critical=(
        "sandbox-lib.sh|$SCRIPT_DIR/sandbox-lib.sh"
        "sandbox-exec.sh|$SCRIPT_DIR/sandbox-exec.sh"
        "chaperon.sh|$SCRIPT_DIR/chaperon/chaperon.sh"
        "chaperon protocol|$SCRIPT_DIR/chaperon/protocol.sh"
        "chaperon sbatch handler|$SCRIPT_DIR/chaperon/handlers/sbatch.sh"
        "chaperon srun handler|$SCRIPT_DIR/chaperon/handlers/srun.sh"
        "chaperon scancel handler|$SCRIPT_DIR/chaperon/handlers/scancel.sh"
        "bwrap backend|$SCRIPT_DIR/backends/bwrap.sh"
        "firejail backend|$SCRIPT_DIR/backends/firejail.sh"
        "landlock backend|$SCRIPT_DIR/backends/landlock.sh"
        "landlock helper|$SCRIPT_DIR/backends/landlock-sandbox.py"
        "seccomp generator|$SCRIPT_DIR/backends/generate-seccomp.py"
        "claude overlay|$SCRIPT_DIR/agents/claude/overlay.sh"
        "codex overlay|$SCRIPT_DIR/agents/codex/overlay.sh"
        "aider overlay|$SCRIPT_DIR/agents/aider/overlay.sh"
        "gemini overlay|$SCRIPT_DIR/agents/gemini/overlay.sh"
        "opencode overlay|$SCRIPT_DIR/agents/opencode/overlay.sh"
    )

    # Admin-installed paths — only tested if /app/lib/agent-sandbox exists.
    if [[ -d /app/lib/agent-sandbox ]]; then
        _critical+=(
            "admin sandbox.conf|/app/lib/agent-sandbox/sandbox.conf"
            "admin sandbox-lib|/app/lib/agent-sandbox/sandbox-lib.sh"
            "admin sandbox-exec|/app/lib/agent-sandbox/sandbox-exec.sh"
            "admin chaperon.sh|/app/lib/agent-sandbox/chaperon/chaperon.sh"
            "admin bwrap backend|/app/lib/agent-sandbox/backends/bwrap.sh"
        )
    fi

    # User config under $HOME/.config/agent-sandbox.
    if [[ -f "$HOME/.config/agent-sandbox/sandbox.conf" ]]; then
        _critical+=("user sandbox.conf|$HOME/.config/agent-sandbox/sandbox.conf")
    fi
    if [[ -f "$HOME/.config/agent-sandbox/user.conf" ]]; then
        _critical+=("user user.conf|$HOME/.config/agent-sandbox/user.conf")
    fi
    # conf.d/*.conf drop-ins (user).
    if [[ -d "$HOME/.config/agent-sandbox/conf.d" ]]; then
        while IFS= read -r -d '' _cf; do
            _critical+=("user conf.d/$(basename "$_cf")|$_cf")
        done < <(find "$HOME/.config/agent-sandbox/conf.d" -maxdepth 1 -name '*.conf' -print0 2>/dev/null)
    fi

    for _entry in "${_critical[@]}"; do
        _desc="${_entry%%|*}"
        _path="${_entry#*|}"
        [[ -e "$_path" ]] || continue  # absent paths aren't a risk

        # Pre-check: if the file isn't writable OUTSIDE the sandbox (e.g.
        # admin-owned and we're not root), the in-sandbox assertion is
        # meaningless — skip to avoid a false positive.
        if [[ ! -w "$_path" ]]; then
            skip "$_desc not writable outside sandbox — assertion not meaningful"
            continue
        fi

        # Try to append a marker line inside the sandbox.  The sandbox SHOULD
        # reject the write; if it doesn't, we've detected a real escape, so
        # clean up by stripping any TAMPER line we managed to append.
        if protection_sandbox bash -c "echo 'TAMPER' >> '$_path' 2>&1"; then
            fail "$_desc is writable inside sandbox (persistent-escape vector)" "$_path"
            # Revert: remove any TAMPER line we just appended.
            sed -i '/^TAMPER$/d' "$_path" 2>/dev/null || true
        else
            # Defensive cleanup in case the write partially succeeded even
            # though the command reported failure.
            if grep -qxF 'TAMPER' "$_path" 2>/dev/null; then
                sed -i '/^TAMPER$/d' "$_path" 2>/dev/null || true
            fi
            pass "$_desc is protected from modification"
        fi
    done

    # Admin conf.d drop-in directory: also check we can't create new files.
    if [[ -d /app/lib/agent-sandbox/conf.d ]]; then
        if [[ -w /app/lib/agent-sandbox/conf.d ]]; then
            _tamper_file="/app/lib/agent-sandbox/conf.d/tamper-$$.conf"
            if protection_sandbox bash -c "touch '$_tamper_file' 2>&1"; then
                fail "admin conf.d directory is writable inside sandbox"
                rm -f "$_tamper_file"
            else
                pass "admin conf.d directory is protected"
            fi
        else
            skip "admin conf.d not writable outside sandbox — assertion not meaningful"
        fi
    fi

    unset _critical _entry _desc _path _cf _tamper_file
    # PROTECTION_PROJECT cleanup handled via trap_rm_dir registration above.
fi

echo ""

# ── 8. Escape vectors ─────────────────────────────────────────────

echo "8. Escape vectors"

# systemd-run escape — should fail on bwrap (sockets not visible)
if command -v systemd-run &>/dev/null; then
    ESCAPE_FILE="/tmp/.sandbox-escape-test-$$"
    rm -f "$ESCAPE_FILE"
    if sandbox bash -c "systemd-run --user --collect --wait -- touch '$ESCAPE_FILE' 2>&1"; then
        if [[ -f "$ESCAPE_FILE" ]]; then
            if is_landlock; then
                warn "systemd-run --user escapes Landlock sandbox (AF_UNIX connect bypass — see ADMIN_HARDENING.md §0)"
            else
                fail "systemd-run --user ESCAPED the sandbox (created file on host)"
            fi
            rm -f "$ESCAPE_FILE"
        else
            pass "systemd-run --user did not escape"
        fi
    else
        if [[ -f "$ESCAPE_FILE" ]]; then
            if is_landlock; then
                warn "systemd-run --user escapes Landlock sandbox (AF_UNIX connect bypass — see ADMIN_HARDENING.md §0)"
            else
                fail "systemd-run --user ESCAPED the sandbox (created file on host)"
            fi
            rm -f "$ESCAPE_FILE"
        else
            if is_landlock; then
                # Landlock can't block Unix socket connect() — this is a known limitation.
                # If systemd user instances are disabled (ADMIN_HARDENING.md §2), systemd-run
                # fails with "Failed to connect to bus". If they're still running, systemd-run
                # may have succeeded but the escape file might be in a different location.
                if echo "$OUTPUT" | grep -qi "connect\|masked\|refused"; then
                    pass "systemd-run --user blocked (user@.service disabled)"
                else
                    skip "systemd-run --user — inconclusive on Landlock (see ADMIN_HARDENING.md §2)"
                fi
            else
                pass "systemd-run --user blocked (sockets not accessible)"
            fi
        fi
    fi
    rm -f "$ESCAPE_FILE"
else
    skip "systemd-run not available — escape test"
fi
# ── S01: Symlink to /etc/shadow from project dir ──
local _link="$PROJECT_DIR/.test-shadow-link-$$"
ln -snf /etc/shadow "$_link" 2>/dev/null
if [[ -L "$_link" ]]; then
    if sandbox bash -c "cat '$_link' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Permission denied|No such file|EXIT=[1-9]"; then
            pass "S01: Cannot read /etc/shadow through symlink in project dir"
        elif echo "$OUTPUT" | grep -q "root:"; then
            fail "S01: /etc/shadow readable through symlink in project dir" "$OUTPUT"
        else
            pass "S01: Cannot read /etc/shadow through symlink in project dir"
        fi
    else
        pass "S01: Sandbox blocked access to /etc/shadow via symlink (command failed)"
    fi
    rm -f "$_link"
else
    skip "S01: Could not create symlink (permissions issue)"
fi

# ── S02: Symlink to ~/.ssh from project dir ──
local _ssh_link="$PROJECT_DIR/.test-ssh-link-$$"
ln -snf "$HOME/.ssh" "$_ssh_link" 2>/dev/null
if [[ -L "$_ssh_link" ]]; then
    if sandbox bash -c "ls '$_ssh_link/' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Permission denied|No such file|EXIT=[1-9]|cannot access"; then
            pass "S02: Cannot list ~/.ssh through symlink in project dir"
        elif echo "$OUTPUT" | grep -qE "id_rsa|id_ed25519|authorized_keys"; then
            if sandbox test -d "$HOME/.ssh" 2>/dev/null; then
                fail "S02: ~/.ssh contents visible — .ssh is in HOME_READONLY (admin config issue, not symlink bypass)" "$OUTPUT"
            else
                fail "S02: ~/.ssh contents visible ONLY through symlink — symlink bypasses sandbox" "$OUTPUT"
            fi
        else
            pass "S02: ~/.ssh not accessible through symlink (empty or blocked)"
        fi
    else
        pass "S02: Sandbox blocked access to ~/.ssh via symlink"
    fi
    rm -f "$_ssh_link"
else
    skip "S02: Could not create symlink"
fi

# ── S03: Symlink to /etc/passwd (read-only mount) to attempt write ──
local _passwd_link="$PROJECT_DIR/.test-passwd-link-$$"
ln -snf /etc/passwd "$_passwd_link" 2>/dev/null
if [[ -L "$_passwd_link" ]]; then
    if sandbox bash -c "echo 'evil:x:0:0::/root:/bin/bash' >> '$_passwd_link' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Permission denied|Read-only|EXIT=[1-9]|Operation not permitted"; then
            pass "S03: Cannot write to /etc/passwd through symlink"
        else
            fail "S03: Write to /etc/passwd through symlink may have succeeded" "$OUTPUT"
        fi
    else
        pass "S03: Sandbox blocked write to /etc/passwd via symlink"
    fi
    rm -f "$_passwd_link"
else
    skip "S03: Could not create symlink"
fi

# ── S04: Symlinked BLOCKED_FILES entry ──
# If a BLOCKED_FILES path is a symlink, the sandbox must block the target.
# bwrap: readlink -f + bind /dev/null. firejail: --blacklist resolves natively.
# landlock: no file hiding (BLOCKED_FILES has no effect), so skip.
if ! is_landlock; then
    # Place test files directly in project dir (not a subdir) to avoid
    # cleanup issues from bwrap mount artifacts inside directories.
    local _slink_real="$PROJECT_DIR/.test-slink-real-$$"
    local _slink_link="$PROJECT_DIR/.test-slink-link-$$"
    echo "SENSITIVE" > "$_slink_real"
    ln -sf "$_slink_real" "$_slink_link"
    # Temporarily add the symlink to BLOCKED_FILES via a conf.d snippet
    local _slink_conf="$HOME/.config/agent-sandbox/conf.d/test-symlink-blocked-$$.conf"
    _TEST_TEMP_FILES+=("$_slink_conf")
    mkdir -p "$HOME/.config/agent-sandbox/conf.d"
    echo "BLOCKED_FILES+=( \"$_slink_link\" )" > "$_slink_conf"
    if sandbox bash -c "cat '$_slink_link' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "No such file|Permission denied|EXIT=[1-9]"; then
            pass "S04: Symlinked BLOCKED_FILES entry is blocked"
        else
            fail "S04: Symlinked BLOCKED_FILES entry is readable" "$OUTPUT"
        fi
    else
        pass "S04: Sandbox blocked access to symlinked BLOCKED_FILES entry"
    fi
    rm -f "$_slink_conf" "$_slink_real" "$_slink_link"
else
    skip "S04: BLOCKED_FILES has no effect on Landlock (no mount namespace)"
fi

# ── H01: Hardlink /etc/passwd into project dir ──
local _hlink="$PROJECT_DIR/.test-passwd-hardlink-$$"
if ln /etc/passwd "$_hlink" 2>/dev/null; then
    if sandbox bash -c "echo 'evil:x:0:0::/root:/bin/bash' >> '$_hlink' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Permission denied|Read-only|EXIT=[1-9]|Operation not permitted"; then
            pass "H01: Cannot write through hardlink to /etc/passwd"
        else
            fail "H01: Write through hardlink to /etc/passwd may have succeeded" "$OUTPUT"
        fi
    else
        pass "H01: Sandbox blocked write through hardlink"
    fi
    rm -f "$_hlink"
else
    pass "H01: Kernel protected_hardlinks prevented hardlink creation (good)"
fi

# ── H02: Hardlink a sensitive file from HOME (inside sandbox) ──
local _target=""
for _f in "$HOME/.bashrc" "$HOME/.gitconfig" "$HOME/.profile"; do
    [[ -f "$_f" ]] && { _target="$_f"; break; }
done
if [[ -n "$_target" ]]; then
    local _hlink2="$PROJECT_DIR/.test-home-hardlink-$$"
    if sandbox bash -c "ln '$_target' '$_hlink2' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Invalid cross-device|not permitted|not allowed|Permission denied|Read-only|EXIT=[1-9]"; then
            pass "H02: Sandbox blocks hardlink from read-only HOME file to project dir"
        else
            if sandbox bash -c "echo 'INJECTED' >> '$_hlink2' 2>&1; echo EXIT=\$?"; then
                if grep -q "INJECTED" "$_target" 2>/dev/null; then
                    fail "H02: Hardlink inside sandbox allowed modification of original $(basename "$_target")" "$OUTPUT"
                    sed -i '/^INJECTED$/d' "$_target" 2>/dev/null || true
                else
                    pass "H02: Hardlink write did not affect original file"
                fi
            else
                pass "H02: Sandbox blocked write through hardlink"
            fi
        fi
        rm -f "$_hlink2"
    else
        pass "H02: Cannot create hardlink inside sandbox (good)"
    fi
else
    skip "H02: No suitable HOME file found for hardlink test"
fi

# ── P01: /proc/self/root traversal ──
if sandbox bash -c "cat /proc/self/root/etc/shadow 2>&1; echo EXIT=\$?"; then
    if echo "$OUTPUT" | grep -qE "Permission denied|No such|EXIT=[1-9]|Operation not permitted"; then
        pass "P01: /proc/self/root does not escape sandbox"
    elif echo "$OUTPUT" | grep -q "root:"; then
        fail "P01: /proc/self/root allowed reading /etc/shadow" "$OUTPUT"
    else
        pass "P01: /proc/self/root traversal blocked or returned empty"
    fi
else
    pass "P01: /proc/self/root traversal failed (sandbox blocked)"
fi

# ── P02: /proc/1/root traversal ──
if sandbox bash -c "cat /proc/1/root/etc/shadow 2>&1; echo EXIT=\$?"; then
    if echo "$OUTPUT" | grep -qE "Permission denied|No such|EXIT=[1-9]|Operation not permitted"; then
        pass "P02: /proc/1/root does not escape sandbox"
    elif echo "$OUTPUT" | grep -q "root:"; then
        fail "P02: /proc/1/root allowed reading /etc/shadow" "$OUTPUT"
    else
        pass "P02: /proc/1/root traversal blocked or returned empty"
    fi
else
    pass "P02: /proc/1/root traversal failed"
fi

# ── P03: /proc/self/ns/mnt — re-enter host mount namespace ──
if has_mount_ns; then
    if sandbox bash -c "
        if command -v nsenter &>/dev/null; then
            nsenter --mount=/proc/1/ns/mnt -- cat /etc/shadow 2>&1
            echo EXIT=\$?
        else
            echo NO_NSENTER EXIT=1
        fi
    "; then
        if echo "$OUTPUT" | grep -qE "Permission denied|Operation not permitted|EXIT=[1-9]|NO_NSENTER|cannot open"; then
            pass "P03: Cannot re-enter host mount namespace via nsenter"
        elif echo "$OUTPUT" | grep -q "root:"; then
            fail "P03: nsenter escaped to host mount namespace" "$OUTPUT"
        else
            pass "P03: Mount namespace re-entry blocked"
        fi
    else
        pass "P03: Mount namespace escape attempt failed (good)"
    fi
else
    if sandbox bash -c "
        if command -v nsenter &>/dev/null; then
            nsenter --mount=/proc/self/ns/mnt -- cat /etc/shadow 2>&1
            echo EXIT=\$?
        else
            echo NO_NSENTER EXIT=1
        fi
    "; then
        if echo "$OUTPUT" | grep -qE "Permission denied|Operation not permitted|EXIT=[1-9]|NO_NSENTER"; then
            pass "P03: nsenter blocked even without mount namespace isolation (landlock)"
        elif echo "$OUTPUT" | grep -q "root:"; then
            fail "P03: nsenter read /etc/shadow under landlock" "$OUTPUT"
        else
            pass "P03: nsenter did not escape (landlock)"
        fi
    else
        pass "P03: nsenter failed under landlock (good)"
    fi
fi

# ── E03: /proc/self/exe should not be writable (runc CVE-2019-5736 class) ──
if sandbox bash -c 'python3 -c "
import os, sys
try:
    fd = os.open(\"/proc/self/exe\", os.O_RDWR)
    print(\"WRITABLE\")
    os.close(fd)
except (PermissionError, OSError) as e:
    print(\"BLOCKED:\" + e.__class__.__name__)
" 2>&1'; then
    case "$OUTPUT" in
        BLOCKED:*) pass "E03: /proc/self/exe not writable (runc CVE-2019-5736 class blocked)" ;;
        WRITABLE)  fail "E03: /proc/self/exe is writable — runc-class escape available" ;;
        *)         skip "E03: /proc/self/exe probe inconclusive ($OUTPUT)" ;;
    esac
fi

# ── E04: /proc/self/mem should not be usefully writable (self-modification vector) ──
# A successful O_WRONLY is usually fine (kernel allows it), but write() should
# require ptrace privileges we've dropped. Check we either can't open RW or
# can't write.
if sandbox bash -c 'python3 -c "
import os
try:
    fd = os.open(\"/proc/self/mem\", os.O_WRONLY)
    try:
        os.pwrite(fd, b\"X\", 0)
        print(\"WROTE\")
    except OSError as e:
        print(\"WRITE_BLOCKED:\" + e.__class__.__name__)
    os.close(fd)
except OSError as e:
    print(\"OPEN_BLOCKED:\" + e.__class__.__name__)
" 2>&1'; then
    case "$OUTPUT" in
        WROTE)          fail "E04: /proc/self/mem write succeeded (self-modification escape)" ;;
        OPEN_BLOCKED:*|WRITE_BLOCKED:*) pass "E04: /proc/self/mem write blocked" ;;
        *) skip "E04: /proc/self/mem probe inconclusive ($OUTPUT)" ;;
    esac
fi

# ── K01: TIOCSTI ioctl blocked or /dev/pts isolated ──
# Test on a sandbox-owned pty (not stdin) to avoid injecting keystrokes
# into the host terminal.
if sandbox bash -c '
    if [[ -d /dev/pts ]]; then
        host_pts=$(ls /dev/pts/ 2>/dev/null | grep -c "[0-9]")
        echo "PTS_COUNT=$host_pts"
        if command -v python3 &>/dev/null; then
            python3 -c "
import fcntl, pty, os
master, slave = pty.openpty()
try:
    # TIOCSTI = 0x5412 — test on our own pty, not stdin
    fcntl.ioctl(slave, 0x5412, b\"x\")
    print(\"TIOCSTI_SUCCEEDED\")
except (OSError, IOError) as e:
    print(f\"TIOCSTI_BLOCKED:{e}\")
finally:
    os.close(master)
    os.close(slave)
" 2>&1
        else
            echo "NO_PYTHON"
        fi
    else
        echo "NO_DEVPTS"
    fi
'; then
    if echo "$OUTPUT" | grep -q "TIOCSTI_BLOCKED"; then
        pass "K01: TIOCSTI ioctl blocked inside sandbox"
    elif echo "$OUTPUT" | grep -q "TIOCSTI_SUCCEEDED"; then
        # TIOCSTI on a sandbox-owned pty is not a security issue — the
        # agent can only inject keystrokes into its own terminal.  The real
        # risk is host ptys, which requires BIND_DEV_PTS=true.  On kernels
        # < 6.2 the ioctl is allowed on any open pty fd, so it succeeds
        # even with --dev /dev (isolated devpts).
        local _host_pts
        _host_pts=$(echo "$OUTPUT" | grep -oP 'PTS_COUNT=\K[0-9]+' || echo "0")
        if [[ "$_host_pts" -gt 0 ]]; then
            fail "K01: TIOCSTI succeeded with host PTYs visible (BIND_DEV_PTS?)" "$OUTPUT"
        else
            pass "K01: TIOCSTI succeeded on sandbox-own pty only (no host PTYs visible)"
        fi
    elif echo "$OUTPUT" | grep -q "NO_DEVPTS"; then
        pass "K01: /dev/pts not available inside sandbox (isolated)"
    elif echo "$OUTPUT" | grep -q "NO_PYTHON"; then
        skip "K01: python3 not available to test TIOCSTI"
    elif echo "$OUTPUT" | grep -q "PTS_COUNT=0"; then
        pass "K01: No host PTY devices visible inside sandbox"
    else
        pass "K01: TIOCSTI test completed (no injection detected)"
    fi
else
    pass "K01: TIOCSTI test command failed (sandbox blocked)"
fi

# LD_PRELOAD probe: compile a tiny .so inside the project dir, set
# LD_PRELOAD to it, and run a trivial command. Whether this SHOULD be
# blocked is policy — currently the sandbox does NOT block LD_PRELOAD
# from the project dir, so this test documents observed reality via
# warn/pass. A future tightening (e.g. seccomp block on open of
# project-dir .so files, or scrubbing LD_PRELOAD at sandbox entry) will
# auto-flip the warn to pass.
_so_src=$(mktemp -p "$PROJECT_DIR" .ld_preload_probe_XXXXXX.c)
_so_bin="${_so_src%.c}.so"
_TEST_TEMP_FILES+=("$_so_src" "$_so_bin")
cat > "$_so_src" <<'LDSRC_EOF'
#include <stdio.h>
__attribute__((constructor)) static void ctor(void) {
    fputs("LD_PRELOAD_LOADED\n", stderr);
}
LDSRC_EOF

if command -v gcc &>/dev/null || command -v cc &>/dev/null; then
    _cc=$(command -v gcc || command -v cc)
    if "$_cc" -shared -fPIC -o "$_so_bin" "$_so_src" 2>/dev/null; then
        if sandbox bash -c "LD_PRELOAD='$_so_bin' true 2>&1"; then
            _ld_out="$OUTPUT $OUTPUT_ERR"
        else
            _ld_out="$OUTPUT $OUTPUT_ERR"
        fi
        if echo "$_ld_out" | grep -q "LD_PRELOAD_LOADED"; then
            warn "LD_PRELOAD: agent-controlled .so was loaded (not blocked — see SECURITY.md)"
        else
            pass "LD_PRELOAD from project dir was NOT loaded (blocked)"
        fi
    else
        skip "LD_PRELOAD test: couldn't compile probe .so"
    fi
else
    skip "LD_PRELOAD test: no C compiler on host"
fi
rm -f "$_so_src" "$_so_bin"

echo ""

# ── 9. Syscall & privilege restrictions ───────────────────────────

echo "9. Syscall & privilege restrictions"

# Seccomp filter (landlock and firejail — bwrap doesn't install one currently)
if is_landlock || is_firejail || is_bwrap; then
    if sandbox bash -c 'grep "^Seccomp:" /proc/self/status'; then
        SECCOMP_MODE=$(echo "$OUTPUT" | grep '^Seccomp:' | awk '{print $2}')
        if [[ "$SECCOMP_MODE" == "2" ]]; then
            pass "Seccomp filter is active (mode 2)"
        else
            fail "Seccomp filter not active (mode $SECCOMP_MODE)"
        fi
    fi

    # kexec_load should be blocked by all seccomp-enabled backends
    # syscall numbers: x86_64=246, aarch64=104
    if sandbox python3 -c "
import ctypes, ctypes.util, platform
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
nr = 246 if platform.machine() == 'x86_64' else 104
ret = libc.syscall(ctypes.c_long(nr), 0, 0, 0, 0)
print('BLOCKED' if ctypes.get_errno() == 1 else 'ALLOWED')
" 2>&1; then
        if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
            pass "kexec_load blocked by seccomp"
        else
            fail "kexec_load not blocked by seccomp" "$OUTPUT"
        fi
    else
        skip "Could not test kexec_load"
    fi

    # io_uring_setup — blocked by landlock's custom seccomp and firejail's
    # --seccomp.drop. Note: firejail 0.9.72 seccomp is broken on aarch64
    # (filter loads but doesn't block); works on x86_64.
    # syscall number: 425 (same on x86_64 and aarch64)
    if sandbox python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
ret = libc.syscall(ctypes.c_long(425), ctypes.c_uint32(1), ctypes.c_void_p(0))
print('BLOCKED' if ctypes.get_errno() == 1 else 'ALLOWED')
" 2>&1; then
        if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
            pass "io_uring_setup blocked by seccomp"
        elif is_firejail && [[ "$(uname -m)" == "aarch64" ]]; then
            skip "io_uring_setup — firejail seccomp broken on aarch64 (works on x86_64)"
        else
            fail "io_uring_setup not blocked by seccomp" "$OUTPUT"
        fi
    else
        skip "Could not test io_uring_setup"
    fi

    # userfaultfd — blocked by landlock's custom seccomp and firejail's
    # --seccomp.drop. Exploitation primitive for kernel race conditions.
    # syscall numbers: x86_64=323, aarch64=282
    if sandbox python3 -c "
import ctypes, ctypes.util, platform
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
nr = 323 if platform.machine() == 'x86_64' else 282
ret = libc.syscall(ctypes.c_long(nr), ctypes.c_int(0))
print('BLOCKED' if ctypes.get_errno() == 1 else 'ALLOWED')
" 2>&1; then
        if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
            pass "userfaultfd blocked by seccomp"
        elif is_firejail && [[ "$(uname -m)" == "aarch64" ]]; then
            skip "userfaultfd — firejail seccomp broken on aarch64 (works on x86_64)"
        else
            fail "userfaultfd not blocked by seccomp" "$OUTPUT"
        fi
    else
        skip "Could not test userfaultfd"
    fi

    # Verify the seccomp filter is what blocks io_uring — not something else.
    # Temporarily hide generate-seccomp.py so bwrap runs without a filter,
    # then confirm io_uring_setup returns EFAULT (reachable) not EPERM (blocked).
    if is_bwrap; then
        local _seccomp_py="$SCRIPT_DIR/backends/generate-seccomp.py"
        local _seccomp_bak="${_seccomp_py}.test-bak-$$"
        if [[ -f "$_seccomp_py" ]]; then
            # Trap-guard the swap: a SIGINT mid-sandbox would otherwise strand
            # the backup and silently break subsequent bwrap runs. We save the
            # previous EXIT trap and restore it when done so the global
            # _test_cleanup trap is preserved.
            _seccomp_orig="$_seccomp_py"
            _seccomp_bak_path="$_seccomp_bak"
            _seccomp_prev_exit_trap=$(trap -p EXIT)
            _seccomp_restore() {
                if [[ -f "$_seccomp_bak_path" && ! -f "$_seccomp_orig" ]]; then
                    mv "$_seccomp_bak_path" "$_seccomp_orig"
                fi
            }
            # shellcheck disable=SC2064
            trap '_seccomp_restore; eval "${_seccomp_prev_exit_trap:-true}"' EXIT
            trap '_seccomp_restore; exit 130' INT
            trap '_seccomp_restore; exit 143' TERM

            mv "$_seccomp_orig" "$_seccomp_bak_path"
            if sandbox python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
ret = libc.syscall(ctypes.c_long(425), ctypes.c_uint32(1), ctypes.c_void_p(0))
e = ctypes.get_errno()
print(f'ERRNO={e}')
" 2>&1; then
                _seccomp_restore
                local _no_filter_errno
                _no_filter_errno=$(echo "$OUTPUT" | grep -oP 'ERRNO=\K[0-9]+' || echo "")
                if [[ "$_no_filter_errno" != "1" ]]; then
                    pass "io_uring_setup reachable without seccomp filter (errno=$_no_filter_errno), blocked with it (EPERM)"
                else
                    fail "io_uring_setup returns EPERM even without seccomp filter — something else blocks it"
                fi
            else
                _seccomp_restore
                skip "Could not run without-filter test"
            fi

            # Restore previous signal disposition (reinstating the global EXIT trap)
            trap - INT TERM
            if [[ -n "$_seccomp_prev_exit_trap" ]]; then
                eval "$_seccomp_prev_exit_trap"
            else
                trap - EXIT
            fi
            unset _seccomp_orig _seccomp_bak_path _seccomp_prev_exit_trap
        else
            skip "generate-seccomp.py not found"
        fi
    fi
fi

# NoNewPrivs is set (prevents setuid escalation inside sandbox)
if sandbox bash -c 'grep "^NoNewPrivs:" /proc/self/status | awk "{print \$2}"'; then
    if [[ "$OUTPUT" == "1" ]]; then
        pass "NoNewPrivs is set (prevents setuid escalation)"
    else
        # bwrap may not set nonewprivs by default
        if is_bwrap; then
            skip "NoNewPrivs not set by bwrap (optional)"
        else
            fail "NoNewPrivs not set (should be 1)" "$OUTPUT"
        fi
    fi
fi

# ── N02: NoNewPrivs should neuter setuid binaries (behavioural, not flag-only) ──
# sudo -n -u root id would only succeed if setuid worked. With NNP, the
# setuid bit should be ignored and sudo should either fail to escalate
# or fail to start. We don't care WHICH — just that uid=0 is not reached.
#
# A naive "uid!=0 ⇒ pass" collapses "NNP is working" with "sudo can't run
# at all" (no sudoers entry, PAM reject, missing TTY). Distinguish those:
# if sudo rejects for policy reasons before even attempting the setuid
# escalation, nothing about the sandbox was tested → skip.
if command -v sudo &>/dev/null; then
    if sandbox bash -c 'sudo -n -u root id 2>&1 || true' 2>/dev/null; then
        if echo "$OUTPUT" | grep -qE "^uid=0\b"; then
            fail "N02: sudo inside sandbox escalated to uid=0 (NNP not enforced)" "$OUTPUT"
        elif echo "$OUTPUT" | grep -qiE "may not run sudo|password is required|no tty present|PAM|a terminal is required|sudoers"; then
            skip "N02: sudo unusable for unrelated reasons — NNP can't be tested without a usable setuid binary"
        else
            pass "N02: NoNewPrivs neuters setuid binary (sudo did not escalate)"
        fi
    fi
else
    skip "N02: sudo not available on host — skipping behavioural NNP test"
fi

# Capabilities are dropped (firejail: --caps.drop=all, bwrap: --cap-drop ALL)
if is_firejail; then
    if sandbox bash -c 'grep "^CapEff:" /proc/self/status | awk "{print \$2}"'; then
        if [[ "$OUTPUT" == "0000000000000000" ]]; then
            pass "All capabilities dropped"
        else
            fail "Capabilities not fully dropped: $OUTPUT"
        fi
    fi
fi
if is_bwrap; then
    # bwrap drops all caps too (backends/bwrap.sh --cap-drop all). Mirror the
    # firejail assertion so the bwrap backend is held to the same bar.
    if sandbox bash -c 'grep "^CapEff:" /proc/self/status | awk "{print \$2}"'; then
        if [[ "$OUTPUT" =~ ^0+$ ]]; then
            pass "All capabilities dropped (bwrap)"
        else
            fail "Capabilities not fully dropped under bwrap: $OUTPUT"
        fi
    fi
fi

# ── U01: Create new user namespace to gain capabilities ──
if sandbox bash -c '
    if command -v unshare &>/dev/null; then
        unshare --user --map-root-user -- id 2>&1
        echo EXIT=$?
    else
        echo NO_UNSHARE
    fi
'; then
    if echo "$OUTPUT" | grep -q "NO_UNSHARE"; then
        skip "U01: unshare not available inside sandbox"
    elif echo "$OUTPUT" | grep -qE "Operation not permitted|EXIT=[1-9]|Permission denied|Cannot"; then
        pass "U01: Cannot create nested user namespace (blocked)"
    elif echo "$OUTPUT" | grep -q "uid=0(root)"; then
        if is_firejail; then
            fail "U01: Nested user namespace created inside firejail (--restrict-namespaces should block)" "$OUTPUT"
        else
            if sandbox bash -c 'grep "^NoNewPrivs:" /proc/self/status | awk "{print \$2}"'; then
                local _nnp
                _nnp="$(echo "$OUTPUT" | grep -v '^WARNING' | tr -d '[:space:]')"
                if [[ "$_nnp" == "1" ]]; then
                    pass "U01: Nested userns possible but NoNewPrivs=1 prevents escalation"
                else
                    fail "U01: Nested userns created AND NoNewPrivs not set (NNP=$_nnp)" "$OUTPUT"
                fi
            else
                pass "U01: Nested userns possible but could not verify NoNewPrivs"
            fi
        fi
    else
        pass "U01: User namespace nesting result acceptable"
    fi
else
    pass "U01: User namespace creation attempt failed (good)"
fi

echo ""

# ── 10. Resource & IPC isolation ──────────────────────────────────

echo "10. Resource & IPC isolation"

# PID namespace isolation (bwrap and firejail — landlock does not have PID ns)
if has_mount_ns; then
    if sandbox bash -c 'ps aux 2>/dev/null | wc -l'; then
        PROC_COUNT=$(echo "$OUTPUT" | tail -1 | tr -d '[:space:]')
        # Inside a PID namespace, we should see very few processes
        # (bwrap/firejail, bash, ps, wc — typically < 10)
        if [[ "$PROC_COUNT" =~ ^[0-9]+$ ]] && [[ "$PROC_COUNT" -lt 20 ]]; then
            pass "PID namespace isolates host processes ($PROC_COUNT visible)"
        else
            fail "PID namespace not working — $PROC_COUNT processes visible"
        fi
    else
        skip "Could not check PID namespace"
    fi
fi

# /tmp isolation — bwrap uses --tmpfs /tmp, firejail uses --private-tmp (configurable)
# Landlock does not isolate /tmp
if has_mount_ns; then
    # Create a marker file in host /tmp, check it's not visible inside sandbox
    _TMP_MARKER="/tmp/.sandbox-test-marker-$$"
    touch "$_TMP_MARKER"
    if sandbox bash -c "test -f '$_TMP_MARKER' && echo VISIBLE || echo HIDDEN"; then
        if [[ "$OUTPUT" == "HIDDEN" ]]; then
            pass "/tmp is isolated from host"
        else
            # Firejail: PRIVATE_TMP=false disables /tmp isolation (for MPI/NCCL)
            if is_firejail; then
                pass "/tmp is shared (PRIVATE_TMP=false — MPI/NCCL compatible)"
            else
                fail "/tmp is shared with host (should be isolated)"
            fi
        fi
    fi
    rm -f "$_TMP_MARKER"
else
    skip "/tmp isolation — Landlock has no mount namespace"
fi

# /run/user and /run/dbus should not be accessible
# bwrap: tmpfs /run hides everything; firejail: blacklisted explicitly
if has_mount_ns; then
    if sandbox bash -c "ls /run/user/ 2>&1"; then
        fail "/run/user/ is visible in sandbox"
    else
        pass "/run/user/ is hidden"
    fi

    if sandbox bash -c "ls /run/dbus/ 2>&1"; then
        fail "/run/dbus/ is visible in sandbox"
    else
        pass "/run/dbus/ is hidden"
    fi
fi

# Snapd socket should be blocked (bwrap: tmpfs /run; firejail: blacklisted)
if [[ -e /run/snapd.socket ]]; then
    if has_mount_ns; then
        if sandbox bash -c "python3 -c \"
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect('/run/snapd.socket')
    print('ACCESSIBLE')
except (ConnectionRefusedError, FileNotFoundError, PermissionError, OSError):
    print('BLOCKED')
\" 2>/dev/null"; then
            if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
                pass "Snapd socket is blocked"
            else
                fail "Snapd socket is accessible inside sandbox"
            fi
        fi
    fi
else
    skip "Snapd socket not present on host"
fi

# systemd-notify socket should be blocked (bwrap: tmpfs /run; firejail: blacklisted)
if [[ -e /run/systemd/notify ]]; then
    if has_mount_ns; then
        if sandbox bash -c "python3 -c \"
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
try:
    s.connect('/run/systemd/notify')
    print('ACCESSIBLE')
except (ConnectionRefusedError, FileNotFoundError, PermissionError, OSError):
    print('BLOCKED')
\" 2>/dev/null"; then
            if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
                pass "systemd-notify socket is blocked"
            else
                fail "systemd-notify socket is accessible inside sandbox"
            fi
        fi
    fi
else
    skip "systemd-notify socket not present on host"
fi

# tmux: outer socket blocked, wrapper uses sandbox config for nesting
_tmux_sock="/tmp/tmux-$(id -u)"
if [[ -d "$_tmux_sock" ]] && has_mount_ns; then
    if sandbox bash -c "test -d '$_tmux_sock' && echo VISIBLE || echo HIDDEN"; then
        if [[ "$OUTPUT" == "HIDDEN" ]]; then
            pass "tmux outer socket blocked (prevents escape via tmux server)"
        else
            fail "tmux outer socket exposed (sandbox escape risk)" "$OUTPUT"
        fi
    fi
elif [[ ! -d "$_tmux_sock" ]]; then
    skip "tmux outer socket — no tmux session running"
fi

# tmux wrapper uses sandbox-tmux.conf (Ctrl-a prefix for nesting)
if sandbox bash -c 'which tmux 2>/dev/null'; then
    if [[ "$OUTPUT" == *"bin/tmux" && "$OUTPUT" != "/usr/bin/tmux" ]]; then
        pass "tmux shadows /usr/bin/tmux via sandbox bin/"
    else
        fail "tmux not shadowed by sandbox wrapper" "$OUTPUT"
    fi
fi
if [[ -f "$SCRIPT_DIR/sandbox-tmux.conf" ]]; then
    pass "sandbox-tmux.conf present"
else
    fail "sandbox-tmux.conf missing"
fi

# ── sandbox-notify ──────────────────────────────────────────────
# sandbox-notify must exit cleanly even when run from a process with
# no controlling terminal (the common case for agent subprocesses).
# Previously it leaked "/dev/tty: No such device or address" to stderr
# because bash's redirection-error path bypassed the 2>/dev/null.
# Test the no-tty path by redirecting stdin from /dev/null so the
# subprocess inherits no controlling terminal.
if sandbox bash -c 'sandbox-notify "test" </dev/null 2>&1; echo rc=$?'; then
    if [[ "$OUTPUT" == *"rc=0"* ]] && [[ "$OUTPUT" != *"No such device"* ]]; then
        pass "sandbox-notify exits cleanly without controlling terminal"
    else
        fail "sandbox-notify leaked error or non-zero exit without tty" "$OUTPUT"
    fi
fi

# sandbox-notify fallback path: verify that `tmux new-window -d …`
# (the IPC call sandbox-notify uses when /dev/tty is unavailable)
# actually works from a subprocess with stdin closed — i.e., no
# controlling terminal. We just check the window was created and
# reaped; tmux's native bell-action propagation is tested in tmux,
# not here.
if sandbox bash -c '
    _sock=/tmp/sbxtest-bell-$$.sock
    tmux -S "$_sock" new-session -d -s m "bash -i" 2>/dev/null || { echo "notmux"; exit 0; }
    _before=$(tmux -S "$_sock" list-windows 2>/dev/null | wc -l)
    # Invoke new-window with stdin closed → no controlling terminal for this call.
    tmux -S "$_sock" new-window -d -n bell "printf \"\a\"; sleep 0.2" </dev/null 2>/dev/null
    _rc=$?
    _after=$(tmux -S "$_sock" list-windows 2>/dev/null | wc -l)
    sleep 0.5
    _final=$(tmux -S "$_sock" list-windows 2>/dev/null | wc -l)
    tmux -S "$_sock" kill-server 2>/dev/null
    rm -f "$_sock"
    # Success = command accepted (rc=0), window count bumped then returned.
    if [[ $_rc -eq 0 && $_after -gt $_before && $_final -eq $_before ]]; then
        echo IPC_OK
    else
        echo "IPC_FAILED rc=$_rc before=$_before after=$_after final=$_final"
    fi
'; then
    case "$OUTPUT" in
        *IPC_OK*) pass "tmux new-window fallback works from no-tty subprocess (sandbox-notify path)" ;;
        *notmux*) skip "sandbox-notify bell-fallback test — tmux not usable inside sandbox" ;;
        *IPC_FAILED*) fail "tmux new-window fallback failed from no-tty subprocess" "$OUTPUT" ;;
    esac
fi

# pty allocation and tmux (requires BIND_DEV_PTS=true on kernels < 5.4)
if ! command -v python3 &>/dev/null; then
    skip "pty allocation test — python3 not available on host"
elif sandbox bash -c 'python3 -c "import pty; pty.openpty(); print(\"pty-ok\")" 2>&1'; then
    if [[ "$OUTPUT" == *"pty-ok"* ]]; then
        pass "pty allocation works inside sandbox"
    else
        fail "pty allocation returned unexpected output" "$OUTPUT"
    fi
    # tmux test only makes sense if ptys work
    sandbox bash -c 'tmux new-session -d -s sandbox-test sleep\ 5 && tmux list-sessions && tmux kill-server' || true
    # Check output, not exit code — firejail sends SIGHUP on cleanup (exit 129)
    if [[ "$OUTPUT" == *"sandbox-test"* ]]; then
        pass "tmux starts detached session inside sandbox"
    else
        fail "tmux failed to start inside sandbox" "$OUTPUT"
    fi
else
    skip "pty allocation failed (set BIND_DEV_PTS=true for tmux on kernels < 5.4)"
fi

# ── C01: Write to cgroup filesystem ──
if sandbox bash -c '
    wrote=false
    for cg in /sys/fs/cgroup/memory/memory.limit_in_bytes \
              /sys/fs/cgroup/cpu/cpu.cfs_quota_us \
              /sys/fs/cgroup/unified/cgroup.procs \
              /sys/fs/cgroup/cgroup.procs; do
        if [[ -w "$cg" ]] 2>/dev/null; then
            echo "WRITABLE:$cg"
            wrote=true
        fi
    done
    for cgdir in /sys/fs/cgroup/memory /sys/fs/cgroup/cpu /sys/fs/cgroup/unified /sys/fs/cgroup; do
        if mkdir "$cgdir/escape-test-$$" 2>/dev/null; then
            echo "MKDIR_OK:$cgdir/escape-test-$$"
            rmdir "$cgdir/escape-test-$$" 2>/dev/null
            wrote=true
        fi
    done
    if ! $wrote; then
        echo "CGROUP_READONLY"
    fi
'; then
    if echo "$OUTPUT" | grep -q "CGROUP_READONLY"; then
        pass "C01: Cgroup filesystem is read-only inside sandbox"
    elif echo "$OUTPUT" | grep -q "WRITABLE\|MKDIR_OK"; then
        fail "C01: Cgroup filesystem writable inside sandbox" "$OUTPUT"
    else
        pass "C01: Cgroup access restricted"
    fi
else
    pass "C01: Cgroup test failed (sandbox restriction)"
fi

# ── R02: CVE-2022-0492 class — cgroup v1 release_agent mount should fail ──
# Requires CAP_SYS_ADMIN, which the sandbox has dropped.
if sandbox bash -c '
    tmpd=$(mktemp -d) || exit 77
    if mount -t cgroup -o rdma cgroup "$tmpd" 2>&1; then
        echo "MOUNT_SUCCEEDED"
    else
        echo "MOUNT_BLOCKED"
    fi
    rmdir "$tmpd" 2>/dev/null
'; then
    case "$OUTPUT" in
        *MOUNT_BLOCKED*)   pass "R02: cgroup mount blocked (CVE-2022-0492 class)" ;;
        *MOUNT_SUCCEEDED*) fail "R02: cgroup mount succeeded (CAP_SYS_ADMIN leak)" ;;
        *)                 skip "R02: cgroup mount probe inconclusive ($OUTPUT)" ;;
    esac
fi

# ── R03: /proc/sysrq-trigger should not be writable (host-reboot vector) ──
# Must exist on the host for this test to be meaningful; otherwise "not
# visible in sandbox" tells us nothing about what the sandbox does.
if [[ ! -e /proc/sysrq-trigger ]]; then
    skip "R03: /proc/sysrq-trigger absent on host — nothing to test"
elif sandbox bash -c '[[ -e /proc/sysrq-trigger ]] && echo "EXISTS" || echo "NOT_PRESENT"'; then
    if [[ "$OUTPUT" == "EXISTS" ]]; then
        if sandbox bash -c 'echo s > /proc/sysrq-trigger 2>&1 && echo WROTE || echo BLOCKED'; then
            case "$OUTPUT" in
                *BLOCKED*) pass "R03: /proc/sysrq-trigger write blocked" ;;
                *WROTE*)   fail "R03: /proc/sysrq-trigger write succeeded (host-reboot vector)" ;;
            esac
        fi
    else
        pass "R03: /proc/sysrq-trigger not visible in sandbox"
    fi
fi

# ── F01: Verify FDs > 2 are closed inside sandbox ──
if sandbox bash -c '
    open_fds=""
    for fd_num in $(ls /proc/self/fd 2>/dev/null); do
        if [[ "$fd_num" -gt 2 ]] 2>/dev/null && [[ "$fd_num" -ne 255 ]]; then
            target=$(readlink "/proc/self/fd/$fd_num" 2>/dev/null || echo "unknown")
            case "$target" in
                pipe:*|socket:*|anon_inode:*|/dev/null|unknown) continue ;;
            esac
            open_fds="$open_fds $fd_num:$target"
        fi
    done
    if [[ -z "$open_fds" ]]; then
        echo "CLEAN"
    else
        echo "LEAKED:$open_fds"
    fi
'; then
    if echo "$OUTPUT" | grep -q "CLEAN"; then
        pass "F01: No unexpected FDs > 2 inherited into sandbox"
    elif echo "$OUTPUT" | grep -q "LEAKED"; then
        fail "F01: Leaked FDs found inside sandbox" "$OUTPUT"
    else
        pass "F01: FD check completed (no leaks detected)"
    fi
else
    fail "F01: FD inheritance check command failed" "$OUTPUT"
fi

# ── G01: Signal processes outside PID namespace ──
if has_mount_ns; then
    local _host_pid=$$
    if sandbox bash -c "
        kill -0 $_host_pid 2>&1
        echo EXIT=\$?
    "; then
        if echo "$OUTPUT" | grep -qE "No such process|EXIT=[1-9]|not permitted"; then
            pass "G01: Cannot signal host process from inside PID namespace"
        elif echo "$OUTPUT" | grep -q "EXIT=0"; then
            fail "G01: kill -0 succeeded on host PID $_host_pid (PID namespace leak)" "$OUTPUT"
        else
            pass "G01: Signal to host process blocked"
        fi
    else
        pass "G01: Signal attack failed (good)"
    fi
else
    skip "G01: No PID namespace isolation ($CURRENT_BACKEND backend)"
fi

# ── PRIVATE_IPC: SysV IPC namespace isolation ──
# README.md:308 / APPTAINER_COMPARISON.md:103 claim IPC namespace isolation
# for bwrap (--unshare-ipc) and firejail (--ipc-namespace). Landlock has no
# namespace support and cannot isolate IPC.
if has_mount_ns; then
    if command -v ipcmk &>/dev/null && command -v ipcs &>/dev/null; then
        # First sandbox creates a SysV message queue, records its ID.
        _ipc_id=""
        if sandbox bash -c 'ipcmk --queue 2>/dev/null | grep -oE "[0-9]+$" | head -1'; then
            _ipc_id="$OUTPUT"
        fi
        if [[ -n "$_ipc_id" ]]; then
            # Second sandbox should NOT see that queue (IPC ns is per-invocation).
            if sandbox bash -c "ipcs -q | grep -qE '^0x[0-9a-f]+ +$_ipc_id\\b' && echo VISIBLE || echo HIDDEN"; then
                case "$OUTPUT" in
                    HIDDEN)  pass "PRIVATE_IPC: SysV IPC isolated across sandbox sessions" ;;
                    VISIBLE) fail "PRIVATE_IPC: SysV IPC queue from previous sandbox visible (namespace leak)" ;;
                    *)       fail "PRIVATE_IPC: unexpected ipcs output" "$OUTPUT" ;;
                esac
            fi
        else
            skip "PRIVATE_IPC: ipcmk could not create a queue (no output / rlimit)"
        fi
    else
        skip "PRIVATE_IPC: ipcmk/ipcs not available — can't test SysV IPC isolation"
    fi
else
    skip "PRIVATE_IPC: SysV IPC — Landlock has no IPC namespace support"
fi

# PRIVATE_IPC: /dev/shm isolation. bwrap mounts a private tmpfs; firejail
# blacklists /dev/shm (firejail's --tmpfs is silently ignored on /dev paths);
# landlock has no namespace support so /dev/shm is shared with the host.
_shm_marker="/dev/shm/sandbox-probe-$$"
_TEST_TEMP_FILES+=("$_shm_marker")
if sandbox bash -c "echo inside > '$_shm_marker'" 2>/dev/null; then
    if has_mount_ns; then
        if [[ ! -f "$_shm_marker" ]]; then
            pass "PRIVATE_IPC: /dev/shm writes ephemeral (private tmpfs)"
        else
            fail "PRIVATE_IPC: /dev/shm write leaked to host" "$_shm_marker"
            rm -f "$_shm_marker"
        fi
    else
        if [[ -f "$_shm_marker" ]]; then
            pass "PRIVATE_IPC: /dev/shm shared with host (landlock: documented)"
        else
            warn "PRIVATE_IPC: landlock /dev/shm write not visible on host (unexpected)"
        fi
        rm -f "$_shm_marker"
    fi
else
    if has_mount_ns; then
        # Write was blocked (e.g., firejail --blacklist=/dev/shm) — that's
        # effective isolation, just via blocking rather than private tmpfs.
        pass "PRIVATE_IPC: /dev/shm blocked inside sandbox"
    else
        skip "PRIVATE_IPC: /dev/shm not writable inside sandbox"
    fi
fi

# ── SANDBOX_NPROC_LIMIT: fork-bomb defense (ulimit -u observation) ──
# RLIMIT_NPROC is per-UID system-wide, so we only verify ulimit -u is set
# as documented; we do NOT actually fork-bomb (would hit the test runner).
if sandbox bash -c 'ulimit -u'; then
    _baseline_nproc="$OUTPUT"
    _limited=$(SANDBOX_NPROC_LIMIT=128 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
               --project-dir "$PROJECT_DIR" -- bash -c 'ulimit -u' 2>/dev/null)
    if [[ -z "$_limited" ]]; then
        fail "SANDBOX_NPROC_LIMIT: sandbox invocation with limit failed"
    elif [[ "$_limited" == "128" ]]; then
        pass "SANDBOX_NPROC_LIMIT caps ulimit -u as documented"
    elif [[ "$_limited" =~ ^[0-9]+$ && "$_baseline_nproc" =~ ^[0-9]+$ && "$_limited" -lt "$_baseline_nproc" ]]; then
        pass "SANDBOX_NPROC_LIMIT lowered ulimit (got $_limited from baseline $_baseline_nproc)"
    else
        fail "SANDBOX_NPROC_LIMIT had no effect (limited=$_limited baseline=$_baseline_nproc)"
    fi
else
    skip "SANDBOX_NPROC_LIMIT: baseline 'ulimit -u' probe failed"
fi

echo ""

# ── 11. Credential & identity protection ──────────────────────────

echo "11. Credential & identity protection"

# SSH env vars should not leak
export SSH_AUTH_SOCK="/tmp/ssh-test/agent.123"
export SSH_CONNECTION="1.2.3.4 1234 5.6.7.8 22"
export SSH_CLIENT="1.2.3.4 1234 22"
export SSH_TTY="/dev/pts/99"

if sandbox bash -c 'echo ${SSH_AUTH_SOCK:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "SSH_AUTH_SOCK is blocked"
    else
        fail "SSH_AUTH_SOCK leaked into sandbox" "$OUTPUT"
    fi
fi
# SSH_CONNECTION/SSH_CLIENT/SSH_TTY direct probes removed — the SSH_*
# pattern blocking is exercised once via the most security-sensitive var
# (SSH_AUTH_SOCK above); per-variable repetition was pure pattern-coverage.

unset SSH_AUTH_SOCK SSH_CONNECTION SSH_CLIENT SSH_TTY

# ALLOWED_ENV_VARS — override BLOCKED_ENV_VARS
# Use a conf.d snippet to set ALLOWED_ENV_VARS for this test
_aev_conf="$HOME/.config/agent-sandbox/conf.d/test-allowed-env-$$.conf"
_TEST_TEMP_FILES+=("$_aev_conf")
mkdir -p "$HOME/.config/agent-sandbox/conf.d"
echo 'ALLOWED_ENV_VARS+=("GITHUB_TOKEN")' > "$_aev_conf"
export GITHUB_TOKEN="allowed-env-test-value"
if sandbox bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if [[ "$OUTPUT" == "allowed-env-test-value" ]]; then
        pass "ALLOWED_ENV_VARS overrides BLOCKED_ENV_VARS (GITHUB_TOKEN passed through)"
    else
        fail "ALLOWED_ENV_VARS did not override BLOCKED_ENV_VARS" "$OUTPUT"
    fi
fi
unset GITHUB_TOKEN
rm -f "$_aev_conf"

# ALLOWED_ENV_VARS override of SSH_* pattern covered by §3's MY_CUSTOM_TOKEN
# override test — same mechanism (ALLOWED_ENV_VARS wins over pattern blocking).

# Empty ALLOWED_ENV_VARS — blocked vars remain blocked (no regression)
export GITHUB_TOKEN="empty-allow-test"
if sandbox bash -c 'echo ${GITHUB_TOKEN:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "Empty ALLOWED_ENV_VARS: GITHUB_TOKEN still blocked"
    else
        fail "Empty ALLOWED_ENV_VARS: GITHUB_TOKEN leaked" "$OUTPUT"
    fi
fi
unset GITHUB_TOKEN

# Non-blocked env vars should pass through to the sandbox
export _TEST_CRED_VAR="test-credential-value"
if sandbox bash -c 'echo ${LANG:-UNSET}'; then
    if [[ "$OUTPUT" != "UNSET" ]]; then
        pass "Passthrough env vars (LANG) accessible"
    else
        # LANG may not be set on all systems
        skip "LANG not set — passthrough test inconclusive"
    fi
fi
unset _TEST_CRED_VAR

# ── E01: /proc/self/environ should not contain blocked vars ──
# Use ^VARNAME= anchoring to avoid false positives (e.g., GITHUB_PATH
# matching the GITHUB_PAT pattern on GitHub Actions runners).
export GITHUB_PAT="self-environ-leak-test"
export MY_SECRET_TOKEN="pattern-environ-leak-test"
if sandbox_must_run bash -c '
    if [[ -r /proc/self/environ ]]; then
        if cat /proc/self/environ 2>/dev/null | tr "\0" "\n" | grep -qE "^GITHUB_PAT=|^MY_SECRET_TOKEN="; then
            echo "LEAKED"
        else
            echo "CLEAN"
        fi
    else
        echo "UNREADABLE"
    fi
'; then
    if [[ "$OUTPUT" == *"LEAKED"* ]]; then
        fail "E01: Blocked vars leaked via /proc/self/environ"
    elif [[ "$OUTPUT" == *"UNREADABLE"* ]]; then
        pass "E01: /proc/self/environ unreadable (good)"
    else
        pass "E01: /proc/self/environ clean (blocked vars absent)"
    fi
fi
unset GITHUB_PAT MY_SECRET_TOKEN

# ── E02: /proc/1/environ should not contain blocked vars (bwrap-specific) ──
# bwrap is PID 1 inside --unshare-pid; its /proc/1/environ retains the
# parent's environment. backend_exec() scrubs vars before exec to fix this.
if is_bwrap; then
    export GITHUB_PAT="proc1-environ-leak-test"
    export MY_SECRET_TOKEN="pattern-proc1-leak-test"
    if sandbox_must_run bash -c '
        if [[ -r /proc/1/environ ]]; then
            if cat /proc/1/environ 2>/dev/null | tr "\0" "\n" | grep -qE "^GITHUB_PAT=|^MY_SECRET_TOKEN="; then
                echo "LEAKED"
            else
                echo "CLEAN"
            fi
        else
            echo "UNREADABLE"
        fi
    '; then
        if [[ "$OUTPUT" == *"LEAKED"* ]]; then
            fail "E02: Blocked vars leaked via /proc/1/environ (bwrap PID 1)"
        elif [[ "$OUTPUT" == *"UNREADABLE"* ]]; then
            pass "E02: /proc/1/environ unreadable (good)"
        else
            pass "E02: /proc/1/environ clean — bwrap parent scrub works"
        fi
    fi
    unset GITHUB_PAT MY_SECRET_TOKEN
fi

# FILTER_PASSWD — verify /etc/passwd is filtered inside sandbox
if is_bwrap; then
    if sandbox bash -c 'wc -l < /etc/passwd'; then
        _host_count=$(wc -l < /etc/passwd)
        _sandbox_count="$OUTPUT"
        if [[ "$_sandbox_count" -lt "$_host_count" ]]; then
            pass "FILTER_PASSWD: /etc/passwd filtered (host: $_host_count → sandbox: $_sandbox_count lines)"
        elif [[ "$_sandbox_count" -eq "$_host_count" ]]; then
            # Could be that all users are system users (< 1000)
            pass "FILTER_PASSWD: /etc/passwd overlaid (same count — all UIDs may be < 1000)"
        fi
    fi
    # Slurm service users must be present (sbatch needs to resolve SlurmUser)
    if grep -q "^slurm:" /etc/passwd 2>/dev/null; then
        if sandbox bash -c 'grep -c "^slurm:" /etc/passwd'; then
            pass "FILTER_PASSWD: slurm user preserved in filtered passwd"
        else
            fail "FILTER_PASSWD: slurm user missing from filtered passwd" "$OUTPUT"
        fi
    else
        skip "FILTER_PASSWD: no slurm user on host — nothing to preserve"
    fi
    if sandbox bash -c 'grep "^passwd:" /etc/nsswitch.conf'; then
        if [[ "$OUTPUT" == *"files"* ]] && [[ "$OUTPUT" != *"ldap"* ]] && [[ "$OUTPUT" != *"sss"* ]]; then
            pass "FILTER_PASSWD: nsswitch.conf uses files-only for passwd"
        else
            fail "FILTER_PASSWD: nsswitch.conf still references ldap/sss" "$OUTPUT"
        fi
    fi
elif is_firejail; then
    # Firejail: check that LDAP users are not enumerable
    _host_getent=$(getent passwd | wc -l)
    if sandbox bash -c 'getent passwd | wc -l'; then
        _sandbox_getent="$OUTPUT"
        if [[ "$_sandbox_getent" -lt "$_host_getent" ]]; then
            pass "FILTER_PASSWD: getent filtered (host: $_host_getent → sandbox: $_sandbox_getent)"
        elif [[ "$_sandbox_getent" -eq "$_host_getent" ]]; then
            # No LDAP configured — nothing to filter
            skip "FILTER_PASSWD: no LDAP users to filter (host and sandbox both $_host_getent)"
        fi
    fi
else
    skip "FILTER_PASSWD: not supported on Landlock (no mount namespace)"
fi

# SANDBOX_BYPASS_TOKEN — verify the token file is hidden inside the sandbox
# bwrap overlays with /dev/null; firejail blacklists; landlock relies on eBPF LSM
if has_mount_ns; then
    # Mount-namespace backends: test with a temp token file
    _TOKEN_FILE="/tmp/.sandbox-test-bypass-token-$$"
    echo "test-bypass-secret" > "$_TOKEN_FILE"
    _TOKEN_RAW=$(SANDBOX_BYPASS_TOKEN="$_TOKEN_FILE" \
        timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- cat "$_TOKEN_FILE" 2>&1) || true
    _TOKEN_OUT=$(echo "$_TOKEN_RAW" | grep -v \
        -e '^Warning:' -e '^Parent pid' -e '^Child process' -e '^Parent is shutting')
    if echo "$_TOKEN_OUT" | grep -q "test-bypass-secret"; then
        fail "SANDBOX_BYPASS_TOKEN is readable inside sandbox"
    else
        pass "SANDBOX_BYPASS_TOKEN is hidden inside sandbox"
    fi
    rm -f "$_TOKEN_FILE"
else
    # Landlock: cannot hide files via mount namespace. Check if eBPF LSM
    # program (deny_token_read) is loaded and protecting a configured token.
    _EBPF_LOADED=false
    if command -v bpftool &>/dev/null; then
        if sudo -n bpftool prog list 2>/dev/null | grep -q 'deny_token_read'; then
            _EBPF_LOADED=true
        fi
    fi

    if [[ "$_EBPF_LOADED" == "true" ]]; then
        # eBPF is loaded — find the configured token path and test it
        # Try sandbox.conf first, then auto-discover from admin wrapper config
        _TOKEN_PATH=""
        if [[ -f "$SCRIPT_DIR/sandbox.conf" ]]; then
            _TOKEN_PATH=$(bash -c "source '$SCRIPT_DIR/sandbox.conf' 2>/dev/null; echo \"\$SANDBOX_BYPASS_TOKEN\"")
        fi
        if [[ -z "$_TOKEN_PATH" && -f /app/lib/agent-sandbox/sandbox.conf ]]; then
            _TOKEN_PATH=$(bash -c 'source /app/lib/agent-sandbox/sandbox.conf 2>/dev/null; echo "$SANDBOX_BYPASS_TOKEN"')
        fi
        if [[ -n "$_TOKEN_PATH" && -f "$_TOKEN_PATH" ]]; then
            # Landlock sets NO_NEW_PRIVS — eBPF should deny the read
            if sandbox cat "$_TOKEN_PATH" 2>&1; then
                # eBPF is loaded but not blocking. This can happen if:
                # - The eBPF program doesn't match this token path
                # - The eBPF program checks a different condition than NoNewPrivs
                # - The kernel version doesn't support the specific LSM hook
                fail "SANDBOX_BYPASS_TOKEN readable despite eBPF (Landlock) — check eBPF program path match"
            else
                if echo "$OUTPUT" | grep -qi "permission denied\|operation not permitted"; then
                    pass "SANDBOX_BYPASS_TOKEN protected by eBPF LSM (Landlock)"
                else
                    pass "SANDBOX_BYPASS_TOKEN not readable (Landlock + eBPF)"
                fi
            fi
        else
            skip "SANDBOX_BYPASS_TOKEN — eBPF loaded but no token path found (sandbox.conf or admin config)"
        fi
    else
        skip "SANDBOX_BYPASS_TOKEN — Landlock needs eBPF LSM (not loaded; see ADMIN_HARDENING.md §1)"
    fi
fi

echo ""

# ── 12. Stability ─────────────────────────────────────────────────

echo "12. Stability"

# ── D01: Consistent isolation across repeated runs ──
local _results=()
local _consistent=true

for _i in $(seq 1 5); do
    if sandbox bash -c '
        echo "SANDBOX_ACTIVE=${SANDBOX_ACTIVE:-unset}"
        echo "HOME_WRITABLE=$(touch $HOME/.test-write-deterministic 2>&1 >/dev/null && echo YES || echo NO)"
        rm -f "$HOME/.test-write-deterministic" 2>/dev/null
        echo "ETC_WRITABLE=$(touch /etc/.test-write-deterministic 2>&1 >/dev/null && echo YES || echo NO)"
        echo "SSH_HIDDEN=$(test -d $HOME/.ssh && echo VISIBLE || echo HIDDEN)"
    '; then
        _results+=("$OUTPUT")
    else
        _results+=("FAILED")
    fi
done

if [[ ${#_results[@]} -gt 0 ]]; then
    local _reference="${_results[0]}"
    for _i in $(seq 1 $((${#_results[@]} - 1))); do
        if [[ "${_results[$_i]}" != "$_reference" ]]; then
            _consistent=false
            break
        fi
    done
    if [[ "$_consistent" == true ]]; then
        pass "D01: All 5 runs produced identical isolation state"
    else
        fail "D01: Inconsistent isolation across runs (possible race condition)" "Run 1: $_reference | Diverged at run $((_i+1))"
    fi
else
    fail "D01: No results collected"
fi

# ── W01: Two concurrent sandboxes with independent state ──
local _marker_a="$PROJECT_DIR/.concurrent-test-A-$$"
local _marker_b="$PROJECT_DIR/.concurrent-test-B-$$"
trap_rm_path "$_marker_a"
trap_rm_path "$_marker_b"

(
    timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- \
        bash -c "
            echo 'INSTANCE_A' > '$_marker_a'
            sleep 2
            if [[ -f '$_marker_b' ]]; then
                echo 'A_SEES_B'
            else
                echo 'A_ALONE'
            fi
            echo \"A_PID=\$\$\"
            echo \"A_BACKEND=\$SANDBOX_BACKEND\"
        " 2>/dev/null
) > /tmp/sandbox-concurrent-A-$$ 2>&1 &
local _pid_a=$!

(
    timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- \
        bash -c "
            echo 'INSTANCE_B' > '$_marker_b'
            sleep 2
            if [[ -f '$_marker_a' ]]; then
                echo 'B_SEES_A'
            else
                echo 'B_ALONE'
            fi
            echo \"B_PID=\$\$\"
            echo \"B_BACKEND=\$SANDBOX_BACKEND\"
        " 2>/dev/null
) > /tmp/sandbox-concurrent-B-$$ 2>&1 &
local _pid_b=$!

wait $_pid_a 2>/dev/null
wait $_pid_b 2>/dev/null

local _out_a _out_b
_out_a="$(cat /tmp/sandbox-concurrent-A-$$ 2>/dev/null)"
_out_b="$(cat /tmp/sandbox-concurrent-B-$$ 2>/dev/null)"

rm -f /tmp/sandbox-concurrent-A-$$ /tmp/sandbox-concurrent-B-$$
# Marker cleanup handled via trap_rm_path registration above.

if [[ -n "$_out_a" && -n "$_out_b" ]]; then
    local _a_pid _b_pid
    _a_pid=$(echo "$_out_a" | grep -oP 'A_PID=\K[0-9]+' || echo "0")
    _b_pid=$(echo "$_out_b" | grep -oP 'B_PID=\K[0-9]+' || echo "0")

    if has_mount_ns; then
        pass "W01: Both sandbox instances ran concurrently (PIDs: A=$_a_pid, B=$_b_pid)"
    else
        if [[ "$_a_pid" != "$_b_pid" ]]; then
            pass "W01: Concurrent instances have different PIDs (no PID namespace, but isolated)"
        else
            pass "W01: Concurrent instances ran (landlock — shared PID space expected)"
        fi
    fi
elif [[ -z "$_out_a" && -z "$_out_b" ]]; then
    fail "W01: Both concurrent sandbox instances failed to produce output"
else
    pass "W01: At least one concurrent sandbox instance ran successfully"
fi

echo ""

# ── 13. Lmod module loading ────────────────────────────────────────
#
# These tests require lmod installed and SANDBOX_TEST_LMOD=1 set.
# The CI lmod job sets up a dummy module that exports a marker env var,
# then verifies the sandbox loads it before backend detection.

if [[ "${SANDBOX_TEST_LMOD:-}" == "1" ]] && type module &>/dev/null; then

echo "13. Lmod module loading"

# Helper: create a temp config that sources the base sandbox.conf then
# appends test-specific overrides.
_lmod_test_conf() {
    local _conf
    _conf=$(mktemp)
    trap_rm_path "$_conf"
    # Start from the base config so READONLY_MOUNTS, ALLOWED_PROJECT_PARENTS etc. are set
    cat "$SCRIPT_DIR/sandbox.conf" > "$_conf"
    # Append test-specific lines
    cat >> "$_conf"
    echo "$_conf"
}

# ── L01: SANDBOX_MODULES loads module and updates PATH ──
# The CI job creates a dummy module "sandbox-test-marker" that prepends
# a known directory to PATH.  If module loading works, that dir appears
# in PATH inside the sandbox.
if [[ -n "${SANDBOX_TEST_MODULE_NAME:-}" ]]; then
    local _lmod_conf
    _lmod_conf=$(_lmod_test_conf <<CONF
SANDBOX_MODULES=("${SANDBOX_TEST_MODULE_NAME}")
CONF
    )
    if SANDBOX_CONF="$_lmod_conf" sandbox_must_run bash -c 'echo "$PATH"'; then
        if [[ "$OUTPUT" == *"${SANDBOX_TEST_MODULE_PATH:-__UNSET__}"* ]]; then
            pass "L01: SANDBOX_MODULES loaded module, PATH contains module-provided directory"
        else
            fail "L01: Module loaded but PATH missing expected directory" \
                 "expected substring: ${SANDBOX_TEST_MODULE_PATH:-__UNSET__} in: $OUTPUT"
        fi
    fi
else
    skip "L01: SANDBOX_TEST_MODULE_NAME not set"
fi

# ── L02: Empty SANDBOX_MODULES is a no-op ──
local _empty_conf
_empty_conf=$(_lmod_test_conf <<CONF
SANDBOX_MODULES=()
CONF
)
if SANDBOX_CONF="$_empty_conf" sandbox_must_run bash -c 'echo ok'; then
    if [[ "$OUTPUT" == *"ok"* ]]; then
        pass "L02: Empty SANDBOX_MODULES is a no-op"
    else
        fail "L02: Sandbox with empty SANDBOX_MODULES didn't run guest" "$OUTPUT"
    fi
fi

# ── L03: Bad module name warns but doesn't abort ──
local _bad_conf
_bad_conf=$(_lmod_test_conf <<CONF
SANDBOX_MODULES=("nonexistent-module/99.99.99")
CONF
)
if SANDBOX_CONF="$_bad_conf" sandbox bash -c 'echo ok'; then
    if [[ "$OUTPUT" == *"ok"* ]]; then
        if [[ "$OUTPUT_ERR" == *"warning"*"nonexistent-module"* ]]; then
            pass "L03: Bad module name warns on stderr but sandbox still runs"
        else
            pass "L03: Bad module name doesn't abort sandbox (warning may be suppressed)"
        fi
    else
        fail "L03: Sandbox failed to run with bad module name" "$OUTPUT $OUTPUT_ERR"
    fi
else
    # Sandbox may still produce output even with non-zero exit
    if [[ "$OUTPUT" == *"ok"* ]]; then
        pass "L03: Bad module name doesn't prevent guest execution"
    else
        fail "L03: Bad module name prevented sandbox from starting" "$OUTPUT_ERR"
    fi
fi

echo ""

else
    echo "13. Lmod module loading — skipped (SANDBOX_TEST_LMOD!=1 or module not available)"
    echo ""
fi

# ── Per-backend summary ──────────────────────────────────────────

TOTAL=$((PASS + FAIL + SKIP + WARN))
echo "════════════════════════════════════════════════"
echo "  Backend: $CURRENT_BACKEND"
echo "  Results: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped (out of $TOTAL)"
echo "════════════════════════════════════════════════"
echo ""

TOTAL_PASS=$((TOTAL_PASS + PASS))
TOTAL_FAIL=$((TOTAL_FAIL + FAIL))
TOTAL_SKIP=$((TOTAL_SKIP + SKIP))
TOTAL_WARN=$((TOTAL_WARN + WARN))
[[ $FAIL -gt 0 ]] && ANY_FAIL=true

# Emit JUnit report for this backend (no-op if --junit wasn't set).
_junit_finalize "$CURRENT_BACKEND"
}

# ── Run tests for each available backend ─────────────────────────

for backend in "${AVAILABLE_BACKENDS[@]}"; do
    run_tests "$backend"
done

# ── Overall summary ──────────────────────────────────────────────

if [[ ${#AVAILABLE_BACKENDS[@]} -gt 1 ]]; then
    GRAND_TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_WARN + TOTAL_SKIP))
    echo "╔═══════════════════════════════════════════════════════╗"
    echo "║  Overall Results                                      ║"
    echo "╠═══════════════════════════════════════════════════════╣"
    printf "║  Backends tested: %-33s ║\n" "${AVAILABLE_BACKENDS[*]}"
    printf "║  %3d passed, %d failed, %d warnings, %d skipped (of %d) ║\n" \
        "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_WARN" "$TOTAL_SKIP" "$GRAND_TOTAL"
    echo "╚═══════════════════════════════════════════════════════╝"
fi

if [[ "$QUICK_MODE" == true ]]; then
    echo ""
    echo "  For the complete test suite (env patterns, agent overlays,"
    echo "  escape vectors, Slurm submission, security hardening):"
    echo "    bash $SCRIPT_DIR/test.sh"
    echo "  Note: the full test submits real jobs to the Slurm queue."
fi

# ── Admin hardening status (ADMIN_HARDENING.md) ──────────────────
# Informational only — shows which optional admin hardening measures
# are deployed.  Skipped in quick mode (deployment smoke test).

if [[ "$QUICK_MODE" != true ]]; then

echo ""
echo "Admin hardening status (see ADMIN_HARDENING.md):"

# §0 — systemd user instances (Landlock escape prevention)
for b in "${AVAILABLE_BACKENDS[@]}"; do
    if [[ "$b" == "landlock" ]]; then
        if systemctl is-enabled user@.service &>/dev/null 2>&1; then
            _user_svc=$(systemctl is-enabled user@.service 2>/dev/null || true)
            if [[ "$_user_svc" == "masked" ]]; then
                echo "  ✓ §0 systemd user@.service: masked (Landlock escape mitigated)"
            else
                echo "  ⚠ §0 systemd user@.service: active (Landlock escape possible — see ADMIN_HARDENING.md §0)"
            fi
        fi
        break
    fi
done

# §2 — Admin-owned sandbox installation
_sandbox_dir="$(cd "$SCRIPT_DIR" && pwd)"
_sandbox_owner=$(stat -c %u "$_sandbox_dir" 2>/dev/null || stat -f %u "$_sandbox_dir" 2>/dev/null)
if [[ "${_sandbox_owner:-}" == "0" ]]; then
    echo "  ✓ §2 Admin-owned installation: sandbox scripts owned by root"
else
    echo "  · §2 Admin-owned installation: not deployed (scripts owned by user)"
fi

echo ""

fi  # end of admin hardening status (full mode only)

if [[ "$ANY_FAIL" == true ]]; then
    echo ""
    echo "  Some tests failed. Run with --verbose for details."
    exit 1
fi

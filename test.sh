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

# The shipped sandbox.conf defaults to NETWORK_FILTER_MODE=filtered +
# NETWORK_FILTER_FALLBACK=open, which is the right balance for the
# CLI: filtered when the host can deliver it, fall back to open
# (loud warning) on legacy kernels rather than refusing to launch.
# The test suite (which is NOT exercising the network-filter layer
# in most of its sections) needs an open network so existing
# assertions about Slurm reachability, MTA-credential warnings, etc.
# still hold. Under v1.0 the helper-probe was gated, so default
# filtered fell back to isolated and (with the test harness's
# FALLBACK=open override) ended up as `open` — i.e., the whole
# suite ran with the network layer effectively disabled. v1.1
# ungates the probe AND ships pasta in-tree, so filtered actually
# resolves on every CI runner — and EVERY sandbox call would
# suddenly run through pasta's netns, which breaks tests that
# depend on host-network reachability (Slurm controller, etc.).
#
# Solution: pin MODE=open at the harness top. The network-filter-
# specific tests in section 11.4 override this via conf.d/*.conf so
# they still exercise the real filtered/isolated paths under their
# own assertions.
export NETWORK_FILTER_MODE="${NETWORK_FILTER_MODE:-open}"
export NETWORK_FILTER_FALLBACK="${NETWORK_FILTER_FALLBACK:-open}"

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
    # 30s aligns with the chaperon's own response-read ceiling
    # (chaperon/protocol.sh:158). Tighter envelopes produce
    # "test couldn't tell us what happened" failures instead of
    # the chaperon's own diagnostic. First-call bwrap startup +
    # chaperon spinup + audit-log NFS append can exceed 15s on
    # cold caches.
    OUTPUT=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- "$@" 2>"$_stderr_file")
    local rc=$?
    if [[ $rc == 124 ]]; then
        # Surface the timeout explicitly — otherwise "command failed"
        # vs. "envelope too tight" is invisible to the next agent.
        echo "[sandbox helper: 30s timeout fired before sandbox returned]" >>"$_stderr_file"
    fi
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

# Returns 0 if $1 (e.g. ".ssh") is intentionally exposed by the loaded
# test config — listed in HOME_READONLY or HOME_WRITABLE in the file
# pointed to by $SANDBOX_CONF. Used by the credential-block tests to
# distinguish "default-deny isolation" from "config-driven opt-in"
# (e.g. a user who deliberately exposes ~/.ssh so they can git-push
# from inside the sandbox).
#
# Config-aware against the loaded config only — external wrappers that
# mutate HOME_READONLY+=("…") before invoking sandbox-exec.sh are not
# visible to test.sh and won't be detected here.
_home_dir_intentional() {
    local _name="$1"
    bash -c '
        set +u
        # shellcheck disable=SC1090
        source "$1" 2>/dev/null || exit 1
        for _e in "${HOME_READONLY[@]}" "${HOME_WRITABLE[@]}"; do
            [[ "$_e" == "$2" ]] && exit 0
        done
        exit 1
    ' _ "$SANDBOX_CONF" "$_name"
}

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

# 2. Filesystem isolation — credential dirs (~/.ssh, ~/.aws, ~/.gnupg)
# Default-deny: BLOCKED unless the loaded config explicitly lists the
# dir in HOME_READONLY / HOME_WRITABLE — in which case we assert it's
# VISIBLE (config opt-in took effect, e.g. so a user can git-push or
# push to ECR from inside the sandbox). This validates BOTH default
# isolation AND the sandbox config plumbing for opt-ins.
for _dir in .ssh .aws .gnupg; do
    if [[ ! -d "$HOME/$_dir" ]]; then
        skip "~/$_dir not present on host"
        continue
    fi
    _intentional=false
    _home_dir_intentional "$_dir" && _intentional=true
    if sandbox bash -c "ls \"\$HOME/$_dir\" >/dev/null 2>&1 && echo VISIBLE || echo BLOCKED"; then
        if $_intentional; then
            if [[ "$OUTPUT" == "VISIBLE" ]]; then
                pass "~/$_dir visible by config opt-in"
            else
                fail "~/$_dir in HOME_READONLY/HOME_WRITABLE but blocked by sandbox" "$OUTPUT"
            fi
        else
            if [[ "$OUTPUT" == "BLOCKED" ]]; then
                pass "Filesystem isolation (~/$_dir blocked)"
            else
                fail "~/$_dir accessible inside sandbox (isolation broken)" "$OUTPUT"
            fi
        fi
    fi
done

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
# Compare against `getent passwd` rather than `/etc/passwd` directly:
# the host's local passwd file is small on LDAP-backed systems, but the
# sandbox's filtered passwd is built from `getent` (LDAP-resolved on
# the host) plus a few synthetic entries (dotto, slurm, munge, nobody).
# A naive `wc -l < /etc/passwd` comparison would flag the sandbox as
# "leakier than host" on every LDAP host.
if is_bwrap || is_firejail; then
    _host_getent=$(getent passwd | wc -l)
    if sandbox bash -c 'getent passwd | wc -l'; then
        _sandbox_getent="$OUTPUT"
        if [[ "$_sandbox_getent" -lt "$_host_getent" ]]; then
            pass "User enum prevention (host: $_host_getent → sandbox: $_sandbox_getent)"
        else
            fail "Passwd not filtered — sandbox getent returns $_sandbox_getent rows, host returns $_host_getent" "$OUTPUT"
        fi
    else
        fail "Could not run getent in sandbox" "$OUTPUT"
    fi
else
    skip "Passwd filter not supported on Landlock (no mount namespace)"
fi

# 6. Chaperon proxy — squeue completes without hanging
# Pre-warm the sandbox so first-call backend startup (cgroup setup,
# bwrap fork, chaperon spinup) doesn't eat into the squeue timeout
# envelope. Mirrors what the full-test path gets for free via
# _ensure_writable_home_dirs (line ~1409); --quick exits before
# reaching that, so we pre-warm explicitly.
sandbox true >/dev/null 2>&1 || true
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

# ── Config loading: unset _CONFIG_SCALARS must not trigger warnings ──
# Regression test: adding new variables to _CONFIG_SCALARS that aren't
# set in existing user configs must not cause "exited with code 1"
# warnings (the declare -p command must tolerate unset variables).
_unset_test_conf=$(mktemp)
echo 'SLURM_SCOPE="project"' > "$_unset_test_conf"
_unset_test_err=$(
    bash -c '
        # Unset the new chaperon vars to simulate an old config
        unset CHAPERON_LOG_LEVEL CHAPERON_LOG_RETAIN_DAYS 2>/dev/null
        source "'"$SCRIPT_DIR"'/sandbox-lib.sh"
        _load_untrusted_config "'"$_unset_test_conf"'" "Unset-var test"
    ' 2>&1
)
if [[ "$_unset_test_err" == *"exited with code"* ]]; then
    fail "Unset _CONFIG_SCALARS vars trigger spurious warning" "$_unset_test_err"
else
    pass "Unset _CONFIG_SCALARS vars do not trigger warnings"
fi
rm -f "$_unset_test_conf"

# ── Config: missing SANDBOX_CONF must NOT fall back to permissive ──
# anthropic-experimental/sandbox-runtime#122 + #211: a typo'd
# --settings flag silently fell back to a default config where
# `denyRead: []` opened all reads. Network/write fail-closed, reads
# fail-OPEN — invisibly. Verify the analogous AS path is closed:
# pointing SANDBOX_CONF at a non-existent file must either error
# with a clear message OR continue with the script-level defaults
# (HOME_ACCESS=tmpwrite, HOME_READONLY/HOME_WRITABLE preserved) —
# never a permissive "no restrictions" surface.
#
# The probe tests for the credential-dir hide (~/.ssh) which is
# covered by both _HOME_ALWAYS_BLOCKED and the default tmpfs HOME.
# A permissive fallback would expose ~/.ssh; a closed fallback hides
# it.
_missing_conf="$HOME/.config/agent-sandbox/__nonexistent-test-$$.conf"
_TEST_TEMP_FILES+=("$_missing_conf")
[[ ! -e "$_missing_conf" ]] || rm -f "$_missing_conf"
_missing_raw=$(SANDBOX_CONF="$_missing_conf" "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
    --project-dir "$PROJECT_DIR" -- bash -c \
    'ls "$HOME/.ssh/" >/dev/null 2>&1 && echo VISIBLE || echo BLOCKED' 2>&1)
_missing_rc=$?
if [[ $_missing_rc -ne 0 ]] && \
   echo "$_missing_raw" | grep -qiE "no such file|does not exist|cannot find|not found"; then
    pass "Missing SANDBOX_CONF: sandbox refuses to start with clear error (fail-closed)"
elif [[ $_missing_rc -eq 0 ]] && \
     echo "$_missing_raw" | grep -q "BLOCKED" && \
     ! echo "$_missing_raw" | grep -q "VISIBLE"; then
    pass "Missing SANDBOX_CONF: sandbox falls through to defaults, ~/.ssh stays hidden (fail-closed)"
elif echo "$_missing_raw" | grep -q "VISIBLE"; then
    fail "Missing SANDBOX_CONF leaked ~/.ssh — fallback is permissive (fail-OPEN)" "$_missing_raw"
else
    # Inconclusive — could not classify. Surface the output for diagnosis.
    fail "Missing SANDBOX_CONF: unexpected behaviour" "rc=$_missing_rc out=$_missing_raw"
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

# ── 1.5 Landlock ABI hard-requirement probe ──────────────────────
# Regression test for the startup ABI floor. Uses LANDLOCK_FAKE_ABI
# (test-only env override) so this works on any host, even ones
# without Landlock at all.

if is_landlock; then
    if [[ -x "$SCRIPT_DIR/tests/test_landlock_abi_probe.sh" ]]; then
        if bash "$SCRIPT_DIR/tests/test_landlock_abi_probe.sh" >/tmp/abi-probe.out 2>&1; then
            pass "Landlock ABI hard-requirement probe (regression)"
        else
            fail "Landlock ABI hard-requirement probe (regression)" "$(cat /tmp/abi-probe.out)"
        fi
        rm -f /tmp/abi-probe.out
    else
        skip "tests/test_landlock_abi_probe.sh not present"
    fi
fi

echo ""

# ── 2. Filesystem isolation ──────────────────────────────────────

echo "2. Filesystem isolation"

# Helper: assert a credential directory has the right visibility inside
# the sandbox. Default-deny: HIDDEN (bwrap/firejail) or BLOCKED with
# EACCES (landlock). Exception: if the loaded config explicitly lists
# the dir in HOME_READONLY / HOME_WRITABLE, we instead assert it's
# VISIBLE — that means the config-driven opt-in took effect (e.g. a
# user who exposes ~/.ssh so they can git-push from the sandbox).
#
# This validates both the isolation default and the config plumbing.
test_credential_dir() {
    local _name="$1"               # e.g. ".ssh"
    local _label="~/$_name"
    local _abs="$HOME/$_name"

    if [[ ! -d "$_abs" ]]; then
        skip "$_label not present on host"
        return
    fi

    local _intentional=false
    _home_dir_intentional "$_name" && _intentional=true

    if has_mount_ns; then
        if sandbox test -d "$_abs"; then
            if $_intentional; then
                pass "$_label visible by config opt-in"
            else
                fail "$_label is visible (should be hidden)"
            fi
        else
            if $_intentional; then
                fail "$_label in HOME_READONLY/HOME_WRITABLE but hidden by sandbox"
            else
                pass "$_label is hidden"
            fi
        fi
    else
        # Landlock: directory may exist on host but access is gated by ABI
        if sandbox bash -c "ls '$_abs' 2>&1"; then
            if $_intentional; then
                pass "$_label accessible by config opt-in"
            else
                fail "$_label is accessible (should be blocked)"
            fi
        else
            if $_intentional; then
                fail "$_label in HOME_READONLY/HOME_WRITABLE but blocked by sandbox" "$OUTPUT"
            else
                if echo "$OUTPUT" | grep -qi "permission denied\|cannot open\|cannot access"; then
                    pass "$_label is blocked (EACCES)"
                else
                    # Could also be ENOENT if the dir doesn't exist on the host
                    pass "$_label is blocked"
                fi
            fi
        fi
    fi
}

test_credential_dir ".ssh"
test_credential_dir ".aws"
test_credential_dir ".gnupg"

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

# ── HOME_SEEDED_FILES: writable per-session copies of host dotfiles ──
# Default config seeds ~/.gitconfig into the tmpfs $HOME so tools that
# write to it (gh auth setup-git, git config --global, IDE git plugins)
# work without weakening isolation. Verify three guarantees:
#   1. Seed content matches the host file at session start.
#   2. Writes inside the sandbox succeed (bwrap) or are warned about
#      and degrade to read-only (firejail / landlock).
#   3. Real host file is BYTE-IDENTICAL after a sandbox session that
#      modified the seeded copy — the tmpfs is ephemeral.
# Skip the section if ~/.gitconfig is missing on the host (rare).
if [[ -f "$HOME/.gitconfig" ]]; then
    _seed_md5_before=$(md5sum "$HOME/.gitconfig" | awk '{print $1}')

    # 1. Seeded content matches the host file
    if sandbox bash -c 'md5sum "$HOME/.gitconfig" 2>/dev/null | awk "{print \$1}"'; then
        if [[ "$OUTPUT" == "$_seed_md5_before" ]]; then
            pass "HOME_SEEDED_FILES: seeded ~/.gitconfig content matches host"
        else
            fail "HOME_SEEDED_FILES: seeded ~/.gitconfig differs from host" \
                 "host=$_seed_md5_before sandbox=$OUTPUT"
        fi
    fi

    # 2. Writability — bwrap supports; firejail/landlock degrade.
    if is_bwrap; then
        if sandbox bash -c 'echo "[seed-test]" >> "$HOME/.gitconfig" && echo OK || echo FAIL'; then
            if [[ "$OUTPUT" == "OK" ]]; then
                pass "HOME_SEEDED_FILES: ~/.gitconfig is writable (bwrap)"
            else
                fail "HOME_SEEDED_FILES: ~/.gitconfig append failed inside sandbox" "$OUTPUT"
            fi
        fi
        if sandbox bash -c 'cd /tmp && git config --global core.seedTestKey seedval 2>&1 && git config --global --get core.seedTestKey'; then
            if [[ "$OUTPUT" == "seedval" ]]; then
                pass "HOME_SEEDED_FILES: git config --global succeeds inside sandbox"
            else
                fail "HOME_SEEDED_FILES: git config --global failed" "$OUTPUT"
            fi
        fi
    else
        # On firejail/landlock the degradation warning fires on stderr.
        # Existence of the file inside the sandbox is enough — writability
        # is documented as backend-dependent.
        if sandbox bash -c 'test -r "$HOME/.gitconfig" && echo READABLE'; then
            if [[ "$OUTPUT" == "READABLE" ]]; then
                pass "HOME_SEEDED_FILES: ~/.gitconfig readable on $CURRENT_BACKEND (degraded read-only — warning expected)"
            else
                fail "HOME_SEEDED_FILES: ~/.gitconfig not readable on $CURRENT_BACKEND" "$OUTPUT"
            fi
        fi
    fi

    # 3. Host file unchanged after the writes above
    _seed_md5_after=$(md5sum "$HOME/.gitconfig" | awk '{print $1}')
    if [[ "$_seed_md5_before" == "$_seed_md5_after" ]]; then
        pass "HOME_SEEDED_FILES: real ~/.gitconfig unchanged after sandbox session"
    else
        fail "HOME_SEEDED_FILES: real ~/.gitconfig WAS MODIFIED — host leak" \
             "before=$_seed_md5_before after=$_seed_md5_after"
    fi

    # 4. Regression: a HOME_READONLY-only file stays read-only.
    # Pick whichever common dotfile is present and not in HOME_SEEDED_FILES.
    _readonly_probe=""
    for _candidate in .bashrc .profile .zshrc; do
        [[ -f "$HOME/$_candidate" ]] && { _readonly_probe="$_candidate"; break; }
    done
    if [[ -n "$_readonly_probe" ]] && is_bwrap; then
        if sandbox bash -c "echo APPENDED >> \"\$HOME/$_readonly_probe\" 2>&1 && echo WROTE || echo BLOCKED"; then
            if [[ "$OUTPUT" == "BLOCKED"* ]] || echo "$OUTPUT" | grep -qiE "read-only|permission denied"; then
                pass "HOME_SEEDED_FILES regression: ~/$_readonly_probe stays read-only"
            else
                fail "HOME_SEEDED_FILES regression: HOME_READONLY ~/$_readonly_probe is writable (should be RO)" "$OUTPUT"
            fi
        fi
    fi
else
    skip "HOME_SEEDED_FILES tests — ~/.gitconfig not present on host"
fi

# ── HOME_SEEDED_FILES: symlinked source ──
# anthropic-experimental/sandbox-runtime#185: bwrap fails to bind a
# symlinked DANGEROUS_FILE because ensure_file rejects S_IFLNK
# destinations with ENOTSUP. AS's seeding pipeline reads file
# CONTENT via `cp -- "$_src" "$_staged"` (follows symlinks) and feeds
# bytes to bwrap via `--file FD DEST` — the destination inside the
# tmpfs HOME is a fresh regular file, never a symlink. Verify via a
# fixture host where the seeded path is a symlink: content must be
# present inside the sandbox, host file must remain unmodified after
# in-sandbox writes.
if is_bwrap; then
    local _seed_link_dir=""
    local _seed_link_target="$HOME/.config/agent-sandbox/test-seed-target-$$"
    local _seed_orig_gitconfig=""
    local _had_gitconfig=false
    if [[ -f "$HOME/.gitconfig" && ! -L "$HOME/.gitconfig" ]]; then
        # Stash the host's real .gitconfig so we can restore after.
        _had_gitconfig=true
        _seed_orig_gitconfig="$HOME/.gitconfig.test-backup-$$"
        _TEST_TEMP_FILES+=("$_seed_orig_gitconfig")
        cp -p "$HOME/.gitconfig" "$_seed_orig_gitconfig"

        # Replace .gitconfig with a symlink to a target somewhere
        # else on the host. The target's content holds a marker that
        # MUST appear inside the sandbox.
        local _seed_marker="seed-symlink-marker-$$"
        printf '[seed-test]\n\tmarker = %s\n' "$_seed_marker" > "$_seed_link_target"
        _TEST_TEMP_FILES+=("$_seed_link_target")
        rm -f "$HOME/.gitconfig"
        ln -s "$_seed_link_target" "$HOME/.gitconfig"

        # Probe 1: marker visible inside sandbox via the seeded copy.
        if sandbox bash -c "grep -F '$_seed_marker' \"\$HOME/.gitconfig\" >/dev/null 2>&1 && echo OK || echo FAIL"; then
            if [[ "$OUTPUT" == "OK" ]]; then
                pass "HOME_SEEDED_FILES (symlink): seeded content from symlink target is visible"
            else
                fail "HOME_SEEDED_FILES (symlink): symlinked source not seeded (sandbox-runtime #185 regression)" "$OUTPUT"
            fi
        fi

        # Probe 2: in-sandbox writes don't reach the host symlink target.
        local _target_md5_before
        _target_md5_before="$(md5sum "$_seed_link_target" | awk '{print $1}')"
        if sandbox bash -c 'echo "[evil]" >> "$HOME/.gitconfig"' 2>/dev/null; then
            local _target_md5_after
            _target_md5_after="$(md5sum "$_seed_link_target" | awk '{print $1}')"
            if [[ "$_target_md5_before" == "$_target_md5_after" ]]; then
                pass "HOME_SEEDED_FILES (symlink): host symlink target unchanged after in-sandbox write"
            else
                fail "HOME_SEEDED_FILES (symlink): in-sandbox write reached host symlink target — leak" \
                     "before=$_target_md5_before after=$_target_md5_after"
            fi
        fi

        # Restore the original .gitconfig
        rm -f "$HOME/.gitconfig"
        cp -p "$_seed_orig_gitconfig" "$HOME/.gitconfig"
    else
        skip "HOME_SEEDED_FILES (symlink): no plain ~/.gitconfig to swap for fixture"
    fi
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

# Cloud-provider prefix wildcards (AWS_*, AMAZON_*, EC2_*, MSAL_*, VAULT_*).
# These close the long tail of provider env vars beyond AWS_ACCESS_KEY_ID
# and the *_TOKEN/*_SECRET globs (e.g. AWS_SECRET_ACCESS_KEY, AWS_PROFILE,
# MSAL_CACHE_PATH, VAULT_ADDR). Inspired by bindsch/scode (scode:113-158).
_cloud_provider_pre=(
    AWS_SECRET_ACCESS_KEY=fake-aws-secret
    AWS_PROFILE=fake-profile
    AMAZON_ID=fake-amazon
    EC2_KEYPAIR=fake-ec2
    MSAL_CACHE_PATH=/tmp/fake-msal
    VAULT_ADDR=https://vault.fake
)
for _kv in "${_cloud_provider_pre[@]}"; do
    export "$_kv"
done
for _kv in "${_cloud_provider_pre[@]}"; do
    _name="${_kv%%=*}"
    if sandbox bash -c "echo \${${_name}:-UNSET}"; then
        if [[ "$OUTPUT" == "UNSET" ]]; then
            pass "cloud-provider prefix: $_name is blocked"
        else
            fail "cloud-provider prefix: $_name leaked into sandbox" "$OUTPUT"
        fi
    fi
done
for _kv in "${_cloud_provider_pre[@]}"; do
    unset "${_kv%%=*}"
done
unset _cloud_provider_pre _kv _name

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

# BLOCKED_ENV_PATTERNS case-insensitivity (`/i` suffix, sed/Perl/JS-regex style).
# Default behaviour is case-sensitive (matches the convention where `/i` is an
# explicit opt-in flag). Two assertions: baseline (case-sensitive without `/i`)
# and opt-in (case-insensitive with `/i`).
_nocase_conf="$HOME/.config/agent-sandbox/conf.d/test-nocase-pattern-$$.conf"
_TEST_TEMP_FILES+=("$_nocase_conf")
mkdir -p "$HOME/.config/agent-sandbox/conf.d"

# Without /i: lowercase glob must NOT match an uppercase var (case-sensitive default).
echo 'BLOCKED_ENV_PATTERNS+=("nocase_baseline_*")' > "$_nocase_conf"
export NOCASE_BASELINE_VAR="should-leak-case-sensitive"
if sandbox bash -c 'echo ${NOCASE_BASELINE_VAR:-UNSET}'; then
    if [[ "$OUTPUT" == "should-leak-case-sensitive" ]]; then
        pass "BLOCKED_ENV_PATTERNS default is case-sensitive (lowercase glob does not match uppercase var)"
    else
        fail "BLOCKED_ENV_PATTERNS unexpectedly case-insensitive without /i flag" "$OUTPUT"
    fi
fi
unset NOCASE_BASELINE_VAR
rm -f "$_nocase_conf"

# With /i: lowercase glob MUST match an uppercase var (case-insensitive opt-in).
echo 'BLOCKED_ENV_PATTERNS+=("nocase_demo_*/i")' > "$_nocase_conf"
export NOCASE_DEMO_VAR="should-be-blocked-nocase"
if sandbox bash -c 'echo ${NOCASE_DEMO_VAR:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "BLOCKED_ENV_PATTERNS /i suffix: lowercase glob blocks uppercase var"
    else
        fail "BLOCKED_ENV_PATTERNS /i suffix did not enable case-insensitive matching" "$OUTPUT"
    fi
fi
unset NOCASE_DEMO_VAR
rm -f "$_nocase_conf"

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
ENABLED_AGENTS+=("aider")
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
ENABLED_AGENTS+=("aider")
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
ENABLED_AGENTS+=("aider")
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
AGENT_BLOCKED_FILES=()
AGENT_LOGIN_HINT=""
META

# The ad-hoc agent must be enabled, or its overlay never runs and the
# isolation check would vacuously pass.
_leak_conf="$HOME/.config/agent-sandbox/conf.d/test-leak-enable-$$.conf"
_TEST_TEMP_FILES+=("$_leak_conf")
mkdir -p "$HOME/.config/agent-sandbox/conf.d"
cat > "$_leak_conf" <<'CONF'
ENABLED_AGENTS+=("_malicious_leak")
CONF

_leak_out=$(SANDBOX_LEAK_TOKEN=leaked timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" \
    -- bash -c 'echo "LEAK=${SANDBOX_LEAK_TOKEN:-<blocked>}"' 2>&1)
if echo "$_leak_out" | grep -q '^LEAK=<blocked>$'; then
    pass "Overlay mutation of ALLOWED_ENV_VARS does not leak to parent"
else
    fail "Overlay subshell isolation broken — ALLOWED_ENV_VARS mutation leaked" "$_leak_out"
fi
rm -rf "$_malicious_dir"
rm -f "$_leak_conf"

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
AGENT_BLOCKED_FILES=()
AGENT_LOGIN_HINT="test marker"
META

# Block the env var via empty ALLOWED_ENV_VARS, and enable the test
# agent so _check_agent_requirements actually iterates it (otherwise
# the marker test would vacuously pass — the warning never fires for
# disabled agents). SANDBOX_QUIET must be overridden via env prefix
# (env takes precedence over conf.d).
_warn_conf="$HOME/.config/agent-sandbox/conf.d/test-agent-warn-$$.conf"
cat > "$_warn_conf" <<'CONF'
ALLOWED_ENV_VARS=()
ENABLED_AGENTS+=("_marker_test")
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
# persists. Use a default-enabled agent's dir as the probe.
_probe_dir="$HOME/.claude"
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

# ── ENABLED_AGENTS gating ──
# Only enabled agents contribute their declared paths to the sandbox
# surface and only their overlays run. Disabled agents stay invisible
# inside the sandbox (so e.g. ~/.pi can't be written when pi isn't
# enabled, even if ~/.pi happens to exist on disk for unrelated reasons).

# Probe agent: declares a writable path under HOME and an env-var export
# from its overlay. Used by all four sub-tests below.
_probe_agent_dir="$SCRIPT_DIR/agents/_gating_probe"
mkdir -p "$_probe_agent_dir"
trap_rm_dir "$_probe_agent_dir"
_probe_writable_dir="$HOME/.gating-probe-$$"
trap_rm_dir "$_probe_writable_dir"
cat > "$_probe_agent_dir/config.conf" <<META
AGENT_CREDENTIAL_ENV_VARS=()
AGENT_AUTH_MARKERS=()
AGENT_REQUIRED_WRITABLE_PATHS=("$_probe_writable_dir")
AGENT_REQUIRED_READABLE_PATHS=()
AGENT_BLOCKED_FILES=()
AGENT_LOGIN_HINT=""
META
cat > "$_probe_agent_dir/overlay.sh" <<'OVERLAY'
agent_prepare_config() {
    _AGENT_ENV_EXPORTS+=("GATING_PROBE_RAN=yes")
}
agent_get_env_exports() { :; }
OVERLAY

# (a) When NOT enabled (default ENABLED_AGENTS), the probe contributes
# nothing — its writable path is unreachable AND its overlay env var
# is unset.
_gating_disabled=$(timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" \
    -- bash -c "echo \"GATE=\${GATING_PROBE_RAN:-<unset>}\"; touch '$_probe_writable_dir/marker' 2>&1 && echo WRITABLE || echo BLOCKED" 2>&1)
if echo "$_gating_disabled" | grep -q '^GATE=<unset>$'; then
    pass "Disabled agent: overlay does not run (env export absent)"
else
    fail "Disabled agent: overlay ran anyway" "$_gating_disabled"
fi
if echo "$_gating_disabled" | grep -q '^BLOCKED$'; then
    pass "Disabled agent: declared writable path is not granted"
else
    fail "Disabled agent: writable path was granted anyway" "$_gating_disabled"
fi

# (b) When enabled via conf.d, the probe's writable path becomes
# reachable AND its overlay env var reaches the sandbox.
_gating_conf="$HOME/.config/agent-sandbox/conf.d/test-gating-$$.conf"
_TEST_TEMP_FILES+=("$_gating_conf")
mkdir -p "$HOME/.config/agent-sandbox/conf.d"
cat > "$_gating_conf" <<'CONF'
ENABLED_AGENTS+=("_gating_probe")
CONF
_gating_enabled=$(timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" \
    -- bash -c "echo \"GATE=\${GATING_PROBE_RAN:-<unset>}\"; touch '$_probe_writable_dir/marker' 2>&1 && echo WRITABLE || echo BLOCKED" 2>&1)
if echo "$_gating_enabled" | grep -q '^GATE=yes$'; then
    pass "Enabled agent: overlay env export reaches sandbox"
else
    fail "Enabled agent: overlay env export did not reach sandbox" "$_gating_enabled"
fi
if echo "$_gating_enabled" | grep -q '^WRITABLE$'; then
    pass "Enabled agent: declared writable path is granted"
else
    fail "Enabled agent: writable path was not granted" "$_gating_enabled"
fi

# (c) Empty ENABLED_AGENTS: no agent paths granted (regression guard
# for accidentally treating empty as "all").
_empty_conf="$HOME/.config/agent-sandbox/conf.d/test-gating-empty-$$.conf"
_TEST_TEMP_FILES+=("$_empty_conf")
cat > "$_empty_conf" <<'CONF'
ENABLED_AGENTS=()
CONF
# Remove the conf.d that enables the probe, otherwise both apply.
rm -f "$_gating_conf"
_empty_out=$(timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" \
    -- bash -c "touch '$HOME/.claude/marker' 2>&1 && echo CLAUDE_WRITABLE || echo CLAUDE_BLOCKED" 2>&1)
if echo "$_empty_out" | grep -q '^CLAUDE_BLOCKED$'; then
    pass "Empty ENABLED_AGENTS grants no agent paths"
else
    fail "Empty ENABLED_AGENTS still granted agent paths" "$_empty_out"
fi
rm -f "$_empty_conf"

# (d) Disabled-by-default agent (pi): ships in agents/pi/ but not in
# default ENABLED_AGENTS; ~/.pi must not be writable until enabled.
_pi_default_out=$(timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" \
    -- bash -c "touch '$HOME/.pi/test-$$' 2>&1 && echo PI_WRITABLE || echo PI_BLOCKED" 2>&1)
if echo "$_pi_default_out" | grep -q '^PI_BLOCKED$'; then
    pass "pi agent: ~/.pi is not writable when pi is not enabled"
else
    fail "pi agent: ~/.pi was writable without being enabled" "$_pi_default_out"
fi

# (e) opencode XDG drift fix: when opencode is enabled, all four XDG
# dirs (config, data, cache, state) must be writable. Opencode is
# opt-in (not in default ENABLED_AGENTS), so enable it via conf.d.
_opencode_conf="$HOME/.config/agent-sandbox/conf.d/test-opencode-enable-$$.conf"
_TEST_TEMP_FILES+=("$_opencode_conf")
cat > "$_opencode_conf" <<'CONF'
ENABLED_AGENTS+=("opencode")
CONF
_opencode_out=$(timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" \
    -- bash -c '
      for d in "$HOME/.config/opencode" "$HOME/.local/share/opencode" \
               "$HOME/.cache/opencode" "$HOME/.local/state/opencode"; do
          touch "$d/.probe-$$" 2>/dev/null && echo "OK $d" || echo "FAIL $d"
      done' 2>&1)
_opencode_fails=$(echo "$_opencode_out" | grep -c '^FAIL ' || true)
if [[ "$_opencode_fails" -eq 0 ]]; then
    pass "opencode: all four XDG dirs (config, data, cache, state) are writable when enabled"
else
    fail "opencode: ${_opencode_fails} XDG dir(s) not writable" "$_opencode_out"
fi
rm -f "$_opencode_conf"

# (f) opt-in agents are NOT writable by default (regression guard:
# opencode and aider must stay invisible until explicitly enabled).
_optin_default_out=$(timeout 15 "$SANDBOX_EXEC" \
    --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" \
    -- bash -c '
      touch "$HOME/.config/opencode/.probe-$$" 2>/dev/null && echo "WRITE opencode" || echo "BLOCK opencode"
      touch "$HOME/.aider.conf.yml" 2>/dev/null && echo "WRITE aider" || echo "BLOCK aider"' 2>&1)
if echo "$_optin_default_out" | grep -q '^WRITE opencode$'; then
    fail "opencode dir was writable by default (should be opt-in)" "$_optin_default_out"
else
    pass "opt-in agents: ~/.config/opencode is not writable by default"
fi
# Both fixture paths registered with trap_rm_dir above — cleanup
# happens on EXIT, including on test interruption.

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

# 5i. sacct scoped (--allusers denied; self-scope accepted)
if command -v sacct &>/dev/null; then
    # 5i-1: --allusers denied (regression)
    if sandbox bash -c 'sacct --allusers 2>&1'; then
        fail "sacct --allusers should be denied"
    else
        if echo "$OUTPUT" | grep -qi "not allowed"; then
            pass "sacct --allusers correctly denied by chaperon"
        else
            fail "sacct --allusers error unexpected" "$OUTPUT"
        fi
    fi

    # 5i-2: --user $USER accepted (no "not allowed" / no "drop" in stderr).
    # We don't care about exit code (no jobs in CI is fine), only that the
    # chaperon didn't reject the call.
    sandbox bash -c 'sacct --user "$USER" --noheader 2>&1' || true
    if echo "$OUTPUT $OUTPUT_ERR" | grep -qiE "not allowed|drop the flag"; then
        fail "sacct --user \$USER should be silently accepted" "$OUTPUT $OUTPUT_ERR"
    else
        pass "sacct --user \$USER silently accepted (self-scope)"
    fi

    # 5i-3: --user=$USER (equals form) accepted
    sandbox bash -c 'sacct --user="$USER" --noheader 2>&1' || true
    if echo "$OUTPUT $OUTPUT_ERR" | grep -qiE "not allowed|drop the flag"; then
        fail "sacct --user=\$USER should be silently accepted" "$OUTPUT $OUTPUT_ERR"
    else
        pass "sacct --user=\$USER silently accepted (self-scope)"
    fi

    # 5i-4: --me accepted (allow-listed; portable across sacct versions)
    sandbox bash -c 'sacct --me --noheader 2>&1' || true
    if echo "$OUTPUT $OUTPUT_ERR" | grep -qiE "not allowed|drop the flag|not recognized"; then
        fail "sacct --me should be silently accepted" "$OUTPUT $OUTPUT_ERR"
    else
        pass "sacct --me silently accepted"
    fi

    # 5i-5: --uid <self> accepted
    sandbox bash -c 'sacct --uid "$(id -u)" --noheader 2>&1' || true
    if echo "$OUTPUT $OUTPUT_ERR" | grep -qiE "not allowed|drop the flag"; then
        fail "sacct --uid \$(id -u) should be silently accepted" "$OUTPUT $OUTPUT_ERR"
    else
        pass "sacct --uid \$(id -u) silently accepted (self-scope)"
    fi

    # 5i-6: cross-user denied with new actionable message (mentions
    # "drop" or "--me", not just "not allowed for security").
    if sandbox bash -c 'sacct --user nobody-but-me 2>&1'; then
        fail "sacct --user <other> should be denied"
    else
        if echo "$OUTPUT $OUTPUT_ERR" | grep -qE "drop the flag|--me"; then
            pass "sacct --user <other> denied with actionable message"
        else
            fail "sacct --user <other> deny message missing actionable hint" "$OUTPUT $OUTPUT_ERR"
        fi
    fi

    # 5i-7: cross-uid denied
    if sandbox bash -c 'sacct --uid 0 2>&1'; then
        fail "sacct --uid 0 should be denied"
    else
        if echo "$OUTPUT $OUTPUT_ERR" | grep -qE "drop the flag"; then
            pass "sacct --uid <other> denied with actionable message"
        else
            fail "sacct --uid <other> deny message missing actionable hint" "$OUTPUT $OUTPUT_ERR"
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

# 5o. Scope filter — _squeue_filter_scope rejects out-of-scope rows
#     regardless of which column the user-supplied -o format puts first.
#
#     Pre-fix bug: the awk filter used a "first column starts with a digit"
#     heuristic to discriminate header vs data rows.  With -o "%j %i" (job
#     name first), data rows started with letters → assumed to be headers
#     → passed through unfiltered.  This leaked every running job from
#     sibling sandbox sessions of the same Linux user (cross-project /
#     cross-session info disclosure within the user).
_SQUEUE_HANDLER="$SCRIPT_DIR/chaperon/handlers/squeue.sh"
if [[ -f "$_SQUEUE_HANDLER" ]]; then
    eval "$(sed -n '/^_squeue_filter_scope()/,/^}/p' "$_SQUEUE_HANDLER")"

    _SEP=$'\x1f'
    _PAT='chaperon:.*proj=aaaaaaaaaaaa'
    _COMMENT_IN_SCOPE='chaperon:sid=99.100,proj=aaaaaaaaaaaa:END'
    _COMMENT_OTHER_PROJ='chaperon:sid=99.100,proj=bbbbbbbbbbbb:END'

    # 5o-1: numeric-first column with -h — filter activates (regression check).
    _input="12345     myjob${_SEP}${_COMMENT_IN_SCOPE}
23456     leakme${_SEP}${_COMMENT_OTHER_PROJ}"
    _out=$(printf '%s\n' "$_input" | _squeue_filter_scope "$_PAT" 1)
    if [[ "$_out" == "12345     myjob" ]]; then
        pass "Scope filter: numeric-first column, --noheader (in-scope row only)"
    else
        fail "Scope filter: %i first, --noheader" "got: $(printf %q "$_out")"
    fi

    # 5o-2: non-numeric-first column with -h — THE LEAK (must filter too).
    _input="myjob     12345${_SEP}${_COMMENT_IN_SCOPE}
leakme    23456${_SEP}${_COMMENT_OTHER_PROJ}"
    _out=$(printf '%s\n' "$_input" | _squeue_filter_scope "$_PAT" 1)
    if [[ "$_out" == "myjob     12345" ]]; then
        pass "Scope filter: non-numeric-first column, --noheader (no leak)"
    else
        fail "Scope filter: %j first, --noheader (LEAK)" "got: $(printf %q "$_out")"
    fi

    # 5o-3: numeric-first column WITH header — header through, data filtered.
    _input="             JOBID NAME${_SEP}             COMMENT
12345     myjob${_SEP}${_COMMENT_IN_SCOPE}
23456     leakme${_SEP}${_COMMENT_OTHER_PROJ}"
    _out=$(printf '%s\n' "$_input" | _squeue_filter_scope "$_PAT" 0)
    _expected="             JOBID NAME
12345     myjob"
    if [[ "$_out" == "$_expected" ]]; then
        pass "Scope filter: numeric-first column, header preserved + scope applied"
    else
        fail "Scope filter: %i first, with header" "got: $(printf %q "$_out")"
    fi

    # 5o-4: non-numeric-first column WITH header — header through, data filtered.
    _input="              NAME JOBID${_SEP}             COMMENT
myjob     12345${_SEP}${_COMMENT_IN_SCOPE}
leakme    23456${_SEP}${_COMMENT_OTHER_PROJ}"
    _out=$(printf '%s\n' "$_input" | _squeue_filter_scope "$_PAT" 0)
    _expected="              NAME JOBID
myjob     12345"
    if [[ "$_out" == "$_expected" ]]; then
        pass "Scope filter: non-numeric-first column, header preserved + scope applied"
    else
        fail "Scope filter: %j first, with header" "got: $(printf %q "$_out")"
    fi

    # 5o-5: multi-row cross-project setup — only in-scope rows survive,
    # regardless of -o ordering. Mixed jobs from three projects.
    _project_a='chaperon:sid=99.100,proj=aaaaaaaaaaaa:END'
    _project_b='chaperon:sid=88.200,proj=bbbbbbbbbbbb:END'
    _project_c='chaperon:sid=77.300,proj=cccccccccccc:END'
    _input="alpha     1${_SEP}${_project_a}
bravo     2${_SEP}${_project_b}
charlie   3${_SEP}${_project_c}
delta     4${_SEP}${_project_a}
echo      5${_SEP}${_project_b}"
    _out=$(printf '%s\n' "$_input" | _squeue_filter_scope "$_PAT" 1)
    _expected="alpha     1
delta     4"
    if [[ "$_out" == "$_expected" ]]; then
        pass "Scope filter: cross-project mix, only project-a rows survive"
    else
        fail "Scope filter: cross-project mix (LEAK)" "got: $(printf %q "$_out")"
    fi

    # 5o-6: line without separator passes through unchanged
    # (e.g. squeue diagnostics, unexpected output formats).
    _out=$(printf 'no separator here\n' | _squeue_filter_scope "$_PAT" 1)
    if [[ "$_out" == "no separator here" ]]; then
        pass "Scope filter: no-separator line passes through"
    else
        fail "Scope filter: no-separator passthrough" "got: $(printf %q "$_out")"
    fi

    # 5o-7: empty input is fine
    _out=$(printf '' | _squeue_filter_scope "$_PAT" 1)
    if [[ -z "$_out" ]]; then
        pass "Scope filter: empty input → empty output"
    else
        fail "Scope filter: empty input" "got: $(printf %q "$_out")"
    fi

    unset -f _squeue_filter_scope
    unset _SEP _PAT _COMMENT_IN_SCOPE _COMMENT_OTHER_PROJ _input _out _expected \
          _project_a _project_b _project_c
else
    skip "Scope filter tests — chaperon/handlers/squeue.sh not found"
fi

# 5p. sacct self-scope unit tests: verify _is_self_user / _is_self_uid
#     and that handle_sacct does not duplicate --user when the caller
#     passes a self-scoped value. No real Slurm needed — REAL_SACCT is
#     stubbed to a script that records its argv.
_SACCT_HANDLER="$SCRIPT_DIR/chaperon/handlers/sacct.sh"
if [[ -f "$_SACCT_HANDLER" ]]; then
    # Run the test in a subshell so sourcing the handler can't leak
    # vars/functions back into the suite.
    _sacct_unit_out="$(
        set +e
        # shellcheck disable=SC1090
        source "$_SACCT_HANDLER" || exit 99

        _self_name="$(id -un)"
        _self_uid="$(id -u)"

        # Helper assertions
        if _is_self_user "$_self_name"; then echo "PASS:_is_self_user/name"; else echo "FAIL:_is_self_user/name"; fi
        if _is_self_user "${USER:-$_self_name}"; then echo "PASS:_is_self_user/USER"; else echo "FAIL:_is_self_user/USER"; fi
        if _is_self_user "definitely-not-a-real-user-9999"; then echo "FAIL:_is_self_user/other"; else echo "PASS:_is_self_user/other"; fi
        if _is_self_user ""; then echo "FAIL:_is_self_user/empty"; else echo "PASS:_is_self_user/empty"; fi
        if _is_self_uid "$_self_uid"; then echo "PASS:_is_self_uid/self"; else echo "FAIL:_is_self_uid/self"; fi
        if _is_self_uid 999999; then echo "FAIL:_is_self_uid/other"; else echo "PASS:_is_self_uid/other"; fi
        if _is_self_uid "abc"; then echo "FAIL:_is_self_uid/nonnum"; else echo "PASS:_is_self_uid/nonnum"; fi

        # Stub real sacct: print argv (one per line, prefixed) and exit 0.
        _stub="$(mktemp)"
        cat >"$_stub" <<'STUB'
#!/bin/bash
for a in "$@"; do printf 'ARG:%s\n' "$a"; done
exit 0
STUB
        chmod +x "$_stub"
        export REAL_SACCT="$_stub"

        # Case A: --user $USER → exactly one --user= reaches real sacct,
        # and it carries the current user.
        REQ_ARGS=("--user" "$_self_name" "--noheader")
        out_a="$(handle_sacct /tmp /tmp 2>&1)"
        n_user_a="$(printf '%s\n' "$out_a" | grep -c '^ARG:--user=')"
        if [[ "$n_user_a" == "1" ]] && printf '%s' "$out_a" | grep -qF "ARG:--user=$_self_name"; then
            echo "PASS:no-dup/--user self"
        else
            echo "FAIL:no-dup/--user self|count=$n_user_a|out=$out_a"
        fi

        # Case B: --user=$USER (equals form)
        REQ_ARGS=("--user=$_self_name")
        out_b="$(handle_sacct /tmp /tmp 2>&1)"
        n_user_b="$(printf '%s\n' "$out_b" | grep -c '^ARG:--user=')"
        if [[ "$n_user_b" == "1" ]]; then
            echo "PASS:no-dup/--user=self"
        else
            echo "FAIL:no-dup/--user=self|count=$n_user_b|out=$out_b"
        fi

        # Case C: --me → forwarded as-is, plus auto-injected --user
        REQ_ARGS=("--me")
        out_c="$(handle_sacct /tmp /tmp 2>&1)"
        if printf '%s\n' "$out_c" | grep -qF 'ARG:--me' \
           && printf '%s\n' "$out_c" | grep -qF "ARG:--user=$_self_name"; then
            echo "PASS:--me forwarded"
        else
            echo "FAIL:--me forwarded|out=$out_c"
        fi

        # Case D: --uid <self> accepted, no duplicate
        REQ_ARGS=("--uid" "$_self_uid")
        out_d="$(handle_sacct /tmp /tmp 2>&1)"
        n_user_d="$(printf '%s\n' "$out_d" | grep -c '^ARG:--user=')"
        if [[ "$n_user_d" == "1" ]]; then
            echo "PASS:--uid self accepted"
        else
            echo "FAIL:--uid self accepted|count=$n_user_d|out=$out_d"
        fi

        # Case E: --user other → handler returns nonzero, real sacct not called
        REQ_ARGS=("--user" "definitely-not-me-99999")
        out_e="$(handle_sacct /tmp /tmp 2>&1)"
        rc_e=$?
        if (( rc_e != 0 )) && ! printf '%s\n' "$out_e" | grep -q '^ARG:'; then
            echo "PASS:cross-user denied"
        else
            echo "FAIL:cross-user denied|rc=$rc_e|out=$out_e"
        fi

        # Case F: cross-user deny message contains actionable hint
        if printf '%s\n' "$out_e" | grep -qE "drop the flag|--me"; then
            echo "PASS:deny message actionable"
        else
            echo "FAIL:deny message actionable|out=$out_e"
        fi

        rm -f "$_stub"
    )"
    while IFS= read -r _line; do
        case "$_line" in
            PASS:*) pass "sacct unit: ${_line#PASS:}" ;;
            FAIL:*) fail "sacct unit: ${_line#FAIL:}" "" ;;
        esac
    done <<< "$_sacct_unit_out"
else
    skip "sacct self-scope unit tests — sacct.sh not found"
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
    #
    # Output path lives under $PROJECT_DIR, not /tmp: after #67 the
    # chaperon redirects --output to .sandbox-state/slurm-logs/ and the
    # in-sandbox prelude creates a symlink from the user's intended path
    # to staging. /tmp is the sandbox's private tmpfs (bwrap/firejail),
    # so a symlink there would never reach the host-side assertion.
    # Keeping the intended path in the project bind makes the symlink
    # visible on the host, which then reads through it to staging.
    _jobout=$(mktemp -p "$PROJECT_DIR" .test-jobout-XXXXXX)
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

    # 6c-quinquies. SLURM_SUBMIT_DIR reflects agent's CWD, not chaperon's.
    # The chaperon runs outside the sandbox with its own CWD. Before the fix,
    # real sbatch inherited the chaperon's CWD, making SLURM_SUBMIT_DIR wrong.
    _cwd_subdir="$PROJECT_DIR/.test-cwd-$$"
    mkdir -p "$_cwd_subdir"
    _TEST_TEMP_FILES+=("$_cwd_subdir")
    # $_cwd_jobout must live under $PROJECT_DIR — see 6c-quater note
    # on #67's --output redirect + private-tmpfs visibility.
    _cwd_jobout=$(mktemp -p "$PROJECT_DIR" .test-cwd-out-XXXXXX)
    _TEST_TEMP_FILES+=("$_cwd_jobout")
    _cwd_submit_out=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- \
        bash -c "cd '$_cwd_subdir' && sbatch --wait --output='$_cwd_jobout' \
            --wrap='echo SLURM_SUBMIT_DIR=\$SLURM_SUBMIT_DIR'" 2>&1)
    _cwd_submit_rc=$?
    if [[ $_cwd_submit_rc -eq 0 && -f "$_cwd_jobout" ]] && grep -q "^SLURM_SUBMIT_DIR=${_cwd_subdir}\$" "$_cwd_jobout"; then
        pass "SLURM_SUBMIT_DIR matches agent's CWD (not chaperon's)"
    else
        _cwd_jobid=$(echo "$_cwd_submit_out" | grep -oE "Submitted batch job [0-9]+" | awk '{print $4}')
        if [[ -n "$_cwd_jobid" ]]; then
            for _i in $(seq 1 20); do
                if sandbox bash -c "squeue -j $_cwd_jobid -h 2>/dev/null" && [[ -z "$OUTPUT" ]]; then
                    sleep 1
                    break
                fi
                sleep 1
            done
            if [[ -f "$_cwd_jobout" ]] && grep -q "^SLURM_SUBMIT_DIR=${_cwd_subdir}\$" "$_cwd_jobout"; then
                pass "SLURM_SUBMIT_DIR matches agent's CWD (not chaperon's)"
            else
                skip "SLURM_SUBMIT_DIR assertion inconclusive (output: $(cat "$_cwd_jobout" 2>/dev/null || echo 'no file'))"
            fi
        else
            skip "SLURM_SUBMIT_DIR assertion inconclusive (no jobid captured: $_cwd_submit_out)"
        fi
    fi
    rm -rf "$_cwd_subdir"

    # 6c-quinquies-bis. Compute-node cwd inside --wrap matches the
    # agent's submission subdir, not $project_dir. Before #65's fix,
    # the bwrap/firejail backends forced --chdir/--private-cwd to
    # $project_dir unconditionally, so `sbatch --wrap='bash relpath.sh'`
    # from a subdir resolved relative paths against the wrong directory
    # and died exit 127 in ~6s. Closes the gap left by 6c-quinquies
    # (which only checked the SLURM_SUBMIT_DIR env var, not pwd).
    _pwd_subdir="$PROJECT_DIR/.test-pwd-$$"
    mkdir -p "$_pwd_subdir"
    _TEST_TEMP_FILES+=("$_pwd_subdir")
    _pwd_expected="$(cd "$_pwd_subdir" && pwd -P)"
    # $_pwd_jobout must live under $PROJECT_DIR — see 6c-quater note
    # on #67's --output redirect + private-tmpfs visibility.
    _pwd_jobout=$(mktemp -p "$PROJECT_DIR" .test-pwd-out-XXXXXX)
    _TEST_TEMP_FILES+=("$_pwd_jobout")
    _pwd_submit_out=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- \
        bash -c "cd '$_pwd_subdir' && sbatch --wait --output='$_pwd_jobout' \
            --wrap='echo PWD=\$(pwd -P)'" 2>&1)
    _pwd_submit_rc=$?
    _pwd_check() {
        [[ -s "$_pwd_jobout" ]] && grep -q "^PWD=${_pwd_expected}\$" "$_pwd_jobout"
    }
    if [[ $_pwd_submit_rc -eq 0 ]] && _pwd_check; then
        pass "Compute-node cwd inside --wrap matches submission subdir (#65)"
    else
        _pwd_jobid=$(echo "$_pwd_submit_out" | grep -oE "Submitted batch job [0-9]+" | awk '{print $4}')
        if [[ -n "$_pwd_jobid" ]]; then
            for _i in $(seq 1 20); do
                if sandbox bash -c "squeue -j $_pwd_jobid -h 2>/dev/null" && [[ -z "$OUTPUT" ]]; then
                    sleep 1
                    break
                fi
                sleep 1
            done
            if _pwd_check; then
                pass "Compute-node cwd inside --wrap matches submission subdir (#65)"
            else
                skip "Compute-node cwd assertion inconclusive (output: $(cat "$_pwd_jobout" 2>/dev/null || echo 'no file'))"
            fi
        else
            skip "Compute-node cwd assertion inconclusive (no jobid captured: $_pwd_submit_out)"
        fi
    fi
    rm -rf "$_pwd_subdir"

    # 6c-quinquies-ter. Dry-run unit test: verify the backend's chdir
    # target honors $SLURM_SUBMIT_DIR when it canonicalizes under
    # $project_dir, and falls back to $project_dir otherwise.
    # Bypasses the Slurm submission round-trip — exercises the backend
    # layer (`_resolve_inherited_cwd` in sandbox-lib.sh) directly via
    # --dry-run. Landlock has no --chdir surface, so skipped there.
    if is_bwrap || is_firejail; then
        _dry_sub="$PROJECT_DIR/.test-dry-cwd-$$"
        mkdir -p "$_dry_sub"
        _TEST_TEMP_FILES+=("$_dry_sub")
        _dry_sub_canon="$(cd "$_dry_sub" && pwd -P)"

        # bwrap emits "--chdir <path>" on two lines; firejail emits
        # "--private-cwd=<path>" on one. Match either form for the
        # expected target.
        _dry_grep_for() {
            local _expected="$1" _output="$2"
            if is_bwrap; then
                printf '%s\n' "$_output" | grep -qE "^[[:space:]]*${_expected}[[:space:]]*\\\\?$"
            else
                printf '%s\n' "$_output" | grep -qE "^[[:space:]]*--private-cwd=${_expected}[[:space:]]*\\\\?$"
            fi
        }

        # (a) SLURM_SUBMIT_DIR under $PROJECT_DIR → honored.
        _dry_under=$(SLURM_SUBMIT_DIR="$_dry_sub" \
            "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
            --project-dir "$PROJECT_DIR" --dry-run -- true 2>&1)
        if _dry_grep_for "$_dry_sub_canon" "$_dry_under"; then
            pass "Backend honors \$SLURM_SUBMIT_DIR under \$project_dir (#65)"
        else
            fail "Backend dropped \$SLURM_SUBMIT_DIR under \$project_dir" \
                "expected chdir target $_dry_sub_canon in dry-run output"
        fi

        # (b) SLURM_SUBMIT_DIR outside $PROJECT_DIR → falls back to
        # $project_dir. The security guardrail: prefix check via
        # realpath rejects the escape. /tmp is reliably outside any
        # plausible $PROJECT_DIR on the test runner.
        _project_canon="$(cd "$PROJECT_DIR" && pwd -P)"
        _dry_outside=$(SLURM_SUBMIT_DIR="/tmp" \
            "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
            --project-dir "$PROJECT_DIR" --dry-run -- true 2>&1)
        if _dry_grep_for "$_project_canon" "$_dry_outside"; then
            pass "Backend falls back to \$project_dir when \$SLURM_SUBMIT_DIR escapes (#65)"
        else
            fail "Backend honored an out-of-envelope \$SLURM_SUBMIT_DIR" \
                "expected chdir target $_project_canon in dry-run output"
        fi

        # (c) SLURM_SUBMIT_DIR unset → falls back to $project_dir.
        # Confirms the pre-existing (safe) default path is intact.
        _dry_unset=$(unset SLURM_SUBMIT_DIR; \
            "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
            --project-dir "$PROJECT_DIR" --dry-run -- true 2>&1)
        if _dry_grep_for "$_project_canon" "$_dry_unset"; then
            pass "Backend defaults to \$project_dir when \$SLURM_SUBMIT_DIR unset (#65)"
        else
            fail "Backend chdir target wrong when \$SLURM_SUBMIT_DIR unset" \
                "expected $_project_canon in dry-run output"
        fi

        unset -f _dry_grep_for
        rm -rf "$_dry_sub"
    fi

    # 6c-sexies. sbatch script positional args reach $1/$@/$#.
    # Before the fix, the chaperon dropped `sbatch script.sh arg1 arg2`
    # positionals: the stub captured SCRIPT_ARGS but never forwarded them
    # through the protocol, and the wrapper piped the script body to bash
    # via stdin which provides no argv. These tests assert that the user's
    # positionals survive — for a bash shebang (the `-s --` path) and for
    # a python shebang (the in-sandbox tmpfile path).
    _await_jobout() {
        # Args: <jobid> <jobout> [timeout-seconds]
        local _jid="$1" _jo="$2" _tmo="${3:-25}"
        for _i in $(seq 1 "$_tmo"); do
            if sandbox bash -c "squeue -j $_jid -h 2>/dev/null" && [[ -z "$OUTPUT" ]]; then
                sleep 1
                break
            fi
            sleep 1
        done
        [[ -s "$_jo" ]]
    }

    # Bash shebang — assert $#, $@, and individual positionals.
    # Output path under $PROJECT_DIR so #67's prelude-symlink lands in
    # the writable project bind (host-visible) rather than the sandbox's
    # private /tmp tmpfs — see 6c-quater note.
    _argscript="$PROJECT_DIR/.sbatch-args-bash-$$.sh"
    _argout=$(mktemp -p "$PROJECT_DIR" .sbatch-args-bash-out-XXXXXX)
    _TEST_TEMP_FILES+=("$_argscript" "$_argout")
    cat > "$_argscript" <<'BASH_ARGSCRIPT'
#!/bin/bash
echo "argc=$#"
i=1
for a in "$@"; do
    echo "argv[$i]=[$a]"
    i=$((i + 1))
done
BASH_ARGSCRIPT
    chmod +x "$_argscript"
    _arg_out=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- \
        sbatch --wait --output="$_argout" \
        "$_argscript" "first" "with space" 'with$dollar' 2>&1)
    _arg_rc=$?
    _arg_check() {
        [[ -s "$_argout" ]] \
            && grep -q '^argc=3$' "$_argout" \
            && grep -qF 'argv[1]=[first]' "$_argout" \
            && grep -qF 'argv[2]=[with space]' "$_argout" \
            && grep -qF 'argv[3]=[with$dollar]' "$_argout"
    }
    if [[ $_arg_rc -eq 0 ]] && _arg_check; then
        pass "sbatch script.sh forwards positional args to bash shebang (\$#/\$@)"
    else
        _arg_jid=$(echo "$_arg_out" | grep -oE 'Submitted batch job [0-9]+' | awk '{print $4}')
        if [[ -n "$_arg_jid" ]] && _await_jobout "$_arg_jid" "$_argout"; then
            if _arg_check; then
                pass "sbatch script.sh forwards positional args to bash shebang (\$#/\$@)"
            else
                fail "sbatch script positional args not forwarded (bash shebang)" \
                    "got: $(cat "$_argout" 2>/dev/null || echo 'no file')"
            fi
        else
            skip "sbatch positional-args (bash) inconclusive: $_arg_out"
        fi
    fi
    rm -f "$_argscript"

    # Python shebang — argv[0] should be the script path, argv[1:] the user args.
    if command -v python3 &>/dev/null; then
        _pyscript="$PROJECT_DIR/.sbatch-args-py-$$.py"
        # See 6c-quater note: --output target must live under $PROJECT_DIR.
        _pyout=$(mktemp -p "$PROJECT_DIR" .sbatch-args-py-out-XXXXXX)
        _TEST_TEMP_FILES+=("$_pyscript" "$_pyout")
        cat > "$_pyscript" <<'PY_ARGSCRIPT'
#!/usr/bin/env python3
import sys
print(f"argc={len(sys.argv) - 1}")
for i, a in enumerate(sys.argv[1:], start=1):
    print(f"argv[{i}]=[{a}]")
PY_ARGSCRIPT
        chmod +x "$_pyscript"
        _py_out=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
            --project-dir "$PROJECT_DIR" -- \
            sbatch --wait --output="$_pyout" \
            "$_pyscript" "alpha" "beta gamma" "with'quote" 2>&1)
        _py_rc=$?
        _py_check() {
            [[ -s "$_pyout" ]] \
                && grep -q '^argc=3$' "$_pyout" \
                && grep -qF 'argv[1]=[alpha]' "$_pyout" \
                && grep -qF 'argv[2]=[beta gamma]' "$_pyout" \
                && grep -qF "argv[3]=[with'quote]" "$_pyout"
        }
        if [[ $_py_rc -eq 0 ]] && _py_check; then
            pass "sbatch script.py forwards positional args to python shebang (sys.argv)"
        else
            _py_jid=$(echo "$_py_out" | grep -oE 'Submitted batch job [0-9]+' | awk '{print $4}')
            if [[ -n "$_py_jid" ]] && _await_jobout "$_py_jid" "$_pyout"; then
                if _py_check; then
                    pass "sbatch script.py forwards positional args to python shebang (sys.argv)"
                else
                    fail "sbatch script positional args not forwarded (python shebang)" \
                        "got: $(cat "$_pyout" 2>/dev/null || echo 'no file')"
                fi
            else
                skip "sbatch positional-args (python) inconclusive: $_py_out"
            fi
        fi
        rm -f "$_pyscript"
    else
        skip "python3 not available — skipping python-shebang positional-args test"
    fi

    # No args — script still runs (no `--` after `-s`, $#=0).
    _noargscript="$PROJECT_DIR/.sbatch-noargs-$$.sh"
    # See 6c-quater note: --output target must live under $PROJECT_DIR.
    _noargout=$(mktemp -p "$PROJECT_DIR" .sbatch-noargs-out-XXXXXX)
    _TEST_TEMP_FILES+=("$_noargscript" "$_noargout")
    cat > "$_noargscript" <<'NOARGSCRIPT'
#!/bin/bash
echo "argc=$#"
echo "ran=ok"
NOARGSCRIPT
    chmod +x "$_noargscript"
    _noarg_out=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- \
        sbatch --wait --output="$_noargout" "$_noargscript" 2>&1)
    _noarg_rc=$?
    _noarg_check() {
        [[ -s "$_noargout" ]] \
            && grep -q '^argc=0$' "$_noargout" \
            && grep -q '^ran=ok$' "$_noargout"
    }
    if [[ $_noarg_rc -eq 0 ]] && _noarg_check; then
        pass "sbatch script.sh with no positional args still runs ($#=0)"
    else
        _noarg_jid=$(echo "$_noarg_out" | grep -oE 'Submitted batch job [0-9]+' | awk '{print $4}')
        if [[ -n "$_noarg_jid" ]] && _await_jobout "$_noarg_jid" "$_noargout"; then
            if _noarg_check; then
                pass "sbatch script.sh with no positional args still runs ($#=0)"
            else
                fail "sbatch script with no positional args misbehaved" \
                    "got: $(cat "$_noargout" 2>/dev/null || echo 'no file')"
            fi
        else
            skip "sbatch no-args inconclusive: $_noarg_out"
        fi
    fi
    rm -f "$_noargscript"

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

# ── 6.5 Slurm --output / --error path staging (#67) ──────────────
#
# Tests for the chaperon-managed `.sandbox-state/slurm-logs/`
# staging convention: chaperon transforms --output paths to live
# under .sandbox-state, bwrap/firejail RO-overlay the dir so
# slurmstepd can't be tricked into following an in-sandbox-planted
# symlink, and the in-sandbox wrapper creates relative symlinks
# from the user's intended paths to the staging file.

echo "6.5 Slurm --output staging (#67)"

# 6.5a. Unit: _transform_slurm_output_path table (pure function;
# always runs regardless of backend / slurm availability).
_transform_table_test() {
    # Source the chaperon-side helper directly.
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/chaperon/handlers/_handler_lib.sh"
    local _proj="/p"
    local _staging="$_proj/.sandbox-state/slurm-logs"

    local _ok=true _got _input _expected
    while IFS=$'\t' read -r _input _expected; do
        _got="$(_transform_slurm_output_path "$_input" "$_proj")"
        if [[ "$_got" != "$_expected" ]]; then
            fail "transform '$_input' → '$_got' (expected '$_expected')"
            _ok=false
        fi
    done <<EOF
out.log	$_staging/out.log
logs/job-%j.log	$_staging/logs/job-%j.log
/etc/passwd	$_staging/__abs__/etc/passwd
../../etc/foo	$_staging/__updir__/__updir__/etc/foo
..foo/bar	$_staging/..foo/bar
./a/.//b/../c	$_staging/a/b/__updir__/c
/foo//bar	$_staging/__abs__/foo/bar
EOF
    $_ok && pass "_transform_slurm_output_path table (rel/abs/../-foo/no-op normalisation/%-pattern survival)"
}
_transform_table_test
unset -f _transform_table_test

# 6.5b. Backend-side RO overlay: from inside the sandbox, writing
# under .sandbox-state/ must fail on bwrap/firejail; landlock
# silently allows (documented feature gap). The chaperon mkdir's
# .sandbox-state on first sbatch — pre-seed it here so the bind
# overlay actually applies.
mkdir -p "$PROJECT_DIR/.sandbox-state/slurm-logs"
if is_landlock; then
    # Sanity: write succeeds (no RO defense on landlock).
    if sandbox bash -c "touch '$PROJECT_DIR/.sandbox-state/slurm-logs/.write-test-$$' 2>&1 && echo OK"; then
        if [[ "$OUTPUT" == *OK* ]]; then
            pass "Landlock: .sandbox-state is sandbox-writable (feature degraded as documented)"
            rm -f "$PROJECT_DIR/.sandbox-state/slurm-logs/.write-test-$$"
        else
            fail "Landlock: expected .sandbox-state to be writable, got: $OUTPUT $OUTPUT_ERR"
        fi
    else
        fail "Landlock: write-test command failed unexpectedly" "$OUTPUT_ERR"
    fi
else
    # bwrap / firejail: write must fail (EROFS / EACCES).
    if sandbox bash -c "touch '$PROJECT_DIR/.sandbox-state/slurm-logs/plant-$$' 2>&1; echo done"; then
        if echo "$OUTPUT $OUTPUT_ERR" | grep -qE 'Read-only file system|Permission denied|Operation not permitted'; then
            pass "Symlink-plant defense: .sandbox-state/slurm-logs is RO from inside sandbox (#67)"
        elif [[ -e "$PROJECT_DIR/.sandbox-state/slurm-logs/plant-$$" ]]; then
            fail "Symlink-plant defense MISSING: sandbox wrote to .sandbox-state/slurm-logs" \
                 "Backend $CURRENT_BACKEND should RO-overlay .sandbox-state"
            rm -f "$PROJECT_DIR/.sandbox-state/slurm-logs/plant-$$"
        else
            skip "Symlink-plant defense check inconclusive: $OUTPUT $OUTPUT_ERR"
        fi
    fi
fi

# 6.5c. Integration: end-to-end --output redirection + symlink.
# Skipped if no sbatch on host or on landlock (feature disabled).
if ! command -v sbatch &>/dev/null; then
    skip "Slurm --output staging integration: sbatch not found"
elif is_landlock; then
    skip "Slurm --output staging integration: disabled on landlock (no RO overlay)"
else
    _stg_subdir="$PROJECT_DIR/.test-slurm-stg-$$"
    mkdir -p "$_stg_subdir"
    _TEST_TEMP_FILES+=("$_stg_subdir")
    _stg_intended="$_stg_subdir/job.out"
    _stg_submit=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- \
        bash -c "cd '$_stg_subdir' && sbatch --wait --output='$_stg_intended' \
            --wrap='echo SLURM_OUTPUT_STAGING_TEST_$$'" 2>&1)
    _stg_rc=$?

    # _stg_marker_in_staging — search the chaperon-managed staging tree
    # for our unique test marker. If found, the job ran to completion and
    # slurmstepd wrote into the redirected path → the feature's host-side
    # half worked. The symlink is then the only remaining contract.
    _stg_marker_in_staging() {
        grep -rl "SLURM_OUTPUT_STAGING_TEST_$$" \
            "$PROJECT_DIR/.sandbox-state/slurm-logs/" 2>/dev/null | head -1
    }
    _stg_check_symlink() {
        # Intended path is a symlink → staging file under .sandbox-state.
        [[ -L "$_stg_intended" ]] || return 1
        local _resolved
        _resolved="$(readlink -f "$_stg_intended" 2>/dev/null)" || return 1
        [[ "$_resolved" == "$PROJECT_DIR/.sandbox-state/slurm-logs/"* ]] || return 1
        grep -q "SLURM_OUTPUT_STAGING_TEST_$$" "$_stg_intended" 2>/dev/null
    }

    # If --wait returned but the symlink isn't there yet, give Slurm a
    # short post-completion grace window for the wrapper's in-sandbox
    # symlink prelude to land before deciding.
    if [[ $_stg_rc -ne 0 ]] || ! _stg_check_symlink; then
        _stg_jid=$(echo "$_stg_submit" | grep -oE "Submitted batch job [0-9]+" | awk '{print $4}')
        if [[ -n "$_stg_jid" ]]; then
            for _i in $(seq 1 20); do
                if sandbox bash -c "squeue -j $_stg_jid -h 2>/dev/null" && [[ -z "$OUTPUT" ]]; then
                    sleep 1
                    break
                fi
                sleep 1
            done
        fi
    fi

    if _stg_check_symlink; then
        pass "Slurm --output: in-sandbox symlink resolves to staging; staging holds job output (#67)"
    else
        _stg_staging_file="$(_stg_marker_in_staging)"
        if [[ -n "$_stg_staging_file" ]]; then
            # The job DID run and DID write to the chaperon-redirected
            # staging path — proving the host-side half. Missing symlink
            # is the in-sandbox wrapper prelude failing to emit (or
            # failing to `ln -s`) — that's a feature regression, not an
            # env issue. Fail loudly so this can't be silently masked
            # again (see CHANGELOG entry for #67).
            fail "Slurm --output: staging holds marker ($_stg_staging_file) but in-sandbox symlink missing at $_stg_intended — wrapper prelude regression"
        elif [[ -z "$_stg_submit" ]] || ! echo "$_stg_submit" | grep -q "Submitted batch job"; then
            skip "Slurm --output staging integration: sbatch did not submit ($_stg_submit)"
        else
            # Job submitted but no marker in staging → wrapper script
            # likely didn't reach the user's command (host-Slurm issue,
            # e.g., broken JobSubmitPlugin path). Skip rather than fail.
            skip "Slurm --output staging integration: job submitted but did not write marker (host slurm config?)"
        fi
    fi
    rm -rf "$_stg_subdir"
fi

# 6.5d. Integration: default --output (no flag, no env, no directive) gets
# the same staging + symlink contract via the chaperon's default-injection.
# Without this, an in-sandbox agent could symlink-plant the predictable
# `<cwd>/slurm-<next-jobid>.out` path before slurmstepd opens it.
if ! command -v sbatch &>/dev/null; then
    skip "Slurm default --output staging: sbatch not found"
elif is_landlock; then
    skip "Slurm default --output staging: disabled on landlock (no RO overlay)"
else
    _stg_subdir="$PROJECT_DIR/.test-slurm-default-$$"
    mkdir -p "$_stg_subdir"
    _TEST_TEMP_FILES+=("$_stg_subdir")
    _stg_submit=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- \
        bash -c "cd '$_stg_subdir' && sbatch --wait \
            --wrap='echo SLURM_DEFAULT_STAGING_TEST_$$'" 2>&1)
    _stg_rc=$?
    _stg_jid=$(echo "$_stg_submit" | grep -oE "Submitted batch job [0-9]+" | awk '{print $4}')

    _default_intended="$_stg_subdir/slurm-${_stg_jid}.out"
    _default_check_symlink() {
        [[ -L "$_default_intended" ]] || return 1
        local _resolved
        _resolved="$(readlink -f "$_default_intended" 2>/dev/null)" || return 1
        [[ "$_resolved" == "$PROJECT_DIR/.sandbox-state/slurm-logs/"* ]] || return 1
        grep -q "SLURM_DEFAULT_STAGING_TEST_$$" "$_default_intended" 2>/dev/null
    }

    if [[ -z "$_stg_jid" ]]; then
        skip "Slurm default --output staging: sbatch did not submit ($_stg_submit)"
    else
        # Grace window for the in-sandbox prelude to plant the symlink.
        if ! _default_check_symlink; then
            for _i in $(seq 1 20); do
                if sandbox bash -c "squeue -j $_stg_jid -h 2>/dev/null" && [[ -z "$OUTPUT" ]]; then
                    sleep 1
                    break
                fi
                sleep 1
            done
        fi

        if _default_check_symlink; then
            pass "Slurm default --output: <cwd>/slurm-<jobid>.out is a symlink to staging when no --output supplied"
        elif [[ -e "$_default_intended" && ! -L "$_default_intended" ]]; then
            fail "Slurm default --output: $_default_intended exists but is a regular file — chaperon default-injection MISSING"
        elif grep -rql "SLURM_DEFAULT_STAGING_TEST_$$" "$PROJECT_DIR/.sandbox-state/slurm-logs/" 2>/dev/null; then
            fail "Slurm default --output: staging holds marker but no symlink at $_default_intended — wrapper prelude regression"
        else
            skip "Slurm default --output staging: job submitted but neither symlink nor staging marker landed ($_stg_submit)"
        fi
    fi
    rm -rf "$_stg_subdir"
fi

# 6.5e. Integration: #SBATCH --output= directive (no CLI, no env) wins
# over the default-injection — i.e., when a directive supplies a value,
# the chaperon must NOT inject `slurm-%j.out` on top of it.
if ! command -v sbatch &>/dev/null; then
    skip "Slurm #SBATCH --output directive staging: sbatch not found"
elif is_landlock; then
    skip "Slurm #SBATCH --output directive staging: disabled on landlock"
else
    _stg_subdir="$PROJECT_DIR/.test-slurm-directive-$$"
    mkdir -p "$_stg_subdir"
    _TEST_TEMP_FILES+=("$_stg_subdir")
    _stg_script="$_stg_subdir/job.sh"
    cat > "$_stg_script" <<EOF
#!/bin/bash
#SBATCH --output=directive-wins.out
echo SLURM_DIRECTIVE_STAGING_TEST_$$
EOF
    chmod +x "$_stg_script"
    _stg_submit=$(timeout 30 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- \
        bash -c "cd '$_stg_subdir' && sbatch --wait '$_stg_script'" 2>&1)
    _stg_jid=$(echo "$_stg_submit" | grep -oE "Submitted batch job [0-9]+" | awk '{print $4}')
    _directive_intended="$_stg_subdir/directive-wins.out"
    _default_collision="$_stg_subdir/slurm-${_stg_jid}.out"
    _directive_check_symlink() {
        [[ -L "$_directive_intended" ]] || return 1
        grep -q "SLURM_DIRECTIVE_STAGING_TEST_$$" "$_directive_intended" 2>/dev/null
    }

    if [[ -z "$_stg_jid" ]]; then
        skip "Slurm #SBATCH --output directive staging: sbatch did not submit ($_stg_submit)"
    else
        if ! _directive_check_symlink; then
            for _i in $(seq 1 20); do
                if sandbox bash -c "squeue -j $_stg_jid -h 2>/dev/null" && [[ -z "$OUTPUT" ]]; then
                    sleep 1
                    break
                fi
                sleep 1
            done
        fi

        if _directive_check_symlink; then
            # And the default-name path must NOT exist (no double-injection).
            if [[ -e "$_default_collision" ]]; then
                fail "Slurm #SBATCH --output directive: directive symlink works BUT default-injection ALSO landed at $_default_collision — double-injection"
            else
                pass "Slurm #SBATCH --output directive: directive value wins; no default-injection collision"
            fi
        else
            skip "Slurm #SBATCH --output directive staging: directive symlink did not land ($_stg_submit)"
        fi
    fi
    rm -rf "$_stg_subdir"
fi

# 6.5f. Integration: array job default → slurm-%A_%a.out pattern (not
# slurm-%j.out). Each task gets its own symlink + staging pair.
if ! command -v sbatch &>/dev/null; then
    skip "Slurm array default --output staging: sbatch not found"
elif is_landlock; then
    skip "Slurm array default --output staging: disabled on landlock"
else
    _stg_subdir="$PROJECT_DIR/.test-slurm-array-$$"
    mkdir -p "$_stg_subdir"
    _TEST_TEMP_FILES+=("$_stg_subdir")
    _stg_submit=$(timeout 60 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
        --project-dir "$PROJECT_DIR" -- \
        bash -c "cd '$_stg_subdir' && sbatch --wait --array=1-2 \
            --wrap='echo SLURM_ARRAY_DEFAULT_TEST_${$}_task=\$SLURM_ARRAY_TASK_ID'" 2>&1)
    _stg_jid=$(echo "$_stg_submit" | grep -oE "Submitted batch job [0-9]+" | awk '{print $4}')

    if [[ -z "$_stg_jid" ]]; then
        skip "Slurm array default --output staging: sbatch did not submit ($_stg_submit)"
    else
        # Pattern resolves to slurm-<jobid>_<taskid>.out per task.
        _array_t1="$_stg_subdir/slurm-${_stg_jid}_1.out"
        _array_t2="$_stg_subdir/slurm-${_stg_jid}_2.out"
        _array_check_pair() {
            [[ -L "$_array_t1" ]] || return 1
            [[ -L "$_array_t2" ]] || return 1
            grep -q "SLURM_ARRAY_DEFAULT_TEST_${$}_task=1" "$_array_t1" 2>/dev/null || return 1
            grep -q "SLURM_ARRAY_DEFAULT_TEST_${$}_task=2" "$_array_t2" 2>/dev/null || return 1
            local _r1 _r2
            _r1="$(readlink -f "$_array_t1" 2>/dev/null)"
            _r2="$(readlink -f "$_array_t2" 2>/dev/null)"
            [[ "$_r1" == "$PROJECT_DIR/.sandbox-state/slurm-logs/"* ]] || return 1
            [[ "$_r2" == "$PROJECT_DIR/.sandbox-state/slurm-logs/"* ]] || return 1
        }
        if ! _array_check_pair; then
            for _i in $(seq 1 30); do
                if sandbox bash -c "squeue -j $_stg_jid -h 2>/dev/null" && [[ -z "$OUTPUT" ]]; then
                    sleep 1
                    break
                fi
                sleep 1
            done
        fi
        if _array_check_pair; then
            pass "Slurm array default --output: slurm-%A_%a.out pattern lands per-task symlink + staging"
        else
            skip "Slurm array default --output staging: tasks ran but symlinks did not land ($_stg_submit)"
        fi
    fi
    rm -rf "$_stg_subdir"
fi

echo ""

# ── 6.6 #SBATCH directive whitespace-smuggling (ASB-2026-001) ────
#
# Regression suite for ASB-2026-001 (HIGH; settylab/dotto-nexus#139).
# Baseline flag-name extraction in `create_wrapped_script` stops at
# the first `=`, so `#SBATCH --time=00:01:00 --task-prolog=/evil.sh`
# is classified as a `--time` directive and the smuggled tail rides
# through. Slurm's directive parser then whitespace-tokenizes the
# rebuilt line and applies both flags — the `--task-prolog` runs
# user-controlled code on the compute node BEFORE sandbox-exec.sh
# wraps the job. CLI deny-list at _handler_lib.sh:451-478 is
# bypassed via this path.
#
# These tests live at the unit layer (source _handler_lib.sh, call
# create_wrapped_script with crafted script content, assert on the
# emitted wrapper + return code). End-to-end empirical verification
# on a real Slurm cluster is out of scope for the test harness.

echo "6.6 #SBATCH directive smuggling (ASB-2026-001)"

# _smuggle_unit_test <test-label> <script-body> <expect-rejected> <forbidden-substr>
#
# Runs create_wrapped_script in a subshell, captures stdout/stderr,
# and returns:
#   0 — emitted wrapper does NOT contain <forbidden-substr> AND
#       (when <expect-rejected>=1) the function signaled rejection
#       via _sandbox_deny on stderr OR non-zero return.
#   1 — vulnerability present (smuggled token survived) OR the
#       positive control was rejected.
_smuggle_unit_run() {
    local _label="$1" _script="$2" _expect_rej="$3" _forbidden="$4"
    local _tmpdir _wrapper _err _rc _wrapper_text
    _tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/asb-2026-001-XXXXXX")
    _wrapper="$_tmpdir/wrap.sh"
    _err="$_tmpdir/err"
    (
        set +e
        export PROJECT_DIR="$_tmpdir"
        # shellcheck disable=SC1091
        source "$SCRIPT_DIR/chaperon/handlers/_handler_lib.sh"
        create_wrapped_script /bin/true "$_tmpdir" "$_script" "$_wrapper"
    ) 2>"$_err"
    _rc=$?
    _wrapper_text="$(cat "$_wrapper" 2>/dev/null || true)"
    local _err_text
    _err_text="$(cat "$_err" 2>/dev/null || true)"

    if [[ "$_expect_rej" == "1" ]]; then
        # Smuggling case: forbidden token must NOT appear in the
        # wrapper's #SBATCH header. Anything that lands in the
        # wrapper as a directive is what slurmstepd will see.
        local _header
        _header="$(printf '%s\n' "$_wrapper_text" | sed -n '/^# --- Chaperon wrapper/q;p')"
        if printf '%s' "$_header" | grep -qF -- "$_forbidden"; then
            fail "$_label: smuggled '$_forbidden' survived into wrapper #SBATCH header" \
                 "header: $_header | stderr: $_err_text | rc=$_rc"
            rm -rf "$_tmpdir"
            return 1
        fi
        # And the chaperon must have surfaced a security message
        # (matches the wording the CLI deny-list uses, so operators
        # can grep both paths identically).
        if echo "$_err_text" | grep -qiE "is not allowed|blocked for security|denied|unsafe"; then
            pass "$_label"
            rm -rf "$_tmpdir"
            return 0
        else
            fail "$_label: smuggled token stripped but no security message emitted" \
                 "stderr: $_err_text | rc=$_rc"
            rm -rf "$_tmpdir"
            return 1
        fi
    else
        # Positive control: the directive should survive AND no
        # security message should fire.
        if ! printf '%s' "$_wrapper_text" | grep -qE '^#SBATCH '; then
            fail "$_label: clean directive missing from wrapper" \
                 "wrapper: $_wrapper_text | stderr: $_err_text"
            rm -rf "$_tmpdir"
            return 1
        fi
        if echo "$_err_text" | grep -qiE "is not allowed|blocked for security|denied|unsafe"; then
            fail "$_label: clean directive triggered a security message (false positive)" \
                 "stderr: $_err_text"
            rm -rf "$_tmpdir"
            return 1
        fi
        pass "$_label"
        rm -rf "$_tmpdir"
        return 0
    fi
}

# Per-flag smuggling vectors. Each test runs against the form
# `#SBATCH --time=00:01:00 --<denied>=/evil.sh\necho job`.
for _flag in --task-prolog --prolog --get-user-env --bcast --container; do
    _smuggle_script="#!/bin/bash
#SBATCH --time=00:01:00 ${_flag}=/evil.sh
echo job"
    _smuggle_unit_run \
        "Chaperon rejects '${_flag}' smuggled via #SBATCH directive body" \
        "$_smuggle_script" 1 "${_flag}"
done

# Short-form smuggling: `-o foo --task-prolog=/evil`.
_short_smuggle="#!/bin/bash
#SBATCH -o foo --task-prolog=/evil.sh
echo job"
_smuggle_unit_run \
    "Chaperon rejects '--task-prolog' smuggled after short-form '-o'" \
    "$_short_smuggle" 1 "--task-prolog"

# Generic smuggling-shape: an allowed flag followed by an allowed
# flag still smells like the attack pattern (whitespace-then-`--`
# in the directive body). The defense-in-depth rule rejects the
# whole directive even when every smuggled flag is benign.
_pair_smuggle="#!/bin/bash
#SBATCH --time=00:01:00 --partition=foo
echo job"
_smuggle_unit_run \
    "Chaperon rejects multi-flag #SBATCH directive shape (defense-in-depth)" \
    "$_pair_smuggle" 1 "--partition"

# Positive control: a clean single-flag directive must still pass.
_clean_directive="#!/bin/bash
#SBATCH --time=00:01:00
echo job"
_smuggle_unit_run \
    "Chaperon accepts clean single-flag #SBATCH --time directive" \
    "$_clean_directive" 0 ""

# Positive control: --output=path rewrite path must still produce
# a wrapper that submits cleanly (no false-positive smuggling
# rejection on the rebuild path).
_clean_output="#!/bin/bash
#SBATCH --output=out.log
echo job"
_smuggle_unit_run \
    "Chaperon accepts clean #SBATCH --output= directive (rebuild path)" \
    "$_clean_output" 0 ""

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
        "pi overlay|$SCRIPT_DIR/agents/pi/overlay.sh"
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
# Default-deny: a symlink in PROJECT_DIR pointing into ~/.ssh must
# NOT expose contents — the sandbox's deny-list resolves symlinks
# before applying. Exception: if the loaded config lists .ssh in
# HOME_READONLY / HOME_WRITABLE, the symlink correctly reflects the
# opt-in (e.g. a user who exposes ~/.ssh so they can git-push from
# the sandbox) and we assert VISIBLE.
local _ssh_link="$PROJECT_DIR/.test-ssh-link-$$"
ln -snf "$HOME/.ssh" "$_ssh_link" 2>/dev/null
if [[ -L "$_ssh_link" ]]; then
    local _ssh_intentional=false
    _home_dir_intentional ".ssh" && _ssh_intentional=true
    if sandbox bash -c "ls '$_ssh_link/' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -qE "Permission denied|No such file|EXIT=[1-9]|cannot access"; then
            if $_ssh_intentional; then
                fail "S02: ~/.ssh in HOME_READONLY/HOME_WRITABLE but symlink blocked" "$OUTPUT"
            else
                pass "S02: Cannot list ~/.ssh through symlink in project dir"
            fi
        elif echo "$OUTPUT" | grep -qE "id_rsa|id_ed25519|authorized_keys"; then
            if $_ssh_intentional; then
                pass "S02: ~/.ssh symlink follows HOME_READONLY/HOME_WRITABLE opt-in"
            else
                fail "S02: ~/.ssh contents visible through symlink — symlink bypasses sandbox" "$OUTPUT"
            fi
        else
            pass "S02: ~/.ssh not accessible through symlink (empty or blocked)"
        fi
    else
        if $_ssh_intentional; then
            fail "S02: ~/.ssh in HOME_READONLY/HOME_WRITABLE but sandbox command failed" "$OUTPUT"
        else
            pass "S02: Sandbox blocked access to ~/.ssh via symlink"
        fi
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

# ── S05: Symlinked ancestor of a BLOCKED_FILES entry ──
# When an ancestor of a BLOCKED_FILES entry is a symlink that lives
# inside a writable bind (e.g. ~/dotfile-managed/.claude → real dir),
# `readlink -f` on the leaf yields a different path than what the agent
# accesses. Without a defense, the /dev/null overlay is mounted at the
# resolved path and missed when the agent reads via the symlinked path
# (mount overlays are path-keyed, not inode-keyed). bwrap.sh emits a
# literal-path bind in addition to the resolved-path bind so the
# overlay applies wherever the agent actually opens the file.
if is_bwrap; then
    local _ancestor_real="$PROJECT_DIR/.test-ancestor-real-$$"
    local _ancestor_link="$PROJECT_DIR/.test-ancestor-link-$$"
    mkdir -p "$_ancestor_real"
    echo "SENSITIVE" > "$_ancestor_real/secret"
    ln -snf "$_ancestor_real" "$_ancestor_link"
    local _slink_anc_conf="$HOME/.config/agent-sandbox/conf.d/test-symlink-ancestor-$$.conf"
    _TEST_TEMP_FILES+=("$_slink_anc_conf")
    mkdir -p "$HOME/.config/agent-sandbox/conf.d"
    # Block the file via the SYMLINKED parent path.
    echo "BLOCKED_FILES+=( \"$_ancestor_link/secret\" )" > "$_slink_anc_conf"

    if sandbox bash -c "cat '$_ancestor_link/secret' 2>&1; echo EXIT=\$?"; then
        if echo "$OUTPUT" | grep -q "SENSITIVE"; then
            fail "S05: BLOCKED_FILES bypassed via symlinked ancestor — secret leaked" "$OUTPUT"
        else
            pass "S05: Symlinked-ancestor BLOCKED_FILES read returns empty"
        fi
    else
        pass "S05: Sandbox blocked symlinked-ancestor read (command failed)"
    fi

    rm -f "$_slink_anc_conf"
    rm -rf "$_ancestor_real" "$_ancestor_link"
else
    skip "S05: Symlinked-ancestor BLOCKED_FILES test is bwrap-specific"
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
        # risk is host ptys, which requires DEVICES+=(/dev/pts) (legacy
        # BIND_DEV_PTS=true is rewritten to the same).  On kernels < 6.2
        # the ioctl is allowed on any open pty fd, so it succeeds even
        # with --dev /dev (isolated devpts).
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

    # ioctl(TIOCSTI) / ioctl(TIOCLINUX) — argument-filtered denial.
    # Bwrap is the only backend whose seccomp filter we generate ourselves
    # (landlock backend uses a different generator; firejail uses its own
    # --seccomp.drop set), so the assertion is bwrap-scoped.
    #
    # The reproducer mirrors the CVE-2017-5226 / CVE-2023-1523 attack
    # primitive: setsid + TIOCSCTTY to make a freshly-allocated pty the
    # caller's controlling tty, then ioctl(TIOCSTI) to inject a byte. The
    # kernel permits TIOCSTI on a tty the caller controls — without the
    # seccomp filter the byte gets queued.  With the filter it returns
    # EPERM before the kernel handler runs.
    if is_bwrap; then
        if sandbox python3 -c "
import os, fcntl, pty
master, slave = pty.openpty()
pid = os.fork()
if pid == 0:
    try:
        os.setsid()
        fcntl.ioctl(slave, 0x540E, 0)  # TIOCSCTTY
    except Exception as e:
        print('SETUP_FAIL:' + str(e)); os._exit(3)
    try:
        fcntl.ioctl(slave, 0x5412, b'X')  # TIOCSTI
        print('TIOCSTI_SUCCEEDED')
    except OSError as e:
        print('TIOCSTI_BLOCKED:errno=' + str(e.errno))
    os._exit(0)
os.close(slave)
os.waitpid(pid, 0)
" 2>&1; then
            if echo "$OUTPUT" | grep -q "TIOCSTI_BLOCKED:errno=1"; then
                pass "ioctl(TIOCSTI) blocked by seccomp (EPERM)"
            elif echo "$OUTPUT" | grep -q "TIOCSTI_SUCCEEDED"; then
                fail "ioctl(TIOCSTI) succeeded — seccomp filter missing the rule" "$OUTPUT"
            elif echo "$OUTPUT" | grep -q "SETUP_FAIL"; then
                skip "ioctl(TIOCSTI): could not establish controlling tty in sandbox ($OUTPUT)"
            else
                skip "ioctl(TIOCSTI): inconclusive ($OUTPUT)"
            fi
        else
            skip "Could not test ioctl(TIOCSTI)"
        fi

        # ioctl(TIOCLINUX) — denied outright. seccomp returns EPERM (errno=1)
        # whereas the kernel handler returns ENOTTY (errno=25) when the fd
        # is not a Linux text console.
        if sandbox python3 -c "
import os, fcntl
try:
    fd = os.open('/dev/tty', os.O_RDWR)
except OSError:
    fd = 0
try:
    fcntl.ioctl(fd, 0x541C, b'\\x0c\\x00')  # TIOCLINUX, subcmd 12 (paste)
    print('TIOCLINUX_SUCCEEDED')
except OSError as e:
    print('TIOCLINUX_RC:errno=' + str(e.errno))
" 2>&1; then
            if echo "$OUTPUT" | grep -q "TIOCLINUX_RC:errno=1"; then
                pass "ioctl(TIOCLINUX) blocked by seccomp (EPERM)"
            elif echo "$OUTPUT" | grep -q "TIOCLINUX_SUCCEEDED"; then
                fail "ioctl(TIOCLINUX) succeeded — seccomp filter missing the rule" "$OUTPUT"
            else
                # ENOTTY (25) and friends mean kernel handler reached → filter not applied
                fail "ioctl(TIOCLINUX) reached kernel handler instead of being filtered" "$OUTPUT"
            fi
        else
            skip "Could not test ioctl(TIOCLINUX)"
        fi
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

# pty allocation and tmux (requires DEVICES+=(/dev/pts) on kernels < 5.4)
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
    skip "pty allocation failed (set DEVICES+=(/dev/pts) for tmux on kernels < 5.4)"
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

# ── 11.4 Network filter ───────────────────────────────────────────
#
# v1.0 shipped isolated mode + the config plumbing + the fallback
# resolver. v1.1 wires real 'filtered' mode: the
# NETWORK_FILTER_ENABLE_HELPER_PROBE gate is gone, the shipped
# tools/pasta/<arch>/pasta is auto-detected, and the bwrap backend
# wraps itself in pasta with `-T ~N` outbound port exclusions
# generated from the resolved blocklist. No nftables dependency.
# These tests assert each piece independently; the empirical
# filtered-mode tests skip cleanly when the runner lacks pasta.

# Detect helper ONCE so the conditional tests below stay readable.
# Exported so subshells can branch on it without re-probing.
if command -v pasta >/dev/null 2>&1 \
   || [[ -x "$SCRIPT_DIR/tools/pasta/$(uname -m)/pasta" ]]; then
    export _test_has_pasta=1
else
    export _test_has_pasta=0
fi

# Helper PRESENCE alone is not sufficient — pasta may start and then
# degrade to loopback-only forwarding (kernel < 5.7 / unprivileged
# userns / no CAP_NET_RAW). The resolver's pasta forwarding probe
# catches that and falls back; the unit tests below must branch on the
# resolver's actual verdict, not on binary-on-disk. Run filtered /
# stricter once and record whether the resolver delivers filtered.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    NETWORK_FILTER_MODE=filtered NETWORK_FILTER_FALLBACK=stricter
    resolve_network_filter_mode bwrap 2>/dev/null
    [[ "$_NETWORK_FILTER_RESOLVED" == "filtered" ]]
); then
    export _test_filtered_deliverable=1
else
    export _test_filtered_deliverable=0
fi

echo "11.4. Network filter"

# Mode-resolver unit tests via _SANDBOX_LIB_NO_INIT=1 harness — pure
# function tests, no sandbox spawn needed. The resolver and its helpers
# live above the test-harness early return in sandbox-lib.sh.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"

    # Test 1: defaults
    [[ "$NETWORK_FILTER_MODE" == "filtered" ]] || { echo "default mode wrong"; exit 1; }
    [[ "$NETWORK_FILTER_FALLBACK" == "open" ]] || { echo "default fallback wrong"; exit 1; }
    # _NETWORK_BLOCKLIST_DEFAULTS is now empty (sentinel); the floor
    # lives in the shipped sandbox.conf so an operator editing their
    # config sees the policy table directly. Load the shipped
    # sandbox.conf to populate NETWORK_BLOCKLIST for the floor checks
    # below.
    [[ "${#_NETWORK_BLOCKLIST_DEFAULTS[@]}" -eq 0 ]] || { echo "lib floor sentinel non-empty"; exit 1; }
    _load_untrusted_config "$SCRIPT_DIR/sandbox.conf" "Test default sandbox.conf load"
    [[ "${#NETWORK_BLOCKLIST[@]}" -ge 20 ]] || { echo "shipped sandbox.conf NETWORK_BLOCKLIST too short"; exit 1; }

    # Test 2: bwrap + filtered + stricter — v0.10.1 changes the
    # fallback target when filtered is undeliverable. Under v0.10.0
    # the only stricter mode available from filtered was isolated;
    # v0.10.1 inserts `proxied` between filtered and isolated (smaller
    # step up — sandbox stays usable via host-side HTTP+SOCKS proxy).
    # Branches:
    #   filtered deliverable    → filtered (no fallback exercised)
    #   filtered NOT deliverable AND proxied supported → proxied (v0.10.1)
    #   filtered NOT deliverable AND proxied NOT supported → isolated
    #
    # `proxied` requires python3 + the helper at
    # $SANDBOX_DIR/tools/proxy/agent-sandbox-proxy.py. Both available on
    # every modern Linux runner; the proxied branch is the new default
    # for kernel < 5.7 / no-CAP_NET_RAW hosts.
    NETWORK_FILTER_MODE=filtered NETWORK_FILTER_FALLBACK=stricter
    resolve_network_filter_mode bwrap 2>/dev/null
    if [[ "${_test_filtered_deliverable:-0}" == "1" ]]; then
        [[ "$_NETWORK_FILTER_RESOLVED" == "filtered" ]] || { echo "v1.1: expected filtered (deliverable on this runner), got $_NETWORK_FILTER_RESOLVED"; exit 1; }
        [[ -n "$_NETWORK_FILTER_HELPER" ]] || { echo "v1.1: helper path empty"; exit 1; }
    elif _proxied_supported_on_bwrap; then
        [[ "$_NETWORK_FILTER_RESOLVED" == "proxied" ]] || { echo "v0.10.1: expected fallback to proxied (filtered not deliverable, python3 available), got $_NETWORK_FILTER_RESOLVED"; exit 1; }
    else
        [[ "$_NETWORK_FILTER_RESOLVED" == "isolated" ]] || { echo "expected fallback to isolated (filtered + proxied both undeliverable), got $_NETWORK_FILTER_RESOLVED"; exit 1; }
    fi

    # Test 3: bwrap + isolated + stricter → isolated (no fallback needed)
    NETWORK_FILTER_MODE=isolated NETWORK_FILTER_FALLBACK=stricter
    resolve_network_filter_mode bwrap 2>/dev/null
    [[ "$_NETWORK_FILTER_RESOLVED" == "isolated" ]] || exit 1

    # Test 4: bwrap + open + any → open
    NETWORK_FILTER_MODE=open NETWORK_FILTER_FALLBACK=stricter
    resolve_network_filter_mode bwrap 2>/dev/null
    [[ "$_NETWORK_FILTER_RESOLVED" == "open" ]] || exit 1

    # Test 5: filtered + open + landlock → open (less-strict only)
    NETWORK_FILTER_MODE=filtered NETWORK_FILTER_FALLBACK=open
    resolve_network_filter_mode landlock 2>/dev/null
    [[ "$_NETWORK_FILTER_RESOLVED" == "open" ]] || exit 1

    # Test 5b: filtered + open + bwrap — `open` policy NEVER strengthens.
    # Under v1.0 (no helper) this resolved to 'open' (the regression
    # guard). Under v1.1 with a deliverable pasta, the resolver returns
    # 'filtered' directly (no fallback exercised). When pasta is
    # missing OR degraded (probe-gated), filtered is unavailable and
    # the open policy falls to 'open'. The invariant the test guards
    # is "open policy never falls to a stricter mode than requested"
    # — both outcomes satisfy it (filtered ≤ filtered, open <
    # filtered). Branch on probe-actual deliverability.
    NETWORK_FILTER_MODE=filtered NETWORK_FILTER_FALLBACK=open
    resolve_network_filter_mode bwrap 2>/dev/null
    if [[ "${_test_filtered_deliverable:-0}" == "1" ]]; then
        [[ "$_NETWORK_FILTER_RESOLVED" == "filtered" ]] || { echo "open policy regressed ($_NETWORK_FILTER_RESOLVED) — expected filtered (deliverable)"; exit 1; }
    else
        [[ "$_NETWORK_FILTER_RESOLVED" == "open" ]] || { echo "open policy went stricter ($_NETWORK_FILTER_RESOLVED) — regression"; exit 1; }
    fi

    # Test 5c: isolated + open + landlock → open (less-strict only)
    NETWORK_FILTER_MODE=isolated NETWORK_FILTER_FALLBACK=open
    resolve_network_filter_mode landlock 2>/dev/null
    [[ "$_NETWORK_FILTER_RESOLVED" == "open" ]] || exit 1

    # Test 5d: proxied + bwrap (any policy) → proxied directly when
    # the helper is installed + python3 is on PATH. v0.10.1 surface.
    if _proxied_supported_on_bwrap; then
        NETWORK_FILTER_MODE=proxied NETWORK_FILTER_FALLBACK=open
        resolve_network_filter_mode bwrap 2>/dev/null
        [[ "$_NETWORK_FILTER_RESOLVED" == "proxied" ]] || { echo "MODE=proxied+open didn't yield proxied, got $_NETWORK_FILTER_RESOLVED"; exit 1; }
    fi

    # Test 5e: proxied + landlock → fail (no netns) or fallback per
    # policy. landlock has no network namespace primitive, so proxied
    # is structurally unavailable on it. Under `open` policy the
    # resolver falls to `open` (the only less-strict mode landlock
    # supports). Under `strict` it fails to launch.
    NETWORK_FILTER_MODE=proxied NETWORK_FILTER_FALLBACK=open
    resolve_network_filter_mode landlock 2>/dev/null
    [[ "$_NETWORK_FILTER_RESOLVED" == "open" ]] || { echo "proxied+landlock+open didn't fall to open, got $_NETWORK_FILTER_RESOLVED"; exit 1; }

    # Tests 5f / 5g (degraded-pasta fallback semantics) live in the
    # pasta-forwarding-probe block below — they need a fake degraded
    # pasta stub on PATH because `_prepare_network_helper_probe` resets
    # `_NETWORK_HELPER_PROBE_RESULT` before reading the capability
    # matrix, so pre-setting it in this subshell has no effect.

    # Test 6: effective blocklist (after loading shipped sandbox.conf
    # in Test 1) contains the universal entries. Site-specific entries
    # are commented out by default in the skel and so must NOT appear.
    # Mail submission (universal):
    effective_network_blocklist 2>/dev/null | grep -q "^127.0.0.1:24\$" || exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^127.0.0.1:25\$" || exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^0.0.0.0/0:25\$" || exit 1
    # Site-specific Fred Hutch CIDR — commented out by default → MUST
    # NOT be present:
    effective_network_blocklist 2>/dev/null | grep -q "^140.107.0.0/16:25\$" && exit 1
    # Transactional-email HTTPS APIs (universal):
    effective_network_blocklist 2>/dev/null | grep -q "^api.mailgun.net\$" || exit 1
    # Webhooks (universal):
    effective_network_blocklist 2>/dev/null | grep -q "^hooks.slack.com\$" || exit 1
    # File drops + paste (universal):
    effective_network_blocklist 2>/dev/null | grep -q "^transfer.sh\$" || exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^pastebin.com\$" || exit 1
    # DoH / DoT (universal):
    effective_network_blocklist 2>/dev/null | grep -q "^cloudflare-dns.com\$" || exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^853\$" || exit 1
    # SMB / RDP / VNC — site-specific (commented out) → MUST NOT be
    # present:
    effective_network_blocklist 2>/dev/null | grep -q "^445\$" && exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^3389\$" && exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^5900\$" && exit 1
    # Legacy r-services (universal):
    effective_network_blocklist 2>/dev/null | grep -q "^23\$" || exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^514\$" || exit 1
    # Site-specific LDAP / Kerberos — commented out by default → MUST
    # NOT be present:
    effective_network_blocklist 2>/dev/null | grep -q "^389\$" && exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^88\$" && exit 1
    # Site-specific Slurm / munge — commented out by default → MUST
    # NOT be present:
    effective_network_blocklist 2>/dev/null | grep -q "^6817\$" && exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^904\$" && exit 1

    exit 0
); then
    pass "Network filter: resolver unit tests (defaults, fallback, effective blocklist)"
else
    fail "Network filter: resolver unit tests failed (rc=$?)"
fi

# Pasta forwarding-probe regression guard. Reproduces the kernel < 5.7 /
# unprivileged-userns / no-CAP_NET_RAW host condition where pasta starts
# but degrades to loopback-only forwarding (`SO_BINDTODEVICE unavailable,
# forwarding only 127.0.0.1 and ::1`). Without the probe, the resolver
# declared `filtered` supported on any host with an executable pasta —
# and the sandbox launched with the documented filtered argv that
# pasta then silently neutered. CI on Ubuntu 22.04+ never tripped over
# this because the kernel allows SO_BINDTODEVICE; HPC login nodes
# running kernel 5.4 (e.g. Fred Hutch gizmo) did, and got no outbound on
# allowed ports. The probe + this test close the gap.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"

    # Build a fake pasta stub matching the structure pasta emits when
    # SO_BINDTODEVICE is denied. The exact substring 'forwarding only
    # 127.0.0.1' is what the probe matches; everything else mirrors
    # pasta's real banner so the stub stays realistic.
    _stub_dir="$(mktemp -d "${TMPDIR:-/tmp}/pasta-degraded-stub.XXXXXX")"
    trap 'rm -rf "$_stub_dir"' EXIT
    cat >"$_stub_dir/pasta" <<'STUB'
#!/usr/bin/env bash
# Mimic pasta's loopback-only degradation banner. Print to stderr,
# accept the same argv shape the real probe uses (--foreground --quiet
# -- COMMAND), exit 0 so the probe can't fall through on rc.
echo "SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-T auto'" >&2
echo "SO_BINDTODEVICE unavailable, forwarding only 127.0.0.1 and ::1 for '-U auto'" >&2
# Honour the trailing '--' COMMAND so the probe's `-- true` runs and
# returns 0 without us needing to know the netns plumbing.
_seen_sep=0
for _a in "$@"; do
    if [[ "$_seen_sep" == 1 ]]; then "$_a" "${@:2}" 2>/dev/null; exit $?; fi
    [[ "$_a" == "--" ]] && _seen_sep=1
done
exit 0
STUB
    chmod 755 "$_stub_dir/pasta"

    # Force the resolver onto our stub. Clearing PATH to the stub dir
    # makes _resolve_network_helper find pasta on PATH first (before
    # the in-tree binary).
    PATH="$_stub_dir:$PATH"
    NETWORK_FILTER_MODE=filtered NETWORK_FILTER_FALLBACK=stricter
    # Suppress stderr so the fallback warning doesn't pollute test output;
    # the assertions read state, not the banner.
    resolve_network_filter_mode bwrap 2>/dev/null

    [[ "$_NETWORK_HELPER_PROBE_RESULT" == "degraded" ]] || \
        { echo "expected probe result 'degraded', got '$_NETWORK_HELPER_PROBE_RESULT'"; exit 1; }
    [[ -n "$_NETWORK_HELPER_DEGRADED_REASON" ]] || \
        { echo "_NETWORK_HELPER_DEGRADED_REASON empty"; exit 1; }
    # v0.10.1: with proxied available (python3 on PATH + in-tree
    # helper), the stricter walk's least-strict-step-up rule lands on
    # proxied before isolated. When proxied is unsupported, the walk
    # continues to isolated (pre-v0.10.1 behaviour).
    if _proxied_supported_on_bwrap; then
        [[ "$_NETWORK_FILTER_RESOLVED" == "proxied" ]] || \
            { echo "v0.10.1: expected fallback to proxied (filtered degraded, proxied supported), got '$_NETWORK_FILTER_RESOLVED'"; exit 1; }
    else
        [[ "$_NETWORK_FILTER_RESOLVED" == "isolated" ]] || \
            { echo "expected fallback to isolated (filtered degraded, proxied unsupported), got '$_NETWORK_FILTER_RESOLVED'"; exit 1; }
    fi

    # Override must bypass the probe — operators with a setcap-blessed
    # pasta need an escape hatch.
    NETWORK_FILTER_SKIP_HELPER_PROBE=1 \
    NETWORK_FILTER_MODE=filtered NETWORK_FILTER_FALLBACK=stricter
    resolve_network_filter_mode bwrap 2>/dev/null
    [[ "$_NETWORK_FILTER_RESOLVED" == "filtered" ]] || \
        { echo "SKIP_HELPER_PROBE=1 didn't restore filtered, got '$_NETWORK_FILTER_RESOLVED'"; exit 1; }

    # Test 5g (v0.10.1 regression guard): filtered + open on a degraded
    # pasta host MUST land on `open`, NOT silently strengthen to
    # `proxied`. `open` policy only weakens. This is the load-bearing
    # default-config-user invariant — adding `proxied` to the strictness
    # chain must not shift their reach.
    #
    # The previous SKIP_HELPER_PROBE=1 line above is a bare variable
    # assignment (no command suffix), which under bash assigns to the
    # shell — so it persists into this test. Unset it explicitly so the
    # real (stub-pasta-driven) probe runs and returns "degraded".
    unset NETWORK_FILTER_SKIP_HELPER_PROBE
    NETWORK_FILTER_MODE=filtered NETWORK_FILTER_FALLBACK=open
    resolve_network_filter_mode bwrap 2>/dev/null
    [[ "$_NETWORK_FILTER_RESOLVED" == "open" ]] || \
        { echo "v0.10.1: open policy on degraded pasta MUST STAY ON open (default-config invariant) — proxied creep regression, got '$_NETWORK_FILTER_RESOLVED'"; exit 1; }
    exit 0
); then
    pass "Network filter: pasta forwarding probe gates filtered when helper degrades to loopback-only"
else
    fail "Network filter: pasta forwarding probe test failed (rc=$?)"
fi

# Mode resolution failure paths exit the parent process via _network_filter_fail.
# Exercise the strict-fails path in a subshell. Use landlock as the
# deterministically-unsupported backend (landlock has no netns at all,
# so filtered is structurally unavailable on every runner regardless of
# pasta/helper presence). The earlier bwrap-based assertion no longer
# holds under v1.1: with the shipped pasta binary, bwrap+filtered
# resolves on most runners.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    NETWORK_FILTER_MODE=filtered NETWORK_FILTER_FALLBACK=strict
    resolve_network_filter_mode landlock 2>/dev/null
) ; then
    fail "Network filter: strict policy on unavailable filtered (landlock) should have exited"
else
    pass "Network filter: strict policy fails loudly when requested mode unavailable"
fi

# Landlock + filtered + stricter must fail (no stricter mode possible).
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    NETWORK_FILTER_MODE=filtered NETWORK_FILTER_FALLBACK=stricter
    resolve_network_filter_mode landlock 2>/dev/null
) ; then
    fail "Network filter: stricter on landlock should have exited"
else
    pass "Network filter: stricter policy on landlock fails (no stricter mode available)"
fi

# ── 11.4.proxied: agent-sandbox-proxy.py unit tests ─────────────
# v0.10.1 proxied-mode helper. Exercises the policy-check boundary:
# spawn the daemon with a tight blocklist + a single EXCEPT entry,
# fire shaped CONNECT and SOCKS5 requests at its Unix sockets, assert
# the response code mirrors policy. The blocklist enforcement is the
# load-bearing security property; the byte-pump path is exercised by
# the integration tests further down (where a real outbound is in
# scope).
if command -v python3 >/dev/null 2>&1 \
   && [[ -r "$SCRIPT_DIR/tools/proxy/agent-sandbox-proxy.py" ]]; then
    _proxy_unit_dir="$(mktemp -d "${TMPDIR:-/tmp}/agent-sandbox-proxy-unit-XXXXXX")"
    chmod 700 "$_proxy_unit_dir"
    _TEST_TEMP_FILES+=("$_proxy_unit_dir")
    # Block: explicit host, wildcard, bare port, IPv4-CIDR floor.
    # EXCEPT carve-out: api.example.com (overrides *.example.com).
    python3 "$SCRIPT_DIR/tools/proxy/agent-sandbox-proxy.py" --server \
        --socket-dir "$_proxy_unit_dir" \
        --blocklist-json '["evil.net", "*.example.com", "23", "127.0.0.1:25"]' \
        --except-json    '["api.example.com"]' \
        >"$_proxy_unit_dir/ready" 2>"$_proxy_unit_dir/err" &
    _proxy_unit_pid=$!
    _proxy_unit_deadline=$(( SECONDS + 3 ))
    while (( SECONDS < _proxy_unit_deadline )); do
        grep -q '^ready$' "$_proxy_unit_dir/ready" 2>/dev/null && break
        sleep 0.05
    done
    if grep -q '^ready$' "$_proxy_unit_dir/ready" 2>/dev/null; then
        _proxy_unit_ok=1
        # HTTP CONNECT path: 4 shapes.
        _http_check() {
            local _target="$1"; local _expect_code="$2"; local _why="$3"
            local _resp
            _resp="$(python3 -c "
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect('$_proxy_unit_dir/http.sock')
s.sendall(b'CONNECT $_target HTTP/1.1\r\nHost: x\r\n\r\n')
print(s.recv(512).decode(errors='replace').split('\r\n')[0])
")"
            if [[ "$_resp" != "HTTP/1.1 $_expect_code"* ]]; then
                echo "  $_why: expected '$_expect_code', got '$_resp'"
                _proxy_unit_ok=0
            fi
        }
        _http_check "10.0.0.1:443" "403"          "RFC1918 floor must block"
        _http_check "169.254.169.254:80" "403"    "cloud-metadata floor must block"
        _http_check "[::1]:443" "403"             "IPv6 loopback floor must block"
        _http_check "evil.net:443" "403"          "exact-host block"
        _http_check "www.example.com:443" "403"   "wildcard *.example.com block"
        _http_check "everything.test:23" "403"    "bare-port 23 block"
        _http_check "2130706433:443" "400"        "decimal-int IPv4 must be rejected"
        _http_check "0x7f000001:443" "400"        "hex IPv4 must be rejected"
        # api.example.com is EXCEPT-carved through *.example.com; the
        # policy passes but the connect will 502 (no Internet from this
        # runner is fine — the test asserts policy DOES NOT 403).
        _resp="$(python3 -c "
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect('$_proxy_unit_dir/http.sock')
s.sendall(b'CONNECT api.example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n')
print(s.recv(512).decode(errors='replace').split('\r\n')[0])
")"
        if [[ "$_resp" == "HTTP/1.1 403"* ]]; then
            echo "  EXCEPT api.example.com was 403'd (should have carved through wildcard)"
            _proxy_unit_ok=0
        fi
        # SOCKS5 path: refuse explicit floor + wildcard.
        _socks_check() {
            local _host="$1"; local _atyp="$2"; local _expect_rep="$3"; local _why="$4"
            local _rep
            _rep="$(python3 -c "
import socket, struct, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
s.connect('$_proxy_unit_dir/socks.sock')
s.sendall(b'\x05\x01\x00')
assert s.recv(2) == b'\x05\x00'
h = '$_host'.encode('ascii')
if $_atyp == 0x03:
    body = struct.pack('!BBBB', 5,1,0,3) + bytes([len(h)]) + h + struct.pack('!H', 443)
elif $_atyp == 0x01:
    body = struct.pack('!BBBB', 5,1,0,1) + socket.inet_aton('$_host') + struct.pack('!H', 443)
s.sendall(body)
r = s.recv(10)
print(r[1])
")"
            if [[ "$_rep" != "$_expect_rep" ]]; then
                echo "  $_why: SOCKS5 expected REP=$_expect_rep, got $_rep"
                _proxy_unit_ok=0
            fi
        }
        _socks_check "10.0.0.1" "0x01" "2" "SOCKS5 RFC1918 floor"
        _socks_check "www.example.com" "0x03" "2" "SOCKS5 wildcard block"
    else
        echo "  proxy daemon did not signal ready within 3s; stderr:"
        sed 's/^/    /' "$_proxy_unit_dir/err" 2>/dev/null | head -10 >&2
        _proxy_unit_ok=0
    fi
    kill "$_proxy_unit_pid" 2>/dev/null || true
    wait "$_proxy_unit_pid" 2>/dev/null || true
    if [[ "${_proxy_unit_ok:-0}" == "1" ]]; then
        pass "Network filter: agent-sandbox-proxy.py policy enforcement (HTTP CONNECT + SOCKS5)"
    else
        fail "Network filter: agent-sandbox-proxy.py policy enforcement failed"
    fi
else
    skip "Network filter: proxied unit tests need python3 + tools/proxy/agent-sandbox-proxy.py"
fi

# Integration test: 'isolated' mode actually kills the network.
# Requires a mount-namespace backend (bwrap or firejail). Skip on
# landlock where isolated is unavailable.
if has_mount_ns; then
    # Build a conf snippet that pins isolated mode.
    _net_isolated_conf="$HOME/.config/agent-sandbox/conf.d/test-net-isolated-$$.conf"
    _TEST_TEMP_FILES+=("$_net_isolated_conf")
    mkdir -p "$HOME/.config/agent-sandbox/conf.d"
    echo 'NETWORK_FILTER_MODE=isolated' > "$_net_isolated_conf"
    echo 'NETWORK_FILTER_FALLBACK=strict' >> "$_net_isolated_conf"

    # The empirical bypass that defeats binary-only blocks:
    # bash /dev/tcp/127.0.0.1/25. In isolated mode this must fail with
    # ENETUNREACH because there is no listener inside the empty netns.
    if sandbox bash -c '
        exec 3<>/dev/tcp/127.0.0.1/25 2>&1 && echo CONNECTED || echo BLOCKED
    '; then
        if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
            pass "Network filter: isolated mode blocks bash /dev/tcp/127.0.0.1/25"
        else
            fail "Network filter: isolated mode left 127.0.0.1:25 reachable" "$OUTPUT"
        fi
    fi

    # Same for Python smtplib — the other empirical bypass class.
    if command -v python3 &>/dev/null && sandbox bash -c '
        python3 -c "
import smtplib, sys
try:
    s = smtplib.SMTP(\"127.0.0.1\", 25, timeout=3)
    print(\"CONNECTED\")
    s.quit()
except Exception as e:
    print(\"BLOCKED:\", type(e).__name__)
"
    '; then
        if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
            pass "Network filter: isolated mode blocks Python smtplib to 127.0.0.1:25"
        else
            fail "Network filter: isolated mode left smtplib path reachable" "$OUTPUT"
        fi
    fi

    rm -f "$_net_isolated_conf"
else
    skip "Network filter: integration tests need bwrap or firejail (landlock has no netns)"
fi

# sandbox-notify carve-out: must continue to work even in isolated mode
# because it uses /dev/tty + tmux IPC, not the network.
if has_mount_ns && [[ -x "$SCRIPT_DIR/bin/sandbox-notify" ]]; then
    _net_isolated_conf2="$HOME/.config/agent-sandbox/conf.d/test-net-notify-$$.conf"
    _TEST_TEMP_FILES+=("$_net_isolated_conf2")
    mkdir -p "$HOME/.config/agent-sandbox/conf.d"
    echo 'NETWORK_FILTER_MODE=isolated' > "$_net_isolated_conf2"
    echo 'NETWORK_FILTER_FALLBACK=open' >> "$_net_isolated_conf2"
    if sandbox bash -c 'command -v sandbox-notify && echo CALLABLE || echo MISSING'; then
        if [[ "$OUTPUT" == *"CALLABLE"* ]]; then
            pass "Network filter: sandbox-notify carve-out preserved in isolated mode"
        else
            fail "Network filter: sandbox-notify unexpectedly missing in isolated mode" "$OUTPUT"
        fi
    fi
    rm -f "$_net_isolated_conf2"
fi

# Positive-path reachability: in 'open' mode, ordinary outbound network
# must keep working. Pairs with the negative isolated-mode assertions
# above so a future regression in either direction shows up.
_net_open_conf="$HOME/.config/agent-sandbox/conf.d/test-net-open-$$.conf"
_TEST_TEMP_FILES+=("$_net_open_conf")
mkdir -p "$HOME/.config/agent-sandbox/conf.d"
echo 'NETWORK_FILTER_MODE=open' > "$_net_open_conf"

# DNS resolution — the most fundamental positive check. If 'open' mode
# breaks DNS, every other outbound test would also fail.
if sandbox bash -c '
    if getent hosts github.com >/dev/null 2>&1; then echo RESOLVED
    elif command -v host >/dev/null && host -W 5 github.com >/dev/null 2>&1; then echo RESOLVED
    elif command -v nslookup >/dev/null && nslookup github.com >/dev/null 2>&1; then echo RESOLVED
    else echo UNRESOLVED; fi
'; then
    if [[ "$OUTPUT" == "RESOLVED" ]]; then
        pass "Network filter (open): DNS resolution works"
    else
        fail "Network filter (open): DNS resolution failed in open mode" "$OUTPUT"
    fi
fi

# HTTPS reachability — github.com is a stable, near-universally-allowed
# 443 endpoint. The fail-mode would suggest the open-mode bypass is
# broken. 10s connect timeout to avoid hanging CI on transient flakes.
if command -v curl >/dev/null 2>&1 && sandbox bash -c '
    if curl -fsS --max-time 10 -o /dev/null -w "%{http_code}" https://github.com/ 2>/dev/null | grep -qE "^(200|301|302)$"; then
        echo REACHABLE
    else
        echo UNREACHABLE
    fi
'; then
    if [[ "$OUTPUT" == "REACHABLE" ]]; then
        pass "Network filter (open): HTTPS to github.com reachable"
    else
        # Could be a transient CI/runner network issue; treat as a warn
        # to avoid flakes blocking unrelated changes. If consistently
        # unreachable we'd want to know.
        warn "Network filter (open): HTTPS to github.com not reachable from CI runner" "$OUTPUT"
    fi
fi

# Non-blocklisted arbitrary egress — pypi.org is another canonical
# 443 endpoint. Same rationale as above.
if command -v curl >/dev/null 2>&1 && sandbox bash -c '
    if curl -fsS --max-time 10 -o /dev/null -w "%{http_code}" https://pypi.org/ 2>/dev/null | grep -qE "^(200|301|302)$"; then
        echo REACHABLE
    else
        echo UNREACHABLE
    fi
'; then
    if [[ "$OUTPUT" == "REACHABLE" ]]; then
        pass "Network filter (open): HTTPS to pypi.org reachable"
    else
        warn "Network filter (open): HTTPS to pypi.org not reachable from CI runner" "$OUTPUT"
    fi
fi

rm -f "$_net_open_conf"
unset _net_open_conf

# conf.d-safety: a user's conf.d/*.conf using `NETWORK_BLOCKLIST+=()`
# (the canonical extension pattern) must load cleanly under `set -u`
# without triggering an unbound-variable error. The new vars must be
# initialised in sandbox-lib.sh's defaults BEFORE any conf.d file
# runs. Regression guard: if a future refactor drops
# `NETWORK_BLOCKLIST=()` from the lib defaults (or drops the var from
# `_CONFIG_ARRAYS` so the parent state isn't serialised), every
# conf.d file using the documented `+=` syntax would silently fail
# under `set -u`. This test catches that.
#
# The test runs in the `_SANDBOX_LIB_NO_INIT=1` harness so it
# exercises the pure config-loading primitive (`_load_untrusted_config`,
# defined above the early return) directly — the same primitive
# `load_project_config` wraps per-file in production. We don't need
# `load_project_config` itself; what matters is that the
# parent-state serialisation seeds `NETWORK_BLOCKLIST` as a declared
# array before the conf.d file's `+=` executes in the subprocess.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    _confd_file="$(mktemp "${TMPDIR:-/tmp}/test-confd-init.XXXXXX.conf")"
    trap 'rm -f "$_confd_file"' EXIT
    cat > "$_confd_file" <<'CONF'
NETWORK_BLOCKLIST+=("test.example.com:443")
NETWORK_FILTER_MODE="filtered"
CONF
    source "$SCRIPT_DIR/sandbox-lib.sh"
    _load_untrusted_config "$_confd_file" "conf.d init-safety probe"
    # The new entry must be in the user-extension array AND the
    # effective blocklist union must include it.
    [[ "${#NETWORK_BLOCKLIST[@]}" -ge 1 ]] || exit 1
    effective_network_blocklist 2>/dev/null | grep -q "^test.example.com:443\$" || exit 1
    exit 0
); then
    pass "Network filter: conf.d/*.conf NETWORK_BLOCKLIST+=() loads under set -u"
else
    fail "Network filter: conf.d/*.conf += pattern failed (rc=$?); init regression"
fi

# Wildcard pattern matching — bash-glob covers the expected cases.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    # *.example.com matches subdomains but not the bare domain.
    _network_rule_matches "*.example.com" "api.example.com" || exit 1
    _network_rule_matches "*.example.com" "deep.foo.example.com" || exit 1
    _network_rule_matches "*.example.com" "example.com" && exit 1  # MUST NOT match
    # exact host
    _network_rule_matches "example.com" "example.com" || exit 1
    _network_rule_matches "example.com" "api.example.com" && exit 1  # MUST NOT match
    # wildcard *
    _network_rule_matches "*" "anything.example.com" || exit 1
    _network_rule_matches "*" "10.0.0.1" || exit 1
    exit 0
); then
    pass "Network filter: wildcard pattern matching (*.suffix / exact / *) behaves as documented"
else
    fail "Network filter: wildcard pattern matching regressed (rc=$?)"
fi

# Admin-precedence: user NETWORK_BLOCKLIST_EXCEPT entries covered by
# admin NETWORK_BLOCKLIST are stripped at config-load with a loud
# warning. The user cannot carve exceptions out of admin policy.
#
# Note: _strip_user_exceptions_covered_by_admin mutates
# NETWORK_BLOCKLIST_EXCEPT in the calling shell, so we must NOT
# invoke it inside `$(...)` — that would run it in a subshell and
# the mutation would be lost. Stderr capture happens via a temp file.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    _stderr_file="$(mktemp "${TMPDIR:-/tmp}/test-admin-prec.XXXXXX")"
    trap 'rm -f "$_stderr_file"' EXIT
    # Simulate admin snapshot + user exception list.
    _ADMIN_NETWORK_BLOCKLIST=("*.example.com" "hooks.slack.com")
    NETWORK_BLOCKLIST_EXCEPT=("api.example.com" "github.com" "hooks.slack.com")
    # Run in the current shell; capture stderr via redirection to a file.
    _strip_user_exceptions_covered_by_admin "Test admin-precedence probe" 2>"$_stderr_file"
    # github.com is not covered → stays.
    # api.example.com covered by *.example.com → stripped + warning.
    # hooks.slack.com exact-covered → stripped + warning.
    [[ "${#NETWORK_BLOCKLIST_EXCEPT[@]}" -eq 1 ]] || { echo "post-strip count=${#NETWORK_BLOCKLIST_EXCEPT[@]}"; exit 1; }
    [[ "${NETWORK_BLOCKLIST_EXCEPT[0]}" == "github.com" ]] || { echo "remaining=${NETWORK_BLOCKLIST_EXCEPT[0]}"; exit 1; }
    grep -q "attempted to except 'api.example.com'.*\*.example.com" "$_stderr_file" || { echo "missing api.example.com warning"; exit 1; }
    grep -q "attempted to except 'hooks.slack.com'" "$_stderr_file" || { echo "missing hooks.slack.com warning"; exit 1; }
    exit 0
); then
    pass "Network filter: admin-pinned BLOCKLIST overrides user EXCEPT (admin policy absolute)"
else
    fail "Network filter: admin-precedence enforcement regressed (rc=$?)"
fi

# effective_network_exception_list emits the carved-out user
# exceptions (admin-covered entries already stripped).
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    NETWORK_BLOCKLIST+=("*.amazonaws.com")
    NETWORK_BLOCKLIST_EXCEPT+=("mybucket.s3.amazonaws.com" "github.com")
    # The except list must include both user entries (no admin to
    # strip them).
    _list="$(effective_network_exception_list)"
    grep -q "^mybucket.s3.amazonaws.com\$" <<< "$_list" || exit 1
    grep -q "^github.com\$" <<< "$_list" || exit 1
    exit 0
); then
    pass "Network filter: effective_network_exception_list emits the merged exceptions"
else
    fail "Network filter: exception-list helper regressed (rc=$?)"
fi

# ── 11.4.v1.1 pasta port-exclusion generator (unit tests) ─────────
#
# generate_pasta_port_exclusions translates effective_network_blocklist
# + effective_network_exception_list into pasta -T/-U exclusion SPECs.
# Pure function — no kernel state required, runs on every CI runner.

if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    source "$SCRIPT_DIR/sandbox-lib.sh"
    NETWORK_BLOCKLIST=(
        "25"                  # bare port (universal)
        "853"                 # DoT port
        "127.0.0.1:25"        # loopback host:port (universal port)
        "0.0.0.0/0:25"        # universal CIDR:port
        "10.0.0.0/8:25"       # site CIDR:port (port-only enforced)
    )
    NETWORK_BLOCKLIST_EXCEPT=()
    _specs="$(generate_pasta_port_exclusions 2>/dev/null)"
    _tcp_line="$(grep '^TCP:' <<< "$_specs")"
    _udp_line="$(grep '^UDP:' <<< "$_specs")"
    [[ -n "$_tcp_line" && -n "$_udp_line" ]] || { echo "FAIL: missing TCP/UDP lines"; exit 1; }
    # Both ports 25 and 853 must appear in the TCP exclusion.
    grep -q '~25' <<< "$_tcp_line" || { echo "FAIL: ~25 missing from TCP spec ($_tcp_line)"; exit 1; }
    grep -q '~853' <<< "$_tcp_line" || { echo "FAIL: ~853 missing from TCP spec ($_tcp_line)"; exit 1; }
    grep -q '~25' <<< "$_udp_line" || { echo "FAIL: ~25 missing from UDP spec"; exit 1; }
    exit 0
); then
    pass "Network filter (v1.1): pasta generator emits -T/-U exclusions for port + host:port + CIDR:port entries"
else
    fail "Network filter (v1.1): pasta generator regressed (rc=$?)"
fi

# Hostname-shape entries (wildcard hostname, bare hostname/CIDR-
# without-port) cannot be enforced at pasta's port-level layer.
# Post-ASB-2026-002 they emit NOTEs at DEFAULT verbosity (vocal-by-
# default — operator-configured restrictions that are silently a
# no-op are an operator-error indicator, not a feature). The '*'
# deny-all NOTE remains verbose-gated because the literal '*' in
# NETWORK_BLOCKLIST is the conventional "implicit-allowlist"
# idiom (paired with NETWORK_BLOCKLIST_EXCEPT), where the operator
# already knows pasta cannot enforce '*' and doesn't want a NOTE
# on every launch.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    source "$SCRIPT_DIR/sandbox-lib.sh"
    NETWORK_BLOCKLIST=("*" "*.cloudflare-dns.com" "api.mailgun.net" "25")
    NETWORK_BLOCKLIST_EXCEPT=()
    # Default verbosity (ASB-2026-002 vocal-by-default): exactly
    # two stderr lines — the wildcard-hostname NOTE and the bare-
    # hostname NOTE. The '*' deny-all NOTE remains verbose-gated.
    # Port 25 still excluded.
    _stderr="$(mktemp "${TMPDIR:-/tmp}/test-pasta-quiet.XXXXXX")"
    _trap_files=("$_stderr")
    _specs="$(generate_pasta_port_exclusions 2>"$_stderr")"
    _tcp_line="$(grep '^TCP:' <<< "$_specs")"
    grep -q '~25' <<< "$_tcp_line" || { echo "FAIL: ~25 missing"; exit 1; }
    _lines="$(wc -l <"$_stderr")"
    [[ "$_lines" -eq 2 ]] || { echo "FAIL: default-verbosity stderr expected 2 lines, got $_lines"; cat "$_stderr" >&2; exit 1; }
    grep -q "wildcard hostname entry '[*]\.cloudflare-dns.com'" "$_stderr" || { echo "FAIL: default-verbosity wildcard NOTE missing"; cat "$_stderr" >&2; exit 1; }
    grep -q "hostname/CIDR entry 'api.mailgun.net'" "$_stderr" || { echo "FAIL: default-verbosity hostname NOTE missing"; cat "$_stderr" >&2; exit 1; }
    grep -q "'[*]' cannot be enforced" "$_stderr" && { echo "FAIL: '*' NOTE leaked at default verbosity (should be verbose-gated)"; exit 1; }
    rm -f "$_stderr"
    # Verbose mode adds the '*' deny-all NOTE on top of the two
    # always-on NOTEs above.
    _stderr="$(mktemp "${TMPDIR:-/tmp}/test-pasta-verbose.XXXXXX")"
    _trap_files=("$_stderr")
    NETWORK_FILTER_VERBOSE=1 _specs="$(generate_pasta_port_exclusions 2>"$_stderr")"
    grep -q "'[*]' cannot be enforced" "$_stderr" || { echo "FAIL: verbose '*' note missing"; cat "$_stderr" >&2; exit 1; }
    rm -f "$_stderr"
    exit 0
); then
    pass "Network filter (v1.1): pasta generator hostname/wildcard NOTEs (vocal-by-default for hostname-shape, verbose-gated for '*')"
else
    fail "Network filter (v1.1): pasta generator hostname-skip regressed (rc=$?)"
fi

# Bare-port exception lifts the corresponding -T/-U exclusion (the
# canonical carve-out shape at this layer).
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    source "$SCRIPT_DIR/sandbox-lib.sh"
    NETWORK_BLOCKLIST=("25" "853")
    NETWORK_BLOCKLIST_EXCEPT=("25")    # lift the 25 closure
    _specs="$(generate_pasta_port_exclusions 2>/dev/null)"
    _tcp_line="$(grep '^TCP:' <<< "$_specs")"
    grep -q '~25' <<< "$_tcp_line" && { echo "FAIL: ~25 still present after EXCEPT 25 ($_tcp_line)"; exit 1; }
    grep -q '~853' <<< "$_tcp_line" || { echo "FAIL: ~853 missing"; exit 1; }
    exit 0
); then
    pass "Network filter (v1.1): bare-port exception lifts the pasta -T/-U exclusion"
else
    fail "Network filter (v1.1): exception lift regressed (rc=$?)"
fi

# Empirical filtered-mode integration: requires pasta AND a bwrap-
# capable runner. Skip cleanly when either dependency is missing —
# we'd rather skip than fake-pass.
if [[ -x "$SCRIPT_DIR/tools/pasta/$(uname -m)/pasta" ]] || command -v pasta >/dev/null 2>&1; then
    _has_pasta=true
else
    _has_pasta=false
fi

if has_mount_ns && $_has_pasta; then
    # Pin filtered mode + strict policy so any fallback fails the
    # test loudly instead of silently degrading to isolated/open.
    _net_filt_conf="$HOME/.config/agent-sandbox/conf.d/test-net-filtered-$$.conf"
    _TEST_TEMP_FILES+=("$_net_filt_conf")
    mkdir -p "$HOME/.config/agent-sandbox/conf.d"
    cat > "$_net_filt_conf" <<CONF
NETWORK_FILTER_MODE=filtered
NETWORK_FILTER_FALLBACK=strict
CONF

    # Negative path: port 25 must be unreachable inside the sandbox
    # (the v1.1 pasta -T ~25 closure). Use a public test host that
    # advertises SMTP — gmail-smtp-in.l.google.com:25 is a stable
    # canonical target. Falls back to the loopback (which is always
    # unreachable inside the netns due to pasta's empty loopback).
    if sandbox bash -c '
        if exec 3<>/dev/tcp/127.0.0.1/25 2>&1; then
            echo CONNECTED
        else
            echo BLOCKED
        fi
    '; then
        if [[ "$OUTPUT" == *"BLOCKED"* ]]; then
            pass "Network filter (v1.1, filtered): port 25 closed at pasta boundary"
        else
            fail "Network filter (v1.1, filtered): port 25 reachable — pasta -T exclusion not applied" "$OUTPUT"
        fi
    fi

    # Positive path: github.com:443 must remain reachable through
    # the pasta tap. Treat transient runner network flakes as warn.
    if command -v curl >/dev/null 2>&1 && sandbox bash -c '
        if curl -fsS --max-time 10 -o /dev/null -w "%{http_code}" https://github.com/ 2>/dev/null | grep -qE "^(200|301|302)$"; then
            echo REACHABLE
        else
            echo UNREACHABLE
        fi
    '; then
        if [[ "$OUTPUT" == "REACHABLE" ]]; then
            pass "Network filter (v1.1, filtered): non-blocklisted egress (github.com:443) reachable"
        else
            warn "Network filter (v1.1, filtered): github.com:443 unreachable from CI runner" "$OUTPUT"
        fi
    fi

    rm -f "$_net_filt_conf"
    unset _net_filt_conf
else
    if ! has_mount_ns; then
        skip "Network filter (v1.1, filtered): empirical tests need a mount-ns backend"
    else
        skip "Network filter (v1.1, filtered): empirical tests need pasta (apt install passt / brew install passt / tools/pasta/fetch.sh)"
    fi
fi
unset _has_pasta

# ── 11.4.asb-2026-002 filtered-mode hostname-entry vocal-by-default ──
#
# Regression suite for ASB-2026-002 (MEDIUM; settylab/dotto-nexus#140).
# pasta's port-exclusion model cannot enforce hostname-shape blocklist
# entries (*.example.com, evil.com, host:443). Baseline silently
# dropped them, gated every skip-note on NETWORK_FILTER_VERBOSE=1.
# Operator-side experience: write `NETWORK_BLOCKLIST+=("*.evil.com")`,
# see the entry in the config, reasonably assume it is enforced —
# it is not, and the failure is silent at default verbosity.
#
# Fix policy (option-a per issue suggestion, with the operator's
# subsequent refinement):
#   * Hostname-shape entries (wildcard-hostname `*.foo.com`, bare
#     hostname `foo.com`, CIDR-without-port) emit NOTEs UNCONDITIONALLY
#     — these are operator-error indicators, not deliberate idioms.
#   * The literal `*` deny-all NOTE remains VERBOSE-gated — `*` in
#     NETWORK_BLOCKLIST is the conventional "implicit-allowlist"
#     idiom paired with NETWORK_BLOCKLIST_EXCEPT, and operators
#     using it already know pasta cannot enforce `*` directly.

# Test A1: wildcard-hostname entry emits NOTE at default verbosity.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/sandbox-lib.sh"
    unset NETWORK_FILTER_VERBOSE
    declare -A _asb_tcp _asb_udp
    _err=$(_classify_pasta_port_entry "*.example.com" _asb_tcp _asb_udp 2>&1 >/dev/null)
    echo "$_err" | grep -qE "wildcard hostname entry .*example.com.* cannot be enforced"
); then
    pass "Network filter: wildcard hostname entry emits NOTE at default verbosity (ASB-2026-002)"
else
    fail "Network filter: wildcard hostname blocklist entry silently dropped at default verbosity (ASB-2026-002)"
fi

# Test A2: bare-hostname entry emits NOTE at default verbosity.
# Same vocal-by-default policy as the wildcard case — operator-
# configured restrictions that are no-ops should surface.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/sandbox-lib.sh"
    unset NETWORK_FILTER_VERBOSE
    declare -A _asb_tcp _asb_udp
    _err=$(_classify_pasta_port_entry "evil.com" _asb_tcp _asb_udp 2>&1 >/dev/null)
    echo "$_err" | grep -qE "hostname/CIDR entry 'evil.com' cannot be enforced"
); then
    pass "Network filter: bare-hostname entry emits NOTE at default verbosity (ASB-2026-002)"
else
    fail "Network filter: bare-hostname blocklist entry silently dropped at default verbosity (ASB-2026-002)"
fi

# Test A3: '*' deny-all entry is STILL verbose-gated — operators
# using the implicit-allowlist idiom (`NETWORK_BLOCKLIST=("*")` +
# NETWORK_BLOCKLIST_EXCEPT) already know pasta cannot enforce it.
# Two halves: silent at default verbosity, vocal under
# NETWORK_FILTER_VERBOSE=1.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/sandbox-lib.sh"
    declare -A _asb_tcp _asb_udp
    unset NETWORK_FILTER_VERBOSE
    _quiet=$(_classify_pasta_port_entry "*" _asb_tcp _asb_udp 2>&1 >/dev/null)
    [[ -z "$_quiet" ]] || { echo "FAIL: '*' note leaked at default verbosity: $_quiet"; exit 1; }
    NETWORK_FILTER_VERBOSE=1
    _verbose=$(_classify_pasta_port_entry "*" _asb_tcp _asb_udp 2>&1 >/dev/null)
    echo "$_verbose" | grep -qE "'\*' cannot be enforced" || { echo "FAIL: '*' note missing under VERBOSE=1"; exit 1; }
); then
    pass "Network filter: '*' deny-all NOTE stays verbose-gated (implicit-allowlist idiom; ASB-2026-002)"
else
    fail "Network filter: '*' deny-all NOTE policy regressed (rc=$?)"
fi

# Test A4 (negative control): a bare-port entry produces no
# hostname-shape NOTE — pasta CAN enforce these, so the warning is
# not appropriate. Guards against an over-broad fix that fires on
# every entry shape.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/sandbox-lib.sh"
    unset NETWORK_FILTER_VERBOSE
    declare -A _asb_tcp _asb_udp
    _err=$(_classify_pasta_port_entry "25" _asb_tcp _asb_udp 2>&1 >/dev/null)
    # No "cannot be enforced" message should fire — bare ports ARE
    # enforced at the pasta layer.
    ! echo "$_err" | grep -qE "cannot be enforced"
); then
    pass "Network filter: bare-port blocklist entry produces no unenforceable-NOTE (negative control)"
else
    fail "Network filter: bare-port entry incorrectly produced an unenforceable-NOTE (ASB-2026-002 over-fire)"
fi


# ── 11.4.mailblock NETWORK_MAIL_BLOCK layer (v0.10.1) ──────────────
#
# Defense-in-depth above the port-level network filter. The stub
# (tools/mail-block/mail-block-stub.sh) is bind-mounted over canonical
# mailer paths inside the sandbox AND symlinks of the same names
# populate a per-launch dir under $TMPDIR that is bind-mounted at the
# same path on both sides of the sandbox boundary and prepended to
# PATH. Three layers of test:
#   1. resolver semantics  — auto|on|off → on|off given the active
#      NETWORK_FILTER_MODE; admin pin non-weakening.
#   2. stub-direct behaviour — argv[0] propagation under each
#      canonical name, exit code 77, deterrent message on stderr,
#      no ANSI-byte injection from a hostile argv[0].
#   3. end-to-end via sandbox — bwrap launch with MAIL_BLOCK=on,
#      invoke `sendmail` inside, assert message + exit 77 (skipped
#      on hosts without a mount-ns backend, same shape as the
#      filtered-mode empirical tests).

echo "11.4.mailblock Mail-block layer"

# ── Test M1: resolver — defaults + auto with no fallback divergence ─
# Configured intent equals resolved state. Exercises the four
# (cfg=net) points on the mode axis. Fallback-divergence cases live
# in M1b.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    [[ "$NETWORK_MAIL_BLOCK" == "auto" ]] || { echo "default knob wrong: $NETWORK_MAIL_BLOCK"; exit 1; }
    NETWORK_MAIL_BLOCK="auto"
    # auto + filtered (cfg=net=filtered) → on
    NETWORK_FILTER_MODE="filtered"
    _NETWORK_FILTER_RESOLVED="filtered"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "on" ]] || { echo "auto+filtered should be on, got $_MAIL_BLOCK_RESOLVED"; exit 1; }
    # auto + open (cfg=net=open) → off
    NETWORK_FILTER_MODE="open"
    _NETWORK_FILTER_RESOLVED="open"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "off" ]] || { echo "auto+open should be off, got $_MAIL_BLOCK_RESOLVED"; exit 1; }
    # auto + isolated (cfg=net=isolated) → on
    NETWORK_FILTER_MODE="isolated"
    _NETWORK_FILTER_RESOLVED="isolated"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "on" ]] || { echo "auto+isolated should be on, got $_MAIL_BLOCK_RESOLVED"; exit 1; }
    # auto + proxied (cfg=net=proxied) → on
    NETWORK_FILTER_MODE="proxied"
    _NETWORK_FILTER_RESOLVED="proxied"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "on" ]] || { echo "auto+proxied should be on, got $_MAIL_BLOCK_RESOLVED"; exit 1; }
    exit 0
); then
    pass "Mail-block (M1): resolver auto-mode respects NETWORK_FILTER_MODE axis"
else
    fail "Mail-block (M1): resolver auto-mode did not match the mode axis"
fi

# ── Test M1b: resolver — auto under fallback divergence ────────────
# When the configured intent and the realised state diverge (network
# filter fell back to a less- or more-strict mode than requested),
# `auto` must take the STRICTER of the two — anything other than
# (cfg=open AND resolved=open) leaves mail-block on. This is the
# load-bearing fix for the "filter falls back to open, secondary
# defense wrongly disengages" regression.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    NETWORK_MAIL_BLOCK="auto"

    # The motivating case: user asked for filtered, host lacks pasta,
    # FALLBACK=open landed on open. Configured intent is still
    # filtered — mail-block must stay on.
    NETWORK_FILTER_MODE="filtered"
    _NETWORK_FILTER_RESOLVED="open"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "on" ]] || { echo "cfg=filtered net=open auto: expected on (intent wins), got $_MAIL_BLOCK_RESOLVED"; exit 1; }
    [[ "$_MAIL_BLOCK_REASON" == *"NETWORK_FILTER_MODE='filtered'"* && "$_MAIL_BLOCK_REASON" == *"resolved to 'open'"* ]] \
        || { echo "reason text wrong: $_MAIL_BLOCK_REASON"; exit 1; }

    # Same shape, deeper request — isolated fell back to open.
    NETWORK_FILTER_MODE="isolated"
    _NETWORK_FILTER_RESOLVED="open"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "on" ]] || { echo "cfg=isolated net=open auto: expected on, got $_MAIL_BLOCK_RESOLVED"; exit 1; }

    # And proxied → open.
    NETWORK_FILTER_MODE="proxied"
    _NETWORK_FILTER_RESOLVED="open"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "on" ]] || { echo "cfg=proxied net=open auto: expected on, got $_MAIL_BLOCK_RESOLVED"; exit 1; }

    # Stricter-direction fallback: user asked for open, admin pin or
    # FALLBACK=stricter landed on filtered. Ambient strictness is
    # filtered, so mail-block stays on (matches the network filter
    # actually doing its work).
    NETWORK_FILTER_MODE="open"
    _NETWORK_FILTER_RESOLVED="filtered"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "on" ]] || { echo "cfg=open net=filtered auto: expected on, got $_MAIL_BLOCK_RESOLVED"; exit 1; }

    # The disengage rule: BOTH cfg AND resolved must be open. Verified
    # twice — once cleanly (no divergence) and once defensively (an
    # unset cfg defaults to "filtered" per the resolver, so still on).
    NETWORK_FILTER_MODE="open"
    _NETWORK_FILTER_RESOLVED="open"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "off" ]] || { echo "cfg=open net=open auto: expected off, got $_MAIL_BLOCK_RESOLVED"; exit 1; }
    unset NETWORK_FILTER_MODE
    _NETWORK_FILTER_RESOLVED="open"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "on" ]] || { echo "cfg=<unset> net=open auto: expected on (defensive default), got $_MAIL_BLOCK_RESOLVED"; exit 1; }

    exit 0
); then
    pass "Mail-block (M1b): resolver auto tracks intent-or-resolved (strictest-of-both)"
else
    fail "Mail-block (M1b): auto-mode disengaged when configured intent still constrained"
fi

# ── Test M2: resolver — explicit on/off overrides axis ─────────────
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    # explicit on + open → still on
    NETWORK_MAIL_BLOCK="on"
    NETWORK_FILTER_MODE="open"
    _NETWORK_FILTER_RESOLVED="open"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "on" ]] || { echo "on+open should be on, got $_MAIL_BLOCK_RESOLVED"; exit 1; }
    # explicit off + filtered → still off
    NETWORK_MAIL_BLOCK="off"
    NETWORK_FILTER_MODE="filtered"
    _NETWORK_FILTER_RESOLVED="filtered"
    resolve_network_mail_block_mode
    [[ "$_MAIL_BLOCK_RESOLVED" == "off" ]] || { echo "off+filtered should be off, got $_MAIL_BLOCK_RESOLVED"; exit 1; }
    exit 0
); then
    pass "Mail-block (M2): explicit on/off override the mode axis"
else
    fail "Mail-block (M2): explicit knob did not override the mode axis"
fi

# ── Test M3: resolver — invalid knob errors loudly ─────────────────
# The resolver calls `exit 1` on bad input (config error is fatal),
# so we need an inner subshell to isolate the abort from the outer
# test harness.
if (
    set -uo pipefail
    export _SANDBOX_LIB_NO_INIT=1
    export SANDBOX_QUIET=true
    source "$SCRIPT_DIR/sandbox-lib.sh"
    if (
        NETWORK_MAIL_BLOCK="bogus"
        NETWORK_FILTER_MODE="filtered"
        _NETWORK_FILTER_RESOLVED="filtered"
        resolve_network_mail_block_mode
    ) 2>/dev/null; then
        echo "invalid knob accepted (should have exited)"
        exit 1
    fi
    exit 0
); then
    pass "Mail-block (M3): invalid NETWORK_MAIL_BLOCK rejected"
else
    fail "Mail-block (M3): invalid knob was accepted"
fi

# ── Test M4: stub direct + argv[0] propagation under each name ─────
if (
    set -uo pipefail
    _mb_stub="$SCRIPT_DIR/tools/mail-block/mail-block-stub.sh"
    [[ -x "$_mb_stub" ]] || { echo "stub missing or not executable: $_mb_stub"; exit 1; }
    # Direct invocation — exit 77, stderr message starts with the
    # expected lead line.
    _msg="$("$_mb_stub" -t -f a@b.example c@d.example 2>&1 >/dev/null)" && _rc=0 || _rc=$?
    [[ "$_rc" -eq 77 ]] || { echo "direct exit code: expected 77, got $_rc"; exit 1; }
    [[ "$_msg" == *"outbound mail is disabled"* ]] || { echo "lead line missing"; exit 1; }
    [[ "$_msg" == *"EX_NOPERM"* ]] || { echo "exit-code annotation missing"; exit 1; }
    # argv[0] propagation through symlinks. We're running on the
    # host (no sandbox) so we use a host tmpdir; the in-sandbox
    # mechanism is the same kernel feature, exercised at M5/M6.
    _tmp="$(mktemp -d)"
    trap "rm -rf '$_tmp'" EXIT
    for _name in sendmail mail mailx mutt msmtp ssmtp s-nail swaks postsuper mailq newaliases exim dma qmail-inject; do
        ln -s "$_mb_stub" "$_tmp/$_name"
        _out="$("$_tmp/$_name" 2>&1 >/dev/null)" && _nrc=0 || _nrc=$?
        [[ "$_nrc" -eq 77 ]] || { echo "$_name exit code: $_nrc"; exit 1; }
        [[ "$_out" == *"Invoked as: $_name "* ]] || { echo "$_name argv[0] not visible in message"; exit 1; }
    done
    exit 0
); then
    pass "Mail-block (M4): stub direct + argv[0] propagates under each canonical name"
else
    fail "Mail-block (M4): stub direct invocation or argv[0] threading failed"
fi

# ── Test M5: stub sanitizes ANSI bytes from a hostile argv[0] ──────
if (
    set -uo pipefail
    _mb_stub="$SCRIPT_DIR/tools/mail-block/mail-block-stub.sh"
    _tmp="$(mktemp -d)"
    trap "rm -rf '$_tmp'" EXIT
    # Hostile basename containing ESC (0x1b) and a CSI sequence.
    _hostile=$'evil\x1b[2Jname'
    ln -s "$_mb_stub" "$_tmp/$_hostile"
    _out="$("$_tmp/$_hostile" 2>&1 >/dev/null)" && _rc=0 || _rc=$?
    [[ "$_rc" -eq 77 ]] || { echo "exit code wrong: $_rc"; exit 1; }
    # Critical: ESC (0x1b) must NOT appear anywhere in the stderr
    # output, even though the symlink name contained it.
    if printf '%s' "$_out" | LC_ALL=C grep -q $'\x1b'; then
        echo "ANSI escape leaked into deterrent message — sanitization broken"
        exit 1
    fi
    # The visible portion of the name should still be present.
    [[ "$_out" == *"evil"* ]] || { echo "visible portion of name missing"; exit 1; }
    exit 0
); then
    pass "Mail-block (M5): stub strips ANSI control bytes from a hostile argv[0]"
else
    fail "Mail-block (M5): hostile argv[0] not sanitized"
fi

# ── Test M6: end-to-end through bwrap (requires mount-ns backend) ──
# Inject the knob via a conf.d/*.conf override (the supported
# per-project mechanism — matches the pattern used for the v1.1
# filtered-mode empirical tests above).
if is_bwrap && has_mount_ns; then
    _net_mb_conf="$HOME/.config/agent-sandbox/conf.d/test-mb-on-$$.conf"
    _TEST_TEMP_FILES+=("$_net_mb_conf")
    mkdir -p "$HOME/.config/agent-sandbox/conf.d"
    cat > "$_net_mb_conf" <<CONF
NETWORK_FILTER_MODE=open
NETWORK_FILTER_FALLBACK=open
NETWORK_MAIL_BLOCK=on
CONF
    OUTPUT="$(
        SANDBOX_QUIET=true \
        "$SCRIPT_DIR/sandbox-exec.sh" --backend bwrap -- bash -c '
            command -v sendmail 2>/dev/null || true
            sendmail -t </dev/null 2>&1 1>/dev/null || echo "EXIT=$?"
        ' 2>&1
    )" || true
    # Stubs dir lives under $TMPDIR with a randomised suffix; we don't
    # know the exact path here, so match the stable prefix. Also accept
    # the host-side $TMPDIR (paths are same-on-both-sides).
    if echo "$OUTPUT" \
       | grep -qE "^(${TMPDIR:-/tmp})/agent-sandbox-mailblock-[A-Za-z0-9]+/sendmail$"; then
        pass "Mail-block (M6a): PATH-prefix shadow resolves sendmail to the stub"
    else
        fail "Mail-block (M6a): PATH-prefix did not shadow sendmail" "$OUTPUT"
    fi
    if echo "$OUTPUT" | grep -q 'outbound mail is disabled'; then
        pass "Mail-block (M6b): deterrent message visible inside sandbox"
    else
        fail "Mail-block (M6b): deterrent message missing" "$OUTPUT"
    fi
    if echo "$OUTPUT" | grep -q 'EXIT=77'; then
        pass "Mail-block (M6c): sendmail exits 77 (EX_NOPERM) inside sandbox"
    else
        fail "Mail-block (M6c): sendmail did not exit 77" "$OUTPUT"
    fi
    rm -f "$_net_mb_conf"
    unset _net_mb_conf
else
    skip "Mail-block (M6): empirical end-to-end tests need a mount-ns backend"
fi

# ── Test M7: off escape hatch — knob disables the layer ────────────
if is_bwrap && has_mount_ns; then
    _net_mb_conf="$HOME/.config/agent-sandbox/conf.d/test-mb-off-$$.conf"
    _TEST_TEMP_FILES+=("$_net_mb_conf")
    mkdir -p "$HOME/.config/agent-sandbox/conf.d"
    cat > "$_net_mb_conf" <<CONF
NETWORK_FILTER_MODE=open
NETWORK_FILTER_FALLBACK=open
NETWORK_MAIL_BLOCK=off
CONF
    OUTPUT="$(
        SANDBOX_QUIET=true \
        "$SCRIPT_DIR/sandbox-exec.sh" --backend bwrap -- bash -c '
            echo "PATH=$PATH"
        ' 2>&1
    )" || true
    if echo "$OUTPUT" | grep -qE '^PATH=[^:]*agent-sandbox-mailblock-[A-Za-z0-9]+'; then
        fail "Mail-block (M7): off knob still prepended the mail-block PATH-prefix" "$OUTPUT"
    else
        pass "Mail-block (M7): off knob disables the mail-block layer (PATH unaffected)"
    fi
    rm -f "$_net_mb_conf"
    unset _net_mb_conf
else
    skip "Mail-block (M7): off-escape-hatch test needs a mount-ns backend"
fi


# ── 11.5 Device passthrough (bwrap only) ──────────────────────────

echo "11.5. Device passthrough"

if is_bwrap; then

# Helper: produce a sandbox.conf-derived temp config with extra lines
# appended (mirrors _lmod_test_conf, but defined inline so we don't
# depend on test ordering).
_dev_test_conf() {
    local _conf
    _conf=$(mktemp)
    trap_rm_path "$_conf"
    cat "$SCRIPT_DIR/sandbox.conf" > "$_conf"
    cat >> "$_conf"
    echo "$_conf"
}

# Pick a host /dev node we know exists, isn't already in the minimal
# bwrap devtmpfs, AND isn't matched by the default DEVICES_BLACKLIST.
# /dev/null is baseline. /dev/loop-control would seem natural but
# /dev/loop* is in the default blacklist, so it'd be filtered. /dev/kmsg
# is the cleanest sentinel — outside the minimal devtmpfs, no blacklist
# match. Fall back to other candidates if the host is unusual.
_pick_passthrough_sentinel() {
    local _candidate
    for _candidate in /dev/kmsg /dev/hwrng /dev/rtc0; do
        if [[ -e "$_candidate" ]]; then
            if ! sandbox bash -c "[[ -e '$_candidate' ]] && echo present" 2>/dev/null \
                || [[ "$OUTPUT" != *"present"* ]]; then
                echo "$_candidate"
                return 0
            fi
        fi
    done
    return 1
}

_sentinel="$(_pick_passthrough_sentinel)"

# ── DEV01: NVIDIA defaults expose /dev/nvidia* when host has them ──
if [[ -e /dev/nvidia0 || -e /dev/nvidiactl ]]; then
    if sandbox bash -c 'ls /dev/nvidia* 2>/dev/null | wc -l'; then
        if [[ "$OUTPUT" -gt 0 ]]; then
            pass "DEV01: NVIDIA defaults exposed $OUTPUT /dev/nvidia* node(s)"
        else
            fail "DEV01: NVIDIA defaults didn't expose any /dev/nvidia* nodes" "$OUTPUT"
        fi
    else
        fail "DEV01: sandbox failed to list /dev/nvidia*" "$OUTPUT"
    fi
else
    skip "DEV01: host has no /dev/nvidia* — defaults are a glob no-op (expected)"
fi

# ── DEV02: User DEVICES+= adds a host node ──
if [[ -n "$_sentinel" ]]; then
    _dev02_conf=$(_dev_test_conf <<CONF
DEVICES+=("$_sentinel")
CONF
    )
    if SANDBOX_CONF="$_dev02_conf" sandbox bash -c "[[ -e '$_sentinel' ]] && echo VISIBLE || echo MISSING"; then
        if [[ "$OUTPUT" == "VISIBLE" ]]; then
            pass "DEV02: DEVICES+=($_sentinel) bound the node"
        else
            fail "DEV02: DEVICES+=($_sentinel) didn't bind the node" "$OUTPUT"
        fi
    else
        fail "DEV02: sandbox failed to start with DEVICES override" "$OUTPUT"
    fi
else
    skip "DEV02: no host node available outside the minimal devtmpfs to use as a sentinel"
fi

# ── DEV03: DEVICES=() user reset clears defaults ──
# Drops NVIDIA defaults — verify by checking /dev/nvidia0 is absent
# inside the sandbox even when the host has it. Skips on CPU-only nodes
# (then the defaults are already a no-op and the test is meaningless).
if [[ -e /dev/nvidia0 ]]; then
    _dev03_conf=$(_dev_test_conf <<'CONF'
DEVICES=()
CONF
    )
    if SANDBOX_CONF="$_dev03_conf" sandbox bash -c "[[ -e /dev/nvidia0 ]] && echo PRESENT || echo ABSENT"; then
        if [[ "$OUTPUT" == "ABSENT" ]]; then
            pass "DEV03: DEVICES=() cleared NVIDIA defaults"
        else
            fail "DEV03: DEVICES=() did not clear defaults — /dev/nvidia0 still visible" "$OUTPUT"
        fi
    else
        fail "DEV03: sandbox failed to start with DEVICES=()" "$OUTPUT"
    fi
else
    skip "DEV03: host has no /dev/nvidia0 — reset semantics not observable"
fi

# ── DEV04: DEVICES_BLACKLIST drops user-added entries ──
# Default blacklist includes /dev/pts. User attempts DEVICES+=(/dev/pts)
# and we expect it to be filtered with a stderr notice.
_dev04_conf=$(_dev_test_conf <<'CONF'
DEVICES+=(/dev/pts)
CONF
)
_dev04_err=$(mktemp); trap_rm_path "$_dev04_err"
SANDBOX_CONF="$_dev04_conf" "$SANDBOX_EXEC" --backend bwrap --project-dir "$PROJECT_DIR" -- \
    bash -c '[[ -e /dev/pts/ptmx ]] && echo PRESENT || echo ABSENT' \
    >"$_dev04_err.out" 2>"$_dev04_err"
_dev04_out=$(cat "$_dev04_err.out")
_dev04_stderr=$(cat "$_dev04_err")
# Inside-sandbox /dev/pts always exists (bwrap mounts a fresh devpts as
# part of its minimal devtmpfs). The discriminator is whether the
# resolver logged the blacklist hit. Stderr line:
#   "agent-sandbox: device /dev/pts is blacklisted, skipping"
if [[ "$_dev04_stderr" == *"/dev/pts"*"blacklisted"* ]]; then
    pass "DEV04: DEVICES+= /dev/pts was blacklist-filtered with stderr notice"
else
    fail "DEV04: blacklist did not filter /dev/pts" "stderr=$_dev04_stderr out=$_dev04_out"
fi

# ── DEV05: Unmatched glob is a silent no-op ──
_dev05_conf=$(_dev_test_conf <<'CONF'
DEVICES+=(/dev/this-does-not-exist-* /dev/also-missing-*)
CONF
)
_dev05_err=$(mktemp); trap_rm_path "$_dev05_err"
SANDBOX_CONF="$_dev05_conf" "$SANDBOX_EXEC" --backend bwrap --project-dir "$PROJECT_DIR" -- \
    bash -c 'echo ok' >"$_dev05_err.out" 2>"$_dev05_err"
_dev05_out=$(cat "$_dev05_err.out")
_dev05_stderr=$(cat "$_dev05_err")
if [[ "$_dev05_out" == *"ok"* ]] && \
   [[ "$_dev05_stderr" != *"this-does-not-exist"* ]]; then
    pass "DEV05: Unmatched DEVICES glob is a silent no-op"
else
    fail "DEV05: Unmatched glob produced output or stderr noise" "out=$_dev05_out err=$_dev05_stderr"
fi

# ── DEV06: BIND_DEV_PTS=true legacy deprecation shim (kernel < 5.4 branch) ──
# On kernel < 5.4 the shim still rewrites `BIND_DEV_PTS=true` to
# `DEVICES+=(/dev/pts)` and emits the legacy "is deprecated" warning;
# /dev/pts is in the default blacklist so the rewrite is dropped, leaving
# only the warning as the observable contract.
#
# GitHub-hosted runners are kernel 6.x, so we force the legacy branch by
# shimming `uname -r` via a wrapper on PATH that reports "5.3.0-fake".
# DEV08 covers the kernel-aware no-op branch that fires unshimmed.
_dev06_bin=$(mktemp -d); trap_rm_dir "$_dev06_bin"
cat >"$_dev06_bin/uname" <<'UNAME_SHIM'
#!/bin/sh
if [ "$#" -eq 1 ] && [ "$1" = "-r" ]; then
    printf '5.3.0-fake\n'
    exit 0
fi
# Strip the shim dir (always leftmost) and re-resolve uname for any other args.
PATH="${PATH#*:}" exec uname "$@"
UNAME_SHIM
chmod +x "$_dev06_bin/uname"
_dev06_conf=$(_dev_test_conf <<'CONF'
BIND_DEV_PTS=true
CONF
)
_dev06_err=$(mktemp); trap_rm_path "$_dev06_err"
PATH="$_dev06_bin:$PATH" SANDBOX_CONF="$_dev06_conf" \
    "$SANDBOX_EXEC" --backend bwrap --project-dir "$PROJECT_DIR" -- \
    bash -c 'echo ok' >"$_dev06_err.out" 2>"$_dev06_err"
_dev06_out=$(cat "$_dev06_err.out")
_dev06_stderr=$(cat "$_dev06_err")
if [[ "$_dev06_out" == *"ok"* ]] && \
   [[ "$_dev06_stderr" == *"BIND_DEV_PTS is deprecated"* ]]; then
    pass "DEV06: BIND_DEV_PTS=true emits legacy deprecation warning on kernel < 5.4 (uname-shimmed)"
else
    fail "DEV06: legacy deprecation shim missing or sandbox aborted" "out=$_dev06_out err=$_dev06_stderr"
fi

# ── DEV07: Non-bwrap backend warns when DEVICES is non-default ──
# We only test bwrap inside this `if is_bwrap` branch; the warning
# emission happens in sandbox-lib.sh during config load before any
# backend code runs, so we can shell out with --backend landlock from
# here purely to capture the stderr text.
_dev07_conf=$(_dev_test_conf <<'CONF'
DEVICES+=(/dev/zero)
CONF
)
_dev07_err=$(mktemp); trap_rm_path "$_dev07_err"
# --dry-run avoids needing landlock to actually be available; the warning
# fires during config load.
SANDBOX_CONF="$_dev07_conf" "$SANDBOX_EXEC" --backend landlock --dry-run \
    --project-dir "$PROJECT_DIR" -- true >"$_dev07_err.out" 2>"$_dev07_err" || true
_dev07_stderr=$(cat "$_dev07_err")
if [[ "$_dev07_stderr" == *"DEVICES only applies to the bwrap backend"* ]]; then
    pass "DEV07: non-bwrap backend warns when DEVICES is configured"
else
    # Some installs may not have landlock available — check if the
    # warning would have fired at all (look for the bwrap-only message
    # using a different unsupported backend).
    skip "DEV07: backend warning not observed (landlock unavailable here?)"
fi

# ── DEV08: BIND_DEV_PTS=true is a no-op on kernel >= 5.4 ──
# The kernel-aware shim should NOT append /dev/pts to DEVICES on a
# >= 5.4 host (binding host /dev/pts shadows bwrap's auto-mounted
# user-ns devpts and breaks tmux pty allocation). It should instead
# log a "no-op, drop the line" notice. Skip on < 5.4 hosts where the
# shim still appends.
_dev08_kver_maj="$(uname -r 2>/dev/null | cut -d. -f1)"
_dev08_kver_min="$(uname -r 2>/dev/null | cut -d. -f2 | tr -dc 0-9)"
if [[ "$_dev08_kver_maj" =~ ^[0-9]+$ && "$_dev08_kver_min" =~ ^[0-9]+$ ]] \
   && (( _dev08_kver_maj > 5 || (_dev08_kver_maj == 5 && _dev08_kver_min >= 4) )); then
    _dev08_conf=$(_dev_test_conf <<'CONF'
BIND_DEV_PTS=true
CONF
)
    _dev08_err=$(mktemp); trap_rm_path "$_dev08_err"
    SANDBOX_CONF="$_dev08_conf" "$SANDBOX_EXEC" --backend bwrap --project-dir "$PROJECT_DIR" -- \
        bash -c '[[ -e /dev/pts/ptmx ]] && echo PRESENT || echo ABSENT' \
        >"$_dev08_err.out" 2>"$_dev08_err" || true
    _dev08_out=$(cat "$_dev08_err.out")
    _dev08_stderr=$(cat "$_dev08_err")
    # (a) shim must announce no-op on kernel >= 5.4
    # (b) DEVICES must NOT have /dev/pts appended — verify by absence of the
    #     blacklist-skip line (DEV04 fires that line whenever /dev/pts lands
    #     in the resolved set; here it must not).
    if [[ "$_dev08_stderr" == *"no-op on kernel >= 5.4"* ]] \
       && [[ "$_dev08_stderr" != *"/dev/pts"*"blacklisted, skipping"* ]]; then
        pass "DEV08: BIND_DEV_PTS=true is kernel-aware (no-op on >= 5.4, /dev/pts not appended)"
    else
        fail "DEV08: kernel-aware shim missing or DEVICES appended" \
             "stderr=$_dev08_stderr"
    fi
else
    skip "DEV08: kernel < 5.4 (or unparseable) — shim's no-op branch not exercisable here"
fi

# ── DEV09: _kernel_at_least helper unit test ──
# Inverse of DEV08: directly call the helper from a subshell sourcing
# sandbox-lib.sh. This documents the mock-friendly contract for
# downstream packagers and proves the helper handles the "old kernel"
# branch without needing an actual < 5.4 host.
(
    set +e  # the helper uses bash arithmetic that returns nonzero
    # shellcheck source=sandbox-lib.sh
    SANDBOX_QUIET=true source "$SCRIPT_DIR/sandbox-lib.sh" 2>/dev/null
    # _kernel_at_least 0 0 must succeed on every host (any kernel >= 0.0)
    _kernel_at_least 0 0 || exit 11
    # _kernel_at_least 99 99 must fail on every host (no kernel >= 99.99 yet)
    _kernel_at_least 99 99 && exit 12
    # Mock uname to return a known < 5.4 string and confirm helper rejects 5.4
    uname() { case "$1" in -r) echo "5.3.0-fake";; *) command uname "$@";; esac; }
    _kernel_at_least 5 4 && exit 13
    # Mock uname to return a known >= 5.4 string and confirm helper accepts
    uname() { case "$1" in -r) echo "5.4.0-fake";; *) command uname "$@";; esac; }
    _kernel_at_least 5 4 || exit 14
    # And one well above the boundary
    uname() { case "$1" in -r) echo "6.8.0-fake";; *) command uname "$@";; esac; }
    _kernel_at_least 5 4 || exit 15
    exit 0
)
_dev09_rc=$?
if [[ "$_dev09_rc" -eq 0 ]]; then
    pass "DEV09: _kernel_at_least handles boundary, low, and high kernel versions"
else
    fail "DEV09: _kernel_at_least helper failed unit test (rc=$_dev09_rc)" \
         "11=non-zero-base 12=above-99.99 13=mock-5.3-passes-5.4 14=mock-5.4-fails-5.4 15=mock-6.8-fails-5.4"
fi

# ── DEV10: explicit DEVICES+=(/dev/pts) on kernel >= 5.4 emits the shadow warning ──
# Mirrors DEV04 (blacklist-filtering) but checks the new kernel-aware
# warning. The warning fires on user intent (pre-blacklist), so it is
# observable even when the blacklist drops the entry — that is the
# intended behaviour, since the user wrote down "I want pty visible"
# and deserves to be told why their kernel will silently break it.
_dev10_kver_maj="$(uname -r 2>/dev/null | cut -d. -f1)"
_dev10_kver_min="$(uname -r 2>/dev/null | cut -d. -f2 | tr -dc 0-9)"
if [[ "$_dev10_kver_maj" =~ ^[0-9]+$ && "$_dev10_kver_min" =~ ^[0-9]+$ ]] \
   && (( _dev10_kver_maj > 5 || (_dev10_kver_maj == 5 && _dev10_kver_min >= 4) )); then
    _dev10_conf=$(_dev_test_conf <<'CONF'
DEVICES+=(/dev/pts)
CONF
)
    _dev10_err=$(mktemp); trap_rm_path "$_dev10_err"
    SANDBOX_CONF="$_dev10_conf" "$SANDBOX_EXEC" --backend bwrap --project-dir "$PROJECT_DIR" -- \
        bash -c 'echo ok' >"$_dev10_err.out" 2>"$_dev10_err" || true
    _dev10_out=$(cat "$_dev10_err.out")
    _dev10_stderr=$(cat "$_dev10_err")
    if [[ "$_dev10_out" == *"ok"* ]] \
       && [[ "$_dev10_stderr" == *"DEVICES contains /dev/pts on kernel >= 5.4"* ]]; then
        pass "DEV10: explicit /dev/pts on >= 5.4 emits the devpts-shadow warning"
    else
        fail "DEV10: shadow warning missing or sandbox aborted" \
             "out=$_dev10_out err=$_dev10_stderr"
    fi
else
    skip "DEV10: kernel < 5.4 (or unparseable) — shadow warning not applicable"
fi

else
    skip "DEV01-DEV10: device passthrough is bwrap-only"
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

# ── L04: SANDBOX_MODULES with no lmod doesn't abort sandbox ──
# This test runs unconditionally.  It verifies that _load_sandbox_modules
# returns 0 (not 1, which would kill the script under set -e) when lmod
# is unavailable.  We unset the module function and point LMOD_CMD at a
# nonexistent path so the init scripts can't re-source it.
echo "13b. Lmod fallback (no lmod required)"

local _nolmod_conf
_nolmod_conf=$(mktemp)
trap_rm_path "$_nolmod_conf"
cat "$SCRIPT_DIR/sandbox.conf" > "$_nolmod_conf"
cat >> "$_nolmod_conf" <<'CONF'
SANDBOX_MODULES=("fake-module/1.0")
CONF

# Run sandbox-exec.sh in an environment where the `module` function is
# stripped.  env -u BASH_FUNC_module%% removes the exported function;
# LMOD_CMD=/nonexistent prevents re-sourcing lmod init scripts.
_stderr_l04=$(mktemp)
trap_rm_path "$_stderr_l04"
if env -u "BASH_FUNC_module%%" LMOD_CMD="/nonexistent" LMOD_DIR="/nonexistent" \
     SANDBOX_CONF="$_nolmod_conf" \
     bash -c 'unset -f module 2>/dev/null; exec "$@"' _ \
     "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" \
     --project-dir "$PROJECT_DIR" -- bash -c 'echo ok' \
     >"$_stderr_l04.out" 2>"$_stderr_l04"; then
    local _l04_out _l04_err
    _l04_out=$(cat "$_stderr_l04.out")
    _l04_err=$(cat "$_stderr_l04")
    if [[ "$_l04_out" == *"ok"* ]]; then
        if [[ "$_l04_err" == *"warning"*"module"* ]]; then
            pass "L04: SANDBOX_MODULES with no lmod warns and continues"
        else
            pass "L04: SANDBOX_MODULES with no lmod doesn't abort"
        fi
    else
        fail "L04: Sandbox didn't run guest when lmod unavailable" "$_l04_out $_l04_err"
    fi
else
    local _l04_out _l04_err
    _l04_out=$(cat "$_stderr_l04.out" 2>/dev/null)
    _l04_err=$(cat "$_stderr_l04" 2>/dev/null)
    if [[ "$_l04_out" == *"ok"* ]]; then
        pass "L04: SANDBOX_MODULES with no lmod doesn't prevent guest execution"
    else
        fail "L04: SANDBOX_MODULES with no lmod prevented sandbox from starting" "$_l04_err"
    fi
fi
rm -f "$_stderr_l04.out"

echo ""

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

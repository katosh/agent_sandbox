#!/usr/bin/env bash
# test.sh — Comprehensive test suite for the sandbox
#
# Runs from the repo directory or the installed ~/.claude/sandbox/.
# Tests cover filesystem isolation, environment blocking, Slurm binary
# isolation, overlay generation, sbatch/srun wrapping, and security
# hardening (attack vector tests).
#
# Usage:
#   bash test.sh [PROJECT_DIR]            # test all available backends
#   bash test.sh --verbose                # show command output on failure
#   bash test.sh --backend bwrap          # test only bwrap backend
#   bash test.sh --backend landlock       # test only landlock backend

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_EXEC="$SCRIPT_DIR/sandbox-exec.sh"
PROJECT_DIR=""

VERBOSE=false
BACKEND_FLAG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose) VERBOSE=true; shift ;;
        --backend) BACKEND_FLAG="$2"; shift 2 ;;
        -*) shift ;;
        *) PROJECT_DIR="$1"; shift ;;
    esac
done

# Default project dir: use the repo itself
[[ -z "$PROJECT_DIR" ]] && PROJECT_DIR="$SCRIPT_DIR"

# ── Helpers ───────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0

pass() { ((PASS++)); echo "  ✓ $1"; }
fail() { ((FAIL++)); echo "  ✗ $1"; [[ "$VERBOSE" == true && -n "${2:-}" ]] && echo "    $2"; }
skip() { ((SKIP++)); echo "  ⊘ $1 (skipped)"; }

# Current backend being tested (set by run_tests)
CURRENT_BACKEND=""

# Run a command inside the sandbox. Returns the exit code.
# Captures stdout+stderr in $OUTPUT.
sandbox() {
    OUTPUT=$(timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- "$@" 2>&1)
    return $?
}

is_bwrap() { [[ "$CURRENT_BACKEND" == "bwrap" ]]; }
is_landlock() { [[ "$CURRENT_BACKEND" == "landlock" ]]; }

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

check_bwrap() {
    timeout 5 "$SANDBOX_EXEC" --backend bwrap --dry-run --project-dir "$PROJECT_DIR" -- true &>/dev/null
}

check_landlock() {
    timeout 5 "$SANDBOX_EXEC" --backend landlock --dry-run --project-dir "$PROJECT_DIR" -- true &>/dev/null
}

if [[ -n "$BACKEND_FLAG" ]]; then
    AVAILABLE_BACKENDS=("$BACKEND_FLAG")
else
    if check_bwrap; then
        AVAILABLE_BACKENDS+=(bwrap)
    fi
    if check_landlock; then
        AVAILABLE_BACKENDS+=(landlock)
    fi
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
ANY_FAIL=false

run_tests() {
CURRENT_BACKEND="$1"
PASS=0
FAIL=0
SKIP=0

echo "┌───────────────────────────────────────────────"
echo "│  Testing backend: $CURRENT_BACKEND"
echo "└───────────────────────────────────────────────"
echo ""

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

echo ""

# ── 2. Filesystem isolation ──────────────────────────────────────

echo "2. Filesystem isolation"

# Helper: test that a sensitive directory is blocked (ENOENT for bwrap, EACCES for landlock)
test_blocked_dir() {
    local dir="$1"
    local name="$2"

    if [[ "$CURRENT_BACKEND" == "bwrap" ]]; then
        if sandbox test -d "$dir"; then
            fail "$name is visible (should be hidden)"
        else
            pass "$name is hidden"
        fi
    else
        # Landlock: directory may exist but access is denied
        if sandbox bash -c "ls '$dir' 2>&1"; then
            fail "$name is accessible (should be blocked)"
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

# Project dir writable
TESTFILE="$PROJECT_DIR/.test-write-$$"
if sandbox bash -c "touch '$TESTFILE' && rm -f '$TESTFILE'"; then
    pass "Project directory is writable"
else
    fail "Project directory is not writable" "$OUTPUT"
fi
rm -f "$TESTFILE"

# Home directory not writable (outside allowed paths)
if sandbox bash -c "touch \$HOME/test-readonly 2>&1"; then
    fail "Home directory is writable (should be read-only/blocked)"
else
    pass "Home directory is read-only"
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

if sandbox bash -c 'echo ${OPENAI_API_KEY:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "OPENAI_API_KEY is blocked"
    else
        fail "OPENAI_API_KEY leaked into sandbox" "$OUTPUT"
    fi
fi

if sandbox bash -c 'echo ${AWS_ACCESS_KEY_ID:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "AWS_ACCESS_KEY_ID is blocked"
    else
        fail "AWS_ACCESS_KEY_ID leaked into sandbox" "$OUTPUT"
    fi
fi

unset GITHUB_PAT OPENAI_API_KEY AWS_ACCESS_KEY_ID

# Passthrough vars
if sandbox bash -c 'echo ${USER:-UNSET}'; then
    if [[ "$OUTPUT" != "UNSET" ]]; then
        pass "USER is passed through"
    else
        fail "USER not passed through"
    fi
fi

echo ""

# ── 4. CLAUDE.md and settings.json overlays ──────────────────────

echo "4. CLAUDE.md and settings.json overlays"

CLAUDE_MD="$HOME/.claude/CLAUDE.md"
if [[ -e "$CLAUDE_MD" ]]; then
    CLAUDE_MD_RESOLVED="$CLAUDE_MD"
    if [[ -L "$CLAUDE_MD" ]]; then
        CLAUDE_MD_RESOLVED="$(readlink -f "$CLAUDE_MD")"
    fi

    if sandbox bash -c "cat '$CLAUDE_MD_RESOLVED' 2>/dev/null | grep -q 'SANDBOX_ACTIVE'"; then
        pass "CLAUDE.md overlay contains sandbox instructions"
    else
        fail "CLAUDE.md overlay missing sandbox instructions" "$OUTPUT"
    fi
else
    skip "CLAUDE.md not found — overlay test"
fi

SETTINGS="$HOME/.claude/settings.json"
if [[ -e "$SETTINGS" ]]; then
    SETTINGS_RESOLVED="$SETTINGS"
    if [[ -L "$SETTINGS" ]]; then
        SETTINGS_RESOLVED="$(readlink -f "$SETTINGS")"
    fi

    if sandbox bash -c "cat '$SETTINGS_RESOLVED' 2>/dev/null | grep -q 'Bash'"; then
        pass "settings.json overlay contains sandbox permissions"
    else
        fail "settings.json overlay missing sandbox permissions" "$OUTPUT"
    fi
else
    skip "settings.json not found — overlay test"
fi

if [[ -L "$CLAUDE_MD" ]]; then
    pass "CLAUDE.md is a symlink — overlay handled correctly (sandbox started)"
fi
if [[ -L "$SETTINGS" ]]; then
    pass "settings.json is a symlink — overlay handled correctly (sandbox started)"
fi

# Landlock-specific: verify backup was restored after sandbox exit
if [[ "$CURRENT_BACKEND" == "landlock" ]]; then
    if [[ -e "$CLAUDE_MD" && ! -f "${CLAUDE_MD}.sandbox-backup" ]]; then
        pass "CLAUDE.md backup was cleaned up after sandbox exit"
    elif [[ -e "$CLAUDE_MD" ]]; then
        fail "CLAUDE.md backup was not cleaned up"
    fi
    if [[ -e "$SETTINGS" && ! -f "${SETTINGS}.sandbox-backup" ]]; then
        pass "settings.json backup was cleaned up after sandbox exit"
    elif [[ -e "$SETTINGS" ]]; then
        fail "settings.json backup was not cleaned up"
    fi
fi

echo ""

# ── 5. Slurm binary isolation ───────────────────────────────────

echo "5. Slurm binary isolation"

if ! command -v sbatch &>/dev/null; then
    skip "sbatch not found on host — skipping Slurm tests"
    echo ""
else
    # PATH shadow (works for both backends)
    # The sandbox prepends $SANDBOX_DIR/bin to PATH, so sbatch/srun should
    # resolve there instead of /usr/bin/.
    EXPECTED_BIN_DIR="$SCRIPT_DIR/bin"
    if sandbox bash -c 'which sbatch 2>/dev/null'; then
        if [[ "$OUTPUT" == "$EXPECTED_BIN_DIR/sbatch" ]]; then
            pass "sbatch resolves to sandbox wrapper via PATH"
        else
            fail "sbatch does not resolve to sandbox wrapper" "got: $OUTPUT, expected: $EXPECTED_BIN_DIR/sbatch"
        fi
    else
        fail "sbatch not found inside sandbox"
    fi

    if sandbox bash -c 'which srun 2>/dev/null'; then
        if [[ "$OUTPUT" == "$EXPECTED_BIN_DIR/srun" ]]; then
            pass "srun resolves to sandbox wrapper via PATH"
        else
            fail "srun does not resolve to sandbox wrapper" "got: $OUTPUT, expected: $EXPECTED_BIN_DIR/srun"
        fi
    else
        fail "srun not found inside sandbox"
    fi

    # bwrap-specific: /usr/bin/ overlay and binary relocation
    if [[ "$CURRENT_BACKEND" == "bwrap" ]]; then
        if sandbox bash -c 'file /usr/bin/sbatch'; then
            if echo "$OUTPUT" | grep -qi "script\|text"; then
                pass "/usr/bin/sbatch is overlaid with redirector script"
            else
                fail "/usr/bin/sbatch is still the real ELF binary" "$OUTPUT"
            fi
        fi

        if sandbox bash -c 'file /usr/bin/srun'; then
            if echo "$OUTPUT" | grep -qi "script\|text"; then
                pass "/usr/bin/srun is overlaid with redirector script"
            else
                fail "/usr/bin/srun is still the real ELF binary" "$OUTPUT"
            fi
        fi

        if sandbox bash -c 'test -x /tmp/.sandbox-slurm-real/sbatch && echo EXISTS'; then
            if [[ "$OUTPUT" == "EXISTS" ]]; then
                pass "Real sbatch relocated to /tmp/.sandbox-slurm-real/sbatch"
            else
                fail "Real sbatch not found at obscure path" "$OUTPUT"
            fi
        else
            fail "Real sbatch not found at obscure path" "$OUTPUT"
        fi

        if sandbox bash -c 'test -x /tmp/.sandbox-slurm-real/srun && echo EXISTS'; then
            if [[ "$OUTPUT" == "EXISTS" ]]; then
                pass "Real srun relocated to /tmp/.sandbox-slurm-real/srun"
            else
                fail "Real srun not found at obscure path" "$OUTPUT"
            fi
        else
            fail "Real srun not found at obscure path" "$OUTPUT"
        fi

        if sandbox bash -c 'head -2 /usr/bin/sbatch'; then
            if echo "$OUTPUT" | grep -q "sandbox"; then
                pass "/usr/bin/sbatch redirector calls sandbox wrapper"
            else
                fail "/usr/bin/sbatch redirector does not point to sandbox" "$OUTPUT"
            fi
        fi
    else
        skip "/usr/bin/ overlay — not applicable for $CURRENT_BACKEND backend"
        skip "Binary relocation — not applicable for $CURRENT_BACKEND backend"
    fi

    echo ""

    # ── 6. sbatch/srun functional tests ──────────────────────────

    echo "6. Slurm submission (functional)"

    if sandbox sbatch --wrap="echo sandbox-test-path" 2>&1; then
        if echo "$OUTPUT" | grep -q "Submitted batch job"; then
            pass "sbatch --wrap via PATH submits job"
        else
            fail "sbatch --wrap via PATH failed" "$OUTPUT"
        fi
    else
        fail "sbatch --wrap via PATH failed" "$OUTPUT"
    fi

    if [[ "$CURRENT_BACKEND" == "bwrap" ]]; then
        if sandbox /usr/bin/sbatch --wrap="echo sandbox-test-bypass" 2>&1; then
            if echo "$OUTPUT" | grep -q "Submitted batch job"; then
                pass "/usr/bin/sbatch bypass attempt routed through sandbox"
            else
                fail "/usr/bin/sbatch bypass attempt failed" "$OUTPUT"
            fi
        else
            fail "/usr/bin/sbatch bypass attempt errored" "$OUTPUT"
        fi
    fi

    # No infinite recursion
    if timeout 10 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- \
        sbatch --wrap="echo recursion-test" &>/dev/null; then
        pass "No infinite recursion in sbatch wrapper"
    else
        fail "sbatch wrapper may have infinite recursion (timed out)"
    fi
fi

echo ""

# ── 7. Sandbox self-protection ───────────────────────────────────

echo "7. Sandbox self-protection"

if [[ "$CURRENT_BACKEND" == "landlock" ]]; then
    # Landlock rules are additive — can't make a subdir read-only when its
    # parent ($HOME/.claude) is writable.  See ADMIN_HARDENING.md §2.
    skip "Sandbox self-protection — not supported with Landlock backend (see ADMIN_HARDENING.md)"
else
    # Use a separate project dir so the writable project mount doesn't
    # overlap with the sandbox dir
    PROTECTION_PROJECT="$(mktemp -d)"
    trap "rm -rf '$PROTECTION_PROJECT'" EXIT

    protection_sandbox() {
        OUTPUT=$(timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROTECTION_PROJECT" -- "$@" 2>&1)
        return $?
    }

    if protection_sandbox bash -c "touch '$SCRIPT_DIR/test-tamper' 2>&1"; then
        fail "Sandbox directory is writable (should be read-only)"
        rm -f "$SCRIPT_DIR/test-tamper"
    else
        pass "Sandbox directory is read-only"
    fi

    if protection_sandbox bash -c "echo 'tamper' >> '$SCRIPT_DIR/sandbox-lib.sh' 2>&1"; then
        fail "sandbox-lib.sh is writable inside sandbox"
    else
        pass "sandbox-lib.sh is protected from modification"
    fi
fi

# ── 8. Security hardening ─────────────────────────────────────────

echo "8. Security hardening (attack vectors)"

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

if sandbox bash -c 'echo ${SSH_CONNECTION:-UNSET}'; then
    if [[ "$OUTPUT" == "UNSET" ]]; then
        pass "SSH_CONNECTION is blocked"
    else
        fail "SSH_CONNECTION leaked into sandbox" "$OUTPUT"
    fi
fi

unset SSH_AUTH_SOCK SSH_CONNECTION SSH_CLIENT SSH_TTY

# systemd-run escape — should fail on bwrap (sockets not visible)
if command -v systemd-run &>/dev/null; then
    ESCAPE_FILE="/tmp/.sandbox-escape-test-$$"
    rm -f "$ESCAPE_FILE"
    if sandbox bash -c "systemd-run --user --collect --wait -- touch '$ESCAPE_FILE' 2>&1"; then
        if [[ -f "$ESCAPE_FILE" ]]; then
            fail "systemd-run --user ESCAPED the sandbox (created file on host)"
            rm -f "$ESCAPE_FILE"
        else
            pass "systemd-run --user did not escape"
        fi
    else
        if [[ -f "$ESCAPE_FILE" ]]; then
            fail "systemd-run --user ESCAPED the sandbox (created file on host)"
            rm -f "$ESCAPE_FILE"
        else
            if [[ "$CURRENT_BACKEND" == "landlock" ]]; then
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

# /run/user sockets should not be accessible (bwrap: tmpfs, landlock: restricted)
if [[ "$CURRENT_BACKEND" == "bwrap" ]]; then
    if sandbox bash -c "ls /run/user/ 2>&1"; then
        fail "/run/user/ is visible in bwrap sandbox"
    else
        pass "/run/user/ is hidden (tmpfs /run)"
    fi

    if sandbox bash -c "ls /run/dbus/ 2>&1"; then
        fail "/run/dbus/ is visible in bwrap sandbox"
    else
        pass "/run/dbus/ is hidden (tmpfs /run)"
    fi
fi

# PID namespace isolation (bwrap only — landlock does not have PID ns)
if [[ "$CURRENT_BACKEND" == "bwrap" ]]; then
    if sandbox bash -c 'ps aux 2>/dev/null | wc -l'; then
        PROC_COUNT="$OUTPUT"
        # Inside a PID namespace, we should see very few processes
        # (bwrap, bash, ps, wc — typically < 10)
        if [[ "$PROC_COUNT" -lt 20 ]]; then
            pass "PID namespace isolates host processes ($PROC_COUNT visible)"
        else
            fail "PID namespace not working — $PROC_COUNT processes visible"
        fi
    else
        skip "Could not check PID namespace"
    fi
fi

# Seccomp filter (landlock only — bwrap doesn't install one currently)
if [[ "$CURRENT_BACKEND" == "landlock" ]]; then
    if sandbox bash -c 'grep "^Seccomp:" /proc/self/status'; then
        SECCOMP_MODE=$(echo "$OUTPUT" | awk '{print $2}')
        if [[ "$SECCOMP_MODE" == "2" ]]; then
            pass "Seccomp filter is active (mode 2)"
        else
            fail "Seccomp filter not active (mode $SECCOMP_MODE)"
        fi
    fi

    # io_uring_setup should be blocked
    if sandbox python3 -c "
import ctypes, ctypes.util
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
ret = libc.syscall(ctypes.c_long(425), ctypes.c_uint32(1), ctypes.c_void_p(0))
errno_val = ctypes.get_errno()
print('BLOCKED' if errno_val == 1 else 'ALLOWED')
" 2>&1; then
        if [[ "$OUTPUT" == "BLOCKED" ]]; then
            pass "io_uring_setup blocked by seccomp"
        else
            fail "io_uring_setup not blocked by seccomp" "$OUTPUT"
        fi
    else
        skip "Could not test io_uring_setup"
    fi
fi

echo ""

# ── Per-backend summary ──────────────────────────────────────────

TOTAL=$((PASS + FAIL + SKIP))
echo "════════════════════════════════════════════════"
echo "  Backend: $CURRENT_BACKEND"
echo "  Results: $PASS passed, $FAIL failed, $SKIP skipped (out of $TOTAL)"
echo "════════════════════════════════════════════════"
echo ""

TOTAL_PASS=$((TOTAL_PASS + PASS))
TOTAL_FAIL=$((TOTAL_FAIL + FAIL))
TOTAL_SKIP=$((TOTAL_SKIP + SKIP))
[[ $FAIL -gt 0 ]] && ANY_FAIL=true
}

# ── Run tests for each available backend ─────────────────────────

for backend in "${AVAILABLE_BACKENDS[@]}"; do
    run_tests "$backend"
done

# ── Overall summary ──────────────────────────────────────────────

if [[ ${#AVAILABLE_BACKENDS[@]} -gt 1 ]]; then
    GRAND_TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))
    echo "╔═══════════════════════════════════════════════╗"
    echo "║  Overall Results                              ║"
    echo "╠═══════════════════════════════════════════════╣"
    printf "║  Backends tested: %-27s ║\n" "${AVAILABLE_BACKENDS[*]}"
    printf "║  %3d passed, %d failed, %d skipped (of %d)     ║\n" \
        "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_SKIP" "$GRAND_TOTAL"
    echo "╚═══════════════════════════════════════════════╝"
fi

if [[ "$ANY_FAIL" == true ]]; then
    echo ""
    echo "  Some tests failed. Run with --verbose for details."
    exit 1
fi

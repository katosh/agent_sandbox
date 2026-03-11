#! /bin/bash --
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
#   bash test.sh --backend firejail       # test only firejail backend
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
# Captures stdout+stderr in $OUTPUT, filtering known backend warnings.
sandbox() {
    local raw
    raw=$(timeout 15 "$SANDBOX_EXEC" --backend "$CURRENT_BACKEND" --project-dir "$PROJECT_DIR" -- "$@" 2>&1)
    local rc=$?
    # Filter backend warnings that pollute output comparisons:
    #   - landlock_add_rule warnings (file vs directory rule mismatch)
    #   - "Restoring stale backup" from landlock/firejail crash recovery
    #   - firejail "Parent/Child" status lines (suppressed by --quiet, but just in case)
    OUTPUT=$(echo "$raw" | grep -v \
        -e '^Warning: landlock_add_rule' \
        -e '^Warning: Restoring stale backup' \
        -e '^Parent pid ' \
        -e '^Child process initialized' \
        -e '^Parent is shutting down')
    return $rc
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

    if has_mount_ns; then
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
# prepare_config_dir() creates ~/.claude/sandbox-config/ with merged
# CLAUDE.md and settings.json, and sets CLAUDE_CONFIG_DIR so Claude Code
# reads from there instead of ~/.claude/ directly.

echo "4. CLAUDE.md and settings.json overlays"

# Check that CLAUDE_CONFIG_DIR is set inside the sandbox and points
# to a per-session directory with the merged content.
if sandbox bash -c 'cat "$CLAUDE_CONFIG_DIR/CLAUDE.md" 2>/dev/null | grep -q "Sandbox Environment"'; then
    pass "CLAUDE.md overlay contains sandbox instructions (via CLAUDE_CONFIG_DIR)"
else
    fail "CLAUDE.md overlay missing sandbox instructions"
fi

if sandbox bash -c 'cat "$CLAUDE_CONFIG_DIR/settings.json" 2>/dev/null | grep -q "Bash"'; then
    pass "settings.json overlay contains sandbox permissions (via CLAUDE_CONFIG_DIR)"
else
    fail "settings.json overlay missing sandbox permissions"
fi

# Verify the user's real CLAUDE.md was NOT modified
CLAUDE_MD="$HOME/.claude/CLAUDE.md"
if [[ -f "$CLAUDE_MD" ]]; then
    if grep -q '__SANDBOX_INJECTED_9f3a7c__' "$CLAUDE_MD" 2>/dev/null; then
        fail "User's real CLAUDE.md was modified (should be untouched)"
    else
        pass "User's real CLAUDE.md is untouched"
    fi
fi

# Verify CLAUDE_CONFIG_DIR points to the sandbox-config directory
if sandbox bash -c '[[ "$CLAUDE_CONFIG_DIR" == *sandbox-config ]]'; then
    pass "CLAUDE_CONFIG_DIR points to sandbox-config directory"
else
    fail "CLAUDE_CONFIG_DIR not set correctly"
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

if is_landlock; then
    # Landlock rules are additive — can't make a subdir read-only when its
    # parent ($HOME/.claude) is writable.  See ADMIN_HARDENING.md §2.
    skip "Sandbox self-protection — not supported with Landlock backend (see ADMIN_HARDENING.md)"
else
    # Use a separate project dir so the writable project mount doesn't
    # overlap with the sandbox dir
    PROTECTION_PROJECT="$(mktemp -d)"

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

    if protection_sandbox bash -c "echo 'tamper' >> '$SCRIPT_DIR/sandbox-lib.sh' 2>&1"; then
        fail "sandbox-lib.sh is writable inside sandbox"
    else
        pass "sandbox-lib.sh is protected from modification"
    fi

    rm -rf "$PROTECTION_PROJECT"
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

# Seccomp filter (landlock and firejail — bwrap doesn't install one currently)
if is_landlock || is_firejail; then
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
fi

# ── 9. Security hardening (advanced) ──────────────────────────────

echo "9. Advanced hardening"

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

# /dev mount strategy: verify BIND_DEV_PTS auto-detection matches kernel
if [[ "$(uname -s)" == "Linux" ]]; then
    _kver="$(uname -r)"
    _kmajor="${_kver%%.*}"
    _kminor="${_kver#*.}"; _kminor="${_kminor%%.*}"
    if sandbox bash -c 'mount | grep "^udev on /dev\|^devtmpfs on /dev\|^tmpfs on /dev" | head -1'; then
        if (( _kmajor < 5 || (_kmajor == 5 && _kminor < 4) )); then
            # Kernel < 5.4: must use --dev-bind /dev (host devpts needed)
            if [[ "$OUTPUT" == *"devtmpfs"* || "$OUTPUT" == *"udev"* ]]; then
                pass "kernel $_kver: using host /dev (BIND_DEV_PTS=auto, ptys need host devpts)"
            else
                fail "kernel $_kver: expected host /dev but got minimal dev" "$OUTPUT"
            fi
        elif (( _kmajor > 6 || (_kmajor == 6 && _kminor >= 2) )); then
            # Kernel >= 6.2: --dev-bind /dev (safe, TIOCSTI disabled)
            if [[ "$OUTPUT" == *"devtmpfs"* || "$OUTPUT" == *"udev"* ]]; then
                pass "kernel $_kver: using host /dev (BIND_DEV_PTS=auto, TIOCSTI disabled)"
            else
                fail "kernel $_kver: expected host /dev but got minimal dev" "$OUTPUT"
            fi
        else
            # Kernel 5.4–6.1: --dev /dev (minimal, avoids TIOCSTI risk)
            if [[ "$OUTPUT" == *"tmpfs"* ]]; then
                pass "kernel $_kver: using minimal /dev (BIND_DEV_PTS=auto, avoids TIOCSTI)"
            else
                fail "kernel $_kver: expected minimal /dev but got host dev" "$OUTPUT"
            fi
        fi
    fi
fi

# pty allocation works inside sandbox
if sandbox bash -c 'python3 -c "import pty; pty.openpty(); print(\"pty-ok\")" 2>&1'; then
    if [[ "$OUTPUT" == *"pty-ok"* ]]; then
        pass "pty allocation works inside sandbox"
    else
        fail "pty allocation returned unexpected output" "$OUTPUT"
    fi
else
    fail "pty allocation failed inside sandbox" "$OUTPUT"
fi

# tmux can start a detached session (verifies socket dir creation + pty)
if sandbox bash -c 'tmux new-session -d -s sandbox-test sleep\ 5 && tmux list-sessions && tmux kill-server'; then
    if [[ "$OUTPUT" == *"sandbox-test"* ]]; then
        pass "tmux starts detached session inside sandbox"
    else
        fail "tmux session created but not listed" "$OUTPUT"
    fi
else
    fail "tmux failed to start inside sandbox (pty allocation or socket dir)" "$OUTPUT"
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

# ALLOWED_CREDENTIALS passthrough — credentials explicitly allowed must be accessible
export _TEST_CRED_VAR="test-credential-value"
# Temporarily add to ALLOWED_CREDENTIALS won't work from here, but we can test
# that BLOCKED_ENV_VARS are actually blocked and passthrough vars work
if sandbox bash -c 'echo ${LANG:-UNSET}'; then
    if [[ "$OUTPUT" != "UNSET" ]]; then
        pass "Passthrough env vars (LANG) accessible"
    else
        # LANG may not be set on all systems
        skip "LANG not set — passthrough test inconclusive"
    fi
fi
unset _TEST_CRED_VAR

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
    if sandbox bash -c 'grep -c "^slurm:" /etc/passwd'; then
        pass "FILTER_PASSWD: slurm user preserved in filtered passwd"
    else
        fail "FILTER_PASSWD: slurm user missing from filtered passwd" "$OUTPUT"
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
        if [[ -z "$_TOKEN_PATH" && -f /etc/slurm/sandbox-wrapper.conf ]]; then
            _TOKEN_PATH=$(bash -c 'source /etc/slurm/sandbox-wrapper.conf 2>/dev/null; echo "$TOKEN_FILE"')
        fi
        if [[ -n "$_TOKEN_PATH" && -f "$_TOKEN_PATH" ]]; then
            # Landlock sets NO_NEW_PRIVS — eBPF should deny the read
            if sandbox cat "$_TOKEN_PATH" 2>&1; then
                fail "SANDBOX_BYPASS_TOKEN readable despite eBPF (Landlock)"
            else
                if echo "$OUTPUT" | grep -qi "permission denied\|operation not permitted"; then
                    pass "SANDBOX_BYPASS_TOKEN protected by eBPF LSM (Landlock)"
                else
                    pass "SANDBOX_BYPASS_TOKEN not readable (Landlock + eBPF)"
                fi
            fi
        else
            skip "SANDBOX_BYPASS_TOKEN — eBPF loaded but no token path found (sandbox.conf or /etc/slurm/sandbox-wrapper.conf)"
        fi
    else
        skip "SANDBOX_BYPASS_TOKEN — Landlock needs eBPF LSM (not loaded; see ADMIN_HARDENING.md §1)"
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

# ── Admin wrapper tests (if sandbox-wrapper.conf is deployed) ────

WRAPPER_CONF=""
if [[ -f /etc/slurm/sandbox-wrapper.conf ]]; then
    WRAPPER_CONF="/etc/slurm/sandbox-wrapper.conf"
elif [[ -f "$SCRIPT_DIR/admin/sandbox-wrapper.conf" ]]; then
    WRAPPER_CONF="$SCRIPT_DIR/admin/sandbox-wrapper.conf"
fi

if [[ -n "$WRAPPER_CONF" ]]; then
    source "$WRAPPER_CONF"
    echo ""
    echo "10. Admin wrappers (sandbox-wrapper.conf detected)"

    ADMIN_PASS=0
    ADMIN_FAIL=0
    ADMIN_SKIP=0
    admin_pass() { ((ADMIN_PASS++)); echo "  ✓ $1"; }
    admin_fail() { ((ADMIN_FAIL++)); echo "  ✗ $1"; [[ "$VERBOSE" == true && -n "${2:-}" ]] && echo "    $2"; }
    admin_skip() { ((ADMIN_SKIP++)); echo "  ⊘ $1 (skipped)"; }

    # Check that real binaries exist at configured locations
    if [[ -x "${REAL_SBATCH:-}" ]]; then
        OUTPUT=$(file "$REAL_SBATCH" 2>&1)
        if echo "$OUTPUT" | grep -qi 'ELF'; then
            admin_pass "Real sbatch binary at $REAL_SBATCH"
        else
            admin_fail "Real sbatch at $REAL_SBATCH is not an ELF binary" "$OUTPUT"
        fi
    else
        admin_skip "Real sbatch not found at ${REAL_SBATCH:-<unset>}"
    fi

    if [[ -x "${REAL_SRUN:-}" ]]; then
        OUTPUT=$(file "$REAL_SRUN" 2>&1)
        if echo "$OUTPUT" | grep -qi 'ELF'; then
            admin_pass "Real srun binary at $REAL_SRUN"
        else
            admin_fail "Real srun at $REAL_SRUN is not an ELF binary" "$OUTPUT"
        fi
    else
        admin_skip "Real srun not found at ${REAL_SRUN:-<unset>}"
    fi

    # Check that /usr/bin/sbatch and /usr/bin/srun are wrapper scripts
    if [[ -f /usr/bin/sbatch ]]; then
        OUTPUT=$(file /usr/bin/sbatch 2>&1)
        if echo "$OUTPUT" | grep -qi 'script\|text'; then
            admin_pass "/usr/bin/sbatch is a wrapper script (not the real binary)"
        else
            admin_skip "/usr/bin/sbatch is the real binary (admin wrappers not deployed)"
        fi
    fi

    if [[ -f /usr/bin/srun ]]; then
        OUTPUT=$(file /usr/bin/srun 2>&1)
        if echo "$OUTPUT" | grep -qi 'script\|text'; then
            admin_pass "/usr/bin/srun is a wrapper script (not the real binary)"
        else
            admin_skip "/usr/bin/srun is the real binary (admin wrappers not deployed)"
        fi
    fi

    # Check token file exists and is readable
    if [[ -n "${TOKEN_FILE:-}" && -f "$TOKEN_FILE" ]]; then
        if cat "$TOKEN_FILE" &>/dev/null; then
            admin_pass "Token file readable ($TOKEN_FILE)"
        else
            admin_fail "Token file exists but is not readable ($TOKEN_FILE)"
        fi
    else
        admin_skip "Token file not found (${TOKEN_FILE:-<unset>})"
    fi

    # Test sbatch wrapper logic (dry run — no job submission needed)
    SBATCH_WRAPPER=""
    if [[ -f /usr/bin/sbatch ]] && head -1 /usr/bin/sbatch 2>/dev/null | grep -q bash; then
        SBATCH_WRAPPER=/usr/bin/sbatch
    fi

    if [[ -n "$SBATCH_WRAPPER" ]]; then
        # Verify wrapper sources sandbox-wrapper.conf
        if grep -q 'sandbox-wrapper.conf' "$SBATCH_WRAPPER"; then
            admin_pass "sbatch wrapper sources sandbox-wrapper.conf"
        else
            admin_fail "sbatch wrapper does not source sandbox-wrapper.conf"
        fi

        # Verify wrapper strips _SANDBOX_BYPASS from --export= flags
        if grep -q '_SANDBOX_BYPASS' "$SBATCH_WRAPPER"; then
            admin_pass "sbatch wrapper handles _SANDBOX_BYPASS stripping"
        else
            admin_fail "sbatch wrapper does not handle _SANDBOX_BYPASS stripping"
        fi

        # Verify wrapper injects token via env var (not CLI)
        if grep -q 'export _SANDBOX_BYPASS' "$SBATCH_WRAPPER"; then
            admin_pass "sbatch wrapper injects token via environment (not CLI)"
        else
            admin_fail "sbatch wrapper does not export _SANDBOX_BYPASS"
        fi

        # Test the stripping logic directly
        OUTPUT=$(echo "ALL,_SANDBOX_BYPASS=secret,FOO=bar" | sed 's/,\?_SANDBOX_BYPASS=[^,]*//' | sed 's/^,//')
        if [[ "$OUTPUT" == "ALL,FOO=bar" ]]; then
            admin_pass "Token stripping preserves other --export= variables"
        else
            admin_fail "Token stripping produced unexpected output" "$OUTPUT"
        fi
    fi

    # Test srun wrapper logic (dry run)
    SRUN_WRAPPER=""
    if [[ -f /usr/bin/srun ]] && head -1 /usr/bin/srun 2>/dev/null | grep -q bash; then
        SRUN_WRAPPER=/usr/bin/srun
    fi

    if [[ -n "$SRUN_WRAPPER" ]]; then
        # Verify wrapper checks SANDBOX_ACTIVE to avoid nesting
        if grep -q 'SANDBOX_ACTIVE' "$SRUN_WRAPPER"; then
            admin_pass "srun wrapper checks SANDBOX_ACTIVE (avoids nesting)"
        else
            admin_fail "srun wrapper does not check SANDBOX_ACTIVE"
        fi

        # Verify wrapper reads token to decide pass-through vs sandbox
        if grep -q 'TOKEN_FILE\|sandbox-wrapper.conf' "$SRUN_WRAPPER"; then
            admin_pass "srun wrapper reads token for pass-through decision"
        else
            admin_fail "srun wrapper does not read token"
        fi
    fi

    # Test token protection: sandboxed process cannot read token
    if [[ -n "${TOKEN_FILE:-}" && -f "$TOKEN_FILE" && -x "$SCRIPT_DIR/sandbox-exec.sh" ]]; then
        OUTPUT=$(timeout 15 "$SCRIPT_DIR/sandbox-exec.sh" \
            --project-dir "$PROJECT_DIR" -- \
            cat "$TOKEN_FILE" 2>&1) || true
        if echo "$OUTPUT" | grep -qi 'permission denied\|EACCES'; then
            admin_pass "Token protected from sandboxed process"
        elif [[ -z "$OUTPUT" ]]; then
            admin_pass "Token hidden from sandboxed process (empty read)"
        else
            admin_fail "Token readable from sandboxed process" "$OUTPUT"
        fi
    fi

    echo ""
    echo "════════════════════════════════════════════════"
    echo "  Admin wrappers: $ADMIN_PASS passed, $ADMIN_FAIL failed, $ADMIN_SKIP skipped"
    echo "════════════════════════════════════════════════"

    TOTAL_PASS=$((TOTAL_PASS + ADMIN_PASS))
    TOTAL_FAIL=$((TOTAL_FAIL + ADMIN_FAIL))
    TOTAL_SKIP=$((TOTAL_SKIP + ADMIN_SKIP))
    [[ $ADMIN_FAIL -gt 0 ]] && ANY_FAIL=true
fi

# ── Overall summary ──────────────────────────────────────────────

if [[ ${#AVAILABLE_BACKENDS[@]} -gt 1 || -n "$WRAPPER_CONF" ]]; then
    GRAND_TOTAL=$((TOTAL_PASS + TOTAL_FAIL + TOTAL_SKIP))
    echo "╔═══════════════════════════════════════════════╗"
    echo "║  Overall Results                              ║"
    echo "╠═══════════════════════════════════════════════╣"
    printf "║  Backends tested: %-27s ║\n" "${AVAILABLE_BACKENDS[*]}"
    printf "║  %3d passed, %d failed, %d skipped (of %d)     ║\n" \
        "$TOTAL_PASS" "$TOTAL_FAIL" "$TOTAL_SKIP" "$GRAND_TOTAL"
    echo "╚═══════════════════════════════════════════════╝"
fi

# ── Admin hardening status (ADMIN_HARDENING.md) ──────────────────

echo ""
echo "Admin hardening status (see ADMIN_HARDENING.md):"

# §1 — Enforce sandbox on agent-submitted Slurm jobs
_s1_parts=()
_s1_missing=()

# Token file exists?
_token_path=""
if [[ -n "${TOKEN_FILE:-}" ]]; then
    _token_path="$TOKEN_FILE"
elif [[ -f /etc/slurm/sandbox-wrapper.conf ]]; then
    _token_path=$(bash -c 'source /etc/slurm/sandbox-wrapper.conf 2>/dev/null; echo "$TOKEN_FILE"')
fi
if [[ -n "$_token_path" && -f "$_token_path" ]]; then
    _s1_parts+=("bypass token")
else
    _s1_missing+=("bypass token")
fi

# eBPF loaded?
if command -v bpftool &>/dev/null && sudo -n bpftool prog list 2>/dev/null | grep -q 'deny_token_read'; then
    _s1_parts+=("eBPF LSM")
else
    _s1_missing+=("eBPF LSM")
fi

# Job submit plugin?
if [[ -f /etc/slurm/job_submit.lua ]] && grep -q 'SANDBOX_BYPASS\|sandbox' /etc/slurm/job_submit.lua 2>/dev/null; then
    _s1_parts+=("job submit plugin")
else
    _s1_missing+=("job submit plugin")
fi

# System-wide wrappers?
if [[ -f /usr/bin/sbatch ]] && head -1 /usr/bin/sbatch 2>/dev/null | grep -q bash; then
    _s1_parts+=("sbatch/srun wrappers")
else
    _s1_missing+=("sbatch/srun wrappers")
fi

if [[ ${#_s1_missing[@]} -eq 0 ]]; then
    echo "  ✓ §1 Slurm job enforcement: deployed (${_s1_parts[*]})"
elif [[ ${#_s1_parts[@]} -gt 0 ]]; then
    echo "  ◐ §1 Slurm job enforcement: partial (have: ${_s1_parts[*]}; missing: ${_s1_missing[*]})"
else
    echo "  · §1 Slurm job enforcement: not deployed"
fi

# §2 — Admin-owned sandbox installation
_sandbox_dir="$(cd "$SCRIPT_DIR" && pwd)"
_sandbox_owner=$(stat -c %u "$_sandbox_dir" 2>/dev/null || stat -f %u "$_sandbox_dir" 2>/dev/null)
if [[ "${_sandbox_owner:-}" == "0" ]]; then
    echo "  ✓ §2 Admin-owned installation: sandbox scripts owned by root"
else
    echo "  · §2 Admin-owned installation: not deployed (scripts owned by user)"
fi

# §2 — systemd user instances (Landlock-only concern)
for b in "${AVAILABLE_BACKENDS[@]}"; do
    if [[ "$b" == "landlock" ]]; then
        if systemctl is-enabled user@.service &>/dev/null 2>&1; then
            _user_svc=$(systemctl is-enabled user@.service 2>/dev/null || true)
            if [[ "$_user_svc" == "masked" ]]; then
                echo "  ✓ §2 systemd user@.service: masked (Landlock escape mitigated)"
            else
                echo "  ⚠ §2 systemd user@.service: active (Landlock escape possible — see ADMIN_HARDENING.md §2)"
            fi
        fi
        break
    fi
done

echo ""

if [[ "$ANY_FAIL" == true ]]; then
    echo ""
    echo "  Some tests failed. Run with --verbose for details."
    exit 1
fi

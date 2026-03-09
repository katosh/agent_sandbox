#!/usr/bin/env bash
# docker-test.sh — Run sandbox tests in Docker containers across Ubuntu versions
#
# Tests bwrap backend with mock Slurm binaries. Landlock code-path tests run
# when kernel lacks support. Full Landlock integration requires a native Linux
# kernel with CONFIG_SECURITY_LANDLOCK=y.
#
# Usage:
#   bash docker-test.sh                  # test all versions
#   bash docker-test.sh 24.04            # test specific version
#   bash docker-test.sh --verbose        # verbose test output

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

VERBOSE=""
VERSIONS=("22.04" "24.04")
SPECIFIC_VERSION=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose) VERBOSE="--verbose"; shift ;;
        *) SPECIFIC_VERSION="$1"; shift ;;
    esac
done

if [[ -n "$SPECIFIC_VERSION" ]]; then
    VERSIONS=("$SPECIFIC_VERSION")
fi

TOTAL_PASS=0
TOTAL_FAIL=0

# ── Build test image ─────────────────────────────────────────────

build_image() {
    local version="$1"
    local tag="sandbox-test:${version}"

    echo "════════════════════════════════════════════════"
    echo "  Building test image: Ubuntu $version"
    echo "════════════════════════════════════════════════"

    docker build --no-cache -q -t "$tag" -f - "$SCRIPT_DIR" <<DOCKERFILE
FROM ubuntu:${version}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \\
    bubblewrap python3 file procps curl \\
    && rm -rf /var/lib/apt/lists/*

RUN printf '#!/bin/bash\\necho "Submitted batch job 12345"\\n' > /usr/bin/sbatch && \\
    chmod +x /usr/bin/sbatch && \\
    printf '#!/bin/bash\\nexec "\$@"\\n' > /usr/bin/srun && \\
    chmod +x /usr/bin/srun

RUN useradd -m -s /bin/bash testuser && \\
    mkdir -p /home/testuser/.ssh && \\
    echo "fake-ssh-key" > /home/testuser/.ssh/id_rsa && \\
    chmod 600 /home/testuser/.ssh/id_rsa && \\
    mkdir -p /home/testuser/.aws && \\
    printf '[default]\\naws_access_key_id=FAKE\\n' > /home/testuser/.aws/credentials && \\
    mkdir -p /home/testuser/.gnupg && \\
    touch /home/testuser/.gnupg/pubring.kbx && \\
    mkdir -p /home/testuser/.claude && \\
    echo '{}' > /home/testuser/.claude/settings.json && \\
    echo '# User CLAUDE.md' > /home/testuser/.claude/CLAUDE.md && \\
    touch /home/testuser/.gitconfig && \\
    chown -R testuser:testuser /home/testuser

COPY . /repo
RUN chown -R testuser:testuser /repo

USER testuser
ENV USER=testuser
WORKDIR /home/testuser
DOCKERFILE

    echo "  ✓ Image built: $tag"
    echo ""
}

# ── Setup script (written as a file, copied into container) ──────

create_setup_script() {
    cat > "$SCRIPT_DIR/.docker-test-setup.sh" <<'SETUP'
#!/usr/bin/env bash
set -euo pipefail

cd /repo
mkdir -p ~/.claude/sandbox/bin ~/.claude/sandbox/backends

for file in sandbox-lib.sh sandbox-exec.sh bwrap-sandbox.sh sbatch-sandbox.sh srun-sandbox.sh sandbox-claude.md sandbox-settings.json test.sh; do
    cp /repo/$file ~/.claude/sandbox/$file
done
for file in sbatch srun; do
    cp /repo/bin/$file ~/.claude/sandbox/bin/$file
done
for file in bwrap.sh landlock.sh landlock-sandbox.py; do
    cp /repo/backends/$file ~/.claude/sandbox/backends/$file
done

chmod +x ~/.claude/sandbox/sandbox-exec.sh
chmod +x ~/.claude/sandbox/bwrap-sandbox.sh
chmod +x ~/.claude/sandbox/sbatch-sandbox.sh
chmod +x ~/.claude/sandbox/srun-sandbox.sh
chmod +x ~/.claude/sandbox/test.sh
chmod +x ~/.claude/sandbox/bin/sbatch
chmod +x ~/.claude/sandbox/bin/srun

cat > ~/.claude/sandbox/sandbox.conf <<'CONF'
ALLOWED_PROJECT_PARENTS=("/home" "$HOME")
READONLY_MOUNTS=("/usr" "/lib" "/lib64" "/bin" "/sbin" "/etc")
SCRATCH_MOUNTS=()
DOTFILES_DIR=""
HOME_READONLY=(".bashrc" ".bash_profile" ".profile" ".gitconfig")
HOME_SYMLINKS=()
HOME_WRITABLE=(".claude" ".claude.json")
BLOCKED_FILES=()
EXTRA_BLOCKED_PATHS=()
BLOCKED_ENV_VARS=("GITHUB_PAT" "GITHUB_TOKEN" "OPENAI_API_KEY" "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "ANTHROPIC_API_KEY")
ALLOWED_CREDENTIALS=()
PASSTHROUGH_ENV_VARS=("LANG" "SHELL" "USER" "LOGNAME" "TERM" "HOME" "PATH")
CONF
SETUP
}

create_bwrap_extra_tests() {
    cat > "$SCRIPT_DIR/.docker-test-bwrap-extra.sh" <<'EXTRA'
#!/usr/bin/env bash
set -euo pipefail

source /repo/.docker-test-setup.sh

echo "=== Additional Slurm & credential tests ==="
echo ""

SANDBOX_EXEC=~/.claude/sandbox/sandbox-exec.sh
PROJECT=$(mktemp -d /home/testuser/project-XXXXXX)
PASS=0
FAIL=0

_pass() { PASS=$((PASS+1)); echo "  ✓ $1"; }
_fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; [[ -n "${2:-}" ]] && echo "    $2"; }

# Slurm: sbatch via PATH
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- which sbatch 2>&1) || true
if echo "$OUTPUT" | grep -q sandbox; then _pass "sbatch → sandbox wrapper via PATH"
else _fail "sbatch not sandbox wrapper" "$OUTPUT"; fi

# Slurm: sbatch --wrap works
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- sbatch --wrap='echo test' 2>&1) || true
if echo "$OUTPUT" | grep -q 'Submitted batch job'; then _pass "sbatch --wrap submits job"
else _fail "sbatch --wrap failed" "$OUTPUT"; fi

# Slurm: /usr/bin/sbatch overlaid
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- file /usr/bin/sbatch 2>&1) || true
if echo "$OUTPUT" | grep -qi 'script\|text'; then _pass "/usr/bin/sbatch overlaid with redirector"
else _fail "/usr/bin/sbatch not overlaid" "$OUTPUT"; fi

# Slurm: real sbatch relocated
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- bash -c 'test -x /tmp/.sandbox-slurm-real/sbatch && echo EXISTS' 2>&1) || true
if [[ "$OUTPUT" == *EXISTS* ]]; then _pass "Real sbatch at /tmp/.sandbox-slurm-real/"
else _fail "Real sbatch not at relocated path" "$OUTPUT"; fi

# Slurm: srun via PATH
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- which srun 2>&1) || true
if echo "$OUTPUT" | grep -q sandbox; then _pass "srun → sandbox wrapper via PATH"
else _fail "srun not sandbox wrapper" "$OUTPUT"; fi

# Security: SSH key blocked
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- cat ~/.ssh/id_rsa 2>&1) || true
if echo "$OUTPUT" | grep -qi 'no such file\|not found'; then _pass "SSH key hidden (ENOENT)"
else _fail "SSH key readable!" "$OUTPUT"; fi

# Security: AWS credentials blocked
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- cat ~/.aws/credentials 2>&1) || true
if echo "$OUTPUT" | grep -qi 'no such file\|not found'; then _pass "AWS creds hidden (ENOENT)"
else _fail "AWS creds readable!" "$OUTPUT"; fi

# Security: env var blocked
export GITHUB_PAT=secret123
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- bash -c 'echo ${GITHUB_PAT:-UNSET}' 2>&1) || true
if [[ "$OUTPUT" == "UNSET" ]]; then _pass "GITHUB_PAT blocked"
else _fail "GITHUB_PAT leaked" "$OUTPUT"; fi

# Security: ANTHROPIC_API_KEY blocked by default
export ANTHROPIC_API_KEY=sk-ant-fake
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- bash -c 'echo ${ANTHROPIC_API_KEY:-UNSET}' 2>&1) || true
if [[ "$OUTPUT" == "UNSET" ]]; then _pass "ANTHROPIC_API_KEY blocked (default)"
else _fail "ANTHROPIC_API_KEY leaked" "$OUTPUT"; fi

# Credentials: Claude auth token accessible
echo '{"token":"fake-claude-token"}' > ~/.claude/.credentials.json
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- cat ~/.claude/.credentials.json 2>&1) || true
if echo "$OUTPUT" | grep -q 'fake-claude-token'; then _pass "Claude .credentials.json accessible"
else _fail "Claude .credentials.json not accessible" "$OUTPUT"; fi

# Credentials: ~/.claude writable
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- bash -c 'touch ~/.claude/test-w && rm ~/.claude/test-w && echo OK' 2>&1) || true
if [[ "$OUTPUT" == "OK" ]]; then _pass "~/.claude writable (session data, auth refresh)"
else _fail "~/.claude not writable" "$OUTPUT"; fi

# Credentials: credential file can be updated (simulates token refresh)
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- bash -c '
    echo "{\"token\":\"refreshed\"}" > ~/.claude/.credentials.json
    cat ~/.claude/.credentials.json
' 2>&1) || true
if echo "$OUTPUT" | grep -q 'refreshed'; then _pass "Credential file updateable (token refresh works)"
else _fail "Cannot update credential file" "$OUTPUT"; fi

# Write: project dir writable
OUTPUT=$(timeout 10 $SANDBOX_EXEC --backend bwrap --project-dir $PROJECT -- bash -c "touch $PROJECT/testfile && rm $PROJECT/testfile && echo OK" 2>&1) || true
if [[ "$OUTPUT" == "OK" ]]; then _pass "Project dir writable"
else _fail "Project dir not writable" "$OUTPUT"; fi

echo ""
echo "Additional tests: $PASS passed, $FAIL failed"
rm -rf $PROJECT
[[ $FAIL -eq 0 ]]
EXTRA
}

create_landlock_codepath_tests() {
    cat > "$SCRIPT_DIR/.docker-test-landlock-codepath.sh" <<'LLTEST'
#!/usr/bin/env bash
set -euo pipefail

source /repo/.docker-test-setup.sh

echo "Landlock code-path tests (no kernel support)"
echo ""

PASS=0
FAIL=0

_pass() { PASS=$((PASS+1)); echo "  ✓ $1"; }
_fail() { FAIL=$((FAIL+1)); echo "  ✗ $1"; [[ -n "${2:-}" ]] && echo "    $2"; }

# Test: --check correctly reports unavailable
OUTPUT=$(python3 ~/.claude/sandbox/backends/landlock-sandbox.py --check 2>&1) || true
if echo "$OUTPUT" | grep -q 'not available'; then
    _pass "landlock-sandbox.py --check correctly reports unavailable"
else
    _fail "--check gave unexpected output" "$OUTPUT"
fi

# Test: sandbox-exec --backend landlock fails gracefully
PROJECT_TMP=$(mktemp -d /home/testuser/ll-test-XXXXXX)
OUTPUT=$(~/.claude/sandbox/sandbox-exec.sh --backend landlock --project-dir $PROJECT_TMP -- echo test 2>&1) || true
rm -rf $PROJECT_TMP
if echo "$OUTPUT" | grep -qi 'not available\|not supported\|error'; then
    _pass "sandbox-exec --backend landlock fails gracefully"
else
    _fail "Did not fail gracefully" "$OUTPUT"
fi

# Test: auto-detection falls back to bwrap
PROJECT_TMP2=$(mktemp -d /home/testuser/ll-test-XXXXXX)
OUTPUT=$(~/.claude/sandbox/sandbox-exec.sh --dry-run --project-dir $PROJECT_TMP2 -- true 2>&1) || true
rm -rf $PROJECT_TMP2
if echo "$OUTPUT" | grep -q 'bubblewrap\|bwrap'; then
    _pass "Auto-detection falls back to bwrap"
else
    _fail "Did not fall back to bwrap" "$OUTPUT"
fi

# Test: argument parsing works
OUTPUT=$(python3 ~/.claude/sandbox/backends/landlock-sandbox.py --ro /usr --rw /tmp -- echo test 2>&1) || true
if echo "$OUTPUT" | grep -q 'not available\|not supported'; then
    _pass "Argument parsing works correctly"
else
    _fail "Unexpected error" "$OUTPUT"
fi

echo ""
echo "Code-path tests: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
LLTEST
}

# ── Create test scripts ──────────────────────────────────────────

create_setup_script
create_bwrap_extra_tests
create_landlock_codepath_tests

trap "rm -f '$SCRIPT_DIR/.docker-test-setup.sh' '$SCRIPT_DIR/.docker-test-bwrap-extra.sh' '$SCRIPT_DIR/.docker-test-landlock-codepath.sh'" EXIT

# ── Run tests ────────────────────────────────────────────────────

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║  Docker Test Suite                            ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

for version in "${VERSIONS[@]}"; do
    build_image "$version"

    # --- bwrap standard test suite ---
    echo "────────────────────────────────────────────────"
    echo "  Ubuntu $version / bwrap / standard test suite"
    echo "────────────────────────────────────────────────"
    if docker run --rm --privileged \
        -v "$SCRIPT_DIR/.docker-test-setup.sh:/repo/.docker-test-setup.sh:ro" \
        "sandbox-test:${version}" bash -c "
        source /repo/.docker-test-setup.sh
        bash ~/.claude/sandbox/test.sh --backend bwrap $VERBOSE
    " 2>&1; then
        echo "  ✓ Standard tests passed"
    else
        echo "  ✗ Standard tests failed"
        ((TOTAL_FAIL++))
    fi
    echo ""

    # --- bwrap additional tests ---
    echo "────────────────────────────────────────────────"
    echo "  Ubuntu $version / bwrap / additional tests"
    echo "────────────────────────────────────────────────"
    if docker run --rm --privileged \
        -v "$SCRIPT_DIR/.docker-test-setup.sh:/repo/.docker-test-setup.sh:ro" \
        -v "$SCRIPT_DIR/.docker-test-bwrap-extra.sh:/repo/.docker-test-bwrap-extra.sh:ro" \
        "sandbox-test:${version}" bash /repo/.docker-test-bwrap-extra.sh 2>&1; then
        ((TOTAL_PASS++))
        echo "  ✓ Ubuntu $version / bwrap: PASSED"
    else
        ((TOTAL_FAIL++))
        echo "  ✗ Ubuntu $version / bwrap: FAILED"
    fi
    echo ""

    # --- Landlock code-path tests ---
    echo "────────────────────────────────────────────────"
    echo "  Ubuntu $version / landlock / code-path tests"
    echo "────────────────────────────────────────────────"

    # Check if kernel supports Landlock
    landlock_check=$(docker run --rm --privileged --security-opt seccomp=unconfined "sandbox-test:${version}" \
        python3 /repo/backends/landlock-sandbox.py --check 2>&1) || true

    if echo "$landlock_check" | grep -q "not available"; then
        echo "  Landlock not available in Docker host kernel (expected on Docker Desktop)."
        echo "  Running code-path tests..."
        echo ""
        if docker run --rm --privileged \
            -v "$SCRIPT_DIR/.docker-test-setup.sh:/repo/.docker-test-setup.sh:ro" \
            -v "$SCRIPT_DIR/.docker-test-landlock-codepath.sh:/repo/.docker-test-landlock-codepath.sh:ro" \
            "sandbox-test:${version}" bash /repo/.docker-test-landlock-codepath.sh 2>&1; then
            ((TOTAL_PASS++))
            echo "  ✓ Ubuntu $version / landlock code-path: PASSED"
        else
            ((TOTAL_FAIL++))
            echo "  ✗ Ubuntu $version / landlock code-path: FAILED"
        fi
    else
        echo "  Landlock available: $landlock_check"
        echo "  Running full integration tests..."
        echo ""
        if docker run --rm --privileged --security-opt seccomp=unconfined \
            -v "$SCRIPT_DIR/.docker-test-setup.sh:/repo/.docker-test-setup.sh:ro" \
            "sandbox-test:${version}" bash -c "
            source /repo/.docker-test-setup.sh
            bash ~/.claude/sandbox/test.sh --backend landlock $VERBOSE
        " 2>&1; then
            ((TOTAL_PASS++))
            echo "  ✓ Ubuntu $version / landlock: PASSED"
        else
            ((TOTAL_FAIL++))
            echo "  ✗ Ubuntu $version / landlock: FAILED"
        fi
    fi
    echo ""
done

echo "════════════════════════════════════════════════"
echo "  Docker tests: $TOTAL_PASS passed, $TOTAL_FAIL failed"
echo "════════════════════════════════════════════════"

if [[ $TOTAL_FAIL -gt 0 ]]; then
    exit 1
fi

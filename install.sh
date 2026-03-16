#!/usr/bin/env bash
# install.sh — Set up the sandbox for Claude Code
#
# What this script does:
#   1. Detects available sandbox backends (bwrap, firejail, landlock)
#   2. Installs bubblewrap via Homebrew if needed (and available)
#   3. Copies sandbox scripts to ~/.claude/sandbox/
#   4. Creates a default sandbox.conf (won't overwrite yours)
#   5. Installs sandbox-claude.md (agent instructions, only visible inside sandbox)
#   6. Runs the test suite to verify everything works
#
# Usage:
#   git clone git@github.com:settylab/agent_sandbox.git
#   bash agent_sandbox/install.sh
#   bash agent_sandbox/install.sh --no-test

set -euo pipefail

SKIP_TEST=false
for arg in "$@"; do
    case "$arg" in
        --no-test|--skip-test) SKIP_TEST=true ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$HOME/.claude/sandbox"

echo "╔═══════════════════════════════════════════════╗"
echo "║  Sandbox Installer                            ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# ── Step 1: Detect / install backends ────────────────────────────

AVAILABLE_BACKENDS=()
BWRAP_BLOCKED=false

# Check bwrap
if command -v bwrap &>/dev/null; then
    if bwrap --ro-bind / / true 2>/dev/null; then
        AVAILABLE_BACKENDS+=(bwrap)
        echo "✓ bubblewrap available: $(bwrap --version)"
    else
        BWRAP_BLOCKED=true
        echo "⚠ bubblewrap installed but cannot create namespaces"
        if [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]] \
           && [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" == "1" ]]; then
            BWRAP_PATH="$(command -v bwrap)"
            echo "  AppArmor restricts unprivileged user namespaces on this system."
            echo ""
            echo "  To enable bwrap, ask your sysadmin to apply ONE of these fixes:"
            echo ""
            echo "  Option 1 — AppArmor profile for bwrap (recommended, scoped):"
            echo "    Create /etc/apparmor.d/bwrap with:"
            echo ""
            echo "      abi <abi/4.0>,"
            echo "      include <tunables/global>"
            echo "      profile bwrap $BWRAP_PATH flags=(unconfined) {"
            echo "        userns,"
            echo "      }"
            echo ""
            echo "    Then: sudo apparmor_parser -r /etc/apparmor.d/bwrap"
            echo ""
            echo "  Option 2 — Disable the restriction globally (easier, broader):"
            echo "    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
            echo ""
        elif [[ -f /proc/sys/kernel/unprivileged_userns_clone ]] \
             && [[ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" != "1" ]]; then
            echo "  Unprivileged user namespaces are disabled."
            echo "  Ask your sysadmin: sudo sysctl -w kernel.unprivileged_userns_clone=1"
        fi
    fi
elif command -v brew &>/dev/null; then
    echo "→ Installing bubblewrap via Homebrew..."
    brew install bubblewrap
    if bwrap --ro-bind / / true 2>/dev/null; then
        AVAILABLE_BACKENDS+=(bwrap)
        echo "  ✓ bubblewrap installed: $(bwrap --version)"
    else
        echo "  ⚠ bubblewrap installed but cannot create namespaces"
    fi
fi

# Check firejail
if command -v firejail &>/dev/null; then
    if firejail --noprofile --quiet -- true 2>/dev/null; then
        AVAILABLE_BACKENDS+=(firejail)
        echo "✓ firejail available: $(firejail --version 2>&1 | head -1)"
    fi
fi

# Check Landlock
if [[ "$(uname -s)" == "Linux" ]] && command -v python3 &>/dev/null; then
    if python3 "$SCRIPT_DIR/backends/landlock-sandbox.py" --check 2>/dev/null; then
        AVAILABLE_BACKENDS+=(landlock)
        LANDLOCK_ABI=$(python3 "$SCRIPT_DIR/backends/landlock-sandbox.py" --check 2>/dev/null)
        echo "✓ Landlock available: $LANDLOCK_ABI"
    fi
fi

if [[ ${#AVAILABLE_BACKENDS[@]} -eq 0 ]]; then
    echo ""
    echo "ERROR: No sandbox backend available."
    echo ""
    echo "  Options:"
    echo "    1. Install bubblewrap: brew install bubblewrap"
    echo "    2. Install firejail: sudo apt install firejail"
    echo "    3. Use a Linux kernel ≥ 5.13 with Landlock enabled"
    echo ""
    exit 1
fi

echo ""
echo "  Available backends: ${AVAILABLE_BACKENDS[*]}"
echo "  (sandbox-exec.sh auto-selects the best one at runtime)"

# ── Step 2: Copy scripts ───────────────────────────────────────

echo ""
echo "→ Installing sandbox scripts to $SANDBOX_DIR/"

mkdir -p "$SANDBOX_DIR/bin"
mkdir -p "$SANDBOX_DIR/backends"
mkdir -p "$SANDBOX_DIR/chaperon/handlers"
mkdir -p "$SANDBOX_DIR/chaperon/stubs"

for file in sandbox-lib.sh sandbox-exec.sh sbatch-sandbox.sh srun-sandbox.sh sandbox-claude.md sandbox-settings.json sandbox-tmux.conf test.sh; do
    cp "$SCRIPT_DIR/$file" "$SANDBOX_DIR/$file"
done

for file in sbatch srun scancel tmux; do
    cp "$SCRIPT_DIR/bin/$file" "$SANDBOX_DIR/bin/$file"
done

for file in bwrap.sh firejail.sh landlock.sh landlock-sandbox.py generate-seccomp.py; do
    cp "$SCRIPT_DIR/backends/$file" "$SANDBOX_DIR/backends/$file"
done

# Chaperon: secure Slurm proxy
for file in chaperon.sh protocol.sh; do
    cp "$SCRIPT_DIR/chaperon/$file" "$SANDBOX_DIR/chaperon/$file"
done
for file in "$SCRIPT_DIR"/chaperon/handlers/*.sh; do
    cp "$file" "$SANDBOX_DIR/chaperon/handlers/"
done
for file in "$SCRIPT_DIR"/chaperon/stubs/*; do
    cp "$file" "$SANDBOX_DIR/chaperon/stubs/"
done

chmod +x "$SANDBOX_DIR/sandbox-exec.sh"
chmod +x "$SANDBOX_DIR/sbatch-sandbox.sh"
chmod +x "$SANDBOX_DIR/srun-sandbox.sh"
chmod +x "$SANDBOX_DIR/test.sh"
chmod +x "$SANDBOX_DIR/bin/sbatch"
chmod +x "$SANDBOX_DIR/bin/srun"
chmod +x "$SANDBOX_DIR/bin/scancel"
chmod +x "$SANDBOX_DIR/bin/tmux"
chmod +x "$SANDBOX_DIR/chaperon/chaperon.sh"
chmod +x "$SANDBOX_DIR"/chaperon/stubs/*
# Re-protect library files that shouldn't be directly executed
chmod -x "$SANDBOX_DIR"/chaperon/stubs/_stub_lib.sh 2>/dev/null || true

echo "  ✓ Scripts installed"

# ── Step 3: Config file ────────────────────────────────────────

if [[ -f "$SANDBOX_DIR/sandbox.conf" ]]; then
    echo "  ✓ sandbox.conf already exists (not overwriting)"
    echo "    Compare with latest: diff $SANDBOX_DIR/sandbox.conf $SCRIPT_DIR/sandbox.conf"
else
    cp "$SCRIPT_DIR/sandbox.conf" "$SANDBOX_DIR/sandbox.conf"
    echo "  ✓ Created sandbox.conf — edit to customize permissions"
fi

# ── Step 4: Agent awareness ─────────────────────────────────────

echo "  ✓ Agent instructions installed (sandbox-claude.md)"
echo "    Only visible to the agent when running inside the sandbox."
echo "    Edit $SANDBOX_DIR/sandbox-claude.md to customize."

# ── Step 5: Test suite ─────────────────────────────────────────

if [[ "$SKIP_TEST" == true ]]; then
    echo ""
    echo "  Skipping test suite (--no-test)"
else
    echo ""
    echo "→ Running quick smoke test..."
    echo ""

    if ! bash "$SANDBOX_DIR/test.sh" --quick; then
        echo ""
        echo "⚠ Some tests failed. Run 'bash $SANDBOX_DIR/test.sh --verbose' for details."
        exit 1
    fi

    echo ""
    echo "  For the full test suite (submits real Slurm jobs):"
    echo "    bash $SANDBOX_DIR/test.sh"
fi

# ── Step 6: Suggest shell alias ───────────────────────────────────

ALIAS_LINE="alias agent-sandbox='~/.claude/sandbox/sandbox-exec.sh -- claude'"
ALIAS_ALREADY=false

for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.dotfiles/.bashrc" "$HOME/.dotfiles/.zshrc"; do
    if [[ -f "$rc" ]] && grep -qF "agent-sandbox" "$rc" 2>/dev/null; then
        ALIAS_ALREADY=true
        break
    fi
done

echo ""
echo "════════════════════════════════════════════════"
echo "  Installation complete! (backends: ${AVAILABLE_BACKENDS[*]})"
echo ""
echo "  Start Claude Code in a sandbox:"
echo "    cd /your/project/dir"
echo "    ~/.claude/sandbox/sandbox-exec.sh -- claude"
echo ""
echo "  Customize permissions:"
echo "    \$EDITOR ~/.claude/sandbox/sandbox.conf"

if [[ "$ALIAS_ALREADY" == false ]]; then
    echo ""
    echo "  ── Optional: add a shell alias ──"
    echo ""
    echo "  For quick access, add this to your shell rc file:"
    echo ""
    echo "    $ALIAS_LINE"
    echo ""
    echo "  Then you can just run:  agent-sandbox"
fi
echo "════════════════════════════════════════════════"

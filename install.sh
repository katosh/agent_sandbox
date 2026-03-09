#!/usr/bin/env bash
# install.sh — Set up the sandbox for Claude Code
#
# What this script does:
#   1. Detects available sandbox backend (bwrap or landlock)
#   2. Installs bubblewrap via Homebrew if needed (and available)
#   3. Copies sandbox scripts to ~/.claude/sandbox/
#   4. Creates a default sandbox.conf (won't overwrite yours)
#   5. Installs sandbox-claude.md (agent instructions, only visible inside sandbox)
#   6. Runs the test suite to verify everything works
#
# Usage:
#   git clone git@github.com:settylab/agent_container.git
#   bash agent_container/install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$HOME/.claude/sandbox"

echo "╔═══════════════════════════════════════════════╗"
echo "║  Sandbox Installer                            ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# ── Step 1: Detect / install backend ─────────────────────────────

DETECTED_BACKEND=""
BWRAP_AVAILABLE=false
LANDLOCK_AVAILABLE=false

# Check bwrap
if command -v bwrap &>/dev/null; then
    if bwrap --ro-bind / / true 2>/dev/null; then
        BWRAP_AVAILABLE=true
        echo "✓ bubblewrap available: $(bwrap --version)"
    else
        echo "⚠ bubblewrap installed but cannot create namespaces"
        # Check why
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
        BWRAP_AVAILABLE=true
        echo "  ✓ bubblewrap installed: $(bwrap --version)"
    else
        echo "  ⚠ bubblewrap installed but cannot create namespaces"
    fi
fi

# Check Landlock
if [[ "$(uname -s)" == "Linux" ]] && command -v python3 &>/dev/null; then
    if python3 "$SCRIPT_DIR/backends/landlock-sandbox.py" --check 2>/dev/null; then
        LANDLOCK_AVAILABLE=true
        LANDLOCK_ABI=$(python3 "$SCRIPT_DIR/backends/landlock-sandbox.py" --check 2>/dev/null)
        echo "✓ Landlock available: $LANDLOCK_ABI"
    fi
fi

# Select backend
if [[ "$BWRAP_AVAILABLE" == true ]]; then
    DETECTED_BACKEND=bwrap
elif [[ "$LANDLOCK_AVAILABLE" == true ]]; then
    DETECTED_BACKEND=landlock
    echo ""
    echo "→ Using Landlock backend (bwrap not available)"
    echo "  Note: Landlock blocks access with EACCES instead of hiding paths (ENOENT)."
    echo "  Functionally equivalent for security — the agent cannot read blocked files."
else
    echo ""
    echo "ERROR: No sandbox backend available."
    echo ""
    echo "  Options:"
    echo "    1. Install bubblewrap: brew install bubblewrap"
    echo "    2. Use a Linux kernel ≥ 5.13 with Landlock enabled"
    echo ""
    exit 1
fi

echo ""
echo "  Selected backend: $DETECTED_BACKEND"

# ── Step 2: Copy scripts ───────────────────────────────────────

echo ""
echo "→ Installing sandbox scripts to $SANDBOX_DIR/"

mkdir -p "$SANDBOX_DIR/bin"
mkdir -p "$SANDBOX_DIR/backends"

for file in sandbox-lib.sh sandbox-exec.sh bwrap-sandbox.sh sbatch-sandbox.sh srun-sandbox.sh sandbox-claude.md sandbox-settings.json test.sh; do
    cp "$SCRIPT_DIR/$file" "$SANDBOX_DIR/$file"
done

for file in sbatch srun; do
    cp "$SCRIPT_DIR/bin/$file" "$SANDBOX_DIR/bin/$file"
done

for file in bwrap.sh landlock.sh landlock-sandbox.py; do
    cp "$SCRIPT_DIR/backends/$file" "$SANDBOX_DIR/backends/$file"
done

chmod +x "$SANDBOX_DIR/sandbox-exec.sh"
chmod +x "$SANDBOX_DIR/bwrap-sandbox.sh"
chmod +x "$SANDBOX_DIR/sbatch-sandbox.sh"
chmod +x "$SANDBOX_DIR/srun-sandbox.sh"
chmod +x "$SANDBOX_DIR/test.sh"
chmod +x "$SANDBOX_DIR/bin/sbatch"
chmod +x "$SANDBOX_DIR/bin/srun"

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

echo ""
echo "→ Running test suite..."
echo ""

if ! bash "$SANDBOX_DIR/test.sh" --backend "$DETECTED_BACKEND"; then
    echo ""
    echo "⚠ Some tests failed. Run 'bash $SANDBOX_DIR/test.sh --backend $DETECTED_BACKEND --verbose' for details."
    exit 1
fi

# ── Step 6: Suggest shell alias ───────────────────────────────────

ALIAS_LINE="alias claude-sandbox='~/.claude/sandbox/sandbox-exec.sh -- claude'"
ALIAS_ALREADY=false

for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.dotfiles/.bashrc" "$HOME/.dotfiles/.zshrc"; do
    if [[ -f "$rc" ]] && grep -qF "claude-sandbox" "$rc" 2>/dev/null; then
        ALIAS_ALREADY=true
        break
    fi
done

echo ""
echo "════════════════════════════════════════════════"
echo "  Installation complete! (backend: $DETECTED_BACKEND)"
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
    echo "  Then you can just run:  claude-sandbox"
fi
echo "════════════════════════════════════════════════"

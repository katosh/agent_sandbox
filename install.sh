#!/usr/bin/env bash
# install.sh — Set up the bubblewrap sandbox for Claude Code
#
# What this script does:
#   1. Installs bubblewrap via Homebrew (if missing)
#   2. Copies sandbox scripts to ~/.claude/sandbox/
#   3. Creates a default sandbox.conf (won't overwrite yours)
#   4. Installs sandbox-claude.md (agent instructions, only visible inside sandbox)
#   5. Runs the test suite to verify everything works
#
# Usage:
#   git clone git@github.com:settylab/agent_container.git
#   bash agent_container/install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$HOME/.claude/sandbox"

echo "╔═══════════════════════════════════════════════╗"
echo "║  Bubblewrap Sandbox Installer                 ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# ── Step 1: Homebrew + bubblewrap ───────────────────────────────

if ! command -v brew &>/dev/null; then
    echo "ERROR: Homebrew (Linuxbrew) not found."
    echo ""
    echo "Install it first:"
    echo '  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
    echo ""
    echo "Then add it to your PATH and re-run this script."
    exit 1
fi

if ! command -v bwrap &>/dev/null; then
    echo "→ Installing bubblewrap via Homebrew..."
    brew install bubblewrap
    echo "  ✓ bubblewrap installed: $(bwrap --version)"
else
    echo "✓ bubblewrap already installed: $(bwrap --version)"
fi

# Verify kernel supports user namespaces
if [[ -f /proc/sys/kernel/unprivileged_userns_clone ]]; then
    if [[ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" != "1" ]]; then
        echo "WARNING: Unprivileged user namespaces are disabled on this kernel."
        echo "  bwrap may not work. Ask your sysadmin to run:"
        echo "    sudo sysctl -w kernel.unprivileged_userns_clone=1"
    fi
fi

# Check for AppArmor restriction on unprivileged user namespaces
# Ubuntu 24.04+ restricts userns even when unprivileged_userns_clone=1
if [[ -f /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
    if [[ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns)" == "1" ]]; then
        BWRAP_PATH="$(command -v bwrap)"
        echo ""
        echo "WARNING: AppArmor restricts unprivileged user namespaces on this system."
        echo "  Ubuntu 24.04+ enables kernel.apparmor_restrict_unprivileged_userns=1"
        echo "  by default, which blocks bwrap even when unprivileged_userns_clone=1."
        echo ""
        echo "  bwrap will fail with: 'setting up uid map: Permission denied'"
        echo ""
        echo "  Ask your sysadmin to apply ONE of these fixes:"
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
        echo "    # To persist: echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-userns.conf"
        echo ""
    fi
fi

# ── Step 2: Copy scripts ───────────────────────────────────────

echo ""
echo "→ Installing sandbox scripts to $SANDBOX_DIR/"

mkdir -p "$SANDBOX_DIR/bin"

for file in sandbox-lib.sh bwrap-sandbox.sh sbatch-sandbox.sh srun-sandbox.sh sandbox-claude.md sandbox-settings.json test.sh; do
    cp "$SCRIPT_DIR/$file" "$SANDBOX_DIR/$file"
done

for file in sbatch srun; do
    cp "$SCRIPT_DIR/bin/$file" "$SANDBOX_DIR/bin/$file"
done

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
# The sandbox dynamically overlays CLAUDE.md with sandbox instructions
# at startup (via sandbox-lib.sh). No modification to the user's
# CLAUDE.md is needed — the agent only sees the instructions when
# running inside the sandbox.

echo "  ✓ Agent instructions installed (sandbox-claude.md)"
echo "    Only visible to the agent when running inside the sandbox."
echo "    Edit $SANDBOX_DIR/sandbox-claude.md to customize."

# ── Step 5: Test suite ─────────────────────────────────────────

echo ""
echo "→ Running test suite..."
echo ""

if ! bash "$SANDBOX_DIR/test.sh"; then
    echo ""
    echo "⚠ Some tests failed. Run 'bash $SANDBOX_DIR/test.sh --verbose' for details."
    exit 1
fi

# ── Step 6: Suggest shell alias ───────────────────────────────────

ALIAS_LINE="alias claude-sandbox='~/.claude/sandbox/bwrap-sandbox.sh -- claude'"
ALIAS_ALREADY=false

# Check common shell rc files
for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.dotfiles/.bashrc" "$HOME/.dotfiles/.zshrc"; do
    if [[ -f "$rc" ]] && grep -qF "claude-sandbox" "$rc" 2>/dev/null; then
        ALIAS_ALREADY=true
        break
    fi
done

echo ""
echo "════════════════════════════════════════════════"
echo "  Installation complete!"
echo ""
echo "  Start Claude Code in a sandbox:"
echo "    cd /your/project/dir"
echo "    ~/.claude/sandbox/bwrap-sandbox.sh -- claude"
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

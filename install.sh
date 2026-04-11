#!/usr/bin/env bash
# install.sh — Set up the sandbox for AI coding agents
#
# What this script does:
#   1. Detects available sandbox backends (bwrap, firejail, landlock)
#   2. Checks for sandbox backends (bwrap, firejail, landlock)
#   3. Copies sandbox scripts to ~/.config/agent-sandbox/
#   4. Installs agent profiles (Claude, Codex, Gemini, Aider, OpenCode)
#   5. Creates a default sandbox.conf (won't overwrite yours)
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
        -h|--help)
            cat <<'HELP'
Usage: bash install.sh [OPTIONS]

Options:
  --no-test, --skip-test    Skip the post-install test suite
  -h, --help                Show this help

What this script does:
  1. Checks for sandbox backends (bwrap, firejail, landlock)
  2. Copies all sandbox scripts to ~/.config/agent-sandbox/
  3. Installs agent profiles (Claude, Codex, Gemini, Aider, OpenCode)
  4. Creates sandbox.conf if it doesn't exist (never overwrites yours)
  6. Creates conf.d/ for per-project overrides
  7. Runs a quick smoke test to verify everything works

Files installed:
  ~/.config/agent-sandbox/sandbox-exec.sh    Main entry point
  ~/.config/agent-sandbox/sandbox.conf       Your permissions config
  ~/.config/agent-sandbox/test.sh            Test suite
  ~/.config/agent-sandbox/agents/            Agent profiles (auto-detected)
  ~/.config/agent-sandbox/chaperon/          Slurm proxy (14 handlers, 19 stubs)
  ~/.config/agent-sandbox/backends/          bwrap, firejail, landlock backends
  ~/.config/agent-sandbox/bin/               PATH-shadowing fallback scripts

Updating:
  Re-run install.sh to update scripts. Your sandbox.conf is preserved.
  Review new options:  diff ~/.config/agent-sandbox/sandbox.conf /path/to/repo/sandbox.conf

Examples:
  bash install.sh                # install + test
  bash install.sh --no-test      # install only (faster)
HELP
            exit 0
            ;;
        --no-test|--skip-test) SKIP_TEST=true ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_DIR="$HOME/.config/agent-sandbox"

echo "╔═══════════════════════════════════════════════╗"
echo "║  Sandbox Installer                            ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""

# ── Step 1: Detect / install backends ────────────────────────────

AVAILABLE_BACKENDS=()
BWRAP_BLOCKED=false

# Check bwrap
if command -v bwrap &>/dev/null; then
    _bwrap_ver=$(bwrap --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' || echo "0.0.0")
    _bwrap_major=${_bwrap_ver%%.*}
    _bwrap_rest=${_bwrap_ver#*.}
    _bwrap_minor=${_bwrap_rest%%.*}
    _bwrap_too_old=false
    if (( _bwrap_major == 0 && _bwrap_minor < 4 )); then
        _bwrap_too_old=true
    fi

    if "$_bwrap_too_old"; then
        echo "⚠ bubblewrap ${_bwrap_ver} is too old (need ≥ 0.4.0 for --chmod, --unsetenv)"
        echo "  Install a newer version: https://github.com/containers/bubblewrap/releases"
        echo "  Or use Homebrew: brew install bubblewrap"
    elif bwrap --ro-bind / / true 2>/dev/null; then
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
            echo "  Ask your sysadmin to create /etc/apparmor.d/bwrap-sandbox with:"
            echo ""
            echo "    abi <abi/4.0>,"
            echo "    include <tunables/global>"
            echo "    profile bwrap-sandbox $BWRAP_PATH flags=(unconfined) {"
            echo "      userns,"
            echo "    }"
            echo ""
            echo "  Then: sudo apparmor_parser -r /etc/apparmor.d/bwrap-sandbox"
            echo ""
        elif [[ -f /proc/sys/kernel/unprivileged_userns_clone ]] \
             && [[ "$(cat /proc/sys/kernel/unprivileged_userns_clone)" != "1" ]]; then
            echo "  Unprivileged user namespaces are disabled."
            echo "  Ask your sysadmin: sudo sysctl -w kernel.unprivileged_userns_clone=1"
        fi
    fi
else
    echo "· bubblewrap not found"
    echo "  bwrap provides the strongest sandbox (mount namespace, PID namespace)."
    echo "  Install options:"
    echo "    System-wide (recommended):  sudo apt install bubblewrap"
    echo "    User-local (no root):       brew install bubblewrap"
    echo "    From source:                https://github.com/containers/bubblewrap"
    echo ""
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
    echo "  Install one of these (in order of recommendation):"
    echo ""
    echo "  1. bubblewrap (strongest — mount + PID namespace, unprivileged):"
    echo "     sudo apt install bubblewrap        # Debian/Ubuntu"
    echo "     sudo dnf install bubblewrap        # RHEL/Fedora"
    echo "     brew install bubblewrap            # user-local, no root"
    echo ""
    echo "  2. firejail (strong — setuid root binary, works without user namespaces):"
    echo "     sudo apt install firejail          # Debian/Ubuntu"
    echo ""
    echo "  3. Landlock (weakest — kernel ≥ 5.13 with CONFIG_SECURITY_LANDLOCK):"
    echo "     No install needed, but your kernel may not support it."
    echo ""
    if "$BWRAP_BLOCKED"; then
        echo "  Note: bwrap IS installed but cannot create namespaces."
        echo "  See the instructions above to fix this."
        echo ""
    fi
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
mkdir -p "$SANDBOX_DIR/conf.d"

for file in sandbox-lib.sh sandbox-exec.sh sbatch-sandbox.sh srun-sandbox.sh sandbox-tmux.conf test.sh; do
    cp "$SCRIPT_DIR/$file" "$SANDBOX_DIR/$file"
done

for file in "$SCRIPT_DIR"/bin/*; do
    cp "$file" "$SANDBOX_DIR/bin/"
done

for file in bwrap.sh firejail.sh landlock.sh landlock-sandbox.py generate-seccomp.py; do
    cp "$SCRIPT_DIR/backends/$file" "$SANDBOX_DIR/backends/$file"
done

# Agent profiles
if [[ -d "$SCRIPT_DIR/agents" ]]; then
    for agent_dir in "$SCRIPT_DIR"/agents/*/; do
        [[ -d "$agent_dir" ]] || continue
        local_agent="$(basename "$agent_dir")"
        mkdir -p "$SANDBOX_DIR/agents/$local_agent"
        for file in "$agent_dir"*; do
            [[ -f "$file" ]] || continue
            cp "$file" "$SANDBOX_DIR/agents/$local_agent/"
        done
        # Clean up stale files from previous installs (home.conf, hide.conf,
        # env.conf were merged into config.conf)
        for _stale in home.conf hide.conf env.conf; do
            rm -f "$SANDBOX_DIR/agents/$local_agent/$_stale" 2>/dev/null || true
        done
    done
    echo "  ✓ Agent profiles installed ($(ls -d "$SANDBOX_DIR"/agents/*/ 2>/dev/null | wc -l) agents)"
fi

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

# Copy example conf.d files (don't overwrite user customizations)
for file in "$SCRIPT_DIR"/conf.d/*.conf; do
    [[ -f "$file" ]] || continue
    local_name="$(basename "$file")"
    if [[ ! -f "$SANDBOX_DIR/conf.d/$local_name" ]]; then
        cp "$file" "$SANDBOX_DIR/conf.d/$local_name"
    fi
done

chmod +x "$SANDBOX_DIR/sandbox-exec.sh"
chmod +x "$SANDBOX_DIR/sbatch-sandbox.sh"
chmod +x "$SANDBOX_DIR/srun-sandbox.sh"
chmod +x "$SANDBOX_DIR/test.sh"
chmod +x "$SANDBOX_DIR"/bin/*
chmod +x "$SANDBOX_DIR/chaperon/chaperon.sh"
chmod +x "$SANDBOX_DIR"/chaperon/stubs/*
# Re-protect library files that shouldn't be directly executed
chmod -x "$SANDBOX_DIR"/chaperon/stubs/_stub_lib.sh 2>/dev/null || true

echo "  ✓ Scripts installed"

# ── Step 3: Config file ────────────────────────────────────────

if [[ -f "$SANDBOX_DIR/sandbox.conf" ]]; then
    echo "  ✓ sandbox.conf already exists (not overwriting)"
    echo "    Review new options:  diff $SANDBOX_DIR/sandbox.conf $SCRIPT_DIR/sandbox.conf"
else
    cp "$SCRIPT_DIR/sandbox.conf" "$SANDBOX_DIR/sandbox.conf"
    echo "  ✓ Created sandbox.conf — edit to customize permissions"
fi

# ── Step 4: Agent awareness ─────────────────────────────────────

echo "  ✓ Agent profiles installed (auto-detected at sandbox start)"
echo "    Profiles: $(ls "$SANDBOX_DIR/agents/" 2>/dev/null | tr '\n' ' ')"
echo "    Edit agent instructions: $SANDBOX_DIR/agents/<name>/agent.md"

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
fi

# ── Step 6: Suggest shell alias ───────────────────────────────────

ALIAS_LINE="alias agent-sandbox='~/.config/agent-sandbox/sandbox-exec.sh --'"
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
echo "  Start an agent in the sandbox:"
echo "    cd /your/project/dir"
echo "    ~/.config/agent-sandbox/sandbox-exec.sh -- claude"
echo "    ~/.config/agent-sandbox/sandbox-exec.sh -- codex"
echo "    ~/.config/agent-sandbox/sandbox-exec.sh -- gemini"
echo ""
echo "  Customize permissions:"
echo "    \$EDITOR ~/.config/agent-sandbox/sandbox.conf"

if [[ "$ALIAS_ALREADY" == false ]]; then
    echo ""
    echo "  ── Optional: add a shell alias ──"
    echo ""
    echo "  For quick access, add this to your shell rc file:"
    echo ""
    echo "    $ALIAS_LINE"
    echo ""
    echo "  Then you can just run:  agent-sandbox claude"
fi
echo "════════════════════════════════════════════════"

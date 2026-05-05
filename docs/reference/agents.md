# Agents

The sandbox supports a growing set of AI coding agents. Each one lives in `agents/<name>/` and is enabled per-user via the `ENABLED_AGENTS` array in `sandbox.conf`. Disabled agents contribute nothing to the sandbox surface — their config dirs stay invisible, so e.g. `~/.pi` doesn't become writable for users who don't run pi.

**Built-in profiles:**

| Agent | Default | Auth dir | Notes |
|-------|---------|----------|-------|
| `claude` | enabled | `~/.claude`, `~/.claude.json`, `~/.local/{state,share}/claude` | OAuth or `ANTHROPIC_API_KEY` |
| `codex` | enabled | `~/.codex` | OAuth (`codex login`) or `OPENAI_API_KEY` |
| `gemini` | enabled | `~/.gemini` | Google OAuth or `GOOGLE_API_KEY` |
| `aider` | **disabled** | (none — env-var only) | Opt-in: `ENABLED_AGENTS+=("aider")` |
| `opencode` | **disabled** | `~/.config/opencode` + `~/.local/{share,state}/opencode` + `~/.cache/opencode` | Opt-in: `ENABLED_AGENTS+=("opencode")` |
| `pi` | **disabled** | `~/.pi/agent` | Opt-in: `ENABLED_AGENTS+=("pi")` |

The default set is conservative on purpose — every enabled agent expands the writable surface to whatever its `config.conf` declares, so dotdir names that could plausibly belong to unrelated user data (`~/.pi`, `~/.config/opencode`, etc.) stay invisible until you opt in.

**Enabling and disabling agents:** edit `ENABLED_AGENTS` in `sandbox.conf`. Adding a name folds that agent's declared writable/readable/blocked paths into the sandbox surface and runs its instruction-merging overlay; removing a name leaves the agent's paths invisible (no auth persistence, no AGENTS.md hide).

```bash
# Enable pi alongside the defaults:
ENABLED_AGENTS+=("pi")

# Or replace the whole list (e.g. solo-claude profile):
ENABLED_AGENTS=("claude")
```

**How a profile is structured:** each `agents/<name>/` directory contains:

| File | Purpose |
|------|---------|
| `config.conf` | Declarative metadata. Lists the writable/readable paths the agent needs, files to hide (real `AGENTS.md` / `CLAUDE.md` so the sandbox-merged copy wins), env vars used for auth, and auth-marker files. When the agent is enabled, these declarations are folded into `HOME_WRITABLE` / `HOME_READONLY` / `BLOCKED_FILES` automatically. |
| `overlay.sh` | Runs at sandbox start (only for enabled agents). Merges `AGENTS.md` (or `CLAUDE.md`) with the sandbox-integrity snippet from `agent.md` into a `sandbox-config/` dir, then exports an env var like `CLAUDE_CONFIG_DIR` / `CODEX_HOME` / `OPENCODE_CONFIG_DIR` / `PI_CODING_AGENT_DIR` so the agent reads from there instead of its real config dir. Runs in a subshell with a guardrail — cannot mutate permission globals. |
| `agent.md` | The sandbox-integrity instruction snippet. Customize per user via `~/.config/agent-sandbox/agents/<name>/agent.md`. |

**Agent API keys are allowed by default** — `ALLOWED_ENV_VARS` in `sandbox.conf` includes `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `CODEX_API_KEY`, and `GOOGLE_API_KEY` so agents that use env-var auth work on first launch. Comment out any entry to block that key.

**Auth persists across sessions** for enabled agents: their declared writable paths survive sandbox exit, and missing directories are auto-created before sandbox start so first-time in-sandbox auth works even if the agent has never been run outside.

**Silencing warnings:** set `SUPPRESS_AGENT_WARNINGS=("claude")` in `sandbox.conf` to silence one agent, or `SUPPRESS_AGENT_WARNINGS=("all")` to silence every agent.

### Adding support for a new agent

To add a tool not on the list above, drop a profile into `agents/<name>/` and add `"<name>"` to `ENABLED_AGENTS`. The recipe:

1. **Find the agent's auth/config dir.** Most CLI agents keep credentials and history under a single dotdir (`~/.toolname` or `~/.config/toolname`). Check the tool's docs or strace the binary on first launch. Note all dirs the tool writes to — some use multiple XDG paths (config, data, cache, state).

2. **Find the agent's instruction file** (if any) and an env var that overrides the agent's config dir. Most modern agents support one (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `OPENCODE_CONFIG_DIR`, `PI_CODING_AGENT_DIR`). The sandbox uses this to point the agent at a sandbox-merged copy of `AGENTS.md` / `CLAUDE.md` so sandbox-integrity instructions are authoritative.

3. **Write `agents/<name>/config.conf`** declaring what the agent needs:
   ```bash
   AGENT_CREDENTIAL_ENV_VARS=("MYTOOL_API_KEY")     # for warning when blocked
   AGENT_AUTH_MARKERS=("$HOME/.mytool/auth.json")   # exists ⇒ "authenticated"
   AGENT_REQUIRED_WRITABLE_PATHS=("$HOME/.mytool")  # auto-folded into HOME_WRITABLE
   AGENT_REQUIRED_READABLE_PATHS=()                 # auto-folded into HOME_READONLY
   AGENT_BLOCKED_FILES=("$HOME/.mytool/AGENTS.md")  # auto-folded into BLOCKED_FILES
   AGENT_LOGIN_HINT="run 'mytool login' inside the sandbox"
   ```

4. **Write `agents/<name>/overlay.sh`** modeled on an existing one (codex is the simplest example) — merge instructions into a `sandbox-config/` dir and export the agent's config-dir env var via `_AGENT_ENV_EXPORTS+=(...)`.

5. **Copy `agents/<name>/agent.md`** from another agent (the wording is generic). Customize if you want different sandbox-integrity messaging for this tool.

6. **Add `"<name>"` to `ENABLED_AGENTS`** in `sandbox.conf` and run the agent — first-time auth and config dirs are auto-created.

The `agents/pi/` profile is a complete worked example for a single-binary CLI agent with one config dir and an env-var override; copy it as a starting point.

## Agent Teams / tmux

The outer tmux socket is blocked (escape risk), but a **nested tmux** running inside the sandbox works well: `agent-sandbox tmux new-session claude` (prefix is `Ctrl-a`). On kernels < 5.4, add `DEVICES+=(/dev/pts)` to `sandbox.conf` for pty allocation (see Known Limitations). Customize via `~/.config/agent-sandbox/sandbox-tmux.conf`.

### Notifications

The sandbox ships `sandbox-notify` (in `bin/`, on PATH) which alerts the user via tmux when an agent needs attention or finishes a turn. It emits a single terminal BEL and lets tmux's own propagation flag both the inner and outer status bars — `monitor-bell` on + `bell-action any` (tmux defaults) means a BEL from an inner pane is forwarded to the client's pty automatically, so one emission marks both nested tmux tabs.

Emission is best-effort and tries two paths:

1. **`/dev/tty`** — for interactive shells and any process that inherited a controlling terminal.
2. **`tmux new-window -d -n '•bell' 'printf "\a"'`** — IPC fallback for agent subprocesses (Claude Code's Bash tool, for example) that have no controlling terminal. The ephemeral window's BEL rides the same tmux bell-action chain. No chaperon relay needed.

For Claude Code, hooks are auto-configured via the settings.json overlay: the `Notification` event (agent needs attention) and `Stop` event (agent finished a turn) both trigger `sandbox-notify`, so the user sees tmux tab alerts without any manual setup. Other agents can call `sandbox-notify "message"` directly.


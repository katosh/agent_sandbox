# Admin Hardening Options

The [sandbox](README.md) is fully user-space — no root or admin involvement needed. Both backends (bubblewrap and Landlock) provide kernel-enforced filesystem isolation for AI coding agents, with Slurm job wrapping as a default-on soft boundary.

This document describes **independent improvements** that could close remaining gaps. Each section is self-contained and can be evaluated against your site's threat model and effort budget. They are ordered roughly from least to most effort.

> **Our priority:** Section 1 (Admin-Managed Slurm Wrappers) is the improvement we'd most like to see. It closes the main gap in the current setup — Slurm PATH shadowing — with moderate admin effort and no workflow changes for users.

### Self-serve vs. admin-enforced

Each improvement falls into one of two categories:

- **Self-serve** — makes it easier for users to sandbox their agents correctly. Works when users follow the setup. Does not prevent a user (or their agent) from bypassing the protection if they try.
- **Admin-enforced** — the admin controls the enforcement mechanism. Users and agents cannot bypass it, even deliberately.

The current user-space sandbox is entirely self-serve: it protects against accidental exposure and autonomous agent misbehavior, but a user who instructs their agent to bypass it can do so. The improvements below range from making the self-serve path smoother to adding hard admin-enforced boundaries.

---

## 1. Admin-Managed Slurm Wrappers

**What it solves:** The user-space sandbox intercepts `sbatch`/`srun` via PATH shadowing (both backends) and binary relocation (bwrap only — real binaries moved to an obscure internal path, `/usr/bin/` overlaid with redirectors). With the Landlock backend, only PATH shadowing is available — the real `/usr/bin/sbatch` remains directly callable. Even with bwrap, the underlying Slurm boundary is soft because the munge authentication socket is mounted inside the sandbox. An agent could bypass the wrappers by calling the real binaries directly (trivial with Landlock, requires path discovery with bwrap), finding other Slurm binaries on the filesystem (e.g. `salloc`, module-loaded copies), talking to `slurmrestd` via `curl`, or crafting raw Slurm RPCs. Admin-managed wrappers with credential gating close this gap for both backends — even if the agent finds a Slurm binary, it can't authenticate without the credential.

**Effort:** Medium. **Category:** Self-serve — strengthens the sandbox for users who opt in, but doesn't force anyone to use it.

### Concept

The admin would provide **sandboxed versions** of `sbatch` and `srun` that:
- Accept the same flags as the real commands — fully transparent to users and scripts
- Wrap every job in the sandbox before submission
- Call the real Slurm binary internally to actually submit

Inside the sandbox, these sandboxed versions **replace** the standard binaries via bind-mount overlay (bwrap) or PATH shadowing (Landlock). The agent (and any scripts it runs) just calls `sbatch` as normal and gets the sandboxed version — no script changes needed.

The standard Slurm binaries are gated behind a credential (token file, env var, or socket) that is hidden inside the sandbox. Even if the agent discovers the real binary path, it can't submit without the credential.

### Setup

**Step 1 — Move the real binaries and gate them.** Replace `/usr/bin/sbatch` with a gateway that checks for a token before calling the real binary:

```bash
#!/bin/bash
# /usr/bin/sbatch — gateway wrapper (admin-installed)
SUBMIT_TOKEN="/etc/slurm/.submit-token"
if [[ ! -r "$SUBMIT_TOKEN" ]]; then
    echo "sbatch: direct submission not available in this environment." >&2
    echo "Hint: use the sandboxed sbatch on your PATH." >&2
    exit 1
fi
exec /usr/libexec/slurm/sbatch-real "$@"
```

```bash
# One-time admin setup
mkdir -p /usr/libexec/slurm
mv /usr/bin/sbatch /usr/libexec/slurm/sbatch-real
mv /usr/bin/srun   /usr/libexec/slurm/srun-real
install -m 0755 gateway-sbatch /usr/bin/sbatch
install -m 0755 gateway-srun   /usr/bin/srun
echo "submit-allowed" > /etc/slurm/.submit-token
chmod 0644 /etc/slurm/.submit-token
```

Outside the sandbox, the token exists — the gateway passes through and users see standard Slurm behavior.

**Step 2 — Install sandboxed sbatch/srun.** Sandboxed versions would be placed at a central location (e.g., `/app/slurm-sandbox/bin/`). These wrap every job in bwrap and call the real binary to submit:

```bash
#!/bin/bash
# /app/slurm-sandbox/bin/sbatch — sandboxed sbatch (admin-installed)
# Accepts the same flags as real sbatch, wraps jobs in bwrap.
REAL_SBATCH="/usr/libexec/slurm/sbatch-real"
BWRAP_SANDBOX="$HOME/.claude/sandbox/bwrap-sandbox.sh"
PROJECT_DIR="${SANDBOX_PROJECT_DIR:-$(pwd)}"

# ... parse sbatch flags, wrap job command in bwrap-sandbox.sh ...

exec "$REAL_SBATCH" "${SBATCH_FLAGS[@]}" \
    --wrap="$BWRAP_SANDBOX --project-dir '$PROJECT_DIR' -- $WRAPPED_CMD"
```

**Step 3 — Configure the bwrap sandbox.** Overlay the sandboxed versions and hide the token:

```bash
# Add to bwrap arguments:
--ro-bind /app/slurm-sandbox/bin/sbatch /usr/bin/sbatch   # overlay: sbatch → sandboxed version
--ro-bind /app/slurm-sandbox/bin/srun   /usr/bin/srun     # overlay: srun → sandboxed version
--ro-bind /dev/null /etc/slurm/.submit-token              # hide token
```

Inside the sandbox:
- `sbatch` → sandboxed version (bind-mount overlay) → wraps in bwrap, calls real binary to submit
- `/usr/bin/sbatch` directly → sandboxed version (same overlay)
- `/usr/libexec/slurm/sbatch-real` directly → real binary, but **fails** (token hidden)

### Alternative credentials to gate on

| Credential | How to block in bwrap | Notes |
|---|---|---|
| Token file (`/etc/slurm/.submit-token`) | `--ro-bind /dev/null /etc/slurm/.submit-token` | Simplest; easy to audit |
| Environment variable (`SLURM_SUBMIT_KEY`) | Add to `BLOCKED_ENV_VARS` in `sandbox.conf` | Easy but env vars are more discoverable |
| Munge socket (`/run/munge/munge.socket.2`) | Don't mount `/run/munge/` | Strongest; blocks all direct Slurm auth. Sandboxed wrappers must submit via slurmrestd or a helper daemon instead of calling the real binary |

---

## 2. Admin-Provided Sandbox Tools (bwrap or Firejail)

**What it solves:** When users install and configure the sandbox themselves, they control the policy — and can weaken it. An admin-provided sandbox tool with a fixed policy turns the sandbox from self-serve to admin-enforced. This also solves the Landlock self-protection problem (see below) — scripts installed to an admin-owned path cannot be modified by the agent.

**Effort:** Low-medium. **Category:** Admin-enforced.

### Admin-installed bwrap with a fixed-policy wrapper

If bwrap were installed system-wide, the admin could provide a **setuid wrapper** that calls bwrap with hardcoded arguments. Users would invoke the wrapper instead of raw bwrap and could not loosen the restrictions:

```bash
# /usr/bin/sandbox-agent — admin-provided wrapper (setuid root or capabilities)
# Users call this instead of bwrap directly.
# The sandbox policy is compiled in — users cannot change mount rules,
# re-expose hidden paths, or weaken environment filtering.

exec bwrap \
    --ro-bind /usr /usr \
    --ro-bind /lib /lib \
    --ro-bind /lib64 /lib64 \
    --tmpfs "$HOME" \
    --bind "$PROJECT_DIR" "$PROJECT_DIR" \
    --ro-bind /dev/null /etc/slurm/.submit-token \
    # ... admin-defined policy ...
    -- "$@"
```

Since the wrapper controls the bwrap arguments, the admin would control:
- Which paths are visible, read-only, or writable
- Which environment variables are blocked
- Whether network namespaces are used
- Which Slurm binaries are overlaid

Users would get a single command (`sandbox-agent -- claude`) with no configuration to manage or misconfigure.

### Firejail

[Firejail](https://firejail.wordpress.com/) is designed for exactly this model. It installs **setuid root** and the admin defines security profiles that users cannot override. The [README](README.md) notes that Firejail requires root — in an admin-hardening context, that's an advantage rather than a limitation.

On top of the filesystem restrictions bwrap provides, Firejail adds:

| Feature | bwrap (user-space) | Firejail (admin-installed) |
|---|---|---|
| Filesystem isolation | Mount namespaces | Mount namespaces + whitelisting |
| Network isolation | Not available (shares host) | Built-in; `--net=none` or `--netfilter` |
| Seccomp filters | Not available | Built-in; restricts which syscalls the process can make |
| Capability dropping | Not available | Built-in; removes Linux capabilities |
| Profile inheritance | Manual (scripts must propagate) | Automatic; child processes inherit restrictions |
| Admin control | Users run raw bwrap, can change args | Admin defines profiles users can't override |

**Example Firejail profile for agent sandboxing:**

```ini
# /etc/firejail/claude-agent.profile
# Admin-defined, users cannot override

# Filesystem
whitelist /fh/fast
read-only /fh/fast
# Project dir made writable at runtime via --whitelist=
blacklist ${HOME}/.ssh
blacklist ${HOME}/.aws
blacklist ${HOME}/.gnupg

# Network — allow only Slurm controller and munge
net none
# Or more selectively:
# netfilter /etc/firejail/slurm-only.net

# Seccomp — drop dangerous syscalls
seccomp

# Capabilities — drop all unnecessary
caps.drop all

# Environment
rmenv GITHUB_PAT
rmenv AWS_SECRET_ACCESS_KEY
# ...
```

```bash
# User runs:
firejail --profile=/etc/firejail/claude-agent.profile -- claude
```

### Tradeoffs

- **bwrap wrapper**: Same tool and mount semantics as the current user-space setup, just with admin-controlled arguments. Both bwrap and Firejail would need to be installed system-wide.
- **Firejail**: More features (network, seccomp, capabilities) out of the box. Provides stronger guarantees with less custom scripting.

Either approach would promote the sandbox from self-serve to admin-enforced.

### Why this matters more for the Landlock backend

With the **bwrap** backend, the sandbox directory (`~/.claude/sandbox/`) is bind-mounted read-only inside the mount namespace — the agent cannot modify the wrapper scripts even though they live under the writable `~/.claude/` tree. Bwrap also **relocates the real Slurm binaries** (`/usr/bin/sbatch`, `/usr/bin/srun`) to an obscure internal path and overlays redirector scripts, so even absolute-path calls go through the sandbox wrappers.

With the **Landlock** backend, neither of these protections is possible — Landlock has no mount namespace, so:

- **Sandbox self-protection:** Landlock rules are *additive*. Granting write access to `~/.claude/` (which Claude Code requires) also grants write access to `~/.claude/sandbox/`. There is no "exclude" or "deny" mechanism, and relocating the scripts elsewhere doesn't help if any ancestor directory is writable.
- **Slurm binary relocation:** The real `/usr/bin/sbatch` and `/usr/bin/srun` remain in place and directly callable. Slurm wrapping relies on PATH shadowing only — the sandbox prepends its `bin/` directory to PATH so that `sbatch` resolves to the wrapper first, but an agent that calls `/usr/bin/sbatch` directly bypasses the wrappers entirely.

The *current* sandbox session is always safe regardless — Landlock rules are kernel-enforced and irrevocable once applied via `landlock_restrict_self()`. The risk is that a modified sandbox script could weaken *future* sessions or *submitted Slurm jobs* (since the Slurm wrappers run the sandbox scripts on compute nodes).

For Landlock deployments where this matters, admin-installing the sandbox scripts to a root-owned path (e.g. `/opt/claude-sandbox/`) is the simplest fix. Landlock's default-deny model means the agent cannot write there unless explicitly granted access. Section 1 (Admin-Managed Slurm Wrappers) addresses the Slurm bypass directly by gating the real binaries behind a credential.

---

## 3. Dedicated `${USER}_ai` Accounts

**What it solves:** True user separation. No amount of bubblewrap can prevent a process from accessing files owned by the same UID. A dedicated OS account (`alice_ai`) would run the agent under a different UID, so filesystem permissions enforce isolation without any sandbox at all.

**Effort:** High (new accounts, group structure, Slurm associations, ACLs). **Category:** Admin-enforced.

### Account and Group Structure

```
User account:   alice        (UID 1001, primary group: alice)
Agent account:  alice_ai     (UID 2001, primary group: alice_ai)
Lab AI group:   mylab_ai     (GID 3001)
```

**Group memberships:**

| Account | Groups | Purpose |
|---|---|---|
| `alice` | `alice`, `alice_ai`, `mylab` | Human can read agent output (via `alice_ai` group) |
| `alice_ai` | `alice_ai`, `mylab_ai` | Agent creates files owned by `alice_ai`; lab-wide agent collaboration via `mylab_ai` |

This means:
- Files the agent creates are owned by `alice_ai:alice_ai`
- The human (`alice`) is in the `alice_ai` group, so they can read/manage agent output
- Multiple agents in the lab share `mylab_ai` for cross-user collaboration
- The agent **cannot** read `alice`'s private files (SSH keys, credentials) because it's a different UID

### Slurm Association

A separate Slurm account and QOS could be created with resource limits:

```bash
sacctmgr add account ai_agents Description="AI agent jobs"
sacctmgr add user alice_ai Account=ai_agents

# Optional: limit resources via QOS
sacctmgr add qos agent_qos \
    MaxTRESPerUser=cpu=64,gres/gpu=2 \
    MaxJobsPerUser=10 \
    MaxSubmitJobsPerUser=20 \
    Priority=10
sacctmgr modify user alice_ai set DefaultQOS=agent_qos
```

### File Permissions

POSIX ACLs on shared data directories would let agents read lab data but not private dirs:

```bash
# Lab shared data: agents can read
setfacl -R -m g:mylab_ai:rX /fh/fast/mylab/shared_data

# User private dirs: no agent access (default — different UID, no group overlap)
# alice_ai cannot read /home/alice/.ssh — OS enforces this

# Agent workspace: both human and agent can read/write
mkdir -p /fh/fast/mylab/user/alice/agent_workspace
chown alice_ai:alice_ai /fh/fast/mylab/user/alice/agent_workspace
chmod 2775 /fh/fast/mylab/user/alice/agent_workspace
```

### Role of bwrap with Dedicated Accounts

OS user separation handles credential isolation — the agent physically cannot read `alice`'s SSH keys or AWS credentials because they're owned by a different UID. However, bwrap remains useful for **fine-grained write restriction within allowed paths**: the agent account may have write access to multiple project directories, but bwrap can restrict a given session to only one.

---

## 4. Network Isolation

**What it solves:** The current sandbox shares the host network stack (required for munge authentication and Slurm communication). This means an agent could use `curl` or `wget` to exfiltrate data.

**Effort:** Medium-high (requires root, iptables/nftables or network namespace configuration). **Category:** Admin-enforced. **Requires:** Dedicated `${USER}_ai` accounts (Section 3) — iptables UID filtering needs a separate agent UID.

### Option A: Per-UID iptables Rules

Outbound network could be blocked for agent UIDs, allowing only what's needed:

```bash
# Allow loopback and established connections
iptables -A OUTPUT -m owner --uid-owner alice_ai -o lo -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner alice_ai -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow munge (unix socket — no iptables rule needed, it's local)
# Allow Slurm controller communication
iptables -A OUTPUT -m owner --uid-owner alice_ai -d <slurmctld_ip> -p tcp --dport 6817 -j ACCEPT

# Allow DNS
iptables -A OUTPUT -m owner --uid-owner alice_ai -p udp --dport 53 -j ACCEPT

# Block everything else
iptables -A OUTPUT -m owner --uid-owner alice_ai -j DROP
```

### Option B: Network Namespace with Socket Forwarding

The agent could run in a network namespace with only the munge socket forwarded:

```bash
# Create namespace
ip netns add agent_ns

# Forward munge socket using socat
socat UNIX-LISTEN:/run/netns/agent_ns/munge.sock,fork \
      UNIX-CONNECT:/run/munge/munge.socket.2 &

# Run agent in namespace
ip netns exec agent_ns su - alice_ai -c "claude"
```

This is more complex but provides stronger isolation — the agent has no network interfaces at all, just the munge socket.

**Complements:** Pairs naturally with dedicated `${USER}_ai` accounts (the iptables rules key off UID). Firejail (Section 2) includes built-in network isolation, which may be simpler than manual iptables setup.

---

## 5. Kernel Upgrade (for Landlock)

**What it solves:** Clusters running older kernels (< 5.13) cannot use the Landlock backend. Upgrading to kernel ≥ 5.13 enables Landlock as a sandbox backend, which is particularly valuable on Ubuntu 24.04+ where AppArmor blocks the unprivileged user namespaces that bwrap requires.

**Effort:** High (kernel upgrade across the cluster). **Category:** Enables self-serve Landlock sandbox.

**Note:** The sandbox already supports Landlock as a first-class backend — auto-detected alongside bwrap. This section is only relevant for clusters still on older kernels. See `backends/landlock-sandbox.py` for the implementation.

### Kernel Version Check

```bash
uname -r
# 4.15.0-213-generic  ← too old for Landlock

# Landlock requires:
# - Kernel >= 5.13 (Ubuntu 22.04+ ships 5.15+)
# - CONFIG_SECURITY_LANDLOCK=y
# - LSM boot parameter includes "landlock"
```

### How Landlock Complements bwrap

- **bwrap** provides mount-namespace isolation: the agent sees a curated filesystem. Paths are hidden entirely (ENOENT). Supports file overlays, Slurm binary relocation, and sandbox self-protection.
- **Landlock** provides LSM-based access control: the agent sees the real filesystem but can't access restricted paths (EACCES). No root or admin help needed — works even when AppArmor blocks user namespaces. No mount namespace means no file overlays, no Slurm binary relocation, and no sandbox self-protection.

On systems where both are available, auto-detection will select bwrap (for its mount-namespace features). On systems where bwrap is blocked, Landlock provides equivalent filesystem isolation with no admin intervention required.

---

## 6. Audit Logging

**What it solves:** Visibility into what the agent did — which files it accessed, which jobs it submitted, and what commands it ran. Useful for compliance, forensics, and debugging.

**Effort:** Low-medium (auditd rules + Slurm accounting config). **Category:** Admin-enforced. **Requires:** Dedicated `${USER}_ai` accounts (Section 3) — auditd filters on UID, so without a separate agent UID there is no way to distinguish agent activity from human activity in the audit log.

### File Access Auditing with auditd

File access by agent accounts could be logged:

```bash
# /etc/audit/rules.d/agent-audit.rules

# Log file opens by alice_ai
-a always,exit -F arch=b64 -S open,openat -F uid=2001 -k agent_file_access

# Log process execution by alice_ai
-a always,exit -F arch=b64 -S execve -F uid=2001 -k agent_exec

# Log network connections by alice_ai
-a always,exit -F arch=b64 -S connect -F uid=2001 -k agent_network
```

Reload rules with `augenrules --load`. Example queries:

```bash
# What files did the agent open?
ausearch -k agent_file_access --uid 2001 -ts today

# What commands did it run?
ausearch -k agent_exec --uid 2001 -ts today
```

### Slurm Job Accounting

With dedicated Slurm accounts (Section 3), all agent jobs are automatically tracked:

```bash
# All jobs submitted by agent accounts
sacct -a --accounts=ai_agents --starttime=2024-01-01 \
    --format=JobID,User,Account,JobName,State,ExitCode,Start,End,Elapsed,MaxRSS

# Resource usage summary
sreport cluster AccountUtilizationByUser Accounts=ai_agents Start=2024-01-01
```

The separate account/QOS makes it trivial to query, report on, and set limits for agent workloads without any custom tooling.

**Complements:** Downstream of dedicated `${USER}_ai` accounts — both auditd and Slurm accounting depend on having a separate UID/account to filter on.

---

## Summary

| # | Improvement | Effort | Category | What It Closes |
|---|---|---|---|---|
| 1 | Admin-managed Slurm wrappers | Medium | Self-serve | Agent submitting unsandboxed Slurm jobs (via relocated binaries, other Slurm CLIs, REST API, or raw munge RPCs) |
| 2 | Admin-provided sandbox tools | Low-medium | Admin-enforced | Users weakening their own sandbox config; also provides sandbox self-protection for Landlock backend |
| 3 | Dedicated `${USER}_ai` accounts | High | Admin-enforced | Same-UID credential access; OS-level separation |
| 4 | Network isolation | Medium-high | Admin-enforced (requires #3) | Data exfiltration via network |
| 5 | Kernel upgrade (for Landlock) | High | Self-serve | Enables Landlock backend on older kernels |
| 6 | Audit logging | Low-medium | Admin-enforced (requires #3) | Visibility, compliance, forensics |

Sections 1, 2, and 5 are independent. Sections 4 and 6 require Section 3 (dedicated accounts).

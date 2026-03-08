# Admin Hardening Guide

The [bubblewrap sandbox](README.md) is fully user-space — no root or admin involvement needed. It provides kernel-enforced filesystem isolation for AI coding agents, with Slurm job wrapping as a default-on soft boundary.

This document is a menu of **independent improvements** an admin can adopt to close remaining gaps. Each section is self-contained: pick what fits your threat model and effort budget. They are ordered roughly from least to most effort.

### Self-serve vs. admin-enforced

Each improvement falls into one of two categories:

- **Self-serve** — makes it easier for users to sandbox their agents correctly. Works when users follow the setup. Does not prevent a user (or their agent) from bypassing the protection if they try.
- **Admin-enforced** — the admin controls the enforcement mechanism. Users and agents cannot bypass it, even deliberately.

The current user-space sandbox is entirely self-serve: it protects against accidental exposure and autonomous agent misbehavior, but a user who instructs their agent to bypass it can do so. The improvements below range from making the self-serve path smoother to adding hard admin-enforced boundaries.

---

## 1. Admin-Managed Slurm Wrappers

**What it solves:** The user-space sandbox intercepts `sbatch`/`srun` via PATH shadowing, but an agent calling `/usr/bin/sbatch` by absolute path bypasses the wrappers. Admin-managed wrappers replace the standard binaries inside the sandbox so there is no unsandboxed Slurm binary reachable by the agent.

**Effort:** Medium. **Category:** Self-serve — strengthens the sandbox for users who opt in, but doesn't force anyone to use it.

### Concept

The admin provides **sandboxed versions** of `sbatch` and `srun` that:
- Accept the same flags as the real commands — fully transparent to users and scripts
- Wrap every job in `bwrap-sandbox.sh` before submission
- Call the real Slurm binary internally to actually submit

Inside the bwrap sandbox, these sandboxed versions **replace** the standard binaries via bind-mount overlay. The agent (and any scripts it runs) just calls `sbatch` as normal and gets the sandboxed version — no script changes needed.

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

**Step 2 — Install sandboxed sbatch/srun.** The admin provides sandboxed versions at a central location (e.g., `/app/slurm-sandbox/bin/`). These wrap every job in bwrap and call the real binary to submit:

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

## 2. Dedicated `${USER}_ai` Accounts

**What it solves:** True user separation. No amount of bubblewrap can prevent a process from accessing files owned by the same UID. A dedicated OS account (`dotto_ai`) runs the agent under a different UID, so filesystem permissions enforce isolation without any sandbox at all.

**Effort:** High (new accounts, group structure, Slurm associations, ACLs). **Category:** Admin-enforced.

### Account and Group Structure

```
User account:   dotto        (UID 1001, primary group: dotto)
Agent account:  dotto_ai     (UID 2001, primary group: dotto_ai)
Lab AI group:   setty_m_ai   (GID 3001)
```

**Group memberships:**

| Account | Groups | Purpose |
|---|---|---|
| `dotto` | `dotto`, `dotto_ai`, `setty_m` | Human can read agent output (via `dotto_ai` group) |
| `dotto_ai` | `dotto_ai`, `setty_m_ai` | Agent creates files owned by `dotto_ai`; lab-wide agent collaboration via `setty_m_ai` |

This means:
- Files the agent creates are owned by `dotto_ai:dotto_ai`
- The human (`dotto`) is in the `dotto_ai` group, so they can read/manage agent output
- Multiple agents in the lab share `setty_m_ai` for cross-user collaboration
- The agent **cannot** read `dotto`'s private files (SSH keys, credentials) because it's a different UID

### Slurm Association

Create a separate Slurm account and QOS with resource limits:

```bash
sacctmgr add account ai_agents Description="AI agent jobs"
sacctmgr add user dotto_ai Account=ai_agents

# Optional: limit resources via QOS
sacctmgr add qos agent_qos \
    MaxTRESPerUser=cpu=64,gres/gpu=2 \
    MaxJobsPerUser=10 \
    MaxSubmitJobsPerUser=20 \
    Priority=10
sacctmgr modify user dotto_ai set DefaultQOS=agent_qos
```

### File Permissions

Use POSIX ACLs on shared data directories so agents can read lab data but not private dirs:

```bash
# Lab shared data: agents can read
setfacl -R -m g:setty_m_ai:rX /fh/fast/setty_m/shared_data

# User private dirs: no agent access (default — different UID, no group overlap)
# dotto_ai cannot read /home/dotto/.ssh — OS enforces this

# Agent workspace: both human and agent can read/write
mkdir -p /fh/fast/setty_m/user/dotto/agent_workspace
chown dotto_ai:dotto_ai /fh/fast/setty_m/user/dotto/agent_workspace
chmod 2775 /fh/fast/setty_m/user/dotto/agent_workspace
```

### Role of bwrap with Dedicated Accounts

OS user separation handles credential isolation — the agent physically cannot read `dotto`'s SSH keys or AWS credentials because they're owned by a different UID. However, bwrap remains useful for **fine-grained write restriction within allowed paths**: the agent account may have write access to multiple project directories, but bwrap can restrict a given session to only one.

---

## 3. Network Isolation

**What it solves:** The current sandbox shares the host network stack (required for munge authentication and Slurm communication). This means an agent could use `curl` or `wget` to exfiltrate data.

**Effort:** Medium-high (requires root, iptables/nftables or network namespace configuration). **Category:** Admin-enforced.

### Option A: Per-UID iptables Rules

Block outbound network for agent UIDs, allowing only what's needed:

```bash
# Allow loopback and established connections
iptables -A OUTPUT -m owner --uid-owner dotto_ai -o lo -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner dotto_ai -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow munge (unix socket — no iptables rule needed, it's local)
# Allow Slurm controller communication
iptables -A OUTPUT -m owner --uid-owner dotto_ai -d <slurmctld_ip> -p tcp --dport 6817 -j ACCEPT

# Allow DNS
iptables -A OUTPUT -m owner --uid-owner dotto_ai -p udp --dport 53 -j ACCEPT

# Block everything else
iptables -A OUTPUT -m owner --uid-owner dotto_ai -j DROP
```

### Option B: Network Namespace with Socket Forwarding

Run the agent in a network namespace with only the munge socket forwarded:

```bash
# Create namespace
ip netns add agent_ns

# Forward munge socket using socat
socat UNIX-LISTEN:/run/netns/agent_ns/munge.sock,fork \
      UNIX-CONNECT:/run/munge/munge.socket.2 &

# Run agent in namespace
ip netns exec agent_ns su - dotto_ai -c "claude"
```

This is more complex but provides stronger isolation — the agent has no network interfaces at all, just the munge socket.

**Complements:** Pairs naturally with dedicated `${USER}_ai` accounts (the iptables rules key off UID).

---

## 4. Kernel Upgrade and Landlock

**What it solves:** The current kernel (4.15) doesn't support [Landlock](https://docs.kernel.org/userspace-api/landlock.html), a Linux Security Module available since kernel 5.13. Landlock provides per-process filesystem access rules without requiring mount namespaces.

**Effort:** High (kernel upgrade across the cluster). **Category:** Self-serve (process restricts itself) or admin-enforced (if configured via system policy).

### What Landlock Provides

Landlock lets an unprivileged process restrict its own filesystem access using a ruleset:

```c
// Pseudocode — Landlock access rule model
struct landlock_ruleset_attr ruleset_attr = {
    .handled_access_fs = LANDLOCK_ACCESS_FS_READ_FILE |
                         LANDLOCK_ACCESS_FS_WRITE_FILE |
                         LANDLOCK_ACCESS_FS_EXECUTE
};

int ruleset_fd = landlock_create_ruleset(&ruleset_attr, ...);

// Allow read access to /fh/fast/setty_m
landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &(struct landlock_path_beneath_attr){
    .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE,
    .parent_fd = open("/fh/fast/setty_m", O_PATH)
});

// Allow write access to project dir only
landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &(struct landlock_path_beneath_attr){
    .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
    .parent_fd = open("/fh/fast/setty_m/user/dotto/project", O_PATH)
});

// Enforce — cannot be undone by the process
landlock_restrict_self(ruleset_fd, 0);
```

Once enforced, the process (and all its children) cannot access anything outside the ruleset. Unlike bwrap, Landlock doesn't use mount namespaces — it works with the real filesystem, just restricts what the process can see.

### How It Complements bwrap

- **bwrap** provides mount-namespace isolation: the agent sees a curated filesystem. Good for hiding paths entirely (e.g., `~/.ssh` doesn't exist).
- **Landlock** provides access-control isolation: the agent sees the real filesystem but can't access restricted paths. Good for fine-grained rules without mount overhead.

On kernel >= 5.13, you could use Landlock instead of bwrap for simpler setups, or layer it on top of bwrap for defense in depth.

### Kernel Version Check

```bash
uname -r
# 4.15.0-213-generic  ← too old for Landlock

# Landlock requires:
# - Kernel >= 5.13
# - CONFIG_SECURITY_LANDLOCK=y
# - LSM boot parameter includes "landlock"
```

---

## 5. Audit Logging

**What it solves:** Visibility into what the agent did — which files it accessed, which jobs it submitted, and what commands it ran. Useful for compliance, forensics, and debugging.

**Effort:** Low-medium (auditd rules + Slurm accounting config). **Category:** Admin-enforced. **Requires:** Dedicated `${USER}_ai` accounts (Section 2) — auditd filters on UID, so without a separate agent UID there is no way to distinguish agent activity from human activity in the audit log.

### File Access Auditing with auditd

Log all file access by agent accounts:

```bash
# /etc/audit/rules.d/agent-audit.rules

# Log file opens by dotto_ai
-a always,exit -F arch=b64 -S open,openat -F uid=2001 -k agent_file_access

# Log process execution by dotto_ai
-a always,exit -F arch=b64 -S execve -F uid=2001 -k agent_exec

# Log network connections by dotto_ai
-a always,exit -F arch=b64 -S connect -F uid=2001 -k agent_network
```

Reload rules:

```bash
augenrules --load
```

Query logs:

```bash
# What files did the agent open?
ausearch -k agent_file_access --uid 2001 -ts today

# What commands did it run?
ausearch -k agent_exec --uid 2001 -ts today
```

### Slurm Job Accounting

With dedicated Slurm accounts (Section 2), all agent jobs are automatically tracked:

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
| 1 | Admin-managed Slurm wrappers | Medium | Self-serve | Agent bypassing Slurm wrappers by absolute path |
| 2 | Dedicated `${USER}_ai` accounts | High | Admin-enforced | Same-UID credential access; OS-level separation |
| 3 | Network isolation | Medium-high | Admin-enforced | Data exfiltration via network |
| 4 | Kernel upgrade + Landlock | High | Self-serve | Simpler/stronger filesystem restrictions |
| 5 | Audit logging | Low-medium | Admin-enforced (requires #2) | Visibility, compliance, forensics |

Sections 1, 3, and 4 are independent. Section 5 requires Section 2 (dedicated accounts).

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

**What it solves:** The user-space Slurm wrappers are a soft boundary — they rely on PATH shadowing (both backends) and binary relocation (bwrap only). An agent can bypass them by calling real binaries directly or using other Slurm CLIs. This section describes a vault-and-gateway approach that strengthens Slurm isolation for both backends.

**Effort:** Medium. **Category:** Self-serve — strengthens the sandbox for users who opt in.

### Design: sandbox vault + token-gated gateway

Move the real Slurm binaries into a **vault directory** (`/sandbox-vault/`) that the sandbox never grants access to. Gate `/usr/bin/sbatch` with a **submit token** stored in the vault — processes that can't read the vault can't authenticate.

#### Vault

```
/sandbox-vault/              # root-owned, 0755
└── slurm/
    ├── sbatch-real          # real Slurm binaries (moved from /usr/bin/)
    ├── srun-real
    └── .submit-token        # random secret, readable by users
```

The sandbox scripts **hardcode a deny** for `/sandbox-vault/` — not in `sandbox.conf`, not user-configurable:

- **bwrap**: the vault is never bind-mounted (invisible inside namespace)
- **Landlock**: the vault is never added to `--ro` or `--rw` rules

If a user puts `/` in `READONLY_MOUNTS`, the sandbox scripts expand it to individual top-level directories, excluding the vault. This is already implemented in `expand_safe_mounts()` in `sandbox-lib.sh`.

#### Gateway

The admin replaces `/usr/bin/sbatch` with a gateway that requires the submit token:

```bash
#!/bin/bash
# /usr/bin/sbatch — gateway wrapper (admin-installed)
TOKEN="$(cat /sandbox-vault/slurm/.submit-token 2>/dev/null)" || {
    echo "sbatch: submission blocked (cannot read submit token)." >&2
    exit 1
}
exec /sandbox-vault/slurm/sbatch-real "$@"
```

Outside the sandbox, the vault is readable — the gateway reads the token and execs the real binary. Inside the sandbox, the vault is blocked — the `cat` fails and submission is denied.

#### How sandboxed processes can still submit

The agent needs to submit Slurm jobs *through* the sandbox wrappers (which ensure every job runs sandboxed on the compute node). The wrappers run inside the sandbox, so they also can't read the vault. How they authenticate depends on the backend:

**bwrap:** The real binary is relocated to `/tmp/.sandbox-slurm-real/sbatch` inside the mount namespace (existing mechanism). The wrapper calls it directly, bypassing the gateway entirely. This is the strongest approach — the agent never sees the real binary path.

**Landlock:** Cannot relocate binaries (no mount namespace). Instead, `sandbox-exec.sh` reads the submit token from the vault *before* applying Landlock restrictions and injects it as the env var `_SANDBOX_SUBMIT_TOKEN`. The gateway accepts this as an alternative authentication path:

```bash
#!/bin/bash
# /usr/bin/sbatch — gateway wrapper (Landlock-aware variant)
# Accept either: (a) direct vault read, or (b) injected token env var.
# The expected token hash is baked in at install time so the gateway
# doesn't need vault access at check time (it may be Landlock-restricted).
EXPECTED_HASH="<sha256 of token, set by admin at install>"
ACTUAL_HASH="$(echo -n "${_SANDBOX_SUBMIT_TOKEN:-}" | sha256sum | cut -d' ' -f1)"
if [[ "$ACTUAL_HASH" == "$EXPECTED_HASH" ]]; then
    exec /usr/libexec/slurm/sbatch-real "$@"
fi
# Fallback: try reading token directly (works outside sandbox)
cat /sandbox-vault/slurm/.submit-token &>/dev/null && \
    exec /sandbox-vault/slurm/sbatch-real "$@"
echo "sbatch: submission blocked." >&2
exit 1
```

> **Landlock caveat:** The injected env var is discoverable by a determined agent (`env`, `/proc/self/environ`). This makes Landlock's Slurm protection weaker than bwrap's binary relocation. For stronger isolation, combine with network restrictions (§4) or use the admin-enforced approach (§2).

### Setup

```bash
# Create the vault and generate a submit token
mkdir -p /sandbox-vault/slurm
head -c 32 /dev/urandom | base64 > /sandbox-vault/slurm/.submit-token
chmod 0644 /sandbox-vault/slurm/.submit-token

# Move real Slurm binaries
mv /usr/bin/sbatch /sandbox-vault/slurm/sbatch-real
mv /usr/bin/srun   /sandbox-vault/slurm/srun-real
# (For Landlock variant: also copy to /usr/libexec/slurm/ so the
# gateway can exec them from inside a Landlock-restricted process)

# Install gateway wrappers
install -m 0755 gateway-sbatch /usr/bin/sbatch
install -m 0755 gateway-srun   /usr/bin/srun
```

### Result

| Agent action | bwrap | Landlock |
|---|---|---|
| `sbatch` (PATH shadow) | Wrapper → relocated binary → submits sandboxed job ✓ | Wrapper → gateway (token from env) → submits sandboxed job ✓ |
| `/usr/bin/sbatch` (direct) | Gateway → can't read vault → **blocked** ✗ | Gateway → no token, can't read vault → **blocked** ✗ |
| Real binary in vault | **ENOENT** (not mounted) ✗ | **EACCES** (vault denied) ✗ |
| `curl` to `slurmrestd` | Works if exposed (see §4) | Works if exposed (see §4) |

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

Landlock has no mount namespace, so unlike bwrap it cannot make the sandbox directory read-only or relocate Slurm binaries. This means an agent could modify the sandbox scripts (weakening future sessions or Slurm job wrappers), and `/usr/bin/sbatch` remains directly callable. The *current* session is always safe — Landlock rules are irrevocable once applied — but future sessions are at risk.

Admin-installing the sandbox scripts to a root-owned path (e.g. `/opt/claude-sandbox/`) is the simplest fix — Landlock's default-deny means the agent can't write there. Section 1 addresses the Slurm bypass by gating the real binaries behind a credential that Landlock blocks access to.

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
| 1 | Admin-managed Slurm wrappers | Medium | Self-serve | Agent submitting unsandboxed Slurm jobs — vault + token-gated gateway (bwrap: strong; Landlock: soft, env var discoverable) |
| 2 | Admin-provided sandbox tools | Low-medium | Admin-enforced | Users weakening their own sandbox config; also provides sandbox self-protection for Landlock backend |
| 3 | Dedicated `${USER}_ai` accounts | High | Admin-enforced | Same-UID credential access; OS-level separation |
| 4 | Network isolation | Medium-high | Admin-enforced (requires #3) | Data exfiltration via network |
| 5 | Kernel upgrade (for Landlock) | High | Self-serve | Enables Landlock backend on older kernels |
| 6 | Audit logging | Low-medium | Admin-enforced (requires #3) | Visibility, compliance, forensics |

Sections 1, 2, and 5 are independent. Sections 4 and 6 require Section 3 (dedicated accounts).

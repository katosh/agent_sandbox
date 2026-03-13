# Admin Hardening Options

> **Disclaimer:** This document reflects personal analysis and has not been formally reviewed by a security professional. The hardening suggestions are best-effort recommendations based on publicly available documentation and testing on a limited set of systems. The environment may differ. Review all changes with your security team before deploying to production.

The [sandbox](README.md) is fully user-space, requiring no root or admin involvement. All three backends (bubblewrap, firejail, and Landlock) provide kernel-enforced filesystem isolation for AI coding agents, with Slurm job wrapping as a default-on soft boundary.

> **Ubuntu 24.04 consideration:** Ubuntu 24.04 enables AppArmor's restriction on unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns=1`), which prevents bubblewrap from working. Without admin intervention, the sandbox falls back to the **Landlock** backend, which has significant limitations (no mount namespace, no `/tmp` isolation, no sandbox self-protection, `systemd-run` escape; see the comparison table under §2). **Recommended:** Create an AppArmor profile to allow bwrap (see §2 below). This is low effort and gives users the strongest backend. Alternatively, installing firejail (setuid) also bypasses the restriction.

This document describes **improvements** that could close remaining gaps. Sections 1 and 2 are independent and can be deployed individually. Sections 3–5 build on each other (4 and 5 require 3). They are ordered roughly from least to most effort.

> **My priority:** Section 1 (enforcing sandbox on agent-submitted Slurm jobs) is the improvement I'd most like to see. It closes the main gap in the current setup (Slurm PATH shadowing) with moderate admin effort and no workflow changes for users.

### Self-serve vs. admin-enforced

Each improvement falls into one of two categories:

- **Self-serve** — makes it easier for users to sandbox their agents correctly. Works when users follow the setup. Does not prevent a user (or their agent) from bypassing the protection if they try.
- **Admin-enforced** — the admin controls the enforcement mechanism. Users and agents cannot bypass it, even deliberately.

The current user-space sandbox is entirely self-serve: it protects against accidental exposure and autonomous agent misbehavior, but a user who instructs their agent to bypass it can do so. The improvements below range from making the self-serve path smoother to adding hard admin-enforced boundaries.

---

## 1. Enforce Sandbox on Agent-Submitted Slurm Jobs

**What it solves:** The user-space Slurm wrappers are a soft boundary — PATH shadowing and binary relocation can be bypassed. This approach ensures every Slurm job submitted from within the sandbox is **sandboxed on the compute node** too, using a Slurm job submit plugin and an eBPF LSM-protected bypass token. Users who do not use the sandbox are unaffected — their workflow does not change.

**Effort:** Medium. **Category:** Admin-enforced.

| Scenario | What happens |
|---|---|
| Agent calls `sbatch` (any method) | No bypass token → plugin wraps job in `sandbox-exec.sh` → **sandboxed** |
| Agent tries to read token file | eBPF LSM checks `no_new_privs` → **EACCES** |
| User outside sandbox | Reads token → passes to sbatch → **unsandboxed** |
| `curl` to `slurmrestd` | Works if exposed (see §4 for network isolation) |

Design, setup instructions, components, and verification steps are in [`slurm-enforce/README.md`](slurm-enforce/README.md). If also deploying Section 2, the Slurm enforcement variables can go directly in `/app/lib/agent-sandbox/sandbox.conf` — one config file for both systems.

---

## 2. Admin-Owned Sandbox Installation

**What it solves:** Two problems at once — **policy enforcement** (admin sets a security baseline that users cannot weaken) and **sandbox self-protection** (with bwrap/firejail, scripts are read-only inside the sandbox; with admin-owned scripts at `/app/lib/agent-sandbox/`, the agent can't modify them even without a mount namespace). Users can customize within bounds via a separate `user.conf` — adding data mounts and extra blocked paths — but cannot remove admin-enforced protections like blocked credentials or hidden paths.

**Effort:** Low-medium. **Category:** Admin-enforced.

Key features:
- **Multi-level config** — admin `sandbox.conf` (set via `_ADMIN_DIR` in `sandbox-lib.sh`, defaults to `/app/lib/agent-sandbox/`) sets the baseline; user config (`user.conf`) and per-project configs (`conf.d/*.conf`) can only add to it. The path is a script variable (not an env var) to prevent agent redirection. User configs run in isolated subprocesses — only known config variables are extracted. Admin values are enforced via comparison+merge after each config layer.
- **Backend selection** — on Ubuntu 24.04+, AppArmor blocks unprivileged user namespaces. An admin AppArmor profile (low effort) enables the recommended bwrap backend. Firejail (setuid) is an alternative. Without either, the sandbox falls back to Landlock with [significant gaps](ADMIN_INSTALL.md#landlock-fallback).
- **Seccomp trade-offs** — all three backends block `io_uring`, `userfaultfd`, and `kexec` via seccomp. See [HPC compatibility analysis](ADMIN_INSTALL.md#seccomp-filter--hpc-compatibility).

For full setup instructions, config hierarchy, backend comparison, and seccomp details, see **[ADMIN_INSTALL.md](ADMIN_INSTALL.md)**. After installation, run `bash test.sh` (backend isolation) and `bash test-admin.sh` (config enforcement) to verify the deployment.

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

### Role of the Sandbox with Dedicated Accounts

OS user separation handles credential isolation — the agent physically cannot read `alice`'s SSH keys or AWS credentials because they're owned by a different UID. However, the sandbox remains useful for **fine-grained write restriction within allowed paths**: the agent account may have write access to multiple project directories, but the sandbox can restrict a given session to only one.

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

## 5. Audit Logging

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
| 1 | [Enforce sandbox on Slurm jobs](#1-enforce-sandbox-on-agent-submitted-slurm-jobs) | Medium | Admin-enforced | Agent submitting unsandboxed Slurm jobs — job submit plugin sandboxes all jobs unless caller provides bypass token (eBPF LSM protects token from `no_new_privs` processes) |
| 2 | [Admin-owned sandbox installation](#2-admin-owned-sandbox-installation) ([details](ADMIN_INSTALL.md)) | Low-medium | Admin-enforced | Users weakening config; sandbox self-protection; multi-level config with post-merge validation; [backend selection](ADMIN_INSTALL.md#choosing-a-backend-on-ubuntu-2404) (bwrap via AppArmor recommended, firejail alternative); [seccomp trade-offs](ADMIN_INSTALL.md#seccomp-filter--hpc-compatibility); [Landlock fallback gaps](ADMIN_INSTALL.md#landlock-fallback) |
| 3 | [Dedicated `${USER}_ai` accounts](#3-dedicated-user_ai-accounts) | High | Admin-enforced | Same-UID credential access; OS-level separation |
| 4 | [Network isolation](#4-network-isolation) | Medium-high | Admin-enforced (requires #3) | Data exfiltration via network |
| 5 | [Audit logging](#5-audit-logging) | Low-medium | Admin-enforced (requires #3) | Visibility, compliance, forensics |

Sections 1 and 2 are independent and can be deployed individually. Section 2 includes backend selection for Ubuntu 24.04+ — an AppArmor profile for bwrap (recommended) or firejail avoids falling back to Landlock. Sections 4 and 5 require Section 3 (dedicated accounts).

---

## Sandbox vs. Apptainer Containers

For a detailed security comparison with Apptainer (the standard HPC container runtime), including default isolation tables, CVE history, architectural weaknesses, and shared gaps, see **[Apptainer Comparison](APPTAINER_COMPARISON.md)**.

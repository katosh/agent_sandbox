# Admin Hardening Options

The [sandbox](README.md) is fully user-space — no root or admin involvement needed. All three backends (bubblewrap, firejail, and Landlock) provide kernel-enforced filesystem isolation for AI coding agents, with Slurm job wrapping as a default-on soft boundary.

> **Ubuntu 24.04 consideration:** A potential OS upgrade to Ubuntu 24.04 would enable AppArmor's restriction on unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns=1`), which prevents bubblewrap from working. In that scenario, the sandbox would automatically use the **Landlock** backend. Landlock provides equivalent kernel-enforced filesystem isolation, but its permission model is **additive only** — you can grant access to paths but cannot carve out exceptions under an already-granted parent. This makes it harder to hide files (like tokens or binaries) from the sandbox using filesystem permissions alone, which is why the hardening approaches below rely on mechanisms outside the filesystem layer (eBPF LSM, Slurm plugins) rather than trying to hide paths.

This document describes **improvements** that could close remaining gaps. Sections 1 and 2 are independent and can be deployed individually. Sections 3–5 build on each other (4 and 5 require 3). They are ordered roughly from least to most effort.

> **Our priority:** Section 1 (sandbox-by-default Slurm submission) is the improvement we'd most like to see. It closes the main gap in the current setup — Slurm PATH shadowing — with moderate admin effort and no workflow changes for users.

### Self-serve vs. admin-enforced

Each improvement falls into one of two categories:

- **Self-serve** — makes it easier for users to sandbox their agents correctly. Works when users follow the setup. Does not prevent a user (or their agent) from bypassing the protection if they try.
- **Admin-enforced** — the admin controls the enforcement mechanism. Users and agents cannot bypass it, even deliberately.

The current user-space sandbox is entirely self-serve: it protects against accidental exposure and autonomous agent misbehavior, but a user who instructs their agent to bypass it can do so. The improvements below range from making the self-serve path smoother to adding hard admin-enforced boundaries.

---

## 1. Sandbox-by-Default Slurm Submission

**What it solves:** The user-space Slurm wrappers are a soft boundary — PATH shadowing and binary relocation can be bypassed. Instead of trying to *block* submission, this approach ensures every Slurm job is **sandboxed by default** at the scheduler level. No matter how the agent submits a job, it runs inside the sandbox. Legitimate unsandboxed jobs require a token that only non-sandboxed processes can access.

**Effort:** Medium. **Category:** Admin-enforced.

### Design: Slurm job submit plugin + eBPF-protected token

#### Job submit plugin

A **Slurm job submit plugin** (`job_submit.lua` or C plugin) intercepts every `sbatch`/`srun` submission:

1. Check if the submission carries a valid **bypass token** (e.g., via `--export=_SANDBOX_BYPASS=<token>`)
2. **Valid token** → job runs as submitted (user is outside the sandbox)
3. **No token or invalid** → plugin prepends `sandbox-exec.sh --project-dir $PWD --` to the job command

This makes sandboxing the *default* for all jobs. The agent doesn't need to be blocked from calling Slurm — any job it submits will be sandboxed regardless of how it gets there.

#### Why eBPF LSM for token protection

The bypass token must be readable by normal users but hidden from sandboxed processes. This is straightforward with bwrap (don't bind-mount the file), but Landlock's permission model is **additive only** — you can grant access to paths but cannot revoke access to a file under an already-granted parent directory. If `/etc` is in `READONLY_MOUNTS` (which it is by default), a Landlock-sandboxed process can read anything in `/etc`, including the token. There is no way to carve out an exception.

An **eBPF LSM program** solves this for both backends uniformly. It attaches to the kernel's `file_open` hook and denies read access to the token file for any process with `no_new_privs` set. Both bwrap and Landlock set `PR_SET_NO_NEW_PRIVS` on the sandboxed process — an irrevocable kernel flag that persists across `fork()` and `exec()`, cannot be unset, and is a process attribute (not a file or env var). Normal user processes do not have it set. The eBPF program (kernel 5.7+, Ubuntu 24.04 supports this) checks this flag at file open time — kernel-enforced, independent of both sandbox backends, and unforgeable even if an agent rewrites every sandbox script.

#### Heterogeneous clusters (bwrap-only nodes)

On older nodes where only bwrap is available (e.g., Ubuntu 18.04, kernel 4.15), eBPF LSM is not supported. On these nodes, bwrap can hide the token via its mount namespace instead. Set `SANDBOX_BYPASS_TOKEN` in `sandbox.conf` and the bwrap backend will automatically overlay the file with `/dev/null` — the sandboxed process reads an empty file rather than the real token. Combined with an admin-owned installation (Section 2), the agent cannot modify `sandbox.conf` to remove the block.

```bash
# In sandbox.conf (admin-owned):
SANDBOX_BYPASS_TOKEN="/etc/slurm/.sandbox-bypass-token"
```

The eBPF program is only needed on nodes that use the Landlock backend, where the additive-only permission model makes it impossible to hide a file under an already-granted parent directory. On a heterogeneous cluster, deploy the eBPF program on Landlock nodes (kernel ≥ 5.7) and rely on bwrap's automatic token hiding on older bwrap-only nodes. The `SANDBOX_BYPASS_TOKEN` setting works with both — bwrap hides it via mount namespace, and the path can also be used to configure the eBPF program's protected inode.

### Setup

```bash
# Generate a bypass token
head -c 32 /dev/urandom | base64 > /etc/slurm/.sandbox-bypass-token
chmod 0644 /etc/slurm/.sandbox-bypass-token

# Install the job submit plugin (see admin/job_submit.lua for a
# working example). Edit SANDBOX_EXEC path to match your install.
cp admin/job_submit.lua /etc/slurm/job_submit.lua

# Enable in slurm.conf:
#   JobSubmitPlugins=lua
# Then: scontrol reconfigure

# Build and load eBPF LSM program (see admin/token_protect.bpf.c
# and admin/README.md for build instructions)
```

Working examples are provided in `admin/`: `job_submit.lua` (Slurm plugin) and `token_protect.bpf.c` (eBPF program). The plugin intercepts batch jobs, checks for the bypass token in `_SANDBOX_BYPASS`, and wraps unvalidated jobs in `sandbox-exec.sh`. The token is cleared from the job environment after validation so it doesn't leak to the compute node. See `admin/README.md` for full setup instructions.

### Tested

All components have been end-to-end tested on an Ubuntu 24.04 VM (kernel 6.8, Slurm 23.11) with both sandbox backends:

- **eBPF LSM program** — compiled with clang/libbpf, loaded via `bpftool prog loadall ... autoattach`. Normal processes can read the token file; processes with `PR_SET_NO_NEW_PRIVS` get `EACCES`.
- **Slurm job submit plugin** — jobs without a bypass token are wrapped in `sandbox-exec.sh`; jobs with a valid `_SANDBOX_BYPASS` token pass through unsandboxed; the token is cleared from the job environment after validation.
- **Combined flow (all backends)** — verified with bwrap, firejail, and Landlock. A sandboxed job cannot read the bypass token (eBPF denies it via `no_new_privs` check), so any Slurm job it submits lacks the token and gets sandboxed by the plugin. Sandboxed jobs show `SANDBOX_ACTIVE=1`, hidden `~/.ssh`, and `EACCES`/`ENOENT` on the token file. Unsandboxed jobs (valid token) see all files normally.
- **Sandbox test suite** — 104 total: 38/38 pass (bwrap), 37/37 pass + 3 skipped (firejail), 29/29 pass + 4 skipped (Landlock). Skips are for backend-specific features (binary relocation, self-protection, /tmp isolation).

The test setup used a single-node Slurm cluster (slurmctld + slurmd + slurmdbd with MariaDB). bwrap on Ubuntu 24.04 requires an AppArmor profile to allow unprivileged user namespaces (the installer prints the needed profile if this is the issue).

### Result

| Scenario | What happens |
|---|---|
| Agent calls `sbatch` (any method) | No bypass token → plugin wraps job in `sandbox-exec.sh` → **sandboxed** |
| Agent tries to read token file | eBPF LSM checks `no_new_privs` → **EACCES** |
| User outside sandbox | Reads token → passes to sbatch → **unsandboxed** ✓ |
| `curl` to `slurmrestd` | Works if exposed (see §4 for network isolation) |

---

## 2. Admin-Owned Sandbox Installation

**What it solves:** Two problems at once — **sandbox self-protection** and **policy enforcement**.

With the Landlock backend (which becomes the only option if the OS is upgraded to Ubuntu 24.04), there is no mount namespace. Unlike bwrap, Landlock cannot make the sandbox directory read-only. If the sandbox scripts live in the user's home directory, an agent could modify them — weakening future sessions or Slurm job wrappers. The *current* session is always safe (Landlock rules are irrevocable once applied), but future sessions and submitted Slurm jobs are at risk. Additionally, when users install and configure the sandbox themselves, they control the policy and can weaken it.

An admin-owned installation solves both: scripts are tamper-proof (the agent can't write to admin-owned paths) and policy is centrally managed.

**Effort:** Low-medium. **Category:** Admin-enforced.

### Setup

Install the sandbox scripts to a **root-owned path** (e.g., `/opt/claude-sandbox/`). Landlock's default-deny means the agent can't write to paths outside its granted directories — the project directory and `~/.claude` are writable but `/opt/` is not.

```bash
# One-time admin setup
cp -r agent_sandbox /opt/claude-sandbox
chown -R root:root /opt/claude-sandbox
chmod -R 755 /opt/claude-sandbox

# Users point their install at the admin-managed copy
ln -sf /opt/claude-sandbox ~/.claude/sandbox
```

The admin controls which paths are visible, which environment variables are blocked, and the Slurm wrapper behavior. Users get sandboxing without managing or misconfiguring policy. The agent cannot tamper with the scripts, sandbox.conf, or Slurm wrappers — even across sessions.

This also fixes the Landlock-specific issue where `~/.claude/CLAUDE.md` and `~/.claude/settings.json` are writable. Since `~/.claude/` must be writable (Claude Code needs it), Landlock's additive-only model cannot make individual files under it read-only. The bwrap backend uses mount overlays for these files, but Landlock cannot. With an admin-owned installation, `sandbox.conf` and the sandbox scripts are protected; the `CLAUDE.md` and `settings.json` overlays remain effective because the in-place swap files are restored on exit.

### Disable systemd user instances (Landlock nodes)

On nodes using the Landlock backend, there is a critical escape vector: Landlock restricts filesystem access but **cannot block Unix domain socket `connect()`**. This is a fundamental kernel limitation (not available in any Landlock ABI version as of kernel 6.11). A sandboxed process can connect to `/run/user/<UID>/systemd/private` and use `systemd-run --user` to execute commands outside the sandbox — at least 5 independent tools can trigger this (`systemd-run`, `busctl`, `gdbus`, `python3-dbus`, `systemctl --user`).

The **bwrap backend is not affected** — it replaces `/run` with a tmpfs and only bind-mounts the munge and nscd sockets.

On HPC compute nodes, systemd user instances are typically unnecessary. Disabling them removes the escape target:

```bash
# Option A: Mask the user@ template service (recommended)
systemctl mask user@.service

# Option B: Limit via logind
# /etc/systemd/logind.conf.d/no-user-sessions.conf
[Login]
UserTasksMax=0
KillUserProcesses=yes
```

Option A is stronger — it prevents the user systemd instance from starting at all. Verify with `systemd-run --user -- id` (should fail with "Failed to connect to bus").

The Landlock backend also installs a **seccomp filter** that blocks dangerous syscalls (`io_uring_setup`, `process_vm_writev`, `kexec_load`, etc.) as defense-in-depth. The filter does not block `connect()` itself (which would break munge authentication), but reduces the kernel attack surface.

### Firejail backend (implemented — `backends/firejail.sh`)

On nodes where AppArmor blocks unprivileged user namespaces (Ubuntu 24.04+), bwrap cannot work without an admin-created AppArmor profile. [Firejail](https://firejail.wordpress.com/) is now implemented as a third sandbox backend. It installs **setuid root**, so it can create mount namespaces regardless of AppArmor settings. The sandbox auto-detects firejail when bwrap is unavailable (priority: bwrap > firejail > landlock).

Firejail closes the remaining gaps that Landlock alone cannot address. A full penetration test has been conducted — see `findings_firejail.md` for the detailed report (43 tests, 26 blocked, 16 escaped/leaked post-remediation). Key comparison:

| Gap (pentest finding) | Landlock | Firejail |
|---|---|---|
| Unix socket `connect()` (D-Bus, snapd, MariaDB) | Cannot block — leaks service info | Mount namespace hides sockets; snapd/systemd-notify/lxd-installer explicitly blacklisted |
| Host process visibility (`ps aux`) | Shared PID namespace — all host processes visible | PID namespace isolates process list (default) |
| `/tmp` cross-session leakage | Shared host `/tmp` | `--private-tmp` gives clean tmpfs |
| Network exfiltration (`curl`, `wget`) | Shares host network — full outbound access | `--net=none` or `--netfilter` for controlled egress |
| Credential exfiltration chain | OAuth tokens readable + network open | Network isolation breaks the chain |
| Sandbox script tampering | Writable under `~/.claude/` (additive-only rules) | Mount namespace makes scripts invisible/read-only |
| `settings.json` / `CLAUDE.md` writability | Cannot make files read-only under writable parent | In-place swap with backup/restore (like landlock) |
| Seccomp coverage | Custom BPF denylist (io_uring, kexec, memfd_create) | Built-in `--seccomp` + `--caps.drop=all` + `--nonewprivs` (io_uring not blocked in v0.9.72) |
| Internal state exposure | N/A | `/run/firejail/mnt/seccomp/` readable (firejail design limitation — reveals BPF filter) |

#### Admin setup for Slurm nodes

```bash
# 1. Install firejail
sudo apt install firejail

# 2. Ensure the slurm user has a system-range UID (< 1000)
#    Firejail filters /etc/passwd, removing UIDs in the dynamic range
#    (~1000–64999, except the current user). If slurm has a high UID
#    (e.g., 6281 from LDAP or 64030 from adduser), sbatch fails inside
#    the sandbox because it can't resolve SlurmUser from slurm.conf.
#    For LDAP-managed environments, change the UID in the directory service.
sudo usermod -u 120 slurm
sudo groupmod -g 120 slurm
# Fix ownership of slurm state dirs after UID change:
sudo find /var/lib/slurm /var/log/slurm /var/spool/slurmd \
    -exec chown slurm:slurm {} + 2>/dev/null

# 3. The sandbox auto-detects firejail — no user config needed.
#    Force firejail for testing:
SANDBOX_BACKEND=firejail ./sandbox-exec.sh -- bash
```

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
| 1 | Sandbox-by-default Slurm submission | Medium | Admin-enforced | Agent submitting unsandboxed Slurm jobs — job submit plugin sandboxes all jobs unless caller provides bypass token (eBPF LSM protects token from `no_new_privs` processes) |
| 2 | Admin-owned sandbox installation | Low-medium | Admin-enforced | Users weakening their own sandbox config; sandbox self-protection; systemd-run escape on Landlock nodes (disable `user@.service`) |
| 3 | Dedicated `${USER}_ai` accounts | High | Admin-enforced | Same-UID credential access; OS-level separation |
| 4 | Network isolation | Medium-high | Admin-enforced (requires #3) | Data exfiltration via network |
| 5 | Audit logging | Low-medium | Admin-enforced (requires #3) | Visibility, compliance, forensics |

Sections 1 and 2 are independent and can be deployed individually. Sections 4 and 5 require Section 3 (dedicated accounts).

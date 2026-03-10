# Admin Hardening Options

The [sandbox](README.md) is fully user-space — no root or admin involvement needed. All three backends (bubblewrap, firejail, and Landlock) provide kernel-enforced filesystem isolation for AI coding agents, with Slurm job wrapping as a default-on soft boundary.

> **Ubuntu 24.04 consideration:** A potential OS upgrade to Ubuntu 24.04 would enable AppArmor's restriction on unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns=1`), which prevents bubblewrap from working. In that scenario, the sandbox would automatically use the **Landlock** backend. Landlock provides equivalent kernel-enforced filesystem isolation, but its permission model is **additive only** — you can grant access to paths but cannot carve out exceptions under an already-granted parent. This makes it harder to hide files (like tokens or binaries) from the sandbox using filesystem permissions alone, which is why the hardening approaches below rely on mechanisms outside the filesystem layer (eBPF LSM, Slurm plugins) rather than trying to hide paths.

This document describes **improvements** that could close remaining gaps. Sections 1 and 2 are independent and can be deployed individually. Sections 3–5 build on each other (4 and 5 require 3). They are ordered roughly from least to most effort.

> **Our priority:** Section 1 (enforcing sandbox on agent-submitted Slurm jobs) is the improvement we'd most like to see. It closes the main gap in the current setup — Slurm PATH shadowing — with moderate admin effort and no workflow changes for users.

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

Design, setup instructions, components, and verification steps are in [`admin/README.md`](admin/README.md).

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

This also protects `sandbox.conf` and the sandbox scripts from tampering — even across sessions. The `CLAUDE.md` and `settings.json` overlays are not affected by this, since they live in a separate per-sandbox config directory (`CLAUDE_CONFIG_DIR`) that is rebuilt on each sandbox start from the user's real config.

### Disable systemd user instances (Landlock-only nodes)

This is only relevant on nodes where neither bwrap nor firejail is installed, so the sandbox falls back to the Landlock backend. Landlock restricts filesystem access but **cannot block Unix domain socket `connect()`** (not available in any Landlock ABI version as of kernel 6.11). A sandboxed process can connect to `/run/user/<UID>/systemd/private` and use `systemd-run --user` to execute commands outside the sandbox.

Both **bwrap** and **firejail** are unaffected — they replace `/run` with a tmpfs or blacklist the socket.

**Current state on gizmo Ubuntu 18 nodes:** `systemd-run --user` works — the escape is viable. The user systemd instance runs gpg-agent sockets (on-demand) but no D-Bus session bus or custom user services.

**What is affected:** `gpg-agent` socket activation (users doing GPG signing would need to start `gpg-agent --daemon` manually) and `systemctl --user` commands.

#### Setup

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

### User enumeration via LDAP/AD

On Active Directory or LDAP-managed clusters, `getent passwd` reveals all users in the directory (~10k+ entries), not just the 30-odd system accounts in `/etc/passwd`. An agent could enumerate the entire organization.

The sandbox mitigates this automatically via `FILTER_PASSWD=true` (default in `sandbox.conf`):

- **bwrap**: overlays `/etc/passwd` (system UIDs + current user only) and `/etc/nsswitch.conf` (`passwd: files` only, no ldap/sss). NSS daemon sockets not bound.
- **firejail**: blacklists NSS daemon sockets (nscd, nslcd, sssd) so `getent passwd` only returns local users.
- **landlock**: not supported — no mount namespace to overlay files or block sockets.

Munge and Slurm are unaffected — munge uses a unix socket, and Slurm resolves its own user from `slurm.conf`. No admin action required.

The Landlock backend also installs a **seccomp filter** that blocks dangerous syscalls as defense-in-depth. The filter does not block `connect()` itself (which would break munge authentication), but reduces the kernel attack surface.

#### Seccomp filter — HPC compatibility trade-offs

The Landlock seccomp filter blocks `io_uring` (kernel I/O bypass) and `kexec_load/kexec_file_load` (kernel replacement). Several other syscalls were **intentionally removed** from the blocklist to avoid breaking legitimate HPC workloads:

| Syscall | HPC use case | Security risk (accepted) |
|---|---|---|
| `memfd_create` | GPU drivers (CUDA, ROCm), JIT compilers (Julia, Numba, PyTorch JIT) | Anonymous executable memory regions |
| `userfaultfd` | Java ZGC/Shenandoah GC, QEMU live migration | Kernel race exploitation (CVE-2021-22555 and others) |
| `process_vm_readv/writev` | MPI shared-memory transport, debuggers (gdb, strace) | Cross-process memory access (mitigated by PID namespace in bwrap/firejail) |

These syscalls are commonly used by GPU compute, MPI multi-rank jobs, and JVM-based bioinformatics tools. Blocking them would silently break `sbatch` jobs using CUDA, multi-rank MPI, or Java pipelines. The filesystem sandbox (Landlock rules) remains the primary isolation mechanism — seccomp is defense-in-depth only.

### Firejail backend (implemented — `backends/firejail.sh`)

On nodes where AppArmor blocks unprivileged user namespaces (Ubuntu 24.04+), bwrap cannot work without an admin-created AppArmor profile. [Firejail](https://firejail.wordpress.com/) is now implemented as a third sandbox backend. It installs **setuid root**, so it can create mount namespaces regardless of AppArmor settings. The sandbox auto-detects firejail when bwrap is unavailable (priority: bwrap > firejail > landlock).

Firejail closes the remaining gaps that Landlock alone cannot address. Key comparison:

| Gap | Landlock | Firejail |
|---|---|---|
| Unix socket `connect()` (D-Bus, snapd, MariaDB) | Cannot block — leaks service info | Mount namespace hides sockets; snapd/systemd-notify/lxd-installer explicitly blacklisted |
| Host process visibility (`ps aux`) | Shared PID namespace — all host processes visible | PID namespace isolates process list (default) |
| `/tmp` cross-session leakage | Shared host `/tmp` | `--private-tmp` gives clean tmpfs |
| Network exfiltration (`curl`, `wget`) | Shares host network — full outbound access | `--net=none` or `--netfilter` for controlled egress |
| Credential exfiltration chain | OAuth tokens readable + network open | Network isolation breaks the chain |
| Sandbox script tampering | Writable under `~/.claude/` (additive-only rules) | Mount namespace makes scripts invisible/read-only |
| `settings.json` / `CLAUDE.md` writability | Cannot make files read-only under writable parent | `CLAUDE_CONFIG_DIR` points to separate sandbox-config directory (no in-place modification) |
| Seccomp coverage | Custom BPF denylist (io_uring, kexec) | Built-in `--seccomp` + `--caps.drop=all` + `--nonewprivs` (io_uring not blocked in v0.9.72) |
| Internal state exposure | N/A | `/run/firejail/mnt/seccomp/` readable (firejail design limitation — reveals BPF filter) |

#### Admin setup for Slurm nodes

```bash
# 1. Install firejail
sudo apt install firejail

# 2. The sandbox auto-detects firejail — no user config needed.
#    Force firejail for testing:
SANDBOX_BACKEND=firejail ./sandbox-exec.sh -- bash
```

The sandbox uses `--allusers` to disable firejail's `/etc/passwd` filtering, which would otherwise remove UIDs >= `UID_MIN` (typically 1000) and break Slurm if the `slurm` user has a UID in that range (common with LDAP). This is safe because `/etc/passwd` is world-readable, `--nonewprivs` prevents setuid escalation, and `--whitelist` already hides other users' home directories.

#### HPC compatibility notes (firejail)

**`/tmp` isolation** (`--private-tmp`): Enabled by default for security. Each sandbox session gets a clean tmpfs at `/tmp`, preventing cross-session data leakage. However, this breaks inter-process communication through `/tmp` — notably MPI shared-memory transport (OpenMPI, MPICH) and NCCL inter-GPU sockets. Users running multi-rank MPI or multi-GPU workloads should set `PRIVATE_TMP=false` in `sandbox.conf`.

**Supplementary groups**: The sandbox preserves group membership (no `--nogroups`). HPC file access relies on supplementary groups (e.g., lab group for `/fh/fast/setty_m/`), so dropping them would silently break access to group-owned data.

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
| 1 | Enforce sandbox on agent-submitted Slurm jobs | Medium | Admin-enforced | Agent submitting unsandboxed Slurm jobs — job submit plugin sandboxes all jobs unless caller provides bypass token (eBPF LSM protects token from `no_new_privs` processes) |
| 2 | Admin-owned sandbox installation | Low-medium | Admin-enforced | Users weakening their own sandbox config; sandbox self-protection; systemd-run escape on Landlock nodes (disable `user@.service`) |
| 3 | Dedicated `${USER}_ai` accounts | High | Admin-enforced | Same-UID credential access; OS-level separation |
| 4 | Network isolation | Medium-high | Admin-enforced (requires #3) | Data exfiltration via network |
| 5 | Audit logging | Low-medium | Admin-enforced (requires #3) | Visibility, compliance, forensics |

Sections 1 and 2 are independent and can be deployed individually. Sections 4 and 5 require Section 3 (dedicated accounts).

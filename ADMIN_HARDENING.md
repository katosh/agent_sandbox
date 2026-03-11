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
- **firejail**: blacklists NSS daemon sockets (nscd, nslcd, sssd) so `getent passwd` only returns local users. **Caveat:** on LDAP/AD clusters where the current user exists only in LDAP (not in local `/etc/passwd`), this breaks user/group resolution entirely, which can cause Slurm failures and shell issues. Set `FILTER_PASSWD=false` in `sandbox.conf` if this applies, or prefer the bwrap backend which handles LDAP users correctly.
- **landlock**: not supported. No mount namespace to overlay files or block sockets.

With bwrap, munge and Slurm are unaffected (munge uses a unix socket, and Slurm resolves its own user from `slurm.conf`). With firejail, verify that the current user and the `slurm` service user are resolvable inside the sandbox when `FILTER_PASSWD=true`.

The Landlock backend also installs a **seccomp filter** that blocks dangerous syscalls as defense-in-depth. The filter does not block `connect()` itself (which would break munge authentication), but reduces the kernel attack surface.

#### Seccomp filter — HPC compatibility trade-offs

The Landlock seccomp filter blocks `io_uring` and `kexec_load/kexec_file_load`. The `io_uring` block is the main security value — it has a [large kernel attack surface](https://security.googleblog.com/2023/06/learnings-from-kctf-vrps-42-linux.html) and is not needed by Claude Code itself. However, it is used by tools that an agent might invoke on behalf of the user:

| Tool | Uses `io_uring` | Reference |
|---|---|---|
| [Node.js](https://nodejs.org/) / libuv | Yes — all async file I/O on modern Linux | [libuv PR #3952](https://github.com/libuv/libuv/pull/3952) |
| [RocksDB](https://rocksdb.org/) | Yes — parallel SST reads via `MultiGet()` | [io_posix.cc](https://github.com/facebook/rocksdb/blob/main/env/io_posix.cc) |
| Rust [tokio-uring](https://github.com/tokio-rs/tokio-uring) | Yes — io_uring-backed async runtime | [io-uring crate](https://github.com/tokio-rs/io-uring) |
| [QEMU](https://www.qemu.org/) | Yes — block I/O backend | [block/io_uring.c](https://github.com/QEMU/qemu/blob/master/block/io_uring.c) |
| DuckDB, SQLite | No | — |

Several other syscalls were **intentionally kept unblocked** to avoid breaking legitimate HPC and data science workloads:

| Syscall | Used by | Security risk (accepted) |
|---|---|---|
| `memfd_create` | [CUDA](https://developer.nvidia.com/cuda-toolkit) / [ROCm](https://rocm.docs.amd.com/) GPU drivers, [PyTorch](https://github.com/pytorch/pytorch/blob/main/aten/src/ATen/MapAllocator.cpp) shared memory, [Numba](https://numba.pydata.org/) JIT, [JAX](https://github.com/jax-ml/jax)/[XLA](https://openxla.org/xla) compiler, [OpenJDK ZGC](https://github.com/openjdk/jdk/blob/master/src/hotspot/os/linux/gc/z/zPhysicalMemoryBacking_linux.cpp) | Anonymous executable memory regions |
| `userfaultfd` | [Java ZGC](https://wiki.openjdk.org/display/zgc) and [Shenandoah](https://wiki.openjdk.org/display/shenandoah) GC, [QEMU live migration](https://www.qemu.org/docs/master/devel/migration.html) | Kernel race exploitation ([CVE-2021-22555](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22555) and others) |
| `process_vm_readv/writev` | [OpenMPI](https://github.com/open-mpi/ompi/blob/main/opal/mca/smsc/cma/smsc_cma_module.c) CMA transport, [strace](https://github.com/strace/strace), [gdb](https://sourceware.org/gdb/) | Cross-process memory access (mitigated by PID namespace in bwrap/firejail) |

Blocking `memfd_create` would silently break CUDA, PyTorch DataLoader (shared-memory IPC), Numba-compiled functions, and JAX/XLA-compiled models. Blocking `userfaultfd` would break Java tools using ZGC (default GC since JDK 15). Blocking `process_vm_readv` would break MPI CMA shared-memory transport used by multi-rank `sbatch` jobs. The filesystem sandbox (Landlock rules) remains the primary isolation mechanism — seccomp is defense-in-depth only.

### Choosing a backend on Ubuntu 24.04+ nodes

On Ubuntu 24.04+, AppArmor blocks unprivileged user namespaces, so bwrap doesn't work out of the box. The admin has three options:

| Option | Effort | Result |
|---|---|---|
| **Do nothing** | None | Sandbox falls back to Landlock (weakest — see gaps below) |
| **Enable bwrap via AppArmor** | Low | Strongest backend — mount namespace, PID namespace, `/tmp` isolation, self-protection |
| **Install firejail** | Low | Strong — setuid binary bypasses AppArmor; mount namespace, PID namespace, seccomp |

**Recommendation:** Enable bwrap. It provides the strongest isolation, is fully unprivileged (no setuid binary on the system), and has a significantly better security track record (4 CVEs with zero root exploits vs firejail's 18 CVEs with 12 root exploits). Firejail is a fallback if bwrap's AppArmor profile is not desired, but installing it adds a setuid-root binary to every node. See the [full CVE comparison](APPTAINER_COMPARISON.md#security-track-record) for details.

#### bwrap vs firejail comparison

| Capability | bwrap | firejail |
|---|---|---|
| Privilege model | Unprivileged (user namespaces) | Setuid root binary |
| Mount namespace | ✓ | ✓ |
| PID namespace | ✓ | ✓ |
| `/tmp` isolation | ✓ (`--tmpfs /tmp`) | ✓ (`--private-tmp`) |
| Sandbox self-protection | ✓ (scripts read-only via bind mount) | ✓ (scripts hidden via mount namespace) |
| User enumeration filtering | ✓ (overlays `/etc/passwd` + `nsswitch.conf`, LDAP-safe) | Partial (blacklists NSS sockets, but breaks LDAP-only users) |
| Slurm binary relocation | ✓ (overlays `/usr/bin/sbatch` with redirector) | PATH-based only (no overlay) |
| Seccomp | Supported but not recommended (see below) | Built-in (`--seccomp` + `--caps.drop=all`) |
| io_uring blocking | Not blocked (used by Node.js, RocksDB, Rust) | Not blocked in firejail v0.9.72 on aarch64 |
| Internal state exposure | None | `/run/firejail/mnt/seccomp/` readable (reveals BPF filter) |
| Attack surface | Minimal, no setuid | Setuid root binary on every node |
| CVE history | [4 CVEs](https://www.opencve.io/cve?search=bubblewrap), 0 root exploits, none since 2020 | [18 CVEs](https://www.cvedetails.com/vulnerability-list/vendor_id-16191/Firejail.html), 12 local root exploits ([details](APPTAINER_COMPARISON.md#firejail-18-cves-12-are-local-root)) |
| AppArmor on Ubuntu 24.04+ | Requires admin AppArmor profile | Works without admin action |

#### Enabling bwrap via AppArmor profile

Create an AppArmor profile that allows bwrap to create user namespaces:

```bash
# Find bwrap path (may be /usr/bin/bwrap or ~/.linuxbrew/bin/bwrap)
BWRAP_PATH=$(command -v bwrap)

cat > /etc/apparmor.d/bwrap-sandbox << EOF
abi <abi/4.0>,
include <tunables/global>

profile bwrap $BWRAP_PATH flags=(unconfined) {
  userns,
}
EOF

apparmor_parser -r /etc/apparmor.d/bwrap-sandbox
```

This allows bwrap (and only bwrap) to create user namespaces. Other programs remain restricted. The profile survives reboots. Verify with:

```bash
# As a regular user — should work after the profile is loaded
bwrap --ro-bind / / -- id
```

If bwrap is installed via Homebrew (`~/.linuxbrew/bin/bwrap`), use that path in the profile. The sandbox auto-detects whichever bwrap is in `$PATH`.

#### Seccomp: not recommended for bwrap

bwrap supports `--seccomp FD` to load a BPF syscall filter. The Landlock backend uses a seccomp filter as **defense-in-depth** because it lacks mount namespace isolation — seccomp compensates for weaker primary isolation. bwrap does not have this problem: mount namespace + PID namespace + `no_new_privs` already provide strong containment.

After accounting for HPC compatibility (keeping `memfd_create` for GPU/JIT, `userfaultfd` for JVM GC, `process_vm_readv` for MPI — see [trade-offs below](#seccomp-filter--hpc-compatibility-trade-offs)), the only syscalls a bwrap seccomp filter would add are:

| Syscall | Blocked by seccomp | Already mitigated by |
|---|---|---|
| `kexec_load` / `kexec_file_load` | Yes | `no_new_privs` (requires `CAP_SYS_BOOT`) |
| `io_uring_setup` / `io_uring_enter` | Yes | Nothing — real attack surface reduction |

So the practical gain is blocking `io_uring` only. However, `io_uring` is used by legitimate tools an agent may invoke — [Node.js/libuv](https://github.com/libuv/libuv/pull/3952) for all async file I/O, [RocksDB](https://github.com/facebook/rocksdb/blob/main/env/io_posix.cc) for parallel reads, and Rust [tokio-uring](https://github.com/tokio-rs/tokio-uring) runtimes. An agent running data processing pipelines or user-requested tools could break silently. The risk-benefit trade-off does not favor enabling seccomp on bwrap for general HPC use. See the [seccomp trade-offs](#seccomp-filter--hpc-compatibility-trade-offs) section for the full analysis.

### Firejail backend (alternative to bwrap)

[Firejail](https://firejail.wordpress.com/) installs **setuid root**, so it can create mount namespaces regardless of AppArmor settings. The sandbox auto-detects firejail when bwrap is unavailable (priority: bwrap > firejail > landlock).

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

### Landlock-only gaps (when neither bwrap nor firejail is available)

If neither bwrap nor firejail is available, the sandbox falls back to Landlock, which has these gaps compared to the mount-namespace backends:

| Gap | Impact |
|---|---|
| Unix socket `connect()` (D-Bus, snapd) | Cannot block — `systemd-run --user` escape viable |
| Host process visibility (`ps aux`) | All host processes visible |
| `/tmp` cross-session leakage | Shared host `/tmp` |
| Network exfiltration | Full outbound network access |
| Sandbox script tampering | Scripts writable under `~/.claude/` |
| User enumeration (LDAP) | Cannot overlay `/etc/passwd` or block NSS sockets |

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
| 2a | Enable bwrap via AppArmor (Ubuntu 24.04+) | Low | Admin-enforced | Landlock fallback limitations — mount namespace, PID namespace, `/tmp` isolation, self-protection |
| 2b | Install firejail (alternative to 2a) | Low | Admin-enforced | Same as 2a, via setuid binary instead of AppArmor profile |
| 3 | Dedicated `${USER}_ai` accounts | High | Admin-enforced | Same-UID credential access; OS-level separation |
| 4 | Network isolation | Medium-high | Admin-enforced (requires #3) | Data exfiltration via network |
| 5 | Audit logging | Low-medium | Admin-enforced (requires #3) | Visibility, compliance, forensics |

Sections 1 and 2 (including 2a/2b) are independent and can be deployed individually. On Ubuntu 24.04+, deploying 2a (AppArmor profile for bwrap) or 2b (firejail) is recommended — without either, the sandbox falls back to Landlock with significant gaps. Sections 4 and 5 require Section 3 (dedicated accounts).

---

## Sandbox vs. Apptainer Containers

For a detailed security comparison with Apptainer (the standard HPC container runtime), including default isolation tables, CVE history, architectural weaknesses, and shared gaps, see **[Apptainer Comparison](APPTAINER_COMPARISON.md)**.

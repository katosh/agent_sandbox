# Admin Hardening Options

> **Disclaimer:** This document reflects personal analysis and has not been formally reviewed by a security professional. The hardening suggestions are best-effort recommendations based on publicly available documentation and testing on a limited set of systems. The environment may differ. Review all changes with your security team before deploying to production.

The [sandbox](README.md) is fully user-space, requiring no root or admin involvement. All three backends (bubblewrap, firejail, and Landlock) provide kernel-enforced filesystem isolation for AI coding agents. Slurm access is mediated by the [chaperon](CHAPERON.md) — a zero-trust proxy that blocks Slurm authentication assets inside the sandbox (bwrap/firejail) and validates every job submission.

> **⚠ Landlock is not a full sandbox.** Landlock cannot block `AF_UNIX connect()` (not available in any Landlock ABI version as of kernel 6.11). This means: (1) the munge socket is reachable, so the **chaperon is fully bypassable** — agents can submit arbitrary unwrapped Slurm jobs; (2) if `user@.service` is running, agents can call `systemd-run --user` to **escape the sandbox entirely** — reading SSH keys, AWS credentials, and writing arbitrary files with no Landlock restrictions. **If Landlock is the only available backend, §0 (disable user@.service) and §1 (SPANK plugin) are mandatory, not optional.** Prefer bwrap or firejail whenever possible.

> **Ubuntu 24.04 consideration:** Ubuntu 24.04 enables AppArmor's restriction on unprivileged user namespaces (`kernel.apparmor_restrict_unprivileged_userns=1`), which prevents bubblewrap from working. Without admin intervention, the sandbox falls back to the **Landlock** backend, which has significant limitations (no mount namespace, no `/tmp` isolation, no sandbox self-protection, `systemd-run` escape; see the comparison table under §2). **Recommended:** Create an AppArmor profile to allow bwrap (see §2 below). This is low effort and gives users the strongest backend. Alternatively, installing firejail (setuid) also bypasses the restriction.

This document describes **improvements** that could close remaining gaps. Sections 1, 2, and 4 are independent and can be deployed individually. Sections 3 and 5 build on each other (5 requires 3; 4 has options that benefit from 3 but does not require it). They are ordered roughly from least to most effort.

> **Update:** The [chaperon](CHAPERON.md) now provides a hard Slurm boundary by default (no admin setup needed). Section 1 below is still useful as a server-side complement, but the chaperon has closed the main gap that motivated it. My current priority is **Section 2** (admin-owned installation for policy enforcement).

### Self-serve vs. admin-enforced

Each improvement falls into one of two categories:

- **Self-serve** — makes it easier for users to sandbox their agents correctly. Works when users follow the setup. Does not prevent a user (or their agent) from bypassing the protection if they try.
- **Admin-enforced** — the admin controls the enforcement mechanism. Users and agents cannot bypass it, even deliberately.

The current user-space sandbox is entirely self-serve: it protects against accidental exposure and autonomous agent misbehavior, but a user who instructs their agent to bypass it can do so. The improvements below range from making the self-serve path smoother to adding hard admin-enforced boundaries.

---

## 0. Disable systemd User Instances (Landlock Escape Prevention)

**What it solves:** Landlock cannot block `AF_UNIX connect()`. If `user@.service` is running, a sandboxed process can call `systemd-run --user` to execute commands **completely outside the sandbox** — reading `~/.ssh`, `~/.aws`, writing arbitrary files, and submitting unwrapped Slurm jobs. This is a **full sandbox escape**, not a partial bypass.

**Effort:** Minimal (one command). **Category:** Admin-enforced. **Mandatory for Landlock deployments.**

```bash
# Mask user@.service — prevents systemd user instances from starting
sudo systemctl mask user@.service

# Verify
systemctl status user@501.service   # should show "masked"
```

**What is affected by disabling:** `gpg-agent` socket activation (users doing GPG signing would need to start `gpg-agent --daemon` manually), `systemctl --user` commands, and any user-level systemd services. On HPC login nodes this is rarely an issue — most user workflows don't depend on systemd user instances.

**Note:** bwrap and firejail are **not affected** — they replace `/run` with a tmpfs (bwrap) or blacklist the socket (firejail), so the D-Bus socket is unreachable regardless.

---

## 1. Enforce Sandbox on Agent-Submitted Slurm Jobs

> **Largely superseded by the chaperon (bwrap/firejail only).** The [chaperon](CHAPERON.md) — a zero-trust Slurm proxy — provides a stronger default boundary than the token-based approach described here. On bwrap/firejail, the chaperon blocks all Slurm authentication assets (munge socket, Slurm binaries, Slurm config) inside the sandbox. **On Landlock, the chaperon is fully bypassable** — Landlock cannot block `AF_UNIX connect()`, so the munge socket is reachable and `/usr/bin/sbatch` is directly callable. **This SPANK plugin section is mandatory for Landlock deployments with Slurm.**

**What it solves:** Server-side enforcement of sandbox wrapping on Slurm jobs, using a job submit plugin and an eBPF LSM-protected bypass token. Complements the chaperon by adding a second enforcement layer at the Slurm controller. Users who do not use the sandbox are unaffected — their workflow does not change.

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

## 4. Network Controls

**What it solves:** The current sandbox shares the host network stack. The [chaperon](CHAPERON.md) removed the dependency on in-sandbox network access for Slurm on bwrap/firejail (munge socket is blocked, all Slurm communication goes through FIFOs). On Landlock, the munge socket remains accessible — see §1. However, the agent still has unrestricted outbound network — it can reach any host the user can, using the same institutional IP.

Agents legitimately need general web access: reading documentation, downloading papers (often through institutional proxy/IP for paywall access), installing packages, cloning repos. The goal is not to cut off network access, but to **route agent traffic through a controllable path** where agent-specific policies can be applied — blocking certain services, logging traffic, or rate-limiting — without breaking research workflows.

**Threat model:** The concern is not bulk data transfer (the agent already has API access to exfiltrate context). It's about preventing the agent from reaching services it shouldn't: SSH to an unsandboxed shell, internal REST APIs, cloud metadata endpoints (169.254.169.254), or other agents' sandboxes. General HTTPS to the open web (research, PyPI, GitHub, paper access) is typically fine.

**Effort:** Varies by option (see below). **Category:** Admin-enforced (Options A, B) or self-serve (Option C).

### Option A: Per-UID iptables/nftables Rules

**Requires:** Dedicated `${USER}_ai` accounts (Section 3). **Effort:** Medium.

The simplest admin approach — iptables `--uid-owner` matches on the agent's UID, so no changes to the sandbox itself are needed. Rules selectively block dangerous services while allowing general web access:

```bash
# Allow loopback and established connections
iptables -A OUTPUT -m owner --uid-owner alice_ai -o lo -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner alice_ai -m state --state ESTABLISHED,RELATED -j ACCEPT

# --- Block dangerous destinations first (order matters: checked before ACCEPT) ---
# Block SSH out (prevents escape to unsandboxed shell)
iptables -A OUTPUT -m owner --uid-owner alice_ai -p tcp --dport 22 -j DROP

# Block cloud metadata endpoint
iptables -A OUTPUT -m owner --uid-owner alice_ai -d 169.254.169.254 -j DROP

# Block internal network ranges (adjust to your environment)
iptables -A OUTPUT -m owner --uid-owner alice_ai -d 10.0.0.0/8 -j DROP
iptables -A OUTPUT -m owner --uid-owner alice_ai -d 172.16.0.0/12 -j DROP

# --- Allow general access (after blocks) ---
# DNS, HTTPS, HTTP — research, API, packages, papers via institutional IP
iptables -A OUTPUT -m owner --uid-owner alice_ai -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner alice_ai -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner alice_ai -p tcp --dport 80 -j ACCEPT

# Drop everything else (non-HTTP protocols to external hosts)
iptables -A OUTPUT -m owner --uid-owner alice_ai -j DROP
```

Rules are evaluated top-to-bottom: dangerous destinations are dropped first, then HTTP/HTTPS to anywhere else is allowed, and non-web protocols (raw TCP, SMTP, etc.) are dropped at the end. This preserves research workflows (paper access, package installation, web search) while blocking known-dangerous paths.

**Pros:** Transparent to the sandboxed process — no proxy configuration needed; institutional IP preserved for paper access; easy to audit and extend. **Cons:** Requires dedicated accounts (Section 3); can't inspect HTTPS content (only destination IP/port); a determined agent could exfiltrate via any allowed HTTPS connection.

### Option B: cgroup + nftables Matching

**Requires:** Admin (nftables, cgroup setup). **Does not require** dedicated accounts. **Effort:** Medium.

Modern nftables (≥ 0.9.3, Linux ≥ 4.10) can match packets by cgroup membership instead of UID. The sandbox launches processes inside a dedicated cgroup slice, and nftables applies the same targeted-block policy as Option A — but keyed on cgroup membership rather than UID:

```bash
# Launch sandbox inside a cgroup slice (sandbox-exec.sh would do this)
systemd-run --user --scope --slice=sandbox.slice -- sandbox-exec.sh ...
```

```nft
table inet sandbox_filter {
    # Destinations to block for sandboxed agents
    set blocked_nets {
        type ipv4_addr; flags interval
        elements = {
            169.254.169.254,    # cloud metadata
            10.0.0.0/8,         # internal network (adjust to environment)
            172.16.0.0/12       # internal network
        }
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Match only sandboxed processes via cgroup
        # (cgroup path varies by distro — verify with: cat /proc/self/cgroup)
        socket cgroupv2 level 2 "user.slice/user-1001.slice/user@1001.service/sandbox.slice" \
            ip daddr @blocked_nets drop

        # Block SSH out from sandbox (prevents escape to unsandboxed shell)
        socket cgroupv2 level 2 "user.slice/user-1001.slice/user@1001.service/sandbox.slice" \
            meta l4proto tcp th dport 22 drop

        # Everything else from sandbox is allowed (research, API, packages)
    }
}
```

**Pros:** No dedicated accounts needed — cgroup membership identifies sandboxed processes; transparent to the process (no proxy config); institutional IP preserved; default-allow keeps research workflows intact; works with any backend. **Cons:** cgroup path hierarchy varies by distro and systemd version — the nftables rules must match the actual cgroup tree; `systemd-run --user --scope` may require `loginctl enable-linger` for the user; multi-user deployments need per-user rules or a common slice.

### Option C: Network Namespace + Policy Proxy

**Does not require** dedicated accounts or admin. **Effort:** Medium-high (self-serve).

Bwrap supports `--unshare-net`, which places the sandbox in a network namespace with **no interfaces at all**. All network access is then restored through a proxy running outside the sandbox, listening on a Unix socket (bind-mounted in, like the chaperon FIFOs). The proxy becomes a policy enforcement point — it can allow general web access while blocking specific destinations, logging requests, or applying rate limits.

```
sandbox-exec.sh
  ├── start policy-proxy on Unix socket (outside sandbox)
  │     ├── allows: general HTTPS/HTTP (research, papers, packages)
  │     ├── blocks: SSH, internal networks, metadata endpoint
  │     └── logs: all CONNECT requests (destination + timestamp)
  ├── --unshare-net (no network interfaces inside sandbox)
  ├── bind-mount proxy socket into sandbox
  ├── export HTTPS_PROXY=http+unix:///path/to/proxy.sock
  └── enter sandbox
        └── all outbound traffic → proxy socket → policy check → internet
```

The proxy could be a lightweight HTTP CONNECT proxy (e.g., a small Go binary, or Python's `http.server` with CONNECT support) with a deny-list of destinations. Since it sees every connection request, it can:

- **Block by destination**: SSH (port 22), internal IPs, metadata endpoints
- **Log**: record every outbound connection for audit
- **Rate-limit**: prevent bulk exfiltration
- **Preserve institutional IP**: the proxy runs on the host, so outbound connections use the institutional IP — paper access through publisher paywalls works as expected

**Pros:** No admin involvement; no dedicated accounts; strongest isolation (zero network interfaces — abstract Unix sockets unreachable); full visibility into outbound connections; policy is code (version-controlled, testable). **Cons:** All tools must respect `HTTPS_PROXY` / `http_proxy` (most do — curl, pip, conda, git, wget — but some don't); the proxy is an additional component to build and maintain; not available on Landlock (no network namespace support); adds a hop for every connection.

### Comparison

| | Accounts? | Admin? | Transparent? | Abstract sockets? | Logging? | Landlock? |
|---|---|---|---|---|---|---|
| **A: UID iptables** | Yes (#3) | Yes | Yes | No | No (add auditd) | Yes |
| **B: cgroup nftables** | No | Yes | Yes | No | No (add auditd) | Yes |
| **C: netns + proxy** | No | No | No (`HTTPS_PROXY`) | Blocked | Built-in | No |

All three options use a **default-allow** policy for general web access (research, packages, papers) with **targeted blocks** on dangerous services (SSH, internal networks, metadata endpoints). The difference is where enforcement happens: in the kernel (A, B) or in a userspace proxy (C).

**Recommendation:** Option B is the best balance for admin-managed deployments — no dedicated accounts needed, transparent to processes, and works with all backends. Option C provides the deepest control (logging, rate-limiting, policy-as-code) and requires no admin, but needs proxy configuration. Option A is simplest if dedicated accounts (Section 3) are already deployed.

---

## 5. Audit Logging

**What it solves:** Visibility into what the agent did — which files it accessed, which jobs it submitted, and what commands it ran. Useful for compliance, forensics, and debugging.

**Built-in chaperon logging:** The chaperon already logs every proxied Slurm request with full arguments, working directory, script size, and all security denials (`_sandbox_deny` / `_sandbox_warn`). Logs are per-session files in `~/.local/state/agent-sandbox/chaperon/`, auto-pruned by age and total size. Configure `CHAPERON_LOG_LEVEL` and `CHAPERON_LOG_RETAIN_DAYS` in `sandbox.conf`. This covers Slurm-level audit without any admin setup. See [CHAPERON.md](CHAPERON.md#logging) for details.

**For system-level audit** (file access, process execution, network connections), dedicated accounts and auditd are needed:

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
| 1 | [Enforce sandbox on Slurm jobs](#1-enforce-sandbox-on-agent-submitted-slurm-jobs) *(largely superseded by [chaperon](CHAPERON.md))* | Medium | Admin-enforced | Server-side complement to the chaperon — job submit plugin sandboxes all jobs unless caller provides bypass token (eBPF LSM protects token from `no_new_privs` processes). Optional if the chaperon meets your needs |
| 2 | [Admin-owned sandbox installation](#2-admin-owned-sandbox-installation) ([details](ADMIN_INSTALL.md)) | Low-medium | Admin-enforced | Users weakening config; sandbox self-protection; multi-level config with post-merge validation; [backend selection](ADMIN_INSTALL.md#choosing-a-backend-on-ubuntu-2404) (bwrap via AppArmor recommended, firejail alternative); [seccomp trade-offs](ADMIN_INSTALL.md#seccomp-filter--hpc-compatibility); [Landlock fallback gaps](ADMIN_INSTALL.md#landlock-fallback) |
| 3 | [Dedicated `${USER}_ai` accounts](#3-dedicated-user_ai-accounts) | High | Admin-enforced | Same-UID credential access; OS-level separation |
| 4 | [Network controls](#4-network-controls) | Medium | Admin-enforced or self-serve | Agent-specific network policy (block SSH escape, internal services, metadata endpoint) while preserving web access for research — three options: UID iptables (requires #3), cgroup nftables (no #3), or netns + policy proxy (no admin) |
| 5 | [Audit logging](#5-audit-logging) | Low-medium | Admin-enforced (requires #3) | Visibility, compliance, forensics |

Sections 1, 2, and 4 are independent and can be deployed individually. Section 1 is optional if the [chaperon](CHAPERON.md) meets your Slurm enforcement needs — it adds server-side defense-in-depth. Section 2 includes backend selection for Ubuntu 24.04+ — an AppArmor profile for bwrap (recommended) or firejail avoids falling back to Landlock. Section 4 applies agent-specific network policy (default-allow for research, targeted blocks on SSH/internal services) with three options — Option C (netns + proxy) requires no admin or dedicated accounts. Section 5 requires Section 3 (dedicated accounts).

---

## Sandbox vs. Apptainer Containers

For a detailed security comparison with Apptainer (the standard HPC container runtime), including default isolation tables, CVE history, architectural weaknesses, and shared gaps, see **[Apptainer Comparison](APPTAINER_COMPARISON.md)**.

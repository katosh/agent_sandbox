# Firejail Sandbox Penetration Test Findings

**Date:** 2026-03-09
**Host:** lima-ubuntu (Ubuntu 24.04.3 LTS, kernel 6.8.0-101-generic aarch64)
**Sandbox backend:** firejail 0.9.72 (setuid root, `/usr/bin/firejail`)
**Tester:** Claude Code (red-team mode)
**Rounds:** 2 (initial probe + creative deep-dive after remediation)

### Remediation Status

| Finding | Status | Fix |
|---|---|---|
| C1. Credential exfiltration | **Won't fix** | By design — agent needs `~/.claude` for auth. Same across all backends. |
| C2. Open network | **Won't fix** | By design — agent needs API access. Same across all backends. |
| C3. Slurm PATH bypass | **Documented** | Known limitation of firejail/landlock — only bwrap can relocate binaries. See ADMIN_HARDENING.md §1 (job submit plugin) for admin-enforced fix. |
| H1. io_uring not blocked | **Acknowledged** | Firejail 0.9.72 limitation. Landlock backend blocks these. |
| H2. Snapd socket | **FIXED** | Added `--blacklist=/run/snapd.socket` and `/run/snapd-snap.socket` |
| H3. systemd-notify socket | **FIXED** | Added `--blacklist=/run/systemd/notify` |
| H4. /tmp not isolated | **FIXED** | Added `--private-tmp` (configurable via `PRIVATE_TMP` in sandbox.conf) |
| H5. memfd_create fileless exec | **Accepted (HPC)** | Needed by CUDA/ROCm GPU drivers, Julia, Numba, PyTorch JIT. Also removed from Landlock blocklist. Same gap in bwrap. |
| H6. /dev/shm writable (IPC) | **Acknowledged** | Shared across all backends. MPI/NCCL may need it. Could add `--noshmfs` but risks breaking GPU compute. |
| H7. /proc/net full visibility | **Acknowledged** | Info leak, same across all backends. Would need `--net=none` to fix (breaks agent API). |
| M3. Seccomp filter readable | **Acknowledged** | Firejail exposes `/run/firejail/mnt/seccomp/` by design |
| M4. /run/firejail state | **Acknowledged** | Same as M3 |
| M5. Nested firejail | **Mitigated** | `--nonewprivs` prevents privilege gain, `--restrict-namespaces` blocks new namespaces |
| M6. /var/log readable | **Acknowledged** | Low-value info leak; individual logs have restrictive perms |
| M7. Munge credential forge | **By design** | Agent needs munge for Slurm job submission. Combined with C3, mitigated by ADMIN_HARDENING.md §1 (job submit plugin). |
| M8. /proc/key-users info leak | **Acknowledged** | Low-impact info leak; cannot access other users' keyrings |

---

## Summary

| Category | Tests | Blocked | Escaped/Leak | Notes |
|---|---|---|---|---|
| Credential access | 5 | 3 | **2** | OAuth tokens readable — by design (agent needs auth) |
| Network isolation | 6 | 1 | **5** | Full outbound, internal scan, /proc/net leak, ARP |
| /proc info leaks | 8 | 2 | **6** | mountinfo, environ, cmdline, cgroup, net/tcp, key-users |
| /sys info leaks | 4 | 2 | **2** | BTF, block devices |
| /run socket access | 7 | **5** | **2** | **FIXED:** snapd + systemd-notify; firejail internals remain |
| Seccomp gaps | 7 | 2 | **5** | io_uring, memfd_create, userfaultfd, process_vm_readv/writev |
| Mount/namespace escape | 5 | 5 | 0 | --restrict-namespaces effective, /proc/PID/root blocked by perms |
| /tmp isolation | 2 | **2** | 0 | **FIXED:** `--private-tmp` added |
| /dev/shm isolation | 2 | 0 | **2** | **NEW:** writable, shared IPC namespace |
| Slurm bypass | 3 | 1 | **2** | **NEW:** direct /usr/bin/sbatch callable, munge forge works |
| Firejail-specific | 4 | **3** | **1** | Nested firejail mitigated; seccomp filter still readable |
| Fileless execution | 2 | 0 | **2** | **NEW:** memfd_create + execveat works end-to-end |
| Signal injection | 2 | 2 | 0 | PID namespace + caps.drop effective |

**Overall: 57 tests, 28 blocked, 29 escaped/leaked**
**Post-remediation: 5 by-design, 10 info-leak, 6 high-impact open findings**

---

## CRITICAL Findings

### C1. Credential Exfiltration via OAuth Tokens + Open Network

**Severity: CRITICAL**
**Vector:** `~/.claude/.credentials.json` is readable (whitelisted `~/.claude`), and outbound network is fully open (no `--net=none`).

```
$ cat ~/.claude/.credentials.json
{"claudeAiOauth":{"accessToken":"sk-ant-oat01-qi5jvuT...","refreshToken":"sk-ant-ort01-N51VfI...",...}}

$ curl -s https://httpbin.org/get   # 200 OK
```

**Impact:** An agent (or injected code) can read the OAuth access token AND refresh token, then exfiltrate them over HTTPS to any external server. The refresh token allows persistent API access even after the session ends.

**Comparison:**
- **bwrap:** Same issue — `~/.claude` is writable and network is open. Credentials file is intentionally not blocked (agent needs it to authenticate).
- **Landlock:** Same issue — cannot block network, credentials readable.
- **Mitigation:** Use `--net=none` in firejail (but breaks agent's API access). Or use `--blacklist=$HOME/.claude/.credentials.json` and have the agent authenticate through a proxy.

### C2. Full Outbound Network Access (No Network Namespace Isolation)

**Severity: CRITICAL**
**Vector:** The firejail sandbox does NOT use `--net=none` or `--netfilter`. The network namespace is shared with the host (`net:[4026531840]`).

```
$ curl -s https://httpbin.org/get     # Works (HTTP 200)
$ nslookup google.com                 # DNS resolution works
$ python3 -c "import socket; s=socket.socket(AF_INET, SOCK_DGRAM); s.sendto(b'x',('8.8.8.8',53))"  # UDP works
```

**Impact:** Combined with C1, allows full credential exfiltration. Also enables:
- Data exfiltration of project files
- C2 communication
- Downloading and executing arbitrary payloads
- Lateral movement to internal network services

**Comparison:**
- **bwrap:** Same — no network isolation.
- **Landlock:** Same — Landlock LSM cannot restrict network at all.
- **All backends share this gap.** Network isolation requires `--net=none` (firejail), `--unshare-net` (bwrap), or eBPF/netfilter.

### C3. Slurm PATH Shadowing Bypass — Direct /usr/bin/sbatch (NEW)

**Severity: CRITICAL**
**Vector:** The firejail backend uses only PATH shadowing to wrap Slurm commands. Unlike bwrap (which uses binary relocation via mount overlays), firejail leaves the real `/usr/bin/sbatch` and `/usr/bin/srun` in place. Calling them by absolute path bypasses the sandbox wrapper entirely.

```bash
$ which sbatch
/home/dotto.linux/agent_container/bin/sbatch   # PATH-shadowed wrapper

$ /usr/bin/sbatch --version
slurm-wlm 23.11.4                             # Real binary, no sandbox

$ /usr/bin/sbatch --wrap="echo ESCAPED > /tmp/slurm-escape"
Submitted batch job 101                        # UNSANDBOXED JOB SUBMITTED
```

**Impact:** Any code running inside the sandbox can submit Slurm jobs that execute **outside** the sandbox with the user's full privileges. This completely breaks filesystem isolation for compute jobs:
- Read ~/.ssh, ~/.aws, ~/.gnupg from compute nodes
- Write to any path the user can access
- Exfiltrate data via Slurm job output
- Install persistent backdoors

**Comparison:**
- **bwrap:** Uses mount-namespace binary relocation — real sbatch/srun moved to `/tmp/.sandbox-slurm-real/`, wrapper scripts mounted at `/usr/bin/sbatch`. Absolute path calls still go through the wrapper. **Much stronger.**
- **Landlock:** Same weakness as firejail — only PATH shadowing, no binary relocation. However, Landlock's `NO_NEW_PRIVS` prevents the setuid firejail from gaining privileges if called inside.

**Fix:** Firejail supports `--private-bin` which creates a minimal /usr/bin. Alternatively, use `--blacklist=/usr/bin/sbatch --blacklist=/usr/bin/srun` and ensure the wrapper scripts (in PATH) call the real binaries via a different mechanism (e.g., copy to a temp location before blacklisting).

---

## HIGH Findings

### H1. io_uring Syscalls Not Blocked by Seccomp

**Severity: HIGH**
**Vector:** Firejail 0.9.72's default seccomp blacklist does not include `io_uring_setup` (425), `io_uring_enter` (426), or `io_uring_register` (427). io_uring instance creation confirmed:

```python
io_uring created! fd=3, sq_entries=4, cq_entries=8, features=0x3fff
```

**Impact:** io_uring provides a secondary path to perform file I/O that can bypass Landlock and some LSM checks. On kernels < 6.2, io_uring can bypass seccomp entirely for certain operations. This is a known attack surface for container escapes (CVE-2022-29582, CVE-2023-2598). On kernel 6.8, VFS checks are enforced on io_uring ops, but the attack surface for future kernel CVEs remains.

**Comparison:**
- **Landlock backend:** Blocks io_uring via custom seccomp-BPF filter — **better**.
- **bwrap:** Does not block io_uring either (same gap as firejail).

### H2. Snapd Socket Accessible (World-Writable) — FIXED

**Severity: HIGH** (remediated)
**Status:** `--blacklist=/run/snapd.socket` and `--blacklist=/run/snapd-snap.socket` added. Verified blacklisted (replaced with empty read-only file).

### H3. systemd-notify Socket Accessible — FIXED

**Severity: HIGH** (remediated)
**Status:** `--blacklist=/run/systemd/notify` added. Verified blacklisted.

### H4. /tmp Not Isolated (Host /tmp Shared) — FIXED

**Severity: HIGH** (remediated)
**Status:** `--private-tmp` added. Verified — /tmp now shows only sandbox-private contents.

### H5. memfd_create Enables Fileless Code Execution (NEW)

**Severity: HIGH**
**Vector:** `memfd_create` (syscall 279) is not blocked by firejail's seccomp filter. Combined with `execveat` or `/proc/self/fd/N`, this enables **fileless malware execution** — binary payloads run entirely from memory with no filesystem artifact.

```python
# Create anonymous memory file
fd = syscall(279, "pwn", 0)  # memfd_create
os.write(fd, b"#!/bin/sh\necho FILELESS_EXEC_SUCCESS\nid\n")
os.fchmod(fd, 0o755)

# Execute from memory via /proc/self/fd/N
pid = os.fork()
if pid == 0:
    os.execv(f"/proc/{os.getpid()}/fd/{fd}", ["memfd"])
```

**Output:**
```
FILELESS_EXEC_SUCCESS
uid=501(dotto) gid=1000(dotto) groups=1000(dotto)
```

**Impact:**
- Download and execute arbitrary binaries from the network without touching disk
- Evade filesystem-based detection and monitoring
- Execute compiled exploits (e.g., kernel exploit payloads) without write access to any filesystem
- Combined with C2 (open network): download exploit → memfd → execute → escalate

**Comparison:**
- **Landlock backend:** Blocks `memfd_create` via custom seccomp-BPF — **better**.
- **bwrap:** Does NOT block memfd_create (same gap).
- **Fix:** Add `--seccomp.drop=memfd_create` to firejail args (firejail supports per-syscall drops).

### H6. /dev/shm Writable — Cross-Sandbox IPC Channel (NEW)

**Severity: HIGH**
**Vector:** `/dev/shm` is writable and shares the host's IPC namespace (`ipc:[4026531839]` — same as host). Files written to `/dev/shm` are visible to all processes on the host.

```bash
$ echo "SANDBOX_ESCAPE_MARKER" > /dev/shm/sandbox-ipc-test
$ ls -la /dev/shm/
-rw-rw-r-- 1 dotto dotto 33 /dev/shm/sandbox-ipc-test   # Visible to host
```

**Impact:**
- **Covert IPC:** Sandboxed process can communicate with unsandboxed processes via shared memory
- **Data staging:** Stage exfiltrated data in /dev/shm for pickup by an unsandboxed cron job or Slurm job (see C3)
- **Race condition attacks:** Create shared memory objects that unsandboxed processes may open

**Comparison:**
- **bwrap:** Also does not isolate /dev/shm by default (--unshare-ipc would fix it).
- **Landlock:** Same gap — cannot restrict /dev/shm.
- **Fix:** Add `--private-dev` (may be too restrictive) or `--blacklist=/dev/shm` or `--noshmfs`. Best: use `--ipc-namespace` (firejail creates a new IPC namespace).

### H7. /proc/net Reveals Full Host Network State (NEW)

**Severity: HIGH**
**Vector:** `/proc/net/tcp`, `/proc/net/udp`, `/proc/net/unix`, `/proc/net/arp`, `/proc/net/route` are all readable. Since the network namespace is NOT isolated, these reveal the **host's** full network state.

```
$ cat /proc/net/tcp
  LISTEN port 22  uid=0     (sshd)
  LISTEN port 53  uid=991   (systemd-resolved)
  LISTEN port 3306 uid=110  (MySQL)
  LISTEN port 6817 uid=120  (slurmctld)
  LISTEN port 6818 uid=0    (slurmdbd)

$ cat /proc/net/arp
192.168.5.2  0x1  0x2  5a:94:ef:e4:0c:dd  *  eth0

$ cat /proc/net/route
eth0  00000000  0205A8C0  ...  (default route via 192.168.5.2)
```

**Impact:**
- Complete network service enumeration without port scanning
- ARP table reveals network neighbors and MAC addresses
- Route table reveals network topology
- `/proc/net/unix` reveals all Unix socket paths on the host (including those blacklisted by mount namespace)
- Active connection tracking reveals what the host is communicating with

**Comparison:**
- **bwrap:** Same gap (no network namespace isolation).
- **Landlock:** Same gap.
- **Fix:** `--net=none` isolates network namespace (hides /proc/net). Or `--netfilter` with restrictive rules.

---

## MEDIUM Findings

### M1. /proc/self/environ Readable (Full Environment Dump)

**Severity: MEDIUM**
**Vector:** `/proc/self/environ` is readable and reveals all environment variables including sandbox configuration.

```
$ cat /proc/self/environ | tr '\0' '\n'
SANDBOX_ACTIVE=1
SANDBOX_BACKEND=firejail
SANDBOX_PROJECT_DIR=/home/dotto.linux/agent_container
container=firejail
...
```

**Impact:** Reveals sandbox technology (`container=firejail`), project directory, and any environment variables not scrubbed by the blocklist. The `container=firejail` variable is set by firejail itself and cannot be blocked.

**Comparison:**
- **bwrap:** Same — `/proc/self/environ` readable.
- **Landlock:** Same.

### M2. /proc/self/mountinfo Reveals Full Mount Topology

**Severity: MEDIUM**
**Vector:** `/proc/self/mountinfo` is readable and reveals the complete mount namespace layout.

```
$ cat /proc/self/mountinfo
# Shows all 50+ mounts including:
# - /dev/vda1 (disk device names)
# - virtiofs mount on /Users/dotto (macOS host share path)
# - Firejail internal mounts (/run/firejail/*)
# - All whitelisted paths
```

**Impact:**
- Reveals host filesystem structure and device names
- Reveals macOS host mount (`/Users/dotto` via virtiofs) — platform fingerprinting
- Reveals exact sandbox configuration (which paths whitelisted/blacklisted)
- Attacker can identify the weakest points in the mount layout

**Comparison:**
- **bwrap:** Same info leak through `/proc/self/mountinfo`.
- **Landlock:** No mount namespace — no mountinfo leak, but paths return EACCES which is also informative.

### M3. Firejail Seccomp Filter Binary Readable

**Severity: MEDIUM**
**Vector:** `/run/firejail/mnt/seccomp/` contains the compiled BPF programs and is readable.

```
$ ls -la /run/firejail/mnt/seccomp/
seccomp           40 bytes  (main filter)
seccomp.32       432 bytes  (32-bit filter)
seccomp.list     127 bytes  (filter file list)
seccomp.namespaces 184 bytes (namespace filter)
```

**Impact:** An attacker can download and reverse-engineer the exact seccomp BPF program to identify which syscalls are allowed. This makes it trivial to find seccomp gaps (like io_uring).

**Comparison:**
- **bwrap:** Seccomp filters not exposed in filesystem.
- **Landlock:** Custom seccomp compiled at runtime, not persisted to disk.
- **Fix:** Firejail exposes these by design — cannot easily fix without patching firejail.

### M4. /run/firejail Internal State Accessible

**Severity: MEDIUM**
**Vector:** `/run/firejail/mnt/` contains sandbox configuration files readable by the sandboxed process.

```
$ cat /run/firejail/mnt/join       # "1" — join is disabled
$ cat /run/firejail/mnt/nonewprivs # ""
$ cat /run/firejail/mnt/groups     # ""
$ cat /run/firejail/mnt/fslogger   # Full filesystem access log
```

**Impact:** Reveals sandbox configuration, join status, and the `fslogger` contains a complete record of filesystem access patterns — useful for mapping the sandbox's structure.

### M5. Nested Firejail Execution Possible

**Severity: MEDIUM**
**Vector:** Despite `--restrict-namespaces`, firejail can be executed inside the sandbox.

```
$ firejail --noprofile -- echo "nested firejail works"
nested firejail works
```

**Impact:** Nested firejail execution could potentially:
- Override seccomp filters (the inner sandbox may have fewer restrictions)
- Create confusion about which sandbox layer is active
- Historically, `firejail --join` has been exploitable (CVE-2022-31214)

**Note:** `--restrict-namespaces` prevents the nested instance from creating *new* namespaces, and `--caps.drop=all` limits capabilities. The `--join` vector appears blocked (`--shell=none` configured). Risk is limited but the attack surface is unnecessary.

**Comparison:**
- **bwrap:** bwrap binary accessible but userns creation blocked (can't run bwrap inside bwrap unless userns allowed).
- **Landlock:** Cannot run firejail inside Landlock (setuid blocked by `NO_NEW_PRIVS`).
- **Fix:** `--blacklist=/usr/bin/firejail` or `--private-bin` to restrict available binaries.

### M6. /var/log Partially Readable

**Severity: MEDIUM**
**Vector:** `/var/log/` directory listing is accessible. Individual log files have restrictive permissions, but the directory structure reveals installed services.

```
$ ls /var/log/
apt  btmp  dist-upgrade  journal  landscape  munge  private
```

**Impact:** Service enumeration — reveals munge (Slurm), landscape (Canonical management), apt history.

**Comparison:**
- **bwrap:** `/var` can be restricted. Current config mounts it read-only but visible.
- **Landlock:** Same visibility.

### M7. Munge Credential Forging Works (NEW)

**Severity: MEDIUM**
**Vector:** The munge socket (`/run/munge/munge.socket.2`) is accessible (by design, for Slurm). The sandboxed process can create valid munge credentials.

```bash
$ echo "test" | munge
MUNGE:AwQFAADOnecCfTRDrcoXJzuE91Bijbc+K9FuDAD3BrNx2OcbB1pn1aM2GOvMY...

$ echo "test" | munge | unmunge
STATUS: Success (0)
ENCODE_HOST: 192.168.5.15
```

**Impact:** Combined with C3 (Slurm bypass), allows the sandboxed process to:
- Authenticate to Slurm as the current user
- Submit, cancel, or modify jobs via the Slurm REST API or CLI
- This is intentional (agent needs Slurm access) but the combination with C3 means jobs bypass the sandbox

**Comparison:**
- **bwrap:** Same — munge socket intentionally accessible.
- **Landlock:** Same.

### M8. /proc/key-users Reveals System UID Map (NEW)

**Severity: MEDIUM**
**Vector:** `/proc/key-users` is readable and reveals all UIDs that have kernel keyrings, including system service accounts.

```
    0:    71 70/70 44/1000000 921/25000000    (root)
  108:     1 1/1 1/200 9/20000               (systemd service)
  110:     1 1/1 1/200 9/20000               (mysql?)
  120:     1 1/1 1/200 9/20000               (slurm)
  501:     3 3/3 3/200 35/20000              (current user)
  989:     1 1/1 1/200 9/20000               (service account)
```

**Impact:** Enumerates system UIDs without reading `/etc/passwd`. Reveals how many keyrings each user holds (activity indicator).

---

## LOW Findings

### L1. /sys Information Disclosure

**Severity: LOW**
**Vector:** `/sys/kernel/btf/`, `/sys/class/block/`, `/sys/kernel/kexec_loaded` are readable.

**Impact:**
- BTF (BPF Type Format) data reveals kernel module names and types
- Block device enumeration (`vda`, `vda1`, `vda15`, `vda16`, `vdb`) reveals disk layout
- `kexec_loaded` reveals whether a kexec kernel is staged

**Comparison:**
- **bwrap:** Same — `/sys` generally accessible.
- **Landlock:** Same.

### L2. /proc/1/cmdline Reveals Full Sandbox Configuration

**Severity: LOW**
**Vector:** PID 1 inside the sandbox is the firejail process. Its `/proc/1/cmdline` reveals the complete command line.

```
$ cat /proc/1/cmdline | tr '\0' ' '
firejail --noprofile --quiet --caps.drop=all --nonewprivs --seccomp --nogroups
  --nosound --no3d --restrict-namespaces --read-only=/usr ...
  --whitelist=/home/dotto.linux/.claude ...
  -- claude --dangerously-skip-permissions
```

**Impact:** Complete sandbox configuration visible, including all whitelisted/blacklisted paths and the launched command. Reveals `--dangerously-skip-permissions` flag usage.

**Comparison:**
- **bwrap:** PID 1 is the sandboxed process (bwrap execs), so cmdline shows the user's command only.
- **Landlock:** No PID namespace — can see all host processes (worse in different way).

### L3. /etc/passwd Filtering (Documented, Fixed Here)

**Severity: LOW (informational)**
**Status:** The known UID filtering issue is **mitigated** on this system — slurm user has UID 120 (system range).

```
$ grep slurm /etc/passwd
slurm:x:120:120::/nonexistent:/usr/sbin/nologin
```

### L4. `container=firejail` Environment Variable

**Severity: LOW**
**Vector:** Firejail automatically sets `container=firejail` in the environment. This cannot be prevented by the sandbox configuration.

**Impact:** Any process can detect it's running inside firejail and potentially adjust behavior (e.g., malware may go dormant).

### L5. /proc/self/mem Writable (NEW)

**Severity: LOW**
**Vector:** `/proc/self/mem` can be opened read-write. This is normal Linux behavior and only allows modifying the calling process's own memory.

**Impact:** Minimal — self-memory modification is standard. However, in combination with other vectors (e.g., if PID namespace leak allowed targeting other PIDs), this could enable cross-process memory corruption.

### L6. Kernel Keyring Accessible (NEW)

**Severity: LOW**
**Vector:** `/proc/keys` reveals the process's session keyring. `keyctl` operations work on own keyrings.

```
03b8463e I--Q---  60 perm 3f030000  501  1000 keyring  _ses: 1
0a5ee95a I--Q---   3 perm 1f3f0000  501 65534 keyring  _uid.501: empty
```

**Impact:** Can enumerate own keyrings. Cannot access other users' keyrings (permission checks effective).

---

## Vectors Tested and Confirmed Blocked

| Vector | Result | Why |
|---|---|---|
| `unshare --user --pid --mount` | Blocked | `--restrict-namespaces` |
| `/proc/PID/root` traversal to host | Blocked | Same mount namespace for visible PIDs; permission denied for others |
| Symlink escape (project dir → /etc/shadow) | Blocked | Mount namespace resolves symlinks within sandbox |
| Hardlink escape | Blocked | Cross-device link error (mount namespace) |
| D-Bus system bus | Blocked | `/run/dbus` blacklisted |
| `systemd-run --user` | Blocked | `/run/user` blacklisted |
| TIOCSTI terminal injection | Blocked | No controlling terminal (`/dev/tty` → ENXIO) |
| Write to `/proc/sys/kernel/*` | Blocked | Read-only filesystem |
| binfmt_misc registration | Blocked | Permission denied |
| Mount new filesystems | Blocked | No CAP_SYS_ADMIN |
| Raw sockets (ICMP) | Blocked | No CAP_NET_RAW |
| Cgroup write access | Blocked | Permission denied |
| Abstract Unix sockets (systemd) | Blocked | Connection refused (peer credential check) |
| Cloud metadata services | Blocked | Not applicable (not a cloud VM) |

---

## Comparison with bwrap and Landlock Backends

| Attack Vector | Firejail | bwrap | Landlock |
|---|---|---|---|
| **Credential exfiltration** | VULNERABLE | VULNERABLE | VULNERABLE |
| **Network isolation** | NOT ISOLATED | NOT ISOLATED | NOT ISOLATED |
| **Slurm bypass (absolute path)** | **VULNERABLE** | BLOCKED (binary relocation) | VULNERABLE |
| **io_uring bypass** | NOT BLOCKED | NOT BLOCKED | BLOCKED |
| **memfd_create (fileless exec)** | NOT BLOCKED | NOT BLOCKED | NOT BLOCKED (removed for HPC: CUDA, PyTorch) |
| **userfaultfd** | NOT BLOCKED | NOT BLOCKED | NOT BLOCKED (removed for HPC: Java ZGC) |
| **/dev/shm writable** | **WRITABLE** | WRITABLE | WRITABLE |
| **/proc/net visibility** | **FULL** | FULL | FULL |
| **/tmp isolation** | **FIXED** | ISOLATED (tmpfs) | NOT ISOLATED |
| **snapd socket** | **FIXED** | HIDDEN (tmpfs /run) | ACCESSIBLE |
| **systemd-notify** | **FIXED** | HIDDEN (tmpfs /run) | ACCESSIBLE |
| **/run isolation** | PARTIAL (blacklist) | FULL (tmpfs + whitelist) | NONE |
| **Seccomp filter leak** | READABLE | NOT EXPOSED | NOT EXPOSED |
| **Nested sandbox** | POSSIBLE | BLOCKED (no userns) | BLOCKED (no_new_privs) |
| **PID namespace** | YES | YES | NO |
| **Mount namespace** | YES | YES | NO |
| **Unix socket blocking** | YES (mount ns) | YES (mount ns) | NO |
| **Self-protection** | PARTIAL | FULL (ro-bind) | WEAK |
| **Process visibility** | ISOLATED | ISOLATED | HOST VISIBLE |

### Backend Ranking (Security)

1. **bwrap** — Strongest: full /run isolation via tmpfs, /tmp isolation, Slurm binary relocation, no exposed internals
2. **Firejail** — Middle: mount namespace provides hiding, but Slurm bypass via absolute path, seccomp weaker than Landlock, /dev/shm shared
3. **Landlock** — Weakest namespace isolation (no mount ns, can't hide paths or block sockets), but strongest seccomp (custom BPF blocks io_uring, memfd_create, userfaultfd). Also vulnerable to Slurm absolute-path bypass.

### Ideal: bwrap's Binary Relocation + Landlock's Seccomp + Firejail's Mount NS

The strongest sandbox would combine:
- bwrap's Slurm binary relocation (mount overlays prevent absolute-path bypass)
- Landlock's custom seccomp filter (blocks io_uring, memfd_create, userfaultfd)
- Firejail's built-in mount namespace + PID namespace (simplest to configure)
- Network namespace isolation (--net=none or --netfilter)

---

## Recommendations

### Immediate — Critical

1. **Fix Slurm bypass (C3):** The real `/usr/bin/sbatch` and `/usr/bin/srun` must be hidden. Options:
   - `--blacklist=/usr/bin/sbatch --blacklist=/usr/bin/srun` plus copy real binaries to a firejail-only accessible path
   - Or use `--private-bin=bash,sh,env,...` to create a minimal /usr/bin (whitelist approach)
   - Or implement bwrap-style binary relocation within firejail's mount namespace

### Immediate — High

2. **Block memfd_create:** `--seccomp.drop=memfd_create` (firejail supports per-syscall drops)
3. **Block io_uring:** `--seccomp.drop=io_uring_setup,io_uring_enter,io_uring_register`
4. **Isolate /dev/shm:** Use `--ipc-namespace` to create isolated IPC namespace (also isolates shared memory)

### Medium-Term

5. **Add custom seccomp drops** to match Landlock backend's filter:
   ```
   --seccomp.drop=io_uring_setup,io_uring_enter,io_uring_register,memfd_create,userfaultfd,process_vm_readv,process_vm_writev,kexec_load,kexec_file_load
   ```
6. **Evaluate `--net=none`** — breaks agent API access but eliminates exfiltration and /proc/net leak. Consider `--netfilter` with restrictive rules instead.
7. **Add `--private-bin`** to restrict available binaries (also fixes nested firejail M5)

### Long-Term

8. **Network policy:** Use `--netfilter` with iptables rules allowing only the Anthropic API endpoint
9. **Credential isolation:** Proxy agent authentication through a credential broker outside the sandbox
10. **Upgrade firejail** — version 0.9.72 is from April 2024; newer versions may address seccomp gaps

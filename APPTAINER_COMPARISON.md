# Sandbox vs. Apptainer Containers

> **Disclaimer:** This is not a formal security audit or a complete vulnerability assessment. It reflects personal research and best-effort analysis of publicly available documentation, CVE databases, and source code. Claims may be incomplete or outdated. If you are making security decisions for your organization, consult your security team and verify the findings independently.

Docker requires root and is not available on shared HPC clusters. The natural comparison is therefore with [Apptainer](https://apptainer.org/) (formerly Singularity), the standard container runtime in HPC. This document puts the sandbox's security posture in perspective by comparing the two approaches head-to-head.

## Design philosophy

Apptainer was designed for **reproducibility**: running the same software stack across different clusters. Its documented philosophy is ["integration over isolation"](https://apptainer.org/docs/admin/main/admin_quickstart.html), meaning containers share the host PID space, network, IPC, and home directory by default. This is deliberate, since HPC workloads need access to GPUs, InfiniBand, parallel filesystems, and Slurm.

This sandbox was designed for **containment**: restricting what AI coding agents (Claude Code, Codex, Gemini CLI, Aider, OpenCode) can see and modify on the host. Its philosophy is isolation-first, with selective holes for what the agent needs (project directory, Slurm via chaperon proxy, agent-specific API keys via config.conf profiles).

These are opposite defaults. An Apptainer container is wide-open unless you lock it down; the sandbox is locked-down unless you open it up.

## Default isolation comparison

| Isolation layer | This sandbox (bwrap) | Apptainer (default) | Apptainer (`--containall`) |
|---|---|---|---|
| Mount namespace | ✓ | ✓ | ✓ |
| PID namespace | ✓ | ✗ (opt-in `--pid`) | ✓ |
| Network namespace | ✗ (shared) | ✗ (shared) | ✗ (shared) |
| IPC namespace | ✗ (shared) | ✗ (opt-in `--ipc`) | ✓ |
| `/tmp` isolation | ✓ (private tmpfs) | ✗ ([bind-mounts host `/tmp`](https://apptainer.org/docs/user/main/bind_paths_and_mounts.html)) | ✓ |
| `/run` isolation | ✓ (private tmpfs) | ✗ | ✗ |
| Home directory | Blank tmpfs + selective re-mount | [Bind-mounts `$HOME`](https://apptainer.org/docs/user/main/bind_paths_and_mounts.html) | Isolated (empty `$HOME`) |
| CWD bind mount | Project dir only | Full CWD | CWD |
| Host `/proc` | Isolated (unshare-pid) | Full host `/proc` | Isolated |
| Env var filtering | ✓ (explicit names + credential patterns: SSH_*, *_TOKEN, CI_*, etc.) | ✗ (inherits host environment) | Partial (`--cleanenv`) |
| Passwd/group filtering | ✓ (system accounts + current user) | Generates container-local files, but includes user info | Same |
| Seccomp | ✓ (bwrap: generated BPF; firejail: --seccomp.drop; landlock: custom) | ✗ ([not applied by default](https://apptainer.org/docs/user/main/security_options.html)) | ✗ |
| io_uring blocked | ✓ (all three backends) | ✗ | ✗ |
| Agent config isolation | ✓ (merged instruction files, kernel-enforced read-only) | n/a | n/a |
| Slurm integration | Chaperon proxy (scoped sbatch/scancel/squeue, CWD validation) | Transparent (no wrapping) | Transparent |

The sandbox provides **stronger default containment** in every category except network namespace (neither isolates the network by default, since both need it for munge/Slurm). Apptainer's `--containall` closes some gaps (PID, IPC, `/tmp`, home) but still does not filter environment variables, does not isolate `/run`, and does not apply seccomp.

## Security track record

All three sandbox backends and Apptainer have public CVE histories. The differences are stark:

| Tool | Total CVEs | Critical | High | Root exploits | Last CVE |
|---|---|---|---|---|---|
| **Bubblewrap** | [4](https://www.opencve.io/cve?search=bubblewrap) | 0 | 3 | 0 | 2020 |
| **Firejail** | [18](https://www.cvedetails.com/vulnerability-list/vendor_id-16191/Firejail.html) | 2 | 13 | 12 | 2022 |
| **Landlock** | 0 | 0 | 0 | 0 | n/a |
| **Apptainer/Singularity** | [18+](https://www.opencve.io/cve?vendor=sylabs&product=singularity) | 2 | ~5 | ~4 | 2025 |

### Bubblewrap (4 CVEs, none since 2020)

Bubblewrap has a remarkably clean record. Its ~1,500-line C codebase is small and auditable. The most commonly cited issue, [CVE-2017-5226](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5226) (TIOCSTI sandbox escape, scored Critical), was actually a Linux kernel/terminal design flaw, not a bubblewrap bug. The kernel fixed it in Linux 6.2. The remaining three CVEs were a dumpable process issue (fixed in 0.1.3), a `/tmp` mount-point race (fixed in 0.3.3), and a setuid-mode privilege issue (fixed in 0.4.1).

### Firejail (18 CVEs, 12 are local root)

Firejail's record is the worst of the group. 12 of its 18 CVEs are direct privilege escalation to root, all exploiting the setuid-root architecture. Notable examples:

| CVE | Severity | Issue |
|---|---|---|
| [CVE-2022-31214](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31214) | High | Local root exploit via `--join` logic. Published PoC works on Debian, Arch, Fedora, openSUSE. |
| [CVE-2020-17368](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-17368) | Critical (9.8) | Shell metacharacter injection via `--output`, enabling command injection |
| [CVE-2019-12499](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12499) | High | Sandboxed code can truncate the firejail binary on the host |
| [CVE-2016-10122](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10122) | High | Environment variables not cleaned (LD_PRELOAD), enabling root shell |

A [2017 oss-security audit](https://seclists.org/oss-sec/2017/q1/25) found "a lot of low hanging exploitable fruit" and concluded that the setuid-root model is fundamentally problematic. A [2022 SUSE security disclosure](https://www.openwall.com/lists/oss-security/2022/06/08/10) demonstrated a full local root exploit chain using CVE-2022-31214. This is the same class of risk as Apptainer's setuid helper, but more frequent and more severe.

### Apptainer/Singularity (18+ CVEs)

Apptainer's CVEs are more varied in severity (more medium-rated issues around image verification and build permissions), but include serious setuid-related privilege escalation:

| CVE | Severity | Issue |
|---|---|---|
| [CVE-2023-30549](https://github.com/apptainer/apptainer/security/advisories/GHSA-j4rf-7357-f4cg) | High | Setuid mode lets unprivileged users trigger kernel filesystem driver bugs (ext4 use-after-free) on user-writable image data, leading to privilege escalation |
| [CVE-2023-38496](https://github.com/apptainer/apptainer/security/advisories/GHSA-mmx5-32m4-wxvx) | High | Ineffective privilege drop allows root-privileged code to run on attacker-controlled config |
| [CVE-2020-15229](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-15229) | High | Path traversal in `unsquashfs`, allowing arbitrary host file overwrite |
| [CVE-2025-65105](https://github.com/apptainer/apptainer/security/advisories/GHSA-j3rw-fx6g-q46j) | Moderate | Container can disable `--security apparmor:` and `--security selinux:` options |

The advisory for CVE-2023-30549 notes that "many ext4 filesystem vulnerabilities similar to the one in CVE-2022-1184 continue to be found, and most of them do not ever have a CVE assigned." The setuid model systematically elevates moderate kernel bugs to exploitable privilege escalation.

### Takeaway

The setuid-root architecture is the common thread. Both firejail and Apptainer's setuid mode have been repeatedly exploited for local root. Bubblewrap avoids this entirely by using unprivileged user namespaces, and Landlock avoids it by being a pure kernel LSM with no userspace privileged component.

When choosing a sandbox backend, this matters: **bwrap has 4 CVEs and zero root exploits; firejail has 18 CVEs and 12 root exploits.** Firejail provides strong isolation features (seccomp, caps dropping) but installs a setuid-root binary on every node. On systems where bwrap is available (or can be enabled via AppArmor), it is the safer choice. See the [bwrap vs firejail comparison](ADMIN_INSTALL.md#bwrap-vs-firejail-comparison) in Admin Install.

## Architectural weaknesses unique to Apptainer

**Admin restrictions are unenforceable in rootless mode.** The Apptainer admin docs explicitly state that the `limit container` and `allow container` directives "are not effective if unprivileged user namespaces are enabled." On systems with unprivileged user namespaces (the default), a user can compile their own Apptainer binary with any configuration and bypass all administrative restrictions. The admin cannot enforce policy when the user controls the binary.

**ECL (Execution Control List) is ineffective in rootless mode.** The container signing and verification mechanism (ECL) is ["only effectively applied when Apptainer is running in setuid mode."](https://apptainer.org/docs/admin/main/configfiles.html) In rootless mode, users can run any container image regardless of signatures.

**SIF image verification has had gaps.** [CVE-2020-13845](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-13845) showed that ECL enforcement compared fingerprints against unsigned SIF descriptors rather than cryptographically validated signatures, a verification bypass.

The sandbox has none of these issues. It does not rely on image verification, does not have a rootless/setuid split in enforcement, and policy is enforced by kernel mechanisms (mount namespace, Landlock LSM) that the user cannot bypass without privilege.

## Shared weaknesses and honest gaps

Neither approach provides complete isolation. Both share these weaknesses:

| Gap | This sandbox | Apptainer |
|---|---|---|
| **Network not isolated** | Shared host network (all backends). Agent can exfiltrate data via HTTP, DNS, or SSH. | Shared host network by default. `--net` available but breaks Slurm/munge. |
| **Abstract Unix sockets** | Accessible since bwrap/firejail share the network namespace. `@/org/freedesktop/...` reachable. | Accessible (shared network namespace). |
| **SSH escape** | If `~/.ssh` is exposed, agent can SSH to localhost for an unsandboxed shell. | `$HOME` bind-mounted by default, so `~/.ssh` is exposed unless `--contain` is used. |
| **`/dev/shm` shared** | Writable and not isolated by default. Covert cross-sandbox IPC possible. | Writable and shared by default. |
| **`memfd_create`** | Not blocked (needed by CUDA, PyTorch, JAX). Docker's default seccomp profile also allows it. `userfaultfd` and `io_uring` are blocked by all three backends via seccomp. | Not blocked (no seccomp by default). |
| **Slurm wrapping** | Soft boundary. Munge auth available, PATH shadowing bypassable (see [Admin Hardening §1](ADMIN_HARDENING.md#1-enforce-sandbox-on-agent-submitted-slurm-jobs)). | No wrapping at all. Slurm fully accessible. |

The sandbox has additional backend-specific gaps documented in the [README's Known Limitations](README.md#known-limitations):

- **Landlock** cannot block Unix socket `connect()` (D-Bus/systemd escape), has no PID namespace, no mount namespace (BLOCKED_FILES and PRIVATE_TMP ineffective), and no LDAP user enumeration filtering.
- **bwrap** seccomp filter is generated at runtime (`generate-seccomp.py`) — verify it loads (no "seccomp" warnings on stderr).
- **All backends** leave IPC namespace and network namespace shared by default. `/dev/shm` and abstract Unix sockets are covert channels between sandbox sessions.

The key difference is not that the sandbox has no gaps (it does), but that its gaps are smaller and better characterized. Apptainer's default posture exposes the entire host environment; the sandbox's default posture hides everything and selectively re-exposes what is needed. Both require admin hardening for strong isolation (see [Admin Hardening §§1-5](ADMIN_HARDENING.md#summary)).

## What Apptainer does better

**Reproducible environments.** Apptainer containers bundle the entire OS userland: a specific Python version, CUDA toolkit, library stack. The sandbox does not provide environment isolation; it restricts the agent within the host environment. If the goal is running a known-good software stack, Apptainer is the right tool.

**Image distribution and caching.** SIF images can be built once, signed, and distributed across clusters. The sandbox has no equivalent and relies on the host's installed software.

**GPU passthrough.** Apptainer has mature `--nv` (NVIDIA) and `--rocm` (AMD) GPU passthrough. The sandbox passes through GPUs implicitly (no mount isolation of `/dev` by default), which works but is less controlled.

**Community and ecosystem.** Apptainer has broad HPC adoption, extensive documentation, and integration with registries (Docker Hub, ORAS, library://). The sandbox is purpose-built for AI coding agents.

The two approaches are complementary, not competing. An agent running inside the sandbox can submit Slurm jobs that use Apptainer containers. The sandbox controls what the agent can access on the host, while Apptainer provides the reproducible environment inside the job. The sandbox's Slurm wrappers ([Admin Hardening §1](ADMIN_HARDENING.md#1-enforce-sandbox-on-agent-submitted-slurm-jobs)) ensure that submitted jobs are also sandboxed, regardless of whether they use Apptainer internally.

## Bottom line

For **AI agent containment on HPC**, the sandbox provides stronger default isolation than Apptainer with less complexity. Apptainer's "integration over isolation" design means that a default container is barely more isolated than running directly on the host: it shares PID space, network, home directory, `/tmp`, and environment variables. Achieving comparable containment with Apptainer requires `--containall --cleanenv --pid` plus a custom seccomp profile, a configuration that most HPC users do not use and that breaks many workflows.

The sandbox achieves this containment out of the box, with HPC-specific accommodations (munge passthrough, Slurm wrapping, supplementary groups, LDAP filtering) built in. With the bwrap backend (recommended), the attack surface is minimal: no setuid helper, no image parsing, no SIF verification code, and only 4 CVEs in a decade (none since 2020). The firejail backend provides comparable isolation but carries a worse CVE record than Apptainer itself (see [Security track record](#security-track-record)).

Neither tool is a complete solution. The sandbox does not isolate the network (an agent can exfiltrate data over HTTP or SSH), does not block `memfd_create` (needed by CUDA/PyTorch, also allowed by Docker's default seccomp), and its Slurm wrapping is a soft boundary. Apptainer shares all of these gaps and more. Both benefit from the admin hardening options described in [Admin Hardening §§1-5](ADMIN_HARDENING.md#summary): dedicated accounts, network isolation, and audit logging close gaps that neither tool addresses alone. The trade-off between them is clear: the sandbox does not provide environment reproducibility, Apptainer does not provide agent containment, and each is the right tool for its purpose.

#!/usr/bin/env python3
"""generate-seccomp — Output a raw seccomp-bpf filter for bwrap --seccomp.

Usage:
    generate-seccomp.py > /tmp/bpf.bin

Generates a denylist BPF filter blocking dangerous syscalls (io_uring,
userfaultfd, kexec) and writes raw struct sock_filter[] to stdout — the
format expected by bwrap --seccomp FD (no sock_fprog header).

Supports x86_64 and aarch64.  Requires only the Python 3 standard library
(struct module for byte packing).  The kernel requirement is seccomp-bpf
support (CONFIG_SECCOMP_FILTER, kernel >= 3.17), which is universally
available on modern distributions.

This script is intentionally self-contained with no imports from other
sandbox modules, so it can be maintained independently.
"""

import platform
import struct
import sys

# --- BPF instruction encoding ---
# Source: linux/bpf_common.h
#   https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf_common.h

BPF_LD  = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_W   = 0x00
BPF_ABS = 0x20
BPF_JEQ = 0x10
BPF_K   = 0x00

# struct sock_filter { __u16 code; __u8 jt; __u8 jf; __u32 k; }  (8 bytes)
# Source: linux/filter.h
#   https://github.com/torvalds/linux/blob/master/include/uapi/linux/filter.h
# Packed as "HBBI" (unsigned short, unsigned char, unsigned char, unsigned int).

# --- Seccomp constants ---
# Source: linux/seccomp.h
#   https://github.com/torvalds/linux/blob/master/include/uapi/linux/seccomp.h

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000  # | errno

# struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; }
SECCOMP_DATA_NR   = 0   # syscall number (offset 0)
SECCOMP_DATA_ARCH = 4   # audit architecture (offset 4)

# --- Audit architecture constants ---
# Source: linux/audit.h
#   https://github.com/torvalds/linux/blob/master/include/uapi/linux/audit.h
# Computed as: EM_<arch> | __AUDIT_ARCH_64BIT (0x80000000) | __AUDIT_ARCH_LE (0x40000000)
#   x86_64:  EM_X86_64  (62)  | 0xC0000000 = 0xC000003E
#   aarch64: EM_AARCH64 (183) | 0xC0000000 = 0xC00000B7
AUDIT_ARCH_X86_64  = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

# --- Blocked syscalls (bwrap subset) ---
#
# Syscall numbers verified against kernel source:
#   x86_64:  arch/x86/entry/syscalls/syscall_64.tbl
#     https://github.com/torvalds/linux/blob/master/arch/x86/entry/syscalls/syscall_64.tbl
#   aarch64: include/uapi/asm-generic/unistd.h (aarch64 uses the generic table)
#     https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h
#
# All of these syscalls are also blocked by Docker's default seccomp
# profile (default-deny, none are in the allowlist):
#   https://github.com/moby/profiles/blob/main/seccomp/default.json
#
# Bwrap already provides PID namespace isolation, so ptrace and
# process_vm_readv/writev are not blocked here (unlike the Landlock
# backend which lacks PID namespace).
#
# === Original three (large new/attack-surface) ===
#
# io_uring:     kernel 5.1+.  Exposes a large, rapidly-evolving kernel
#               attack surface.  Docker 25.0+ blocks it by default
#               (https://github.com/moby/moby/pull/46762).
#               No HPC workload requires it — I/O falls back to normal
#               read/write syscalls.
#
# userfaultfd:  lets userspace stall kernel page faults — a standard
#               primitive for exploiting kernel race conditions
#               (CVE-2021-22555, CVE-2024-1086).  Only needed by QEMU
#               postcopy and CRIU lazy restore.  Kernel restricts
#               unprivileged access since 5.11.
#
# kexec_load/kexec_file_load:  load a new kernel.  Requires
#               CAP_SYS_BOOT (blocked by no_new_privs), but defense
#               in depth — seccomp catches it even if caps leak.
#
# === Additional defense-in-depth set (cap-denied already) ===
#
# Each of the following is already blocked by capability checks or
# equivalent kernel gating when invoked from an unprivileged sandbox
# (see the reachability probe summary in pentest/round2_findings.md).
# Adding them here is pure belt-and-suspenders: if a kernel bug or
# configuration mistake ever leaked the gating capability, the
# seccomp filter would still reject the call.  Zero observable effect
# on HPC/ML workloads.
#
# bpf:          loads eBPF programs.  Requires CAP_BPF/CAP_SYS_ADMIN
#               for most operations.  Only bcc/bpftrace/tracing tools
#               use it; no HPC workload does.  Large kernel-resident
#               verifier is a recurring CVE source.
#
# mount / umount2 / pivot_root:  filesystem-namespace mutation.
#               CAP_SYS_ADMIN-gated; useless outside privileged
#               contexts.  Defense in depth against userns + cap-leak
#               chains.
#
# reboot:       halts the machine.  CAP_SYS_BOOT-gated.
#
# swapon / swapoff:  swap-space manipulation.  CAP_SYS_ADMIN-gated.
#
# personality:  sets execution-domain quirks (e.g. legacy
#               READ_IMPLIES_EXEC).  Some values are used by the
#               kernel exploit-mitigation bypass CVE-2022-1499 and
#               similar.  Docker restricts to "safe" values; we deny
#               outright since no legitimate user code calls it.
#
# acct:         BSD process accounting.  CAP_SYS_PACCT-gated.
#
# quotactl:     filesystem quota control.  CAP_SYS_ADMIN-gated.
#
# kcmp:         compares two processes' resources (kernel pointers,
#               file descriptors).  Requires CAP_SYS_PTRACE on cross-
#               UID targets; same-UID inspection can be abused for
#               kernel-pointer leaks.

_BLOCKED_SYSCALLS = {
    AUDIT_ARCH_X86_64: {
        # --- Original attack-surface trio ---
        "io_uring_setup":    425,   # syscall_64.tbl: 425 common io_uring_setup
        "io_uring_enter":    426,   # syscall_64.tbl: 426 common io_uring_enter
        "io_uring_register": 427,   # syscall_64.tbl: 427 common io_uring_register
        "kexec_load":        246,   # syscall_64.tbl: 246 64     kexec_load
        "kexec_file_load":   320,   # syscall_64.tbl: 320 common kexec_file_load
        "userfaultfd":       323,   # syscall_64.tbl: 323 common userfaultfd
        # --- Defense-in-depth (already cap-denied) ---
        "bpf":               321,   # syscall_64.tbl: 321 common bpf
        "mount":             165,   # syscall_64.tbl: 165 common mount
        "umount2":           166,   # syscall_64.tbl: 166 common umount2
        "pivot_root":        155,   # syscall_64.tbl: 155 common pivot_root
        "reboot":            169,   # syscall_64.tbl: 169 common reboot
        "swapon":            167,   # syscall_64.tbl: 167 common swapon
        "swapoff":           168,   # syscall_64.tbl: 168 common swapoff
        "personality":       135,   # syscall_64.tbl: 135 common personality
        "acct":              163,   # syscall_64.tbl: 163 common acct
        "quotactl":          179,   # syscall_64.tbl: 179 common quotactl
        "kcmp":              312,   # syscall_64.tbl: 312 common kcmp
    },
    AUDIT_ARCH_AARCH64: {
        # --- Original attack-surface trio ---
        "io_uring_setup":    425,   # asm-generic/unistd.h: __NR_io_uring_setup    425
        "io_uring_enter":    426,   # asm-generic/unistd.h: __NR_io_uring_enter    426
        "io_uring_register": 427,   # asm-generic/unistd.h: __NR_io_uring_register 427
        "kexec_load":        104,   # asm-generic/unistd.h: __NR_kexec_load        104
        "kexec_file_load":   294,   # asm-generic/unistd.h: __NR_kexec_file_load   294
        "userfaultfd":       282,   # asm-generic/unistd.h: __NR_userfaultfd       282
        # --- Defense-in-depth (already cap-denied) ---
        "bpf":               280,   # asm-generic/unistd.h: __NR_bpf               280
        "mount":              40,   # asm-generic/unistd.h: __NR_mount              40
        "umount2":            39,   # asm-generic/unistd.h: __NR_umount2            39
        "pivot_root":         41,   # asm-generic/unistd.h: __NR_pivot_root         41
        "reboot":            142,   # asm-generic/unistd.h: __NR_reboot            142
        "swapon":            224,   # asm-generic/unistd.h: __NR_swapon            224
        "swapoff":           225,   # asm-generic/unistd.h: __NR_swapoff           225
        "personality":        92,   # asm-generic/unistd.h: __NR_personality        92
        "acct":               89,   # asm-generic/unistd.h: __NR_acct               89
        "quotactl":           60,   # asm-generic/unistd.h: __NR_quotactl           60
        "kcmp":              272,   # asm-generic/unistd.h: __NR_kcmp              272
    },
}


def _bpf_stmt(code, k):
    """Encode a BPF statement: struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }"""
    return struct.pack("HBBI", code, 0, 0, k)


def _bpf_jump(code, k, jt, jf):
    """Encode a BPF jump instruction."""
    return struct.pack("HBBI", code, jt, jf, k)


def build_seccomp_bpf(blocked, audit_arch):
    """Build raw BPF instructions (array of struct sock_filter) for a seccomp denylist.

    Returns bytes — no sock_fprog header, just the filter instructions.
    This is the format expected by bwrap --seccomp FD.
    """
    insns = b""

    # Load architecture
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH)
    # If arch doesn't match, skip to ALLOW
    insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch, 1, 0)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

    # Load syscall number
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR)

    # For each blocked syscall: if match, jump to DENY
    blocked_list = list(blocked.values())
    for i, nr in enumerate(blocked_list):
        remaining = len(blocked_list) - i - 1
        insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, remaining + 1, 0)

    # Default: allow
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    # Block: return EPERM (1)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1)

    return insns


def main():
    machine = platform.machine()
    if machine == "x86_64":
        audit_arch = AUDIT_ARCH_X86_64
    elif machine == "aarch64":
        audit_arch = AUDIT_ARCH_AARCH64
    else:
        print(f"Error: unsupported architecture {machine}", file=sys.stderr)
        sys.exit(1)

    blocked = _BLOCKED_SYSCALLS.get(audit_arch, {})
    if not blocked:
        print(f"Error: no blocked syscalls for {machine}", file=sys.stderr)
        sys.exit(1)

    bpf = build_seccomp_bpf(blocked, audit_arch)

    # Write raw binary to stdout — must use buffer mode for null bytes
    sys.stdout.buffer.write(bpf)
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()

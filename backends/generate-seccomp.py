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

# --- BPF instruction encoding (linux/bpf_common.h) ---

BPF_LD  = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_W   = 0x00
BPF_ABS = 0x20
BPF_JEQ = 0x10
BPF_K   = 0x00

# --- Seccomp constants (linux/seccomp.h) ---

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000  # | errno

# struct seccomp_data offsets
SECCOMP_DATA_NR   = 0   # syscall number
SECCOMP_DATA_ARCH = 4   # audit architecture

# Audit architectures (linux/audit.h)
AUDIT_ARCH_X86_64  = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

# --- Blocked syscalls (bwrap subset) ---
#
# Bwrap already provides PID namespace isolation, so ptrace and
# process_vm_readv/writev are not blocked here (unlike the Landlock
# backend which lacks PID namespace).
#
# io_uring:     kernel 5.1+.  Exposes a large, rapidly-evolving kernel
#               attack surface.  Docker 25.0+ blocks it by default.
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

_BLOCKED_SYSCALLS = {
    AUDIT_ARCH_X86_64: {
        "io_uring_setup":    425,
        "io_uring_enter":    426,
        "io_uring_register": 427,
        "kexec_load":        246,
        "kexec_file_load":   320,
        "userfaultfd":       323,
    },
    AUDIT_ARCH_AARCH64: {
        "io_uring_setup":    425,
        "io_uring_enter":    426,
        "io_uring_register": 427,
        "kexec_load":        104,
        "kexec_file_load":   294,
        "userfaultfd":       282,
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

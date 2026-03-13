#!/usr/bin/env python3
"""landlock-sandbox — Apply Landlock LSM filesystem restrictions, then exec a command.

Usage:
    landlock-sandbox.py --check
    landlock-sandbox.py [--ro PATH]... [--rw PATH]... [--no-seccomp] -- CMD [ARGS...]

Landlock restricts filesystem access for the current process and all descendants.
Unlike bwrap, it does not create a new mount namespace — restricted paths return
EACCES instead of ENOENT.

A basic seccomp filter is also applied (unless --no-seccomp is given) to block
dangerous syscalls like io_uring_setup and process_vm_writev that are not needed
by normal workloads but expand the kernel attack surface.
"""

import argparse
import ctypes
import ctypes.util
import os
import struct
import sys

# --- Landlock constants (from linux/landlock.h) ---

LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

# Filesystem access rights (ABI v1)
LANDLOCK_ACCESS_FS_EXECUTE     = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE  = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE   = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR    = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR  = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR   = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR    = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG    = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK   = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO   = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK  = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM    = 1 << 12
# ABI v2
LANDLOCK_ACCESS_FS_REFER       = 1 << 13
# ABI v3
LANDLOCK_ACCESS_FS_TRUNCATE    = 1 << 14

LANDLOCK_RULE_PATH_BENEATH = 1

# Syscall numbers (same on x86_64 and aarch64 for kernel >= 5.13)
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_ADD_RULE       = 445
SYS_LANDLOCK_RESTRICT_SELF  = 446

PR_SET_NO_NEW_PRIVS = 38

# --- Seccomp constants (from linux/seccomp.h, linux/bpf_common.h) ---

SECCOMP_SET_MODE_FILTER = 1
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000  # | errno
SECCOMP_RET_LOG   = 0x7FFC0000  # allow but log (for debugging)

# BPF instruction encoding
BPF_LD  = 0x00
BPF_JMP = 0x05
BPF_RET = 0x06
BPF_W   = 0x00
BPF_ABS = 0x20
BPF_JEQ = 0x10
BPF_K   = 0x00

# struct seccomp_data offsets
SECCOMP_DATA_NR = 0       # syscall number
SECCOMP_DATA_ARCH = 4     # audit architecture

# Audit architectures
AUDIT_ARCH_X86_64  = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

# Dangerous syscalls to block, keyed by audit architecture.
# These expand the kernel attack surface without being needed by
# normal scientific computing workloads.
#
# HPC compatibility: the following syscalls are intentionally NOT blocked
# because they are used by legitimate HPC software:
#
#   memfd_create     — GPU drivers (CUDA, ROCm), JIT compilers (Julia,
#                      Numba, PyTorch JIT), some Python C extensions.
#                      Risk: can create anonymous executable memory regions.
#
#   userfaultfd      — BLOCKED. Lets attackers stall kernel threads to
#                      exploit race conditions (CVE-2021-22555, CVE-2024-1086).
#                      Only used by QEMU postcopy migration and CRIU lazy
#                      restore — neither relevant for HPC. Java ZGC uses
#                      colored pointers, not userfaultfd. Docker blocks it
#                      by default. Kernel restricts unprivileged access
#                      since 5.11 (vm.unprivileged_userfaultfd=0).
#
#   process_vm_readv — MPI shared-memory transport (cross-rank data
#   process_vm_writev  transfer on same node), debuggers (gdb, strace).
#                      Risk: can read/write memory of same-UID processes
#                      (mitigated by PID namespace in bwrap/firejail).
#                      Blocked on Landlock because it has no PID namespace.
#                      If MPI CMA transport is needed, remove from blocklist.
#
#   ptrace           — debugger attach. Without PID namespace (Landlock),
#                      an agent could ptrace sibling processes to extract
#                      memory (e.g., bypass tokens from sbatch wrappers).
#                      Blocked on Landlock; bwrap/firejail have PID ns.
#
# memfd_create is NOT blocked (GPU compute, CUDA, JIT compilers).
# The filesystem sandbox (Landlock rules) remains the primary isolation.
_BLOCKED_SYSCALLS = {
    AUDIT_ARCH_X86_64: {
        "io_uring_setup":      425,
        "io_uring_enter":      426,
        "io_uring_register":   427,
        "kexec_load":          246,
        "kexec_file_load":     320,
        "userfaultfd":         323,
        "ptrace":              101,
        "process_vm_readv":    310,
        "process_vm_writev":   311,
    },
    AUDIT_ARCH_AARCH64: {
        "io_uring_setup":      425,
        "io_uring_enter":      426,
        "io_uring_register":   427,
        "kexec_load":          104,
        "kexec_file_load":     294,
        "userfaultfd":         282,
        "ptrace":              117,
        "process_vm_readv":    270,
        "process_vm_writev":   271,
    },
}


def _bpf_stmt(code, k):
    """Encode a BPF statement: struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }"""
    return struct.pack("HBBI", code, 0, 0, k)


def _bpf_jump(code, k, jt, jf):
    """Encode a BPF jump instruction."""
    return struct.pack("HBBI", code, jt, jf, k)



def install_seccomp_filter():
    """Install a seccomp-bpf filter blocking dangerous syscalls.

    Returns True if installed, False if seccomp is not available.
    The filter uses a denylist approach: block specific dangerous syscalls,
    allow everything else. This is less restrictive than a full allowlist
    but avoids breaking legitimate tools (Slurm, conda, module, etc.).
    """
    import platform
    machine = platform.machine()
    if machine == "x86_64":
        audit_arch = AUDIT_ARCH_X86_64
    elif machine == "aarch64":
        audit_arch = AUDIT_ARCH_AARCH64
    else:
        print(f"Warning: seccomp not supported on {machine}, skipping", file=sys.stderr)
        return False

    blocked = _BLOCKED_SYSCALLS.get(audit_arch, {})
    if not blocked:
        return False

    # Build BPF program:
    #   1. Load architecture, verify it matches
    #   2. Load syscall number
    #   3. Compare against each blocked syscall
    #   4. Default: allow
    insns = b""

    # Load arch
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH)
    # Jump over the rest if arch doesn't match (allow everything on unknown arch)
    insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch, 1, 0)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

    # Load syscall number
    insns += _bpf_stmt(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR)

    # For each blocked syscall: if match, return EPERM
    blocked_list = list(blocked.values())
    for i, nr in enumerate(blocked_list):
        # If this is the last one, jf goes to ALLOW (1 insn away)
        # Otherwise jf goes to next comparison
        remaining = len(blocked_list) - i - 1
        insns += _bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, remaining + 1, 0)

    # Default: allow
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    # Block: return EPERM (1)
    insns += _bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1)

    # struct sock_fprog { unsigned short len; struct sock_filter *filter; }
    n_insns = len(insns) // 8
    filter_buf = ctypes.create_string_buffer(insns)

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    prog = SockFprog(n_insns, ctypes.addressof(filter_buf))

    # __NR_seccomp: 317 on x86_64, 277 on aarch64
    NR_SECCOMP = 317 if audit_arch == AUDIT_ARCH_X86_64 else 277

    # PR_SET_NO_NEW_PRIVS must be set before seccomp (already done by Landlock)
    ret = libc().syscall(
        ctypes.c_long(NR_SECCOMP),
        ctypes.c_ulong(SECCOMP_SET_MODE_FILTER),
        ctypes.c_ulong(0),
        ctypes.byref(prog),
    )
    if ret < 0:
        errno = ctypes.get_errno()
        if errno == 38:  # ENOSYS
            print("Warning: seccomp not supported by kernel, skipping", file=sys.stderr)
        else:
            print(f"Warning: seccomp filter install failed (errno={errno}), skipping", file=sys.stderr)
        return False

    return True


def _get_libc():
    path = ctypes.util.find_library("c")
    if not path:
        print("Error: libc not found", file=sys.stderr)
        sys.exit(1)
    return ctypes.CDLL(path, use_errno=True)


_libc = None

def libc():
    global _libc
    if _libc is None:
        _libc = _get_libc()
    return _libc


def detect_abi_version():
    """Detect the Landlock ABI version supported by the running kernel."""
    ret = libc().syscall(
        ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET),
        ctypes.c_void_p(None),
        ctypes.c_size_t(0),
        ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
    )
    if ret < 0:
        errno = ctypes.get_errno()
        if errno == 38:   # ENOSYS
            return 0
        if errno == 95:   # EOPNOTSUPP
            return 0
        return 0
    return ret


def get_handled_access(abi_version):
    """Return the bitmask of access rights supported by this ABI version."""
    access = (
        LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
    )
    if abi_version >= 2:
        access |= LANDLOCK_ACCESS_FS_REFER
    if abi_version >= 3:
        access |= LANDLOCK_ACCESS_FS_TRUNCATE
    return access


READ_ACCESS = (
    LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
)


def get_write_access(abi_version):
    """Write access rights, adjusted for ABI version."""
    access = (
        LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM
    )
    if abi_version >= 2:
        access |= LANDLOCK_ACCESS_FS_REFER
    if abi_version >= 3:
        access |= LANDLOCK_ACCESS_FS_TRUNCATE
    return access


def landlock_create_ruleset(handled_access_fs):
    """Create a Landlock ruleset. Returns the ruleset fd."""
    # struct landlock_ruleset_attr { __u64 handled_access_fs; }
    attr = struct.pack("Q", handled_access_fs)
    attr_buf = ctypes.create_string_buffer(attr)

    fd = libc().syscall(
        ctypes.c_long(SYS_LANDLOCK_CREATE_RULESET),
        ctypes.byref(attr_buf),
        ctypes.c_size_t(len(attr)),
        ctypes.c_uint32(0),
    )
    if fd < 0:
        errno = ctypes.get_errno()
        if errno == 38:
            print("Error: Landlock is not supported by this kernel (ENOSYS)", file=sys.stderr)
        elif errno == 95:
            print("Error: Landlock is disabled (EOPNOTSUPP)", file=sys.stderr)
        else:
            print(f"Error: landlock_create_ruleset failed (errno={errno})", file=sys.stderr)
        sys.exit(1)
    return fd


def _is_dir(mode):
    """Check if a stat mode indicates a directory."""
    import stat
    return stat.S_ISDIR(mode)


def get_file_access(abi_version):
    """Access rights applicable to regular files (not directories)."""
    access = (
        LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
    )
    if abi_version >= 3:
        access |= LANDLOCK_ACCESS_FS_TRUNCATE
    return access


def landlock_add_rule(ruleset_fd, path, access_rights, abi_version=1):
    """Add a path-beneath rule to a Landlock ruleset."""
    try:
        path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        # Path doesn't exist — skip silently (matches bwrap behavior)
        return

    try:
        # For regular files, strip directory-only access rights.
        # Landlock returns EINVAL if you pass READ_DIR, MAKE_DIR, etc.
        # for a non-directory path.
        stat_info = os.fstat(path_fd)
        if not _is_dir(stat_info.st_mode):
            access_rights &= get_file_access(abi_version)

        # struct landlock_path_beneath_attr {
        #     __u64 allowed_access;
        #     __s32 parent_fd;
        # };
        attr = struct.pack("Qi", access_rights, path_fd)
        attr_buf = ctypes.create_string_buffer(attr)

        ret = libc().syscall(
            ctypes.c_long(SYS_LANDLOCK_ADD_RULE),
            ctypes.c_int(ruleset_fd),
            ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH),
            ctypes.byref(attr_buf),
            ctypes.c_uint32(0),
        )
        if ret < 0:
            errno = ctypes.get_errno()
            print(f"Warning: landlock_add_rule failed for {path} (errno={errno})", file=sys.stderr)
    finally:
        os.close(path_fd)


def landlock_restrict_self(ruleset_fd):
    """Enforce the Landlock ruleset on the current process."""
    ret = libc().prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if ret < 0:
        print("Error: prctl(PR_SET_NO_NEW_PRIVS) failed", file=sys.stderr)
        sys.exit(1)

    ret = libc().syscall(
        ctypes.c_long(SYS_LANDLOCK_RESTRICT_SELF),
        ctypes.c_int(ruleset_fd),
        ctypes.c_uint32(0),
    )
    if ret < 0:
        errno = ctypes.get_errno()
        print(f"Error: landlock_restrict_self failed (errno={errno})", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Landlock filesystem sandbox",
        usage="%(prog)s [--ro PATH]... [--rw PATH]... -- CMD [ARGS...]",
    )
    parser.add_argument("--check", action="store_true",
                        help="Check if Landlock is available, print ABI version, and exit")
    parser.add_argument("--ro", action="append", default=[],
                        metavar="PATH", help="Read-only (+ execute) path")
    parser.add_argument("--rw", action="append", default=[],
                        metavar="PATH", help="Read-write path")
    parser.add_argument("--no-seccomp", action="store_true",
                        help="Skip seccomp filter installation")
    parser.add_argument("rest", nargs=argparse.REMAINDER)

    args = parser.parse_args()

    # --- Check mode ---
    if args.check:
        abi = detect_abi_version()
        if abi == 0:
            print("landlock: not available", file=sys.stderr)
            sys.exit(1)
        print(f"landlock: ABI v{abi}")
        sys.exit(0)

    # --- Parse command ---
    cmd = args.rest
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("No command specified after --")

    # --- Detect ABI ---
    abi = detect_abi_version()
    if abi == 0:
        print("Error: Landlock is not available on this kernel", file=sys.stderr)
        sys.exit(1)

    handled = get_handled_access(abi)
    write_access = get_write_access(abi)

    # --- Create ruleset ---
    ruleset_fd = landlock_create_ruleset(handled)

    # --- Add rules ---
    for path in args.ro:
        # Grant only read + execute, clipped to what the kernel handles
        landlock_add_rule(ruleset_fd, path, READ_ACCESS & handled, abi)

    for path in args.rw:
        # Grant full access, clipped to what the kernel handles
        landlock_add_rule(ruleset_fd, path, (READ_ACCESS | write_access) & handled, abi)

    # --- Restrict self ---
    landlock_restrict_self(ruleset_fd)
    os.close(ruleset_fd)

    # --- Seccomp filter ---
    if not args.no_seccomp:
        install_seccomp_filter()

    # --- Exec ---
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()

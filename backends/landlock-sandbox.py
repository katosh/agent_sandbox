#!/usr/bin/env python3
"""landlock-sandbox — Apply Landlock LSM filesystem restrictions, then exec a command.

Usage:
    landlock-sandbox.py --check
    landlock-sandbox.py [--ro PATH]... [--rw PATH]... [--deny PATH]... -- CMD [ARGS...]

Landlock restricts filesystem access for the current process and all descendants.
Unlike bwrap, it does not create a new mount namespace — restricted paths return
EACCES instead of ENOENT.
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


def landlock_add_rule(ruleset_fd, path, access_rights):
    """Add a path-beneath rule to a Landlock ruleset."""
    try:
        path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        # Path doesn't exist — skip silently (matches bwrap behavior)
        return

    try:
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
        landlock_add_rule(ruleset_fd, path, READ_ACCESS & handled)

    for path in args.rw:
        # Grant full access, clipped to what the kernel handles
        landlock_add_rule(ruleset_fd, path, (READ_ACCESS | write_access) & handled)

    # --- Restrict self ---
    landlock_restrict_self(ruleset_fd)
    os.close(ruleset_fd)

    # --- Exec ---
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()

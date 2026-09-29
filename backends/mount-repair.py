#!/usr/bin/env python3
"""Re-create one lost protective mount inside a running bwrap sandbox.

Used by the mount guard (sandbox-lib.sh §Mount guard, MOUNT_GUARD=repair).

    mount-repair.py PID MNTNS_INODE KIND PATH [TYPE UID]

    PID          a process in the sandbox's mount namespace
    MNTNS_INODE  inode number of that namespace (guards against pid reuse)
    KIND         null   read-only /dev/null over a file (BLOCKED_FILES mask)
                 tmpfs  empty tmpfs over a directory (EXTRA_BLOCKED_PATHS)
                 tmpfs-ro  the same, read-only (the original tmpfs was
                        remounted read-only, e.g. under a read-only $HOME)
                 ro     read-only bind of PATH onto itself (the object the
                        host sees at PATH right now)
    PATH         absolute mount point, as listed in the sandbox's mountinfo
    TYPE, UID    (ro only) expected file type (f|d) and owner uid of the
                 host object at PATH, recorded when the sandbox started

Why this works unprivileged: bwrap's mount namespace is owned by a user
namespace that the invoking user created, so a process of that user in
the initial user namespace holds every capability in it. The helper
enters that user namespace (the mount namespace's owner, found with
NS_GET_USERNS, which is not necessarily the sandboxed process's own
nested user namespace) and the mount namespace, and uses the fd-based
mount API (open_tree/fsmount + mount_setattr + move_mount, Linux >= 5.12),
so no path is resolved twice and nothing depends on the sandbox's /proc
(whose pid namespace does not contain this process).

Safety (a repair may never make the sandbox less safe):
  * Only these three shapes are created; each can only hide or make
    read-only what the sandbox can already see: /dev/null and an empty
    tmpfs reveal nothing, and a read-only bind of the object that is
    already visible at PATH (verified by device and inode) reveals
    nothing new and removes write access.
  * Every path component is opened with O_NOFOLLOW, on the host and in the
    sandbox. A symlink anywhere (e.g. one the agent planted at the target
    while it was exposed) is refused, as is a missing target, a type or
    owner change of the host object, and a sandbox object that is not
    the host object.
  * All mount operations act on the file descriptors that were checked.
  * Nothing is imported or loaded once inside: the sandbox's filesystem
    is agent-controlled in places (e.g. a writable ~/.local), and this
    process keeps the user's host credentials. The guard runs it with
    `python3 -I` (no user site, no PYTHONPATH, no script dir), every
    module and libc symbol is resolved before setns, and sys.path is
    emptied before entering.

Exit status: 0 repaired; 1 refused (reason on stderr); 2 not supported
here (kernel, permissions, namespace gone).
"""
import ctypes
import errno
import fcntl
import os
import stat
import sys

SYS_open_tree, SYS_move_mount = 428, 429          # same on every arch
SYS_fsopen, SYS_fsconfig, SYS_fsmount = 430, 431, 432
SYS_mount_setattr = 442
OPEN_TREE_CLONE = 1
AT_EMPTY_PATH = 0x1000
MOVE_MOUNT_F_EMPTY_PATH, MOVE_MOUNT_T_EMPTY_PATH = 0x4, 0x40
FSOPEN_CLOEXEC = FSMOUNT_CLOEXEC = 1
FSCONFIG_SET_STRING, FSCONFIG_CMD_CREATE = 1, 6
MOUNT_ATTR_RDONLY, MOUNT_ATTR_NOSUID, MOUNT_ATTR_NODEV = 0x1, 0x2, 0x4
CLONE_NEWNS, CLONE_NEWUSER = 0x00020000, 0x10000000
NS_GET_USERNS = 0xb701
ST_RDONLY = 1

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.setns.restype = ctypes.c_int      # resolve both symbols on the host


class Refused(Exception):
    pass


class Unsupported(Exception):
    pass


class MountAttr(ctypes.Structure):
    _fields_ = [("attr_set", ctypes.c_uint64), ("attr_clr", ctypes.c_uint64),
                ("propagation", ctypes.c_uint64), ("userns_fd", ctypes.c_uint64)]


def _sys(nr, name, *args):
    # Pass every integer as a full long: syscall(2) is variadic, and a
    # 32-bit int in a 64-bit argument register may carry garbage above.
    args = [ctypes.c_long(a) if isinstance(a, int) else a for a in args]
    r = libc.syscall(ctypes.c_long(nr), *args)
    if r < 0:
        e = ctypes.get_errno()
        exc = Unsupported if e in (errno.ENOSYS, errno.EPERM) else Refused
        raise exc("%s: %s" % (name, os.strerror(e)))
    return r


def _setns(fd, nstype, what):
    if libc.setns(fd, nstype) != 0:
        raise Unsupported("cannot enter the sandbox's %s namespace: %s"
                          % (what, os.strerror(ctypes.get_errno())))


def _walk(path):
    """Open PATH as O_PATH without following a symlink in any component.
    Returns (fd, stat). Raises Refused."""
    parts = path.split("/")[1:]
    fd = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for i, name in enumerate(parts):
            last = i == len(parts) - 1
            flags = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
            if not last:
                flags |= os.O_DIRECTORY
            try:
                nfd = os.open(name, flags, dir_fd=fd)
            except OSError as e:
                where = "/".join(parts[:i + 1])
                if e.errno == errno.ENOENT:
                    raise Refused("/%s does not exist" % where)
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise Refused("/%s is a symlink or not a directory (not followed)" % where)
                raise Refused("/%s: %s" % (where, e.strerror))
            os.close(fd)
            fd = nfd
        st = os.fstat(fd)
        if stat.S_ISLNK(st.st_mode):
            os.close(fd)
            raise Refused("%s is a symlink (not followed)" % path)
        return fd, st
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def repair(pid, ns_ino, kind, path, want_type=None, want_uid=None):
    if (not path.startswith("/") or path == "/" or "//" in path or path.endswith("/")
            or any(c in (".", "..") for c in path.split("/")[1:])):
        raise Refused("not a canonical absolute path: %r" % path)
    if kind not in ("null", "tmpfs", "tmpfs-ro", "ro"):
        raise Refused("unknown kind %r" % kind)
    try:
        mntfd = os.open("/proc/%d/ns/mnt" % pid, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as e:
        raise Unsupported("sandbox mount namespace not reachable: %s" % e.strerror)
    if os.fstat(mntfd).st_ino != ns_ino:
        raise Unsupported("pid %d is no longer in the sandbox's mount namespace" % pid)
    try:
        usrfd = fcntl.ioctl(mntfd, NS_GET_USERNS)
    except OSError as e:
        raise Unsupported("cannot find the namespace's owning user namespace: %s" % e.strerror)

    host = None
    if kind == "ro":
        # The host object at PATH, before entering: what the sandbox must
        # see at PATH, too (bwrap bound PATH onto itself).
        hfd, host = _walk(path)
        os.close(hfd)
        is_dir = stat.S_ISDIR(host.st_mode)
        if not (is_dir or stat.S_ISREG(host.st_mode)):
            raise Refused("host %s is neither a file nor a directory" % path)
        if want_type and want_type != ("d" if is_dir else "f"):
            raise Refused("host %s changed type since the sandbox started" % path)
        if want_uid is not None and host.st_uid != want_uid:
            raise Refused("host %s changed owner (uid %d, was %d)" % (path, host.st_uid, want_uid))

    # From here on nothing may be imported: paths would resolve in the
    # sandbox's (partly agent-writable) filesystem.
    sys.path[:] = []
    sys.meta_path[:] = [m for m in sys.meta_path if getattr(m, "__name__", "") in
                        ("BuiltinImporter", "FrozenImporter")]
    _setns(usrfd, CLONE_NEWUSER, "user")
    _setns(mntfd, CLONE_NEWNS, "mount")
    os.chdir("/")

    tfd, tst = _walk(path)
    attr = MountAttr(MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV, 0, 0, 0)
    if kind == "ro":
        if (tst.st_dev, tst.st_ino) != (host.st_dev, host.st_ino):
            raise Refused("the sandbox's %s is not the host's object" % path)
        mfd = _sys(SYS_open_tree, "open_tree", tfd, b"",
                   OPEN_TREE_CLONE | os.O_CLOEXEC | AT_EMPTY_PATH)
        attr.attr_set |= MOUNT_ATTR_RDONLY
    elif kind == "null":
        if stat.S_ISDIR(tst.st_mode):
            raise Refused("%s is now a directory; /dev/null cannot mask it" % path)
        nfd, nst = _walk("/dev/null")
        if not stat.S_ISCHR(nst.st_mode) or nst.st_rdev != os.makedev(1, 3):
            raise Refused("the sandbox's /dev/null is not the null device")
        mfd = _sys(SYS_open_tree, "open_tree", nfd, b"",
                   OPEN_TREE_CLONE | os.O_CLOEXEC | AT_EMPTY_PATH)
        attr.attr_set |= MOUNT_ATTR_RDONLY
    else:
        if not stat.S_ISDIR(tst.st_mode):
            raise Refused("%s is no longer a directory; a tmpfs cannot mask it" % path)
        fs = _sys(SYS_fsopen, "fsopen", b"tmpfs", FSOPEN_CLOEXEC)
        _sys(SYS_fsconfig, "fsconfig", fs, FSCONFIG_SET_STRING, b"source", b"tmpfs", 0)
        _sys(SYS_fsconfig, "fsconfig", fs, FSCONFIG_SET_STRING, b"mode", b"0755", 0)
        _sys(SYS_fsconfig, "fsconfig", fs, FSCONFIG_CMD_CREATE, None, None, 0)
        mfd = _sys(SYS_fsmount, "fsmount", fs, FSMOUNT_CLOEXEC, 0)
        if kind == "tmpfs-ro":
            attr.attr_set |= MOUNT_ATTR_RDONLY
    _sys(SYS_mount_setattr, "mount_setattr", mfd, b"", AT_EMPTY_PATH,
         ctypes.byref(attr), ctypes.sizeof(attr))
    mst = os.fstat(mfd)
    _sys(SYS_move_mount, "move_mount", mfd, b"", tfd, b"",
         MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH)

    # Verify by path: PATH now resolves to the new mount's root.
    vfd, vst = _walk(path)
    try:
        if (vst.st_dev, vst.st_ino) != (mst.st_dev, mst.st_ino):
            raise Refused("mounted, but %s does not show the new mount" % path)
        if attr.attr_set & MOUNT_ATTR_RDONLY and not os.fstatvfs(vfd).f_flag & ST_RDONLY:
            raise Refused("mounted, but %s is not read-only" % path)
    finally:
        os.close(vfd)


def main(argv):
    if len(argv) not in (5, 7):
        sys.stderr.write(__doc__)
        return 2
    try:
        pid, ns_ino = int(argv[1]), int(argv[2])
        want_type = argv[5] if len(argv) == 7 else None
        want_uid = int(argv[6]) if len(argv) == 7 else None
    except ValueError:
        sys.stderr.write("mount-repair: bad numeric argument\n")
        return 2
    try:
        repair(pid, ns_ino, argv[3], argv[4], want_type, want_uid)
    except Refused as e:
        sys.stderr.write("%s\n" % e)
        return 1
    except Unsupported as e:
        sys.stderr.write("%s\n" % e)
        return 2
    except OSError as e:
        sys.stderr.write("%s\n" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

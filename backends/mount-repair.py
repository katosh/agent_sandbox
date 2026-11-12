#!/usr/bin/env python3
"""Re-create one lost protective mount inside a running bwrap sandbox.

Used by the mount guard (sandbox-lib.sh §Mount guard, MOUNT_GUARD=repair).

    mount-repair.py PID MNTNS_INODE KIND PATH [TYPE UID [OPTS]]

    PID          a process in the sandbox's mount namespace
    MNTNS_INODE  inode number of that namespace (guards against pid reuse)
    KIND         null   read-only /dev/null over a file (BLOCKED_FILES mask)
                 tmpfs  empty tmpfs over a directory (EXTRA_BLOCKED_PATHS)
                 tmpfs-ro  the same, read-only (the original tmpfs was
                        remounted read-only, e.g. under a read-only $HOME)
                 ro     read-only bind of PATH onto itself (the object the
                        host sees at PATH right now)
                 rw     writable bind of PATH onto itself, for a project or
                        extra-writable directory that fell through to the
                        read-only parent bind after losing its own mount
                 revoke remount the topmost mount at PATH read-only (live
                        reload: a writable bind that left the config). It
                        keeps the mount's nosuid/nodev/noexec/noatime
                        options and never detaches anything; if files are
                        open for writing through the mount the kernel
                        refuses (EBUSY) and the helper exits 3, leaving
                        the mount writable.
                 detach lazily unmount the topmost mount at PATH (live
                        reload --force-detach). Open handles keep their
                        access; only the path stops showing the mount.
    PATH         absolute mount point, as listed in the sandbox's mountinfo
    TYPE, UID    (ro, rw) expected file type (f|d) and owner uid of the
                 host object at PATH, recorded when the sandbox started
    OPTS         (ro, rw) the per-mount options the lost mount had, as in
                 mountinfo ("rw,nosuid,nodev,relatime"); only nosuid,
                 nodev, noexec, noatime and nodiratime are carried over
                 (default nosuid,nodev)

The bind kinds use the classic mount(2) calls (MS_BIND, then MS_REMOUNT)
because the descriptor-based API cannot clear a read-only flag inherited
from the parent bind before Linux 5.12 (mount_setattr). The path is
resolved once without following symlinks and then once more by mount(2)
inside the sandbox; a new mount that does not show the host's object is
detached again. ro uses the descriptor-based API where the kernel has it.

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

ro and rw are idempotent: if the topmost mount at PATH already shows the
host's object with the requested read-only state, nothing is mounted
(stderr says "already present", exit 0), so a repeated or concurrent
repair never stacks a second mount. The mount table is opened through
the host's /proc before entering and read again just before mounting.

The helper refuses to act unless the user namespace that owns the target
mount namespace is owned by the calling uid and is not the one it is
running in (the host's), so it can never mount anything in a namespace
it does not already hold full rights in.

Exit status: 0 repaired; 1 refused (reason on stderr); 2 not supported
here (kernel, permissions, namespace gone); 3 busy (revoke only: files
are open for writing, the mount was left as it was).
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
NS_GET_OWNER_UID = 0xb704
MS_RDONLY, MS_NOSUID, MS_NODEV, MS_NOEXEC = 1, 2, 4, 8
MS_NOATIME, MS_NODIRATIME, MS_REMOUNT, MS_BIND = 1024, 2048, 32, 4096
MNT_DETACH = 2
OPT_FLAGS = {"nosuid": MS_NOSUID, "nodev": MS_NODEV, "noexec": MS_NOEXEC,
             "noatime": MS_NOATIME, "nodiratime": MS_NODIRATIME}

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
libc.setns.restype = ctypes.c_int      # resolve these symbols on the host,
libc.mount.restype = ctypes.c_int      # not in the sandbox's filesystem
libc.umount2.restype = ctypes.c_int


class Refused(Exception):
    pass


class Unsupported(Exception):
    pass


class Busy(Exception):
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


def _unescape(field):
    """Undo mountinfo's octal escapes (space, tab, newline and backslash
    are written as a backslash and three octal digits). Plain string
    code: nothing may be imported once inside the sandbox."""
    out, i, n = [], 0, len(field)
    while i < n:
        c = field[i]
        d = field[i + 1:i + 4]
        if c == "\\" and len(d) == 3 and all(x in "01234567" for x in d):
            out.append(chr(int(d, 8)))
            i += 4
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _mount_point_listed(mifd, path):
    """True when PATH is a mount point in the mount table read from MIFD
    (a descriptor of the sandbox's /proc/PID/mountinfo opened before
    entering; a read after setns still shows that namespace, without
    going through the sandbox's /proc)."""
    os.lseek(mifd, 0, os.SEEK_SET)
    chunks = []
    while True:
        b = os.read(mifd, 65536)
        if not b:
            break
        chunks.append(b)
    for line in os.fsdecode(b"".join(chunks)).split("\n"):
        f = line.split(" ")
        if len(f) > 5 and _unescape(f[4]) == path:
            return True
    return False


def _mount_options(mifd, path):
    """Per-mount options (mountinfo field 6) of the topmost mount listed
    at PATH, or None. Same table and escaping as _mount_point_listed."""
    os.lseek(mifd, 0, os.SEEK_SET)
    chunks = []
    while True:
        b = os.read(mifd, 65536)
        if not b:
            break
        chunks.append(b)
    opts = None
    for line in os.fsdecode(b"".join(chunks)).split("\n"):
        f = line.split(" ")
        if len(f) > 5 and _unescape(f[4]) == path:
            opts = f[5]
    return opts


def _already_present(mifd, path, host, read_only):
    """True when the topmost mount at PATH already is what a repair would
    create: PATH is a mount point, resolves (the topmost mount decides
    path resolution) to the host's object and has the requested
    read-only state. Anything that cannot be established counts as not
    present, and the repair then runs as before."""
    try:
        if mifd is None or not _mount_point_listed(mifd, path):
            return False
        vfd, vst = _walk(path)
    except (OSError, Refused):
        return False
    try:
        if (vst.st_dev, vst.st_ino) != (host.st_dev, host.st_ino):
            return False
        return bool(os.fstatvfs(vfd).f_flag & ST_RDONLY) == read_only
    except OSError:
        return False
    finally:
        os.close(vfd)


def _have_mount_setattr():
    """True when the kernel implements mount_setattr (Linux 5.12). An
    invalid descriptor gets EBADF from a kernel that has it."""
    r = libc.syscall(ctypes.c_long(SYS_mount_setattr), ctypes.c_long(-1),
                     b"", ctypes.c_long(AT_EMPTY_PATH), None, ctypes.c_long(0))
    return not (r < 0 and ctypes.get_errno() == errno.ENOSYS)


def _opts_flags(opts):
    flags = 0
    for o in (opts or "nosuid,nodev").split(","):
        flags |= OPT_FLAGS.get(o, 0)
    return flags


def _bind_classic(path, read_only, flags, host):
    """Bind PATH onto itself in the current mount namespace, then set the
    mount's flags. The source is resolved in this namespace, where PATH
    now falls through to the parent bind of the same host directory."""
    tfd, tst = _walk(path)
    os.close(tfd)
    if (tst.st_dev, tst.st_ino) != (host.st_dev, host.st_ino):
        raise Refused("the sandbox's %s is not the host's object" % path)
    bpath = path.encode()
    if libc.mount(bpath, bpath, None, MS_BIND, None) != 0:
        raise Refused("bind %s: %s" % (path, os.strerror(ctypes.get_errno())))
    want = MS_REMOUNT | MS_BIND | flags | (MS_RDONLY if read_only else 0)
    if libc.mount(None, bpath, None, want, None) != 0:
        err = os.strerror(ctypes.get_errno())
        # The new mount may not carry the intended flags (read-only
        # lost, or a parent's flag locked): never leave it in place.
        libc.umount2(bpath, MNT_DETACH)
        raise Refused("remount %s: %s" % (path, err))
    vfd, vst = _walk(path)
    try:
        if (vst.st_dev, vst.st_ino) != (host.st_dev, host.st_ino):
            libc.umount2(bpath, MNT_DETACH)
            raise Refused("mounted, but %s does not show the host's object" % path)
        if bool(os.fstatvfs(vfd).f_flag & ST_RDONLY) != read_only:
            libc.umount2(bpath, MNT_DETACH)
            raise Refused("mounted, but %s has the wrong read-only state" % path)
    finally:
        os.close(vfd)


def _revoke(mifd, path, detach):
    """Make the topmost mount at PATH read-only (detach: unmount it
    lazily). Runs inside the sandbox's namespaces."""
    cur = _mount_options(mifd, path)
    if cur is None:
        raise Refused("%s is not a mount point in the sandbox" % path)
    bpath = path.encode()
    if detach:
        if libc.umount2(bpath, MNT_DETACH) != 0:
            raise Refused("detach %s: %s" % (path, os.strerror(ctypes.get_errno())))
        return
    # Keep the options the mount has: a bind remount that drops a locked
    # one (nosuid, nodev, ...) is refused by the kernel.
    flags = _opts_flags(cur)
    want = MS_REMOUNT | MS_BIND | MS_RDONLY | flags
    if libc.mount(None, bpath, None, want, None) != 0:
        e = ctypes.get_errno()
        if e == errno.EBUSY:
            raise Busy("%s has files open for writing; left writable" % path)
        raise Refused("remount %s read-only: %s" % (path, os.strerror(e)))
    vfd, _ = _walk(path)
    try:
        if not os.fstatvfs(vfd).f_flag & ST_RDONLY:
            raise Refused("remounted, but %s is not read-only" % path)
    finally:
        os.close(vfd)


def repair(pid, ns_ino, kind, path, want_type=None, want_uid=None, opts=None):
    if (not path.startswith("/") or path == "/" or "//" in path or path.endswith("/")
            or any(c in (".", "..") for c in path.split("/")[1:])):
        raise Refused("not a canonical absolute path: %r" % path)
    if kind not in ("null", "tmpfs", "tmpfs-ro", "ro", "rw", "revoke", "detach"):
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
    # Only a namespace we own (and are not already in: the host's) may be
    # entered; anything else is refused before a single setns().
    try:
        owner = int.from_bytes(fcntl.ioctl(usrfd, NS_GET_OWNER_UID, bytes(4)), sys.byteorder)
        own_user = os.stat("/proc/self/ns/user")
    except OSError as e:
        raise Unsupported("cannot identify the namespace's owner: %s" % e.strerror)
    if owner != os.geteuid():
        raise Refused("the sandbox's user namespace is owned by uid %d, not by us" % owner)
    if os.fstat(usrfd).st_ino == own_user.st_ino:
        raise Refused("the target is in our own user namespace (the host's); refusing")

    # The sandbox's mount table, opened before entering (see
    # _mount_point_listed), for the idempotence check below. The
    # namespace is checked again after the open, so a recycled pid
    # cannot hand us another namespace's table.
    mifd = None
    if kind in ("ro", "rw", "revoke", "detach"):
        try:
            mifd = os.open("/proc/%d/mountinfo" % pid, os.O_RDONLY | os.O_CLOEXEC)
            if os.stat("/proc/%d/ns/mnt" % pid).st_ino != ns_ino:
                os.close(mifd)
                mifd = None
        except OSError:
            mifd = None

    if kind in ("revoke", "detach"):
        # Live reload: act on the mount that is there. No host object is
        # involved, so nothing is resolved before entering.
        if mifd is None:
            raise Unsupported("the sandbox's mount table could not be opened")
    classic = kind == "rw" or (kind == "ro" and not _have_mount_setattr())
    host = None
    if kind in ("ro", "rw"):
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

    if kind in ("revoke", "detach"):
        _revoke(mifd, path, kind == "detach")
        return

    # Idempotent for ro and rw: a second repair of the same path (a late
    # first one, a concurrent run) must not stack an identical mount on a
    # good one. Only these two kinds are checked: their identity is the
    # host's object (device and inode) plus the read-only state, which can
    # be established exactly. A mask (null, tmpfs) has no host object to
    # compare, and masking again what is already masked would at best hide
    # what the agent wrote into the old tmpfs, so masks keep their
    # one-shot semantics (the guard asks for them only once the mount is
    # gone).
    if kind in ("ro", "rw") and _already_present(mifd, path, host, kind == "ro"):
        sys.stderr.write("already present: %s is mounted %s as expected; nothing mounted\n"
                         % (path, "read-only" if kind == "ro" else "writable"))
        return

    if classic:
        _bind_classic(path, kind == "ro", _opts_flags(opts), host)
        return

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
    if len(argv) not in (5, 7, 8):
        sys.stderr.write(__doc__)
        return 2
    try:
        pid, ns_ino = int(argv[1]), int(argv[2])
        want_type = argv[5] if len(argv) >= 7 else None
        want_uid = int(argv[6]) if len(argv) >= 7 else None
        opts = argv[7] if len(argv) == 8 else None
    except ValueError:
        sys.stderr.write("mount-repair: bad numeric argument\n")
        return 2
    try:
        repair(pid, ns_ino, argv[3], argv[4], want_type, want_uid, opts)
    except Refused as e:
        sys.stderr.write("%s\n" % e)
        return 1
    except Unsupported as e:
        sys.stderr.write("%s\n" % e)
        return 2
    except Busy as e:
        sys.stderr.write("%s\n" % e)
        return 3
    except OSError as e:
        sys.stderr.write("%s\n" % e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

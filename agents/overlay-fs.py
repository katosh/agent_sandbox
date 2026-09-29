#!/usr/bin/env python3
"""overlay-fs.py — symlink-safe filesystem primitives for agent overlays.

Agent overlays (agents/<name>/overlay.sh) run on the HOST, outside the
sandbox, before every launch. They write into directories that are
writable from INSIDE the sandbox (~/.claude/sandbox-config, ~/.codex,
...). Anything an agent plants there -- a symlink, a directory where a
file is expected, a pre-created temp name -- must never redirect a
host-side write, copy or delete to a path outside that directory.

Plain shell (`cp -r`, `>`, `mv`, `ln -sf`, `rm -rf`) resolves every
path component through symlinks and re-resolves the path on each call,
so it cannot give that guarantee. This helper does all overlay file
operations through directory file descriptors opened with O_NOFOLLOW,
creates files with O_EXCL (which never follows a symlink), and verifies
renames by inode. The only path it trusts is the ROOT argument (the
agent's own config directory, e.g. ~/.claude, which a user may keep as
a dotfiles symlink and which the sandbox cannot replace because it is
the bind-mount / Landlock rule root).

Sub-commands (all paths absolute; REL is relative to ROOT; exit 0 = ok):

  mkdir ROOT REL [--no-replace]
      Ensure ROOT/REL exists as a real directory, creating missing
      components. A symlink or non-directory at the LAST component is
      removed and replaced by a fresh directory (the sandbox-config dir
      is ours to own) unless --no-replace is given; a symlink at any
      earlier component is refused (exit 3). The directory is made
      owner-writable.

  write ROOT REL NAME MODE
      Atomically replace ROOT/REL/NAME with stdin: O_EXCL temp file in
      the same directory, fchmod MODE (octal), rename, verify by inode.

  read ROOT REL [--allow PREFIX]... [--deny PREFIX]...
      Print ROOT/REL to stdout. A regular file is read without following
      symlinks. If the leaf is a symlink, it is followed only when its
      canonical target is a regular file under some --allow prefix and
      under no --deny prefix (the caller passes the paths the sandbox
      can already see, so the copy never grants a new read). The target
      is opened component by component with O_NOFOLLOW, so it cannot be
      swapped after the check. Exit 2 = absent, exit 3 = refused.

  sync ROOT CFGREL REALREL [options]
      Populate ROOT/CFGREL (the sandbox-config dir) from the entries of
      ROOT/REALREL (the agent's real config dir):
        --skip NAME        do not touch this entry name (repeatable)
        --skip-glob GLOB   ditto, fnmatch pattern (repeatable)
        --merge-dirs       a real directory left in CFGREL (session data
                           written to a stale copy) is merged no-clobber
                           into the real counterpart, then replaced by a
                           symlink. Symlinks / special files inside it
                           are dropped, never followed. Without this
                           option such a directory is left untouched.
        --copy NAME        keep NAME as a private regular-file copy
                           (copy-on-launch) instead of a symlink: an
                           in-sandbox copy newer than the real file is
                           kept, otherwise it is refreshed from the real
                           file (read with the same --allow/--deny policy
                           as `read`). Writes inside the sandbox then
                           never reach the real file.
        --allow/--deny     policy for --copy sources (see `read`).
      Every other entry becomes a symlink CFGREL/NAME -> REAL/NAME,
      except that a regular file in CFGREL newer than the real entry is
      kept (a token refreshed inside the sandbox via write+rename).

  ensure-file ROOT REL NAME CONTENT
      Create ROOT/REL/NAME with CONTENT if nothing exists at that name
      (O_EXCL: an existing file or a dangling symlink is left alone).

Python >= 3.6 (RHEL 8's default).
"""

import errno
import fnmatch
import os
import stat
import sys

try:
    import secrets
    _rand = lambda: secrets.token_hex(8)  # noqa: E731
except ImportError:  # pragma: no cover
    import binascii
    _rand = lambda: binascii.hexlify(os.urandom(8)).decode()  # noqa: E731

O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | O_CLOEXEC


class Refused(Exception):
    """An unsafe filesystem shape (symlink where a real entry is required)."""


def warn(msg):
    sys.stderr.write("sandbox: overlay: %s\n" % msg)


def _split(rel):
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if ".." in parts:
        raise Refused("'..' not allowed in %r" % rel)
    return parts


def open_root(root):
    # The root itself is trusted and may be a (user-made) symlink.
    return os.open(root, os.O_RDONLY | os.O_DIRECTORY | O_CLOEXEC)


def open_dir_at(dfd, name):
    """openat(dfd, name) as a directory, never following a symlink."""
    try:
        return os.open(name, DIR_FLAGS, dir_fd=dfd)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            raise Refused("%s is a symlink or not a directory" % name)
        raise


def walk(root, rel, create=False, replace_leaf=False):
    """Return an fd for ROOT/REL opened without following symlinks below ROOT."""
    parts = _split(rel)
    fd = open_root(root)
    try:
        for i, name in enumerate(parts):
            leaf = i == len(parts) - 1
            try:
                nfd = open_dir_at(fd, name)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(name, 0o777, dir_fd=fd)
                except FileExistsError:
                    pass
                nfd = open_dir_at(fd, name)
            except Refused:
                if not (leaf and replace_leaf):
                    raise Refused("%s/%s: symlink or non-directory in path"
                                  % (root, "/".join(parts[:i + 1])))
                # A planted symlink / file at the sandbox-config name:
                # unlinkat() removes the link itself, never its target.
                warn("replacing unexpected non-directory %s/%s"
                     % (root, "/".join(parts)))
                os.unlink(name, dir_fd=fd)
                os.mkdir(name, 0o777, dir_fd=fd)
                nfd = open_dir_at(fd, name)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def lstat_at(dfd, name):
    try:
        return os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def rmtree_at(dfd, name):
    """rm -rf of dfd/name that never follows a symlink."""
    st = lstat_at(dfd, name)
    if st is None:
        return
    if not stat.S_ISDIR(st.st_mode):
        os.unlink(name, dir_fd=dfd)
        return
    try:
        sub = open_dir_at(dfd, name)
    except Refused:  # swapped for a symlink in the meantime
        os.unlink(name, dir_fd=dfd)
        return
    try:
        try:
            os.chmod(sub, stat.S_IMODE(os.fstat(sub).st_mode) | 0o700)
        except OSError:
            pass
        for child in os.listdir(sub):
            rmtree_at(sub, child)
    finally:
        os.close(sub)
    os.rmdir(name, dir_fd=dfd)


def write_at(dfd, name, data, mode):
    """Atomically install DATA at dfd/name. Returns True on success."""
    for _ in range(5):
        tmp = ".%s.tmp.%s" % (name, _rand())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                view = view[n:]
            os.fchmod(fd, mode)
            st = os.fstat(fd)
        finally:
            os.close(fd)
        try:
            os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
        except OSError as e:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
            if e.errno == errno.EISDIR or e.errno == errno.ENOTEMPTY:
                # A directory was planted at NAME: remove it, retry.
                rmtree_at(dfd, name)
                continue
            raise
        now = lstat_at(dfd, name)
        if now is not None and (now.st_dev, now.st_ino) == (st.st_dev, st.st_ino):
            return True
        # Our temp name was swapped between close and rename: whatever
        # landed at NAME is not ours. Remove it (never following) and retry.
        warn("temp file for %s was tampered with; retrying" % name)
        if now is not None:
            if stat.S_ISDIR(now.st_mode):
                rmtree_at(dfd, name)
            else:
                os.unlink(name, dir_fd=dfd)
    return False


def _under(path, prefixes):
    for p in prefixes:
        p = p.rstrip("/") or "/"
        if p == "/" or path == p or path.startswith(p + "/"):
            return True
    return False


def open_canonical_file(path):
    """Open canonical PATH walking from / with O_NOFOLLOW on every component."""
    parts = _split(path)
    fd = os.open("/", DIR_FLAGS)
    try:
        for name in parts[:-1]:
            nfd = open_dir_at(fd, name)
            os.close(fd)
            fd = nfd
        try:
            ffd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                          | O_CLOEXEC, dir_fd=fd)
        except OSError as e:
            if e.errno == errno.ELOOP:
                raise Refused("%s changed while reading" % path)
            raise
    finally:
        os.close(fd)
    return ffd


def read_fd_all(fd):
    chunks = []
    while True:
        b = os.read(fd, 1 << 16)
        if not b:
            return b"".join(chunks)
        chunks.append(b)


def read_policy(dfd, name, shown, allow, deny):
    """Return bytes of dfd/name, or None if absent. Raises Refused."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | O_CLOEXEC,
                     dir_fd=dfd)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno != errno.ELOOP:
            raise
        # Leaf is a symlink. Resolve through /proc/self/fd so the parent
        # directory is the one we hold, not a re-resolved path.
        target = os.path.realpath("/proc/self/fd/%d/%s" % (dfd, name))
        if not os.path.isabs(target) or target.startswith("/proc/"):
            raise Refused("%s: cannot resolve symlink" % shown)
        if _under(target, deny):
            raise Refused("%s is a symlink to %s, which is masked inside the "
                          "sandbox; not copying it" % (shown, target))
        if not _under(target, allow):
            raise Refused("%s is a symlink to %s, which the sandbox cannot "
                          "read; not copying it (add the target's directory "
                          "to HOME_READONLY to include it)" % (shown, target))
        try:
            fd = open_canonical_file(target)
        except FileNotFoundError:
            return None  # dangling link: treat as absent
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused("%s is not a regular file" % shown)
        return read_fd_all(fd)
    finally:
        os.close(fd)


def copy_file_at(src_dfd, src_name, dst_dfd, dst_name, st):
    """No-clobber copy of one regular file; symlinks never followed."""
    try:
        s = os.open(src_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                    | O_CLOEXEC, dir_fd=src_dfd)
    except OSError as e:
        if e.errno == errno.ELOOP:
            return True  # swapped for a symlink: drop it
        raise
    try:
        sst = os.fstat(s)
        if not stat.S_ISREG(sst.st_mode):
            return True
        try:
            d = os.open(dst_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                        | os.O_NOFOLLOW | O_CLOEXEC,
                        stat.S_IMODE(sst.st_mode) & 0o777, dir_fd=dst_dfd)
        except FileExistsError:
            return True  # cp -n semantics: keep the existing entry
        try:
            while True:
                b = os.read(s, 1 << 16)
                if not b:
                    break
                view = memoryview(b)
                while view:
                    n = os.write(d, view)
                    view = view[n:]
            os.utime(d, ns=(sst.st_atime_ns, sst.st_mtime_ns))
        finally:
            os.close(d)
    finally:
        os.close(s)
    return True


def merge_tree(src, dst):
    """No-clobber merge of dir fd SRC into dir fd DST. Never follows links."""
    ok = True
    for name in os.listdir(src):
        st = lstat_at(src, name)
        if st is None:
            continue
        try:
            if stat.S_ISDIR(st.st_mode):
                s = open_dir_at(src, name)
                try:
                    try:
                        os.mkdir(name, stat.S_IMODE(st.st_mode) | 0o700,
                                 dir_fd=dst)
                    except FileExistsError:
                        pass
                    d = open_dir_at(dst, name)  # Refused if a symlink
                    try:
                        ok = merge_tree(s, d) and ok
                    finally:
                        os.close(d)
                finally:
                    os.close(s)
            elif stat.S_ISREG(st.st_mode):
                ok = copy_file_at(src, name, dst, name, st) and ok
            # symlinks, fifos, sockets, devices: dropped on purpose
        except Refused as e:
            warn("merge: skipping %s (%s)" % (name, e))
        except OSError as e:
            warn("merge: %s: %s" % (name, e.strerror))
            ok = False
    return ok


def _is_newer(a, b):
    return a.st_mtime_ns > b.st_mtime_ns


def cmd_mkdir(root, rel, *opts):
    replace = "--no-replace" not in opts
    fd = walk(root, rel, create=True, replace_leaf=replace)
    try:
        st = os.fstat(fd)
        if st.st_uid != os.getuid():
            raise Refused("%s/%s is not owned by us" % (root, rel))
        os.chmod(fd, stat.S_IMODE(st.st_mode) | 0o700)
    finally:
        os.close(fd)
    return 0


def cmd_write(root, rel, name, mode):
    data = sys.stdin.buffer.read()
    fd = walk(root, rel)
    try:
        return 0 if write_at(fd, name, data, int(mode, 8)) else 1
    finally:
        os.close(fd)


def cmd_ensure_file(root, rel, name, content):
    fd = walk(root, rel)
    try:
        try:
            f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                        | O_CLOEXEC, 0o600, dir_fd=fd)
        except FileExistsError:
            return 0
        try:
            os.write(f, content.encode())
        finally:
            os.close(f)
    finally:
        os.close(fd)
    return 0


def _parse_policy(args):
    allow, deny, rest = [], [], []
    it = iter(args)
    for a in it:
        if a == "--allow":
            allow.append(next(it))
        elif a == "--deny":
            deny.append(next(it))
        else:
            rest.append(a)
    return allow, deny, rest


def cmd_read(root, rel, args):
    allow, deny, _ = _parse_policy(args)
    parts = _split(rel)
    fd = walk(root, "/".join(parts[:-1]))
    try:
        data = read_policy(fd, parts[-1], os.path.join(root, rel), allow, deny)
    finally:
        os.close(fd)
    if data is None:
        return 2
    sys.stdout.buffer.write(data)
    return 0


def cmd_sync(root, cfgrel, realrel, args):
    allow, deny, rest = _parse_policy(args)
    skip, skip_glob, copy = set(), [], set()
    merge_dirs = False
    it = iter(rest)
    for a in it:
        if a == "--skip":
            skip.add(next(it))
        elif a == "--skip-glob":
            skip_glob.append(next(it))
        elif a == "--copy":
            copy.add(next(it))
        elif a == "--merge-dirs":
            merge_dirs = True
        else:
            raise SystemExit("overlay-fs sync: unknown option %s" % a)

    real_path = os.path.join(root, realrel) if _split(realrel) else root
    rfd = walk(root, realrel)
    cfd = walk(root, cfgrel)
    try:
        for name in sorted(os.listdir(rfd)):
            if name in skip or any(fnmatch.fnmatchcase(name, g) for g in skip_glob):
                continue
            item = os.path.join(real_path, name)
            ist = lstat_at(rfd, name)
            if ist is None:
                continue
            tst = lstat_at(cfd, name)

            if name in copy:
                if tst is not None and stat.S_ISREG(tst.st_mode):
                    try:
                        real_st = os.stat(name, dir_fd=rfd)
                    except OSError:
                        real_st = None
                    if real_st is None or _is_newer(tst, real_st):
                        continue  # in-sandbox copy is fresher: keep it
                try:
                    data = read_policy(rfd, name, item, allow, deny)
                except Refused as e:
                    warn(str(e))
                    data = None
                if data is None:
                    continue
                write_at(cfd, name, data, 0o600)
                continue

            if tst is not None and stat.S_ISDIR(tst.st_mode):
                # A real directory in sandbox-config (the agent created it
                # before the real one existed, or rewrote a symlink).
                if os.path.ismount("/proc/self/fd/%d/%s" % (cfd, name)):
                    continue
                if not merge_dirs:
                    continue  # leave in-sandbox data where it is
                else:
                    try:
                        dst = open_dir_at(rfd, name)
                    except Refused:
                        # Real entry is a symlink or a file: never merge
                        # through it. Leave the sandbox copy alone.
                        warn("not merging %s: real entry %s is not a plain "
                             "directory" % (name, item))
                        continue
                    try:
                        src = open_dir_at(cfd, name)
                    except Refused:
                        os.close(dst)
                        continue
                    try:
                        ok = merge_tree(src, dst)
                    finally:
                        os.close(src)
                        os.close(dst)
                    if not ok:
                        continue  # keep the copy; nothing is lost
                    rmtree_at(cfd, name)
                tst = None

            if tst is not None and stat.S_ISREG(tst.st_mode):
                try:
                    real_st = os.stat(name, dir_fd=rfd)
                except OSError:
                    real_st = None
                if real_st is not None and _is_newer(tst, real_st):
                    continue  # refreshed inside the sandbox: keep it
            if tst is not None and stat.S_ISLNK(tst.st_mode):
                try:
                    if os.readlink(name, dir_fd=cfd) == item:
                        continue
                except OSError:
                    pass
            # Replace whatever is there (never following it) with the link.
            tmp = ".%s.lnk.%s" % (name, _rand())
            os.symlink(item, tmp, dir_fd=cfd)
            try:
                os.rename(tmp, name, src_dir_fd=cfd, dst_dir_fd=cfd)
            except OSError as e:
                os.unlink(tmp, dir_fd=cfd)
                if e.errno not in (errno.EISDIR, errno.ENOTEMPTY, errno.EBUSY):
                    warn("cannot link %s: %s" % (name, e.strerror))
    finally:
        os.close(rfd)
        os.close(cfd)
    return 0


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 64
    cmd, a = argv[1], argv[2:]
    try:
        if cmd == "mkdir" and len(a) in (2, 3):
            return cmd_mkdir(*a)
        if cmd == "write" and len(a) == 4:
            return cmd_write(*a)
        if cmd == "ensure-file" and len(a) == 4:
            return cmd_ensure_file(*a)
        if cmd == "read" and len(a) >= 2:
            return cmd_read(a[0], a[1], a[2:])
        if cmd == "sync" and len(a) >= 3:
            return cmd_sync(a[0], a[1], a[2], a[3:])
    except Refused as e:
        warn(str(e))
        return 3
    except FileNotFoundError as e:
        warn("%s: %s" % (e.filename or cmd, e.strerror))
        return 2
    except OSError as e:
        warn("%s: %s" % (e.filename or cmd, e.strerror))
        return 1
    sys.stderr.write("overlay-fs: bad usage: %s\n" % " ".join(argv[1:]))
    return 64


if __name__ == "__main__":
    sys.exit(main(sys.argv))

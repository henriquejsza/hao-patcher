"""Safe file and text handling for hao when it runs as root or handles other people's data.

  harden_env(env)        run as root: drop hao's developer variables (they choose what root runs, reads or writes),
                         use the system PATH and, under sudo, the sudo user's home from the account database; called
                         before hao computes any path
  create(path, data)     a new file, never through a symlink or over an existing file; mode and owner set on the
                         open descriptor
  open_log(path)         append to a log, never through a symlink; created 0600
  read_small(path)       a regular file that is not a symlink, owned by root or OWNERS, at most a size, else None
  text(s)                external text for the terminal: control characters and bidi overrides made visible
"""
import os
import re
import stat
from pathlib import Path

# hao's own variables a user's environment could carry into a root run; each one changes what root executes, reads,
# writes or where it looks (developer overrides; HAO_STICK is set by the USB installer's launcher, where only root exists)
DEVELOPER = ('HAO_LAUNCHER', 'HAO_LOGS', 'HAO_RECORD', 'HAO_ANYWHERE', 'HAO_STICK', 'HAO_DISK_FLOOR_GB',
             'HAO_NO_RICH', 'HAO_PALETTE')
SYSTEM_PATH = '/usr/bin:/bin:/usr/sbin:/sbin'
UNKNOWN_UID = 99            # a volume mounted with owners ignored (the USB installer's HAO in the Recovery)


class _Owned:
    """This process's user, or the 'unknown' owner of a volume whose owners are ignored."""
    def __contains__(self, uid):
        return uid in (os.geteuid(), UNKNOWN_UID)


OWNED = _Owned()


def elevated(env=None, euid=None):
    """Root started by a user through sudo (not the Recovery's root, where no user exists)."""
    env = os.environ if env is None else env
    return (os.geteuid() if euid is None else euid) == 0 and bool(env.get('SUDO_USER') or env.get('SUDO_UID'))


def harden_env(env=None, euid=None, home_of=None):
    """As root: remove DEVELOPER variables and TMPDIR, set PATH to the system's. HAO_STICK stays only for a root that
    no user started (the USB installer's Recovery, whose launcher sets it). Under sudo HOME becomes the sudo user's
    home as the account database has it. Returns the names removed."""
    env = os.environ if env is None else env
    if (os.geteuid() if euid is None else euid) != 0:
        return []
    by_sudo = elevated(env, 0)
    drop = [k for k in DEVELOPER + ('TMPDIR',) if k != 'HAO_STICK' or by_sudo]
    gone = [k for k in drop if k in env]
    for k in gone:
        del env[k]
    env['PATH'] = SYSTEM_PATH
    if by_sudo:
        home = (home_of or _home_of)(env)
        if home:
            env['HOME'] = home
        else:
            env.pop('HOME', None)
    return gone


def _home_of(env):
    import pwd
    try:
        if env.get('SUDO_UID', '').isdigit():
            return pwd.getpwuid(int(env['SUDO_UID'])).pw_dir
        return pwd.getpwnam(env.get('SUDO_USER', '')).pw_dir
    except (KeyError, ValueError):
        return None


def sudo_owner(env=None):
    """(uid, gid) of the user who ran sudo, when hao runs as root through sudo; else None."""
    env = os.environ if env is None else env
    if os.geteuid() == 0 and env.get('SUDO_UID', '').isdigit() and env.get('SUDO_GID', '').isdigit():
        return int(env['SUDO_UID']), int(env['SUDO_GID'])
    return None


def as_user(owner, fn):
    """FN() run in a child process with OWNER's (uid, gid) and no supplementary groups; its return value (a string)
    comes back. Root writing for a user does it as that user, so the user's folders (and any symlink in them) give
    root nothing: the kernel checks the user's own rights."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.close(r)
            os.setgroups([])
            os.setgid(owner[1])
            os.setuid(owner[0])
            out = fn()
            os.write(w, ('ok\0' + str(out)).encode())
            code = 0
        except BaseException as x:          # noqa: B902 - reported to the parent, never raised in the child
            try:
                os.write(w, ('err\0%s\0%s' % (type(x).__name__, x)).encode())
            except OSError:
                pass
        finally:
            os._exit(code)
    os.close(w)
    data = b''
    while True:
        chunk = os.read(r, 65536)
        if not chunk:
            break
        data += chunk
    os.close(r)
    os.waitpid(pid, 0)
    parts = data.decode(errors='replace').split('\0')
    if parts[0] == 'ok':
        return parts[1]
    kind, msg = (parts[1], parts[2]) if len(parts) >= 3 else ('OSError', 'the writer stopped')
    raise (FileExistsError if kind == 'FileExistsError' else OSError)(msg)


def create(path, data, mode=0o600, owner=None):
    """Write DATA (str or bytes) to a new file at PATH: O_EXCL and O_NOFOLLOW, so neither an existing file nor a
    symlink planted at the name is written through; mode and owner (uid, gid) are set on the descriptor."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0), mode)
    try:
        os.fchmod(fd, mode)
        if owner is not None:
            os.fchown(fd, owner[0], owner[1])
        with os.fdopen(fd, 'wb', closefd=False) as f:
            f.write(data.encode() if isinstance(data, str) else data)
    finally:
        os.close(fd)
    return Path(path)


def private_dir(path, mode=0o700):
    """PATH as a folder of this user (root: root) that is not a symlink, has no symlinked folder above it, and is not
    writable by others; created MODE if missing, an existing one of ours narrowed to MODE."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True, mode=mode)
    st = os.lstat(str(p))
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise OSError('%s is not a plain folder' % p)
    if os.path.realpath(str(p)) != os.path.abspath(str(p)) and not _firmlinked(p):
        raise OSError('%s has a symlinked folder above it' % p)
    if st.st_uid not in OWNED:
        raise OSError('%s belongs to another user' % p)
    if st.st_uid == os.geteuid() and st.st_mode & 0o7777 != mode:
        os.chmod(str(p), mode)
    return p


def _firmlinked(p):
    """P's real path differs from its absolute path only by macOS's own /var, /tmp and /etc -> /private/... links."""
    real, path = os.path.realpath(str(p)), os.path.abspath(str(p))
    for top in ('/var/', '/tmp/', '/etc/'):
        if path.startswith(top) or path == top.rstrip('/'):
            path = '/private' + path
            break
    return real == path


def open_log(path):
    """A text file to append to: never through a symlink, never a FIFO or device, never a file with another name
    (hard link) or another owner; created or narrowed to 0600."""
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
                 | getattr(os, 'O_CLOEXEC', 0), 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid not in OWNED:
            raise OSError('%s is not a plain log file of this user' % path)
        os.fchmod(fd, 0o600)
        import fcntl
        fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) & ~os.O_NONBLOCK)
    except BaseException:
        os.close(fd)
        raise
    return os.fdopen(fd, 'a', encoding='utf-8', errors='replace')


def read_small(path, limit=4 << 20, owners=None):
    """The text of PATH when it is a regular file, not a symlink, at most LIMIT bytes and (with OWNERS) owned by
    root or one of OWNERS; else None. Read through the descriptor that was checked."""
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_CLOEXEC', 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return None
        if owners is not None and st.st_uid not in set(owners) | {0}:
            return None
        with os.fdopen(fd, 'rb', closefd=False) as f:
            return f.read(limit + 1)[:limit].decode('utf-8', errors='replace')
    finally:
        os.close(fd)


CONTROL = re.compile('[\x00-\x08\x0b-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]')


def clean(value):
    """VALUE (decoded JSON) with every string in it passed through text()."""
    if isinstance(value, str):
        return text(value)
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, dict):
        return {text(k) if isinstance(k, str) else k: clean(v) for k, v in value.items()}
    return value


def text(s):
    """S with control characters (escape sequences included) and bidi overrides shown as \\xNN / \\uNNNN, so text
    from backends, files or the network cannot move the cursor, recolour or rewrite what the terminal shows."""
    if not isinstance(s, str):
        s = str(s)
    return CONTROL.sub(lambda m: ('\\x%02x' % ord(m.group())) if ord(m.group()) < 0x100 else '\\u%04x' % ord(m.group()), s)

"""Safe file and text handling for hao when it runs as root or handles other people's data.

  harden_env(env)        run elevated from a user (sudo): drop hao's developer variables (they choose what root runs,
                         reads or writes) and use the system PATH, before anything else runs
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


def elevated(env=None, euid=None):
    """Root started by a user through sudo (not the Recovery's root, where no user exists)."""
    env = os.environ if env is None else env
    return (os.geteuid() if euid is None else euid) == 0 and bool(env.get('SUDO_USER') or env.get('SUDO_UID'))


def harden_env(env=None, euid=None):
    """Under sudo: remove DEVELOPER variables and TMPDIR, set PATH to the system's. Returns the names removed."""
    env = os.environ if env is None else env
    if not elevated(env, euid):
        return []
    gone = [k for k in DEVELOPER + ('TMPDIR',) if k in env]
    for k in gone:
        del env[k]
    env['PATH'] = SYSTEM_PATH
    return gone


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
    """PATH as a folder that is not a symlink (created MODE if missing; an existing one keeps its mode)."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True, mode=mode)
    st = os.lstat(str(p))
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise OSError('%s is not a plain folder' % p)
    return p


def open_log(path):
    """A text file to append to: never through a symlink, created 0600."""
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0),
                 0o600)
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


def text(s):
    """S with control characters (escape sequences included) and bidi overrides shown as \\xNN / \\uNNNN, so text
    from backends, files or the network cannot move the cursor, recolour or rewrite what the terminal shows."""
    if not isinstance(s, str):
        s = str(s)
    return CONTROL.sub(lambda m: ('\\x%02x' % ord(m.group())) if ord(m.group()) < 0x100 else '\\u%04x' % ord(m.group()), s)

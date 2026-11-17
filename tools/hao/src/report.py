"""hao report: one text file a developer needs to diagnose a failed run, made to attach to a GitHub issue.

It holds: hao's release and commit, this Mac (sw_vers, model, CPU, memory, SIP, boot arguments), the `hao detect`
profile, the log of the last hao command (create-installer, build-disk and install keep their console events in
LOGS: /Library/Logs/hao when run as root, else ~/Library/Logs/hao), the install record
(/private/var/db/hao/install-record.json) and the live patch records, when there are any.

No private data: the serial number and hardware UUID, the computer and host names, user names (home folders become
USER), Wi-Fi network names, e-mail and hardware (MAC) addresses are replaced before anything is written.
"""
import datetime
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess

import detect as DETECT
import safety as SAFE
import livepatch as LP

TOP = Path(__file__).resolve().parents[3]
SYSTEM_LOGS = Path('/Library/Logs/hao')
STATE = Path('/private/var/db/hao')
KEEP = 30                                     # command logs kept per folder
USER = 'USER'
HOME = re.compile(r'(/Users/)(?!Shared\b)([^/\s"\'\\]+)')
LABELLED = [
    # key or label, then its value: serials, UUIDs, Wi-Fi names and the like as plists, JSON and tool output show them
    (re.compile(r'((?:IOPlatformSerialNumber|serial[ _-]?number|SerialNumber|IOPlatformUUID|Hardware UUID|'
                r'Provisioning UDID)["\']?\s*(?:\([^)]*\))?\s*[:=]\s*["\']?)([^"\'\s,<]+)', re.I), '[removed]'),
    (re.compile(r'((?:SSID(?:_STR)?|Network ?Name|Current Network Information)["\']?\s*[:=]\s*["\']?)([^"\'\n,<]+)',
                re.I), '[wifi]'),
]
EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
URL_SECRET = re.compile(r'(\b[a-z][a-z0-9+.-]*://)[^/\s@:]+(?::[^/\s@]*)?@', re.I)
URL_QUERY = re.compile(r'(\b[a-z][a-z0-9+.-]*://[^\s?#"\']+)\?[^\s#"\']+', re.I)
SECRET_NAMES = r'(?:password|passwd|passphrase|secret|token|api[_-]?key|access[_-]?key|auth(?:orization)?|cookie|session)'
SECRET_FIELD = re.compile(r'("[A-Za-z0-9_-]*%s[A-Za-z0-9_-]*"\s*:\s*)"(?:[^"\\]|\\.)*"' % SECRET_NAMES, re.I)
BEARER = re.compile(r'(\b(?:Bearer|Basic|token)\s+)[^\s"\',;&]+', re.I)
SECRET_WORD = re.compile(r'(\b[A-Za-z0-9_-]*%s[A-Za-z0-9_-]*\s*[=:]\s*)(?!\[removed\])(?:(?:Bearer|Basic)\s+)?[^\s"\',;&]+'
                         % SECRET_NAMES, re.I)
URL_FRAGMENT = re.compile(r'(\b[a-z][a-z0-9+.-]*://[^\s#"\']+)#[^\s"\']+', re.I)
MAC_ADDRESS = re.compile(r'\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b')


def log_dir(env=None, euid=None):
    """Where this run keeps its command log: HAO_LOGS, else the USB installer's logs/ (HAO_STICK), else
    /Library/Logs/hao as root, else ~/Library/Logs/hao. (Under sudo hao drops HAO_LOGS and HAO_STICK first.)"""
    env = os.environ if env is None else env
    if env.get('HAO_LOGS'):
        return Path(env['HAO_LOGS'])
    if env.get('HAO_STICK'):
        return Path(env['HAO_STICK']) / 'logs'
    if (os.geteuid() if euid is None else euid) == 0:
        return SYSTEM_LOGS
    return Path(env.get('HOME') or Path.home()) / 'Library' / 'Logs' / 'hao'


def log_dirs(env=None):
    """Every folder a command log may be in, newest first is decided by the files themselves."""
    env = os.environ if env is None else env
    if env.get('HAO_LOGS'):
        return [Path(env['HAO_LOGS'])]
    out = [Path(env['HAO_STICK']) / 'logs'] if env.get('HAO_STICK') else []
    out += [SYSTEM_LOGS, Path(env.get('HOME') or Path.home()) / 'Library' / 'Logs' / 'hao']
    if env.get('SUDO_USER'):
        home = SAFE._home_of(env)
        if home:
            out.append(Path(home) / 'Library' / 'Logs' / 'hao')
    return list(dict.fromkeys(out))


def version():
    """{'release', 'commit'}: release.json beside hao names the release and the commit it was cut from; a checkout
    names its own commit."""
    out = {}
    rel = TOP / 'tools' / 'hao' / 'release.json'
    if rel.is_file():
        try:
            r = json.loads(rel.read_text())
            out['release'], out['release_commit'] = r.get('release'), r.get('hao_patcher')
        except ValueError:
            out['release'] = 'release.json unreadable'
    stamp = TOP / 'tools' / 'hao' / 'VERSION'          # written by the hao-command recipe when it stages hao
    if not (TOP / '.git').exists() and stamp.is_file():
        out['commit'] = stamp.read_text().strip()
    if (TOP / '.git').exists():
        r = subprocess.run(['git', '-C', str(TOP), 'describe', '--always', '--dirty', '--abbrev=12'],
                           capture_output=True, text=True)
        if r.returncode == 0:
            out['commit'] = r.stdout.strip()
    return out


def save_log(command, argv, events, folder=None, ver=None, now=None):
    """Keep COMMAND's console events as FOLDER/COMMAND-DATE.json, 0600 in a 0700 folder, created new (never through a
    symlink or over a file); the oldest beyond KEEP go (plain files only). Returns the path, or None when it cannot be
    written."""
    folder = Path(folder) if folder else log_dir()
    stamp = (now or datetime.datetime.now()).strftime('%Y%m%d-%H%M%S')
    data = json.dumps({'command': command, 'argv': list(argv), 'hao': ver if ver is not None else version(),
                       'events': events}, indent=1, default=str) + '\n'
    try:
        SAFE.private_dir(folder)
        path = None
        for n in range(10):
            candidate = folder / ('%s-%s%s.json' % (command, stamp, '-%d' % n if n else ''))
            try:
                path = SAFE.create(candidate, data, 0o600)
                break
            except FileExistsError:
                continue
        if path is None:
            return None
        plain = [p for p in folder.glob('*-*.json') if p.is_file() and not p.is_symlink()]
        for old in sorted(plain, key=lambda p: p.lstat().st_mtime)[:-KEEP]:
            old.unlink()
        return path
    except OSError:
        return None


def log_owners(env=None):
    """Whose logs a root run may read: root's and the sudo user's (none else)."""
    env = os.environ if env is None else env
    return {os.geteuid()} | ({int(env['SUDO_UID'])} if env.get('SUDO_UID', '').isdigit() else set())


def owners_of(folder, env=None):
    """Whose files FOLDER may hold, for root to read them: the system log folder and the install record's folder are
    root's; the USB installer's logs root's (or its volume's unknown owner); any other folder is the user's (the sudo
    user's under sudo), never root's: a user's folder that leads to root's files gives root nothing to read."""
    env = os.environ if env is None else env
    folder = Path(folder)
    if folder == SYSTEM_LOGS or folder == STATE:
        return {0}
    if env.get('HAO_STICK') and folder == Path(env['HAO_STICK']) / 'logs':
        return {0, SAFE.UNKNOWN_UID}
    if os.geteuid() == 0 and env.get('SUDO_UID', '').isdigit():
        return {int(env['SUDO_UID'])}
    return {os.geteuid()}


def plain_folder(folder, owners):
    """FOLDER is a folder (no symlink at it or above it) owned by one of OWNERS."""
    try:
        st = os.lstat(str(folder))
    except OSError:
        return False
    import stat as _st
    if not _st.S_ISDIR(st.st_mode) or st.st_uid not in owners:
        return False
    return os.path.realpath(str(folder)) == os.path.abspath(str(folder)) or SAFE._firmlinked(Path(folder))


SCAN_LIMIT = 1000


def candidates(folders, env=None):
    """[(mtime, path)] of command logs that root may read, newest first: plain files (not links) in plain folders, both
    owned as owners_of says; at most SCAN_LIMIT entries are looked at per folder."""
    import stat as _st
    found = []
    for f in folders:
        owners = owners_of(f, env)
        if not plain_folder(f, owners):
            continue
        try:
            with os.scandir(str(f)) as it:
                for n, e in enumerate(it):
                    if n >= SCAN_LIMIT:
                        break
                    if not re.fullmatch(r'[A-Za-z0-9._-]+-[0-9-]+\.json', e.name):
                        continue
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if _st.S_ISREG(st.st_mode) and st.st_uid in owners:
                        found.append((st.st_mtime, Path(e.path)))
        except OSError:
            continue
    return sorted(found, reverse=True)


def last_log(folders, env=None):
    """The newest command log root may read (candidates())."""
    found = candidates(folders, env)
    return found[0][1] if found else None


def _out(host, *argv):
    r = host.run(list(argv), check=False)
    return r.stdout.decode(errors='replace').strip() if r.returncode == 0 else ''


def secrets(host, env):
    """{text: replacement} of what identifies this Mac or its owner."""
    found = {}
    pe = {}
    try:
        p = plistlib.loads(host.run(['ioreg', '-a', '-r', '-d', '1', '-c', 'IOPlatformExpertDevice'],
                                    check=False).stdout or b'')
        pe = p[0] if isinstance(p, list) and p else p if isinstance(p, dict) else {}
    except Exception:
        pass
    for key, label in (('IOPlatformSerialNumber', '[serial]'), ('IOPlatformUUID', '[uuid]')):
        if isinstance(pe.get(key), str):
            found[pe[key]] = label
    for argv in (['scutil', '--get', 'ComputerName'], ['scutil', '--get', 'LocalHostName'], ['hostname']):
        name = _out(host, *argv)
        if name:
            found[name] = '[computer name]'
            found[name.split('.')[0]] = '[computer name]'
    for key in ('SUDO_USER', 'USER', 'LOGNAME'):
        if env.get(key) and env[key] != 'root':
            found[env[key]] = USER
            full = _out(host, 'id', '-F', env[key])
            if full:
                found[full] = '[name]'
    home = env.get('HOME', '')
    if home.startswith('/Users/') and home.count('/') == 2:
        found[home.rsplit('/', 1)[1]] = USER
    return {k: v for k, v in found.items() if len(k) >= 3}


def scrub(text, private):
    """TEXT with PRIVATE's strings ({text: replacement}) and every labelled serial, UUID, Wi-Fi name, e-mail and
    hardware address replaced; the name of each home folder becomes USER."""
    text = HOME.sub(lambda m: m.group(1) + USER, text)
    for pattern, label in LABELLED:
        text = pattern.sub(lambda m: m.group(1) + label, text)
    text = URL_SECRET.sub(lambda m: m.group(1) + '[credentials]@', text)    # https://user:pass@host
    text = SECRET_FIELD.sub(lambda m: m.group(1) + '"[removed]"', text)       # "password": "..."
    text = BEARER.sub(lambda m: m.group(1) + '[removed]', text)               # Bearer ...
    text = SECRET_WORD.sub(lambda m: m.group(1) + '[removed]', text)          # token=..., password: ...
    text = URL_FRAGMENT.sub(lambda m: m.group(1) + '#[fragment]', text)
    text = URL_QUERY.sub(lambda m: m.group(1) + '?[query]', text)             # tokens in query strings
    text = EMAIL.sub('[email]', text)
    text = MAC_ADDRESS.sub('[hardware address]', text)
    for secret in sorted(private, key=len, reverse=True):
        text = re.sub(r'(?<![A-Za-z0-9])%s(?![A-Za-z0-9])' % re.escape(secret), private[secret], text)
    return text


def _json(path, env=None):
    owners = owners_of(Path(path).parent, env)
    text = SAFE.read_small(path, owners=owners) if plain_folder(Path(path).parent, owners) else None
    if text is None:
        return '(not read: %s is not a plain file in a plain folder of its owner, or is larger than 4 MB)' % path
    try:
        return json.dumps(json.loads(text), indent=1, default=str, ensure_ascii=False)
    except RecursionError:
        return 'unreadable: nested too deeply'
    except (OSError, ValueError) as x:
        return 'unreadable: %s' % x


def collect(host, env=None, folders=None, state=STATE, ver=None, now=None):
    """The report's text, scrubbed."""
    env = dict(os.environ) if env is None else env
    folders = log_dirs(env) if folders is None else folders
    when = now or datetime.datetime.now()
    parts = ['hao report  %s' % when.strftime('%Y-%m-%d %H:%M:%S'),
             'For a GitHub issue. Removed before writing: serial number, hardware UUID, computer name, user names, '
             'Wi-Fi names, e-mail and hardware addresses, credentials and query strings in URLs. Read it before you '
             'share it: messages from programs can hold other details.']

    def section(title, body):
        parts.extend(['', '== ' + title, body.rstrip() or '(none)'])

    v = ver if ver is not None else version()
    section('hao', '\n'.join('%-15s %s' % (k, v[k]) for k in ('release', 'release_commit', 'commit') if v.get(k))
            or 'version unknown (no release.json and no git checkout)')
    csr = host.csr_config()
    boot_args = _out(host, 'nvram', 'boot-args').partition('\t')[2]
    mem = _out(host, 'sysctl', '-n', 'hw.memsize')
    section('This Mac', '\n'.join([
        _out(host, 'sw_vers'),
        'model          %s' % _out(host, 'sysctl', '-n', 'hw.model'),
        'cpu            %s' % _out(host, 'sysctl', '-n', 'machdep.cpu.brand_string'),
        'memory         %s' % ('%d GB' % (int(mem) // (1 << 30)) if mem.isdigit() else 'unknown'),
        'machine        %s' % _out(host, 'uname', '-m'),
        'kernel         %s' % _out(host, 'uname', '-v'),
        'SIP (csr)      %s' % ('unknown' if csr is None else '0x%x' % csr),
        'boot-args      %s' % (boot_args or '(none)'),
        'running as     %s' % ('root' if host.euid() == 0 else 'a user')]))
    try:
        p = DETECT.profile(DETECT.facts(host))
        p['target'] = DETECT.target_for_model(p['model'])[0]
        section('hao detect', json.dumps(p, indent=1))
    except (DETECT.DetectError, LP.PatchError, OSError, KeyError, ValueError) as x:
        section('hao detect', 'failed: %s' % x)
    log = last_log(folders, env)
    section('Last command' + (' (%s)' % log.name if log else ''), _json(log) if log else
            'no hao command log (looked in %s)' % ', '.join(str(f) for f in folders))
    others = [p.name for _, p in candidates(folders, env) if p != log]
    if others:
        section('Earlier command logs', '\n'.join(others[:KEEP]))
    record = Path(state) / 'install-record.json'
    section('Install record', _json(record) if record.is_file() else 'none (%s)' % record)
    try:
        recs = LP.records(state)
    except (OSError, ValueError):
        recs = []
    if recs:
        section('Live patches', '\n'.join('%s %s packs %s snapshot %s' % (r.get('id'), r.get('state'),
                                                                          ','.join(r.get('packs', [])), r.get('snapshot'))
                                          for r in recs))
    return scrub('\n'.join(parts) + '\n', secrets(host, env))


def default_output(now=None, cwd=None):
    """hao-report-DATE.txt in the current folder (the release folder the user ran hao from), else /private/tmp."""
    name = 'hao-report-%s.txt' % (now or datetime.datetime.now()).strftime('%Y%m%d-%H%M%S')
    cwd = Path(cwd or os.getcwd())
    return (cwd if os.access(cwd, os.W_OK) else Path('/private/tmp')) / name


def write(path, text, env=None):
    """Write the report; under sudo, give it to the user who ran sudo so they can attach and delete it."""
    env = os.environ if env is None else env
    path = Path(path)
    owner = SAFE.sudo_owner(env)

    def new():
        # a new file only: an existing name (or a symlink planted at it) is never written through
        for n in range(10):
            candidate = path if n == 0 else path.with_name('%s-%d%s' % (path.stem, n, path.suffix))
            try:
                return str(SAFE.create(candidate, text, 0o600))
            except FileExistsError:
                continue
        raise FileExistsError('%s and nine numbered names next to it exist already' % path)
    # under sudo the file is written by the sudo user itself, so the user's folders (and any link in them) can lead
    # root nowhere: the kernel checks the user's own rights
    return Path(SAFE.as_user(owner, new) if owner else new())


def report(a, c, host, env=None, folders=None, state=STATE, ver=None):
    path = Path(a.output).expanduser() if getattr(a, 'output', None) else default_output()
    text = collect(host, env, folders, state, ver)
    try:
        path = write(path, text, env)
    except OSError:
        if getattr(a, 'output', None):
            raise
        path = write(Path('/private/tmp') / path.name, text, env)      # the current folder is not the user's
    c.event('report', path=str(path), bytes=len(text))
    c.done('report written to %s' % path.resolve(), path=str(path))
    c.print('Read it, then attach it to a GitHub issue: serials, user and Wi-Fi names, addresses and credentials '
            'are removed, but messages from programs can hold other details.', 'quiet')
    return 0

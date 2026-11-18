"""The commit a producer runs from: git's HEAD in a checkout, else the commit `git archive` wrote into
pipeline/SOURCE_COMMIT (export-subst, .gitattributes) when the release archive was made. A user's folder is such an
archive: no .git, and clean by construction, so its dirty flag is False."""
from pathlib import Path
import re
import subprocess

TOP = Path(__file__).resolve().parents[1]


def _git(top, *args):
    # this checkout only (it may be a user's, read under sudo: git otherwise refuses another owner's repository)
    r = subprocess.run(['git', '-c', 'safe.directory=%s' % top, '-C', str(top), *args], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def commit(top=TOP):
    head = _git(top, 'rev-parse', 'HEAD') if (Path(top) / '.git').exists() else None
    if head:
        return head
    stamped = (Path(top) / 'pipeline' / 'SOURCE_COMMIT')
    text = stamped.read_text().strip() if stamped.is_file() else ''
    return text if re.fullmatch(r'[0-9a-f]{40}', text) else ''


def dirty(top=TOP, *paths):
    if not (Path(top) / '.git').exists():
        return False
    return bool(_git(top, 'status', '--porcelain', '--', *map(str, paths)))


def git_env(environ, top=TOP):
    """ENVIRON's additions that make git trust TOP (only) in every program run below it: a user's checkout read as
    root under sudo, which git otherwise refuses as another owner's ("dubious ownership"). Configuration from the
    environment is command-line scope, which safe.directory honours."""
    n = int(environ.get('GIT_CONFIG_COUNT') or 0)
    for i in range(n):
        if (environ.get('GIT_CONFIG_KEY_%d' % i), environ.get('GIT_CONFIG_VALUE_%d' % i)) == ('safe.directory', str(top)):
            return {}
    return {'GIT_CONFIG_COUNT': str(n + 1), 'GIT_CONFIG_KEY_%d' % n: 'safe.directory', 'GIT_CONFIG_VALUE_%d' % n: str(top)}

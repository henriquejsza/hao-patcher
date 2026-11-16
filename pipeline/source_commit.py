"""The commit a producer runs from: git's HEAD in a checkout, else the commit `git archive` wrote into
pipeline/SOURCE_COMMIT (export-subst, .gitattributes) when the release archive was made. A user's folder is such an
archive: no .git, and clean by construction, so its dirty flag is False."""
from pathlib import Path
import re
import subprocess

TOP = Path(__file__).resolve().parents[1]


def _git(top, *args):
    r = subprocess.run(['git', '-C', str(top), *args], capture_output=True, text=True)
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

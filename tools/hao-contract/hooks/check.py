#!/usr/bin/env python3
"""Hygiene hooks for the hao repositories: no private string in a commit message or in a staged change.

    check.py commit-msg FILE     the message git is about to record (git's comment lines are ignored)
    check.py pre-commit          the lines the staged change adds (git diff --cached)

What counts as private is kept outside every repository (HYGIENE.md section 1). The lists are named, one per line
`KIND PATH`, in hao-hygiene-lists beside the installed hook (written by hooks/install, never tracked):
  names PATH      LABEL: TEXT       literal private names (hao_contract.py's format)
  patterns PATH   LABEL<TAB>REGEX   private patterns
  wording PATH    LABEL<TAB>REGEX   internal wording a public message or doc must not use (HYGIENE 2.6)
plus any absolute home folder. The private names, patterns and home folders are checked in the message and in every
added line. The wording is checked in the message and in the added lines of documentation (*.md, patch.json).
A finding prints its label and where it is, never the matched text. Exit status 1 when anything is found.
"""
import os
from pathlib import Path
import re
import subprocess
import sys

HOME = re.compile('(?<![A-Za-z0-9_.])/' r'(Users/(?!Shared\b|[A-Z_]+\b)[A-Za-z]|home/[a-z])')   # built from parts
LISTS = Path(__file__).resolve().with_name('hao-hygiene-lists')
DOCS = re.compile(r'(\.md|(^|/)patch\.json)$')


def literal(path):
    out = []
    if path.is_file():
        for line in path.read_text(errors='replace').splitlines():
            label, sep, text = line.split('#', 1)[0].strip().partition(':')
            if sep and text.strip():
                out.append((label.strip(), re.compile(re.escape(text.strip()))))
    return out


def regexes(path):
    out = []
    if path.is_file():
        for line in path.read_text(errors='replace').splitlines():
            if line.strip() and not line.lstrip().startswith('#') and '\t' in line:
                label, _, rx = line.partition('\t')
                out.append((label.strip(), re.compile(rx.strip(), re.I)))
    return out


def lists():
    out = {}
    path = Path(os.environ.get('HAO_HYGIENE_LISTS') or LISTS)
    if path.is_file():
        for line in path.read_text().splitlines():
            kind, _, file = line.strip().partition(' ')
            if kind and file and not kind.startswith('#'):
                out.setdefault(kind, []).append(Path(os.path.expanduser(file.strip())))
    return out


def rules():
    l = lists()
    private = [('home folder', HOME)] + [r for f in l.get('names', []) for r in literal(f)] + \
        [r for f in l.get('patterns', []) for r in regexes(f)]
    return private, [r for f in l.get('wording', []) for r in regexes(f)]


def findings(text, checks):
    return sorted({label for label, rx in checks if rx.search(text)})


def message(path):
    private, wording = rules()
    body = '\n'.join(l for l in Path(path).read_text(errors='replace').splitlines() if not l.startswith('#'))
    return ['commit message names a %s' % label for label in findings(body, private + wording)]


def staged():
    diff = subprocess.run(['git', 'diff', '--cached', '-U0', '--no-color', '--no-ext-diff', '--diff-filter=ACMR'],
                          capture_output=True, text=True, errors='replace', check=True).stdout
    private, wording = rules()
    out, name, line = [], None, 0
    for row in diff.splitlines():
        if row.startswith('+++ '):
            name = row[6:] if row.startswith('+++ b/') else None
        elif row.startswith('@@'):
            m = re.search(r'\+(\d+)', row)
            line = int(m.group(1)) if m else 0
        elif row.startswith('+') and name:
            checks = private + (wording if DOCS.search(name) else [])
            out += ['%s:%d names a %s' % (name, line, label) for label in findings(row[1:], checks)]
            line += 1
    return out


def main(argv):
    if len(argv) == 2 and argv[0] == 'commit-msg':
        bad, what = message(argv[1]), 'the commit message'
    elif argv == ['pre-commit']:
        bad, what = staged(), 'the staged change'
    else:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    for b in bad:
        print('hygiene: ' + b, file=sys.stderr)
    if bad:
        print('hygiene: %s was refused (HYGIENE.md: public repositories carry no private names, paths or internal '
              'wording). Reword it and commit again.' % what, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

"""The hao commands' output: five detail levels over one stream of events (the owner-endorsed console mockups).

  quiet   --quiet       progress and the one question that matters
  steps   (default)     one line per step, each with its check
  files   --show        one line per file or repair; full reports on failure
  edits   --show-edits  origin, bytes and reason of each change
  json    --log json    every event as one JSON line, for tools and CI

Every event is also kept (Console.events) so a command can write it into its record (the install record, a build
record). Lines a level does not show are still events. Output goes to OUT (stdout); questions read from ASK.

Colour (the mockups' palette): green check marks and "sha256 ✓", cyan progress, bold step headers and names, dim
notes and paths, yellow warnings and "will be erased", red ✗ and STOPPED, origin tags in their colours (Apple grey,
Tahoe orange, OCLP purple, hao teal). Only when the stream is a terminal, NO_COLOR is unset or empty and TERM is not
"dumb"; --log json is never coloured, and events never hold colour codes. The 256-colour values are chosen to read
on a white background (the Recovery's Terminal) as well as a dark one; a terminal without 256 colours gets the 8
basic ones.
"""
import json
import os
import re
import sys
import time

LEVELS = ('quiet', 'steps', 'files', 'edits', 'json')


# kind -> SGR parameters. 256 colours: 28 green #008700, 160 red #d70000, 136 amber #af8700, 31 blue-cyan #0087af,
# 244 grey #808080, 166 orange #d75f00, 97 purple #875faf, 30 teal #008787: each readable on white and on black.
SGR_256 = {'ok': '38;5;28', 'bad': '1;38;5;160', 'warn': '38;5;136', 'bar': '38;5;31', 'bold': '1', 'dim': '2',
           'apple': '38;5;244', 'tahoe': '38;5;166', 'oclp': '38;5;97', 'hao': '38;5;30'}
SGR_8 = {'ok': '32', 'bad': '1;31', 'warn': '33', 'bar': '36', 'bold': '1', 'dim': '2',
         'apple': '90', 'tahoe': '33', 'oclp': '35', 'hao': '36'}
ORIGINS = {'apple': 'Apple', 'tahoe': 'Tahoe', 'oclp': 'OCLP', 'hao': 'hao'}
ANSI = re.compile(r'\033\[[0-9;]*m')
ERASED = re.compile(r'([Ee]verything on (?:it|\S+(?: [^.?]*?)?) will be erased|will be erased)')


def colour_for(stream, env=None):
    """Whether STREAM gets colour: a terminal, NO_COLOR unset or empty (no-color.org), TERM not "dumb"."""
    env = os.environ if env is None else env
    if env.get('NO_COLOR') or env.get('TERM') == 'dumb':
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


class Style:
    """paint(kind, text): TEXT in KIND's colour when ON, else TEXT unchanged."""

    def __init__(self, on, env=None):
        env = os.environ if env is None else env
        self.on = on
        self.codes = SGR_256 if '256' in env.get('TERM', '') or env.get('COLORTERM') else SGR_8

    def __call__(self, kind, text):
        if not self.on or not text:
            return text
        return '\033[%sm%s\033[0m' % (self.codes[kind], text)

    def origin(self, kind, width=0):
        """The origin tag of KIND (apple, tahoe, oclp, hao; '' for none), padded to WIDTH before it is coloured."""
        name = ORIGINS.get(kind, '')
        return self(kind, '%-*s' % (width, name)) if name else ' ' * width

    def erased(self, text):
        """TEXT with its "will be erased" phrase in the warning colour."""
        return ERASED.sub(lambda m: self('warn', m.group(1)), text) if self.on else text


def plain(text):
    return ANSI.sub('', text) if isinstance(text, str) else text


def level_of(a):
    """The level an argparse namespace's --quiet / --show / --show-edits / --log json chose."""
    if getattr(a, 'log', None) == 'json':
        return 'json'
    if getattr(a, 'quiet', False):
        return 'quiet'
    if getattr(a, 'show_edits', False):
        return 'edits'
    if getattr(a, 'show', False):
        return 'files'
    return 'steps'


def add_level_flags(parser):
    g = parser.add_mutually_exclusive_group()
    g.add_argument('--quiet', action='store_true', help='progress only')
    g.add_argument('--show', action='store_true', help='one line per file or repair')
    g.add_argument('--show-edits', action='store_true', help='every edit: origin, bytes, reason')
    g.add_argument('--log', choices=['json'], help='every event as one JSON line')


class Stopped(Exception):
    """A check failed: the command stops and Console.stopped prints what happened, why it matters, what to do."""

    def __init__(self, what, why=None, cause=None, options=(), untouched=None):
        super().__init__(what)
        self.what, self.why, self.cause, self.options, self.untouched = what, why, cause, list(options), untouched


class Console:
    def __init__(self, level='steps', out=None, ask=None, clock=time.monotonic, colour=None, err=None, env=None):
        if level not in LEVELS:
            raise ValueError('level is one of %s' % ', '.join(LEVELS))
        self.level = level
        self.out = out or sys.stdout
        self.ask = ask or input
        self.clock = clock
        self.events = []
        self.total = 0
        self.index = 0
        self.started = clock()
        self._err, self._colour, self._env = err, colour, env
        self.paint = Style(level != 'json' and (colour_for(self.out, env) if colour is None else colour), env)
        enc = (getattr(self.out, 'encoding', None) or 'utf-8').lower()
        self.ok = self.paint('ok', '✓' if 'utf' in enc else 'ok')
        self.bad = self.paint('bad', '✗' if 'utf' in enc else 'FAILED')

    # -- plumbing
    @property
    def err(self):
        """Where warnings and stop reports go: ERR, else sys.stderr as it is now."""
        return self._err or sys.stderr

    @property
    def paint_err(self):
        on = self.level != 'json' and (colour_for(self.err, self._env) if self._colour is None else self._colour)
        return Style(on, self._env)

    def at(self, level):
        """Whether text meant for LEVEL is shown (json shows events, not text)."""
        return self.level != 'json' and LEVELS.index(self.level) >= LEVELS.index(level)

    def print(self, text='', level='steps'):
        if self.at(level):
            print(self.paint.erased(text), file=self.out, flush=True)

    def event(self, ev, **fields):
        e = dict(ev=ev, t=round(self.clock() - self.started, 3), **{k: plain(v) for k, v in fields.items()})
        self.events.append(e)
        if self.level == 'json':
            print(json.dumps(e, default=str), file=self.out, flush=True)
        return e

    # -- the shapes the mockups use
    def banner(self, text, **fields):
        self.event('run.start', text=text, **fields)
        head, sep, rest = text.partition('  ')
        self.print(self.paint('bold', head) + sep + rest)

    def steps(self, n):
        self.total, self.index = n, 0

    def step(self, title, note=None, **fields):
        self.index += 1
        self.event('step.start', step=title, index=self.index, of=self.total, **fields)
        if self.level == 'quiet':
            self.print(self.paint('bold', '%s...' % title), 'quiet')
        else:
            head = '[%d/%d] %s' % (self.index, self.total, title) if self.total else title
            self.print(self.paint('bold', head) + ('  ' + self.paint('dim', note) if note else ''))

    def item(self, text, level='steps', ok=None, **fields):
        """One line under a step; OK True adds the check mark. Kept as an event when FIELDS are given."""
        if fields:
            self.event(fields.pop('ev', 'item'), text=text, ok=ok, **fields)
        if ok and text.endswith('sha256'):   # "sha256 ✓" is one green check, as in the mockups
            self.print('  ' + text[:-6] + self.paint('ok', 'sha256 ') + self.ok, level)
            return
        self.print('  ' + text + (('  ' + self.ok) if ok else ''), level)

    def detail(self, text, level='edits'):
        self.print('            ' + self.paint('dim', text), level)

    def note(self, text, **fields):
        self.event('note', text=text, **fields)
        self.print('  ' + self.paint('warn', 'note') + '  ' + text, 'steps')

    def warning(self, text):
        self.event('warning', text=text)
        if self.level != 'json':
            print(self.paint_err('warn', 'warning:') + ' ' + text, file=self.err, flush=True)

    def confirm(self, question, word, given=None):
        """Ask QUESTION and require WORD typed (or GIVEN, from a flag). False when it does not match."""
        self.event('confirm', question=question, word=word, given=given is not None)
        if self.level != 'json' or given is None:
            print(self.paint.erased(question), file=self.out, flush=True)
        answer = given if given is not None else self.ask('Type %s to continue: ' % self.paint('bold', word))
        ok = answer.strip() == word
        self.event('confirmed' if ok else 'declined')
        return ok

    def done(self, text, **fields):
        self.event('run.end', ok=True, text=text, seconds=round(self.clock() - self.started, 1), **fields)
        self.print('%s %s' % (self.ok, text), 'quiet')

    def stopped(self, x):
        self.event('run.end', ok=False, what=x.what, why=x.why, cause=x.cause, options=x.options)
        if self.level == 'json':
            return
        w, s = self.err, self.paint_err
        print('\n%s %s' % (s('bad', 'STOPPED'), x.untouched or ''), file=w)
        for label, text in (('What happened', x.what), ('Why it matters', x.why), ('Likely cause', x.cause)):
            if text:
                print('  %s%s' % (s('bold', '%-17s' % label), text), file=w)
        if x.options:
            print('\n  ' + s('bold', 'What you can do'), file=w)
            for i, o in enumerate(x.options, 1):
                print('    %d  %s' % (i, o), file=w)
        w.flush()


def human_size(n):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1000 or unit == 'TB':
            return ('%d %s' if unit == 'B' else '%.1f %s') % (n, unit)
        n /= 1000.0

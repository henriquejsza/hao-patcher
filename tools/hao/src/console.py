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
import shutil
import sys
import threading
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
        # From the USB installer (HAO_STICK) the Recovery's Terminal is dark: its own 8 ANSI colours suit its
        # background, the 256-colour values (chosen to read on white) do not. HAO_PALETTE=8|256 chooses.
        palette = env.get('HAO_PALETTE') or ('8' if env.get('HAO_STICK') else '')
        self.codes = SGR_8 if palette == '8' else SGR_256 if palette == '256' or '256' in env.get('TERM', '') or \
            env.get('COLORTERM') else SGR_8

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


# Spinner frames and bar cells: quarter and full blocks on a UTF-8 terminal, ASCII where the stream is not UTF-8 or
# HAO_ASCII is set. Only glyphs Menlo and SF Mono have themselves (✓ ✗ ▖ █ ░ … · →): a Recovery may lack the
# fallback fonts a full macOS draws braille spinners with.
SPIN = {True: '▖▘▝▗', False: '-\\|/'}
CELLS = {True: ('█', '░'), False: ('#', '.')}
TICK = 0.1                    # seconds between redraws of a live line
HEARTBEAT = 30                # seconds between "still working" lines when the output is not a terminal


def animate_for(stream, env=None):
    """Whether STREAM gets lines redrawn in place: a terminal, NO_COLOR unset or empty, TERM not "dumb"."""
    return colour_for(stream, env)


def elapsed(seconds):
    """41s, 3m 52s, 1h 02m."""
    s = int(round(seconds))
    if s < 60:
        return '%ds' % s
    if s < 3600:
        return '%dm %02ds' % divmod(s, 60)
    return '%dh %02dm' % (s // 3600, s % 3600 // 60)


def fit(text, width):
    """TEXT cut to WIDTH visible characters (colour codes kept, a reset added when cut), so a line redrawn with \\r
    never wraps."""
    if width <= 0 or len(plain(text)) <= width:
        return text
    out, seen, i = [], 0, 0
    while i < len(text) and seen < width - 1:
        m = ANSI.match(text, i)
        if m:
            out.append(m.group()); i = m.end(); continue
        out.append(text[i]); seen += 1; i += 1
    return ''.join(out) + '…' + ('\033[0m' if '\033[' in text else '')


def bar(fraction, width, utf=True):
    full, empty = CELLS[utf]
    n = max(0, min(width, int(round(fraction * width))))
    return full * n + empty * (width - n)


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
    g.add_argument('-v', '--show', action='store_true', help='one line per file or repair')
    g.add_argument('--show-edits', action='store_true', help='every edit: origin, bytes, reason')
    g.add_argument('--log', choices=['json'], help='every event as one JSON line')


class Stopped(Exception):
    """A check failed: the command stops and Console.stopped prints what happened, why it matters, what to do."""

    def __init__(self, what, why=None, cause=None, options=(), untouched=None, log=None):
        super().__init__(what)
        self.what, self.why, self.cause, self.options, self.untouched = what, why, cause, list(options), untouched
        self.log = log


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
        e = os.environ if env is None else env
        self.utf = 'utf' in enc and not e.get('HAO_ASCII')
        self.ok = self.paint('ok', '✓' if self.utf else 'ok')
        self.bad = self.paint('bad', '✗' if self.utf else 'FAILED')
        self.animate = level != 'json' and (animate_for(self.out, env) if colour is None else colour)
        self.width = lambda: shutil.get_terminal_size((100, 24)).columns
        self.live = None          # the Task whose line is being redrawn, if any
        self.lock = threading.RLock()
        self.heartbeat = HEARTBEAT

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
            with self.lock:
                self._clear_live()
                print(self.paint.erased(text), file=self.out, flush=True)
                self._draw_live()

    def _clear_live(self):
        if self.live is not None and self.animate:
            self.out.write('\r\033[K')

    def _draw_live(self):
        if self.live is not None and self.animate:
            self.out.write(fit(self.live.render(), self.width() - 1))
            self.out.flush()

    def task(self, text, level='steps', total=None, unit=None, **fields):
        """A line that is being worked on: a spinner (or a bar, with TOTAL) and the time so far, redrawn in place on a
        terminal; elsewhere nothing until it ends, and a "still working" line every HEARTBEAT seconds. End it with
        .end(); as a context manager it ends with ✓, or ✗ when the block raises."""
        return Task(self, text, level, total, unit, fields)

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

    def step(self, title, note=None, quiet=True, **fields):
        """A numbered step's header ([N/M] TITLE  NOTE); at --quiet its title, unless QUIET is False (a command whose
        --quiet output is one bar)."""
        self.index += 1
        self.event('step.start', step=title, index=self.index, of=self.total, **fields)
        if self.level == 'quiet' and not quiet:
            return
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
            with self.lock:
                self._clear_live()
                print(self.paint_err('warn', 'warning:') + ' ' + text, file=self.err, flush=True)
                self._draw_live()

    def confirm(self, question, word, given=None):
        """Ask QUESTION and require WORD typed (or GIVEN, from a flag). False when it does not match."""
        self.event('confirm', question=question, word=word, given=given is not None)
        if self.level != 'json' or given is None:
            print(self.paint.erased(question), file=self.out, flush=True)
        answer = given if given is not None else self.ask('Type %s to continue: ' % self.paint('bold', word))
        ok = answer.strip() == word
        self.event('confirmed' if ok else 'declined')
        return ok

    def took(self):
        """The time since the command started, as the last line says it ("in 41m 18s")."""
        return elapsed(self.clock() - self.started)

    def done(self, text, **fields):
        took = self.clock() - self.started
        self.event('run.end', ok=True, text=text, seconds=round(took, 1), **fields)
        self.print('%s %s%s' % (self.ok, text, '  ' + self.paint('dim', 'in ' + elapsed(took))
                                if took >= 60 and ' in ' not in text else ''), 'quiet')

    def stopped(self, x):
        """The failure layout (variation 7): STOPPED and what was left untouched, then what happened, why it
        matters, the likely cause, numbered things to do, and the log."""
        self.event('run.end', ok=False, what=x.what, why=x.why, cause=x.cause, options=x.options, log=x.log)
        with self.lock:
            if self.live is not None:
                self.live.end(False)
        if self.level == 'json':
            return
        w, s = self.err, self.paint_err
        untouched = x.untouched or ''
        if untouched:
            untouched = untouched[0].upper() + untouched[1:] + ('' if untouched.endswith('.') else '.')
        print('\n%s\n' % ' '.join(x for x in (s('bad', 'STOPPED'), untouched) if x), file=w)
        for label, text in (('What happened', x.what), ('Why it matters', x.why), ('Likely cause', x.cause)):
            if text:
                print('  %s%s' % (s('bold', '%-17s' % label), text), file=w)
        if x.options:
            print('\n  ' + s('bold', 'What you can do'), file=w)
            for i, o in enumerate(x.options, 1):
                print('    %d  %s' % (i, o), file=w)
        if x.log:
            print('\n  ' + s('dim', 'Log: %s' % x.log), file=w)
        w.flush()


class Task:
    """One line being worked on (Console.task). update() changes its text or count; end() prints its final line."""

    def __init__(self, c, text, level, total, unit, fields):
        self.c, self.text, self.level, self.total, self.unit = c, text, level, total, unit
        self.done = 0
        self.tail = ''
        self.started = c.clock()
        self.frame = 0
        self.ended = False
        self.shown = c.at(level)
        self.beat = self.started
        self.fields = fields
        c.event('task.start', text=text, total=total, unit=unit, **fields)
        if self.shown:
            with c.lock:
                if c.live is not None:          # one live line at a time: the older one ends as it stands
                    c.live.end(None)
                c.live = self
                c._draw_live()
            self._thread = None
            if c.animate:
                self._stop = threading.Event()
                self._thread = threading.Thread(target=self._spin, daemon=True)
                self._thread.start()

    def __enter__(self):
        return self

    def __exit__(self, kind, value, tb):
        if not self.ended:
            self.end(kind is None)
        return False

    def _spin(self):
        while not self._stop.wait(TICK):
            with self.c.lock:
                if self.ended:
                    return
                self.frame += 1
                self.c._clear_live()
                self.c._draw_live()

    def seconds(self):
        return self.c.clock() - self.started

    def render(self, final=None):
        """The line as it stands: text, then a bar and count (with a total) or a spinner, then the time so far."""
        c, utf = self.c, self.c.utf
        line = self.text
        if self.total:
            f = min(1.0, self.done / float(self.total)) if self.total else 0
            line += ' ' + c.paint('bar', bar(f, 20, utf)) + ' ' + self.count()
        if self.tail and final is None:
            line += '  ' + c.paint('dim', self.tail)
        if final is None:
            spin = SPIN[utf]
            line += '  ' + c.paint('bar', spin[self.frame % len(spin)]) + ' ' + c.paint('dim', elapsed(self.seconds()))
        return line

    def count(self):
        if self.unit == 'bytes':
            return '%s / %s' % (human_size(self.done), human_size(self.total))
        if self.unit == '%':
            return '%3d%%' % (100 * self.done // max(self.total, 1))
        return '%d/%d%s' % (self.done, self.total, ' ' + self.unit if self.unit else '')

    def update(self, text=None, done=None, total=None, tail=None):
        with self.c.lock:
            if text is not None:
                self.text = text
            if total is not None:
                self.total = total
            if done is not None:
                self.done = done
            if tail is not None:
                self.tail = tail
            if self.shown and not self.ended:
                if self.c.animate:
                    self.c._clear_live()
                    self.c._draw_live()
                elif self.c.clock() - self.beat >= self.c.heartbeat:
                    self.pulse()

    def pulse(self):
        """Without a terminal: one "still working" line (called by update and by Runner's ticks)."""
        if self.shown and not self.c.animate and not self.ended:
            self.beat = self.c.clock()
            what = plain(self.text).strip()
            more = ' ' + plain(self.count()) if self.total else ''
            print('  ... %s%s (%s so far)' % (what, more, elapsed(self.seconds())), file=self.c.out, flush=True)

    def drop(self):
        """End without a final line (a line another one sums up)."""
        c = self.c
        with c.lock:
            if self.ended:
                return
            self.ended = True
            if c.live is self:
                c._clear_live()
                c.live = None
            c.event('task.end', text=self.text, ok=True, seconds=round(self.seconds(), 1), shown=False, **self.fields)
        if getattr(self, '_thread', None) is not None:
            self._stop.set()

    def end(self, ok=True, note=None, timed=True):
        """The final line: ✓ (OK True), ✗ (False) or nothing (None), NOTE, and the time it took when TIMED."""
        if self.ended:
            return
        c = self.c
        with c.lock:
            self.ended = True
            if self.total and ok:
                self.done = self.total
            mark = {True: c.ok, False: c.bad}.get(ok, '')
            line = self.render(final=True)
            line += ('  ' + mark if mark else '') + ('  ' + note if note else '')
            secs = self.seconds()
            if timed and secs >= 1:
                line += '  ' + c.paint('dim', elapsed(secs))
            if c.live is self:
                c._clear_live()
                c.live = None
            if self.shown:
                print(c.paint.erased(line), file=c.out, flush=True)
            c.event('task.end', text=self.text, ok=ok, note=note, seconds=round(secs, 1), **self.fields)
        if getattr(self, '_thread', None) is not None:
            self._stop.set()


def human_size(n):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1000 or unit == 'TB':
            return ('%d %s' if unit == 'B' else '%.1f %s') % (n, unit)
        n /= 1000.0

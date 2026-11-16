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
from pathlib import Path
import re
import shutil
import sys
import threading
import time

LEVELS = ('quiet', 'steps', 'files', 'edits', 'json')


# kind -> SGR parameters: the Hao Console Variations mockups' tokens at the nearest 256-colour values, one set for a
# dark terminal (the Recovery's, the mockups' dark cards) and one for a light one (the mockups' white installer cards).
#   kind   token  dark mockup -> 256          light mockup -> 256
#   ok     g      #62d394 -> 78  #5fd787      #1a7f37 -> 29  #00875f
#   bar    c      #6db7ff -> 75  #5fafff      #0a5fb4 -> 25  #005faf
#   warn   y      #f1c453 -> 221 #ffd75f      #8f5d00 -> 94  #875f00
#   bad    r      #ff7a7a -> 210 #ff8787 bold #c62828 -> 160 #d70000 bold
#   dim    d      #8a8f99 -> 245 #8a8a8a      #6b7280 -> 243 #767676
#   apple  a      #c3c8d0 -> 251 #c6c6c6      #4b5563 -> 240 #585858
#   tahoe  t      #f0a54e -> 215 #ffaf5f      #9c5300 -> 130 #af5f00
#   oclp   o      #c79dff -> 183 #d7afff      #7a3fb8 -> 97  #875faf
#   hao    h      #5fd6b4 -> 79  #5fd7af      #0b7d5f -> 29  #00875f
#   bold   b      bold
SGR_DARK = {'ok': '38;5;78', 'bar': '38;5;75', 'warn': '38;5;221', 'bad': '1;38;5;210', 'dim': '38;5;245',
            'apple': '38;5;251', 'tahoe': '38;5;215', 'oclp': '38;5;183', 'hao': '38;5;79', 'bold': '1'}
SGR_LIGHT = {'ok': '38;5;29', 'bar': '38;5;25', 'warn': '38;5;94', 'bad': '1;38;5;160', 'dim': '38;5;243',
             'apple': '38;5;240', 'tahoe': '38;5;130', 'oclp': '38;5;97', 'hao': '38;5;29', 'bold': '1'}
SGR_256 = SGR_DARK


def _rgb(hexes, bold=('bad', 'bold')):
    out = {}
    for kind, h in hexes.items():
        rgb = '38;2;%d;%d;%d' % tuple(int(h[i:i + 2], 16) for i in (0, 2, 4)) if h else ''
        out[kind] = ';'.join(x for x in ('1' if kind in bold else '', rgb) if x)
    return out


# with COLORTERM=truecolor (or 24bit): the mockups' own colours
TRUE_DARK = _rgb({'ok': '62d394', 'bar': '6db7ff', 'warn': 'f1c453', 'bad': 'ff7a7a', 'dim': '8a8f99', 'apple': 'c3c8d0',
                  'tahoe': 'f0a54e', 'oclp': 'c79dff', 'hao': '5fd6b4', 'bold': ''})
TRUE_LIGHT = _rgb({'ok': '1a7f37', 'bar': '0a5fb4', 'warn': '8f5d00', 'bad': 'c62828', 'dim': '6b7280', 'apple': '4b5563',
                   'tahoe': '9c5300', 'oclp': '7a3fb8', 'hao': '0b7d5f', 'bold': ''})
SGR_8 = {'ok': '32', 'bad': '1;31', 'warn': '33', 'bar': '36', 'bold': '1', 'dim': '2',
         'apple': '90', 'tahoe': '33', 'oclp': '35', 'hao': '36'}
ORIGINS = {'apple': 'Apple', 'tahoe': 'Tahoe', 'oclp': 'OCLP', 'hao': 'hao'}
ANSI = re.compile(r'\033\[[0-9;]*m')
ERASED = re.compile(r'([Ee]verything on (?:it|\S+(?: [^.?]*?)?) will be erased|will be erased)')


_THEME = []


def theme(env=None, ask=None):
    """'dark' or 'light': HAO_THEME, else the terminal's background (an OSC 11 query, answered within 0.2 s by
    Terminal, iTerm2 and xterm; asked once), else 'dark' (the Recovery's Terminal is dark)."""
    env = os.environ if env is None else env
    if env.get('HAO_THEME') in ('dark', 'light'):
        return env['HAO_THEME']
    if not _THEME:
        rgb = (ask or ask_background)()
        _THEME.append('dark' if rgb is None else ('light' if 0.299 * rgb[0] + 0.587 * rgb[1] + 0.114 * rgb[2] > 0.5
                                                  else 'dark'))
    return _THEME[0]


def ask_background(timeout=0.2):
    """The terminal's background as (r, g, b) in 0..1, or None: OSC 11 on /dev/tty, its answer read raw."""
    try:
        import select
        import termios
        import tty
        fd = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY)
    except (OSError, ImportError):
        return None
    try:
        old = termios.tcgetattr(fd)
    except termios.error:
        os.close(fd)
        return None
    answer = b''
    try:
        tty.setraw(fd)
        os.write(fd, b'\033]11;?\033\\')
        end = time.monotonic() + timeout
        while time.monotonic() < end and not (answer.endswith(b'\007') or answer.endswith(b'\033\\')):
            r, _, _ = select.select([fd], [], [], max(0, end - time.monotonic()))
            if not r:
                break
            answer += os.read(fd, 64)
    except OSError:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSAFLUSH, old)
        os.close(fd)
    m = re.search(rb'rgb:([0-9a-fA-F]+)/([0-9a-fA-F]+)/([0-9a-fA-F]+)', answer)
    if not m:
        return None
    return tuple(int(x, 16) / float(16 ** len(x) - 1) for x in m.groups())


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
        # HAO_PALETTE=8|256 chooses; otherwise 256 colours where the terminal says it has them, for its background
        # (HAO_THEME=dark|light, else what the terminal answers when asked, else dark).
        palette = env.get('HAO_PALETTE', '')
        if not on:
            self.codes = SGR_8            # never drawn; and no question to the terminal when nothing is coloured
        elif palette == '8' or (palette != '256' and '256' not in env.get('TERM', '') and not env.get('COLORTERM')):
            self.codes = SGR_8
        else:
            light = theme(env) == 'light'
            if env.get('COLORTERM') in ('truecolor', '24bit') and palette != '256':
                self.codes = TRUE_LIGHT if light else TRUE_DARK
            else:
                self.codes = SGR_LIGHT if light else SGR_DARK

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
SPIN = {True: '-\\|/', False: '-\\|/'}     # the mockups' spinner, in the bar colour
CELLS = {True: ('█', '░'), False: ('#', '.')}
TICK = 0.1                    # seconds between redraws of a live line
SHOW_TIME = 30                # a finished line gives its time from this many seconds (the mockups: long steps only)
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


COMMAND = re.compile(r'(^|: |as: |run |again: )((?:sudo )?(?:\./hao|hao|/Volumes/\S+/(?:install|report|hao))\b[^,;()]*?)(?=$| \(|,|;)')
MARK_COLUMN = 62              # where ✓ / ✗ stand on step and item lines, so they line up as in the mockups


def at_column(text, column=MARK_COLUMN):
    """TEXT padded with spaces to COLUMN visible characters (unchanged when it is longer)."""
    return text + ' ' * max(2, column - len(plain(text)))


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


VENDOR = Path(__file__).resolve().parents[1] / 'vendor'


def rich_modules(env=None):
    """(Console, Live, Text) from the vendored Rich (tools/hao/vendor, its LICENSE and NOTICE.md there), or None
    when HAO_NO_RICH is set or it cannot be imported (the console then redraws lines itself)."""
    env = os.environ if env is None else env
    if env.get('HAO_NO_RICH'):
        return None
    if str(VENDOR) not in sys.path:
        sys.path.insert(0, str(VENDOR))
    try:
        from rich.console import Console as RichConsole
        from rich.live import Live
        from rich.text import Text
    except ImportError:
        return None
    return RichConsole, Live, Text


class PlainSurface:
    """A terminal without Rich: the live line is redrawn with \\r and erase-line by the task's own thread."""
    threaded = True

    def __init__(self, c):
        self.c = c

    def line(self, text, stream=None):
        print(text, file=stream or self.c.out, flush=True)

    def start(self, task):
        self.c._draw_live()

    def refresh(self):
        self.c._clear_live()
        self.c._draw_live()

    def stop(self):
        self.c._clear_live()

    def pause(self):
        self.c._clear_live()

    def resume(self):
        self.c._draw_live()

    def save(self, path):
        return False


class RichSurface:
    """A terminal through Rich: finished lines are printed above a Live region holding the line being worked on;
    Rich refreshes it (10 a second), hides the cursor meanwhile and measures cells for cropping. HAO_RECORD=FILE keeps
    everything drawn and saves it as SVG (or HTML, by FILE's suffix) when the command ends."""
    threaded = False

    def __init__(self, c, modules, record=False):
        RichConsole, self.Live, self.Text = modules
        self.c = c
        self.rc = RichConsole(file=c.out, force_terminal=True, color_system='truecolor', highlight=False, markup=False,
                              emoji=False, soft_wrap=True)
        # the record holds only finished lines (no live frames): the screen as it is left
        import io
        self.rec = RichConsole(file=io.StringIO(), force_terminal=True, color_system='256', highlight=False,
                               markup=False, emoji=False, soft_wrap=True, record=True, width=c.width()) if record else None
        self.live = None

    def line(self, text, stream=None):
        if stream is not None and stream is not self.c.out:
            self.pause()
            print(text, file=stream, flush=True)
            self.resume()
            return
        self.rc.print(self.Text.from_ansi(text), soft_wrap=True)
        if self.rec is not None:
            self.rec.print(self.Text.from_ansi(text), soft_wrap=True)

    def _renderable(self):
        task = self.c.live
        if task is None:
            return self.Text('')
        task.frame = int(time.monotonic() / TICK)
        return self.Text.from_ansi(fit(task.render(), self.c.width() - 1), no_wrap=True, end='')

    def start(self, task):
        self.stop()
        self.live = self.Live(get_renderable=self._renderable, console=self.rc, refresh_per_second=1 / TICK,
                              transient=True, redirect_stdout=False, redirect_stderr=False)
        self.live.start()

    def refresh(self):
        if self.live is not None:
            self.live.refresh()

    def stop(self):
        if self.live is not None:
            self.live.stop()
            self.live = None

    def pause(self):
        if self.live is not None:
            self.live.stop()

    def resume(self):
        if self.live is not None:
            self.live.start()

    def save(self, path):
        if self.rec is None:
            return False
        if str(path).endswith('.html'):
            self.rec.save_html(str(path))
        else:
            self.rec.save_svg(str(path), title='hao')
        return True


class Stopped(Exception):
    """A check failed: the command stops and Console.stopped prints what happened, why it matters, what to do."""

    def __init__(self, what, why=None, cause=None, options=(), untouched=None, log=None, code=None):
        super().__init__(what)
        self.what, self.why, self.cause, self.options, self.untouched = what, why, cause, list(options), untouched
        self.log, self.code = log, code       # code: the exit code (src/frontdoor.py), when the raiser knows it


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
        self.column = MARK_COLUMN     # where ✓ stands (the mockups: 60 for create-installer, 78 for install)
        self.bar_column = 46          # where a bar starts (the mockups' P(label, 44) after the two-space indent)
        self.bar_width = 20
        self.gap = False              # a blank line before each step header (create-installer's rhythm)
        self.muted = False            # print nothing (events are still kept): a backend's own header is replaced
        self.release = None           # the release (or dev COMMIT) the header names
        self.hide = ()                # lines (by their start) a command does not show
        modules = rich_modules(e) if self.animate else None
        self.surface = RichSurface(self, modules, record=bool(e.get('HAO_RECORD'))) if modules else PlainSurface(self)
        self.record = e.get('HAO_RECORD')

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
        if self.hide and text and plain(text).startswith(self.hide):
            return
        if self.at(level) and not self.muted:
            with self.lock:
                if isinstance(self.surface, PlainSurface):
                    self._clear_live()
                    print(self.paint.erased(text), file=self.out, flush=True)
                    self._draw_live()
                else:
                    self.surface.line(self.paint.erased(text))

    def save_record(self):
        """HAO_RECORD=FILE: the run as drawn, saved (SVG, or HTML for a .html FILE). True when saved."""
        if not self.record:
            return False
        self.surface.stop()
        try:
            return self.surface.save(self.record)
        except OSError:
            return False

    def _clear_live(self):
        if self.live is not None and self.animate:
            self.out.write('\r\033[K')

    def _draw_live(self):
        if self.live is not None and self.animate:
            self.out.write(fit(self.live.render(), self.width() - 1))
            self.out.flush()

    def col(self):
        """The check column, moved left on a narrow terminal so a line with its time still fits."""
        return min(self.column, self.width() - 14) if self.animate else self.column

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
        release = getattr(self, 'release', None)
        if release:
            head += ' ' + release
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
            if self.gap and self.index > 1:
                self.print('')
            self.print(self.paint('bold', head) + ('  ' + (note if '\033[' in note or not self.paint.on
                                                          else self.paint('dim', note)) if note else ''))

    def item(self, text, level='steps', ok=None, **fields):
        """One line under a step; OK True adds the check mark. Kept as an event when FIELDS are given."""
        if fields:
            self.event(fields.pop('ev', 'item'), text=text, ok=ok, **fields)
        if ok and text.endswith('sha256'):   # "sha256 ✓" is one green check, as in the mockups
            self.print('  ' + text[:-6] + self.paint('ok', 'sha256 ') + self.ok, level)
            return
        self.print((at_column('  ' + text, self.col()) + self.ok) if ok else '  ' + text, level)

    def detail(self, text, level='edits'):
        self.print('            ' + self.paint('dim', text), level)

    def note(self, text, **fields):
        self.event('note', text=text, **fields)
        self.print('  ' + self.paint('warn', 'note') + '  ' + text, 'steps')

    def warning(self, text):
        self.event('warning', text=text)
        if self.level != 'json':
            with self.lock:
                if isinstance(self.surface, PlainSurface):
                    self._clear_live()
                    print(self.paint_err('warn', 'warning:') + ' ' + text, file=self.err, flush=True)
                    self._draw_live()
                else:
                    self.surface.line(self.paint_err('warn', 'warning:') + ' ' + text, stream=self.err)

    def confirm(self, question, word, given=None):
        """Ask QUESTION and require WORD typed (or GIVEN, from a flag). False when it does not match."""
        self.event('confirm', question=question, word=word, given=given is not None)
        if self.level != 'json' or given is None:
            print(self.paint.erased(question), file=self.out, flush=True)
        answer = given if given is not None else self.ask('Type %s to continue: ' % self.paint('bold', word))
        ok = answer.strip() == word
        self.event('confirmed' if ok else 'declined')
        if ok and given is None and self.level != 'json':
            self.print('', 'quiet')                    # the mockups: a blank line after the typed word
        return ok

    def took(self):
        """The time since the command started, as the last line says it ("in 41m 18s")."""
        return elapsed(self.clock() - self.started)

    def done(self, text, lead=None, more=(), **fields):
        """The last line: LEAD (default ✓) and TEXT, with the time it took unless TEXT says it; then MORE, dim."""
        took = self.clock() - self.started
        self.event('run.end', ok=True, text=text, seconds=round(took, 1), **fields)
        self.print('%s %s%s' % (lead or self.ok, text, '  ' + self.paint('dim', 'in ' + elapsed(took))
                                if took >= 60 and ' in ' not in text and lead is None else ''), 'quiet')
        for line in more:
            self.print(self.paint('dim', line), 'quiet')

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
                print('  %-17s%s' % (label, text), file=w)
        if x.options:
            print('\n  What you can do', file=w)
            for i, o in enumerate(x.options, 1):
                print('    %d  %s' % (i, COMMAND.sub(lambda m: m.group(1) + s('bold', m.group(2)), o)), file=w)
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
                if c.animate:
                    c.surface.start(self)
            self._thread = None
            if c.animate and c.surface.threaded:
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
            at = getattr(self, 'bar_at', c.bar_column)
            line = at_column(line, at) if len(plain(line)) < at else line + ' '
            line += c.paint('bar', bar(f, getattr(self, 'width', None) or c.bar_width, utf)) + ' ' + self.count()
        if self.tail and final is None:
            line += '  ' + c.paint('dim', self.tail)
        if final is None:
            spin = SPIN[utf]
            line = at_column(line, c.col()) + c.paint('bar', spin[self.frame % len(spin)]) + '  ' + \
                c.paint('dim', elapsed(self.seconds()))
        return line

    def count(self):
        if self.unit == 'bytes':
            return size_pair(self.done, self.total)
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
                    self.c.surface.refresh()
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
                if c.animate:
                    c.surface.stop()
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
            note = note or getattr(self, 'final_note', None)
            line = (at_column(line, c.col()) + mark if mark else line) + ('  ' + note if note else '')
            secs = self.seconds()
            if timed and secs >= SHOW_TIME:
                line += '  ' + c.paint('dim', elapsed(secs))
            if c.live is self:
                if c.animate:
                    c.surface.stop()
                c.live = None
            if self.shown:
                if c.animate:
                    c.surface.line(c.paint.erased(line))
                else:
                    print(c.paint.erased(line), file=c.out, flush=True)
            c.event('task.end', text=self.text, ok=ok, note=note, seconds=round(secs, 1), **self.fields)
        if getattr(self, '_thread', None) is not None:
            self._stop.set()


def size_pair(done, total):
    """"14.8 / 14.8 GB": both in the total's unit, the unit once (the mockups' download lines)."""
    for unit, scale in (('TB', 1e12), ('GB', 1e9), ('MB', 1e6), ('KB', 1e3)):
        if total >= scale:
            width = len('%.1f' % (total / scale))
            return '%*.1f / %.1f %s' % (width, done / scale, total / scale, unit)
    return '%d / %d B' % (done, total)


def human_size(n):
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1000 or unit == 'TB':
            return ('%d %s' if unit == 'B' else '%.1f %s') % (n, unit)
        n /= 1000.0

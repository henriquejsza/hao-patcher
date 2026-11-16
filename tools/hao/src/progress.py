"""Backend commands seen through the console: their output goes to a log file, the screen gets steps in plain words.

hao's backends (golden-run --stage-kit, golden-assemble.sh and golden-image.py, the stick writer) print what they do
for developers: commands, JSON dumps, diskutil chatter. Runner runs such a command with its output going to the log
file only, and renders what it understands:

  STEP NAME                  golden-image.py's steps (LAYERS, "recipe NAME", "overlay NAME", "post NAME") and
                             golden-pristine.sh's sub-steps, as numbered phases and one line per step
  + COMMAND                  golden-run's commands while it stages a kit, as what is being prepared
  @hao {JSON}                an event any backend may print (the interface agreed with builder):
                               {"ev": "step", "name": NAME}                         as STEP NAME
                               {"ev": "progress", "done": N, "total": M, "unit": "bytes"|"files"|"%"}
                               {"ev": "item", "text": TEXT, "ok": true, "level": "steps"}
                               {"ev": "note", "text": TEXT}
                               {"ev": "stop", "what": ..., "why": ..., "cause": ..., "options": [...]}

Runner(c, command) is called like subprocess.call(argv) and returns the exit status, so a backend that takes a run=
function takes it unchanged. On a terminal the current step has a spinner and its time, redrawn in place; elsewhere a
"still working" line comes every 30 s. At --quiet the install is one bar with the phase's name.
"""
import collections
import datetime
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import threading
import time

# The install's phases (variation 5's [N/7]), each with golden-image.py's steps that belong to it, in order.
Phase = collections.namedtuple('Phase', 'title note steps seconds')
INSTALL = (
    Phase('Lay out the disk', None, ('layout',), 120),
    Phase('Copy macOS 27', 'from Apple\'s macOS 27 installer', ('golden-system', 'group-volumes'), 380),
    Phase('Add Intel support', 'Tahoe\'s kernel extensions and boot files, OCLP\'s legacy hardware support',
          ('golden-finalize', 'boot-and-esp', 'hardware'), 170),
    Phase('Link the kernel', 'Tahoe\'s kmutil', ('recipe darwin27-kernel',), 155),
    Phase('Apply packs', 'each file checked against its manifest', ('recipe', 'overlay'), 1615),
    Phase('Seal', None, ('snapshot',), 65),
    Phase('Make it bootable', None, ('posts', 'post', 'efi-bundle'), 35),
)
# seconds: the 2026-11-16 builder VM assembly (golden-26B131-20261116-111912); only the --quiet bar's pace uses them.

# What each step does, in the words the screen uses (internal names stay in the log).
SAY = {
    'tools': 'copy the installer\'s tools and Python',
    'layout': 'GPT partition map and an APFS container',
    'golden-system': 'the System volume, from the installer\'s filesystem image',
    'group-volumes': 'Data, Preboot, Recovery and VM volumes',
    'golden-finalize': 'Tahoe\'s Intel drivers, the Data template and firmlinks',
    'golden-data': 'the Data volume template',
    'golden-firmlinks': 'firmlinks',
    'tahoe-extensions': 'Tahoe\'s Intel kernel extensions',
    'intel-kdk': 'Intel kernel extensions from the KDK',
    'darwin27-kernel-file': 'the Darwin 27 kernel',
    'tahoe-native': 'Tahoe\'s Intel system programs',
    'boot-and-esp': 'Intel boot files and the EFI partition',
    'hardware': 'OCLP\'s legacy hardware support: graphics, Wi-Fi, audio',
    'recipe darwin27-kernel': 'kernel collections linked, kernel repairs bound',
    'recipe golden-gate-userspace': 'build the system cryptex (the shared cache); the longest step',
    'recipe golden-gate-native-identities': 'Intel identities for Apple\'s programs',
    'recipe hao-runtime': 'hao, which runs ARM-only apps',
    'snapshot': 'update Preboot, bless, take the system snapshot',
    'posts': 'settings, caches and the OpenCore configuration',
    'efi-bundle': 'unmount the new volumes',
}
STAGE = (   # golden-run --stage-kit's "+ COMMAND" lines, in the words the screen uses
    (r'inputs\.sh', 'every input checked against its sha256'),
    (r'minimal-native', 'Tahoe\'s Intel system programs'),
    (r'minimal-extensions', 'Tahoe\'s Intel kernel extensions'),
    (r'minimal-boot', 'Intel boot files'),
    (r'minimal-driverkit', 'Tahoe\'s DriverKit drivers'),
    (r'minimal-recovery', 'Recovery files'),
    (r'oclp-hardware', 'OCLP\'s legacy hardware files'),
    (r'build-efi\.py', 'OpenCore for this Mac'),
    (r'metallib|shader', 'Metal libraries'),
)
ERROR = re.compile(r'(error|failed|refused|exception|cannot|could not|not found|no such)', re.I)
NOISE = re.compile(r'^(\+ |INFO:|\{|\[|Volume |Started |Finished |Waiting |Unmounting|Mounting)')


def output_log(command, now=None, env=None):
    """Where COMMAND's backend output goes: the stick's logs folder when run from the stick (a Recovery's own disk
    is gone after a restart), else the command logs folder (src/report.py)."""
    env = os.environ if env is None else env
    stamp = (now or datetime.datetime.now()).strftime('%Y%m%d-%H%M%S')
    if env.get('HAO_STICK'):
        folder = Path(env['HAO_STICK']) / 'logs'
    else:
        import report
        folder = report.log_dir(env)
    return folder / ('%s-%s.log' % (command, stamp))


def pack_name(pack):
    return 'other fixes' if pack in (None, '', '(no pack)') else pack


class Runner:
    """run(argv) -> exit status, like subprocess.call; see the module text."""

    def __init__(self, c, command, groups=None, log=None, popen=subprocess.Popen, env=None):
        self.c, self.command, self.popen = c, command, popen
        self.groups = groups or {}
        self.log = Path(log) if log else None
        self.env = env
        self.tail = collections.deque(maxlen=40)
        self.error = None            # the last line that reads like an error
        self.stop = None             # an "@hao stop" event's fields
        self.view = None

    def pack_of(self, recipe):
        for pack, names in self.groups.items():
            if recipe in names:
                return pack
        return None

    def logfile(self):
        if self.log is None:
            self.log = output_log(self.command)
        try:
            self.log.parent.mkdir(parents=True, exist_ok=True)
            return open(self.log, 'a', encoding='utf-8', errors='replace')
        except OSError:
            self.log = Path(os.environ.get('TMPDIR', '/tmp')) / self.log.name
            return open(self.log, 'a', encoding='utf-8', errors='replace')

    def view_for(self, argv):
        words = [str(x) for x in argv]
        if any(w.endswith('golden-assemble.sh') for w in words):
            return Assembly(self)
        if '--stage-kit' in words:
            return Single(self, 'prepare the kit: each changed file made once, checked and signed', STAGE)
        if '--collect-kit' in words:
            return Single(self, 'keep the sealed system images for the next build', level='files')
        return Single(self, ' '.join(Path(words[0]).name.split() + words[1:2]), level='files')

    def __call__(self, argv, **kw):
        c = self.c
        self.view = view = self.view_for(argv)
        out = self.logfile()
        c.event('backend', argv=[str(x) for x in argv], log=str(self.log))
        out.write('\n### %s  %s\n' % (datetime.datetime.now().isoformat(timespec='seconds'),
                                      ' '.join(str(x) for x in argv)))
        out.flush()
        env = dict(self.env if self.env is not None else os.environ, HAO_EVENTS='1', PYTHONUNBUFFERED='1')
        view.start()
        try:
            p = self.popen([str(x) for x in argv], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, **kw)
        except OSError as x:
            out.write('cannot start: %s\n' % x)
            out.close()
            self.error = str(x)
            view.end(127)
            return 127
        lines = queue.Queue()

        def read():
            for raw in iter(p.stdout.readline, b''):
                lines.put(raw.decode('utf-8', errors='replace'))
            lines.put(None)
        threading.Thread(target=read, daemon=True).start()
        ticked = time.monotonic()
        try:
            while True:
                try:
                    line = lines.get(timeout=1)
                except queue.Empty:
                    line = ''
                if time.monotonic() - ticked >= 1:
                    ticked = time.monotonic()
                    view.tick()
                if line is None:
                    break
                if not line:
                    continue
                out.write(line)
                out.flush()
                self.feed(view, line.rstrip('\n'))
            rc = p.wait()
        except KeyboardInterrupt:
            p.terminate()
            rc = p.wait()
            view.end(rc or 130)
            out.close()
            raise
        out.write('### exit %d\n' % rc)
        out.close()
        view.end(rc)
        return rc

    def feed(self, view, line):
        text = line.strip()
        if text.startswith('@hao '):
            try:
                ev = json.loads(text[5:])
            except ValueError:
                return
            kind = ev.get('ev')
            if kind == 'step':
                view.step(str(ev.get('name', '')))
            elif kind == 'progress':
                view.progress(ev.get('done'), ev.get('total'), ev.get('unit'))
            elif kind == 'item':
                self.c.item(str(ev.get('text', '')), ev.get('level', 'steps'), ok=ev.get('ok'))
            elif kind == 'note':
                self.c.note(str(ev.get('text', '')))
            elif kind == 'stop':
                self.stop = ev
            return
        if text.startswith('STEP '):
            view.step(text[5:].strip())
            return
        if text.startswith('RESUME at '):
            view.resumed = True
            return
        if text.startswith('+ '):
            view.command(text[2:])
        if text:
            self.tail.append(text)
            if ERROR.search(text) and not text.startswith(('+ ', 'RESULT rc=0')):
                self.error = text

    def explain(self, x):
        """Fill a Stopped report from what the backend said: its own stop event, else its last error line, and the
        log's path."""
        if self.stop:
            for k in ('what', 'why', 'cause', 'untouched'):
                if self.stop.get(k):
                    setattr(x, k, self.stop[k])
            x.options = list(self.stop.get('options') or []) + [o for o in x.options if o not in
                                                                 (self.stop.get('options') or [])]
        elif not x.cause and self.error:
            x.cause = 'the last message was: ' + self.error[:200]
        if self.log and not x.log:
            x.log = str(self.log)
        return x


class Single:
    """One line for the whole command: a spinner and the time; what it is on now (from STAGE) after the text."""

    def __init__(self, runner, text, labels=(), level='steps'):
        self.r, self.text, self.labels, self.level = runner, text, labels, level
        self.task = None
        self.resumed = False

    def start(self):
        self.task = self.r.c.task('  ' + self.text, self.level)

    def command(self, cmd):
        for pattern, say in self.labels:
            if re.search(pattern, cmd):
                self.task.update(tail=say)
                return

    def step(self, name):
        self.task.update(tail=SAY.get(name, ''))

    def progress(self, done, total, unit):
        self.task.unit = unit
        self.task.update(done=done, total=total)

    def tick(self):
        self.task.update()

    def end(self, rc):
        self.task.tail = ''
        self.task.end(rc == 0)


class Assembly:
    """golden-assemble.sh: the seven phases, one line per step, one line per pack, the --quiet bar."""

    def __init__(self, runner, phases=INSTALL):
        self.r, self.c, self.phases = runner, runner.c, phases
        self.index = 0             # the phase being worked on, 1-based; 0 before the first
        self.task = None
        self.resumed = False
        self.packs = collections.OrderedDict()   # pack -> recipes applied in this phase
        self.posts = []
        self.recipe_line = False   # the line on screen is one recipe's
        self.last = None
        self.bar = None
        self.phase_started = time.monotonic()

    # -- phases
    def phase_of(self, name):
        kind = name.split(' ', 1)[0]
        for i, ph in enumerate(self.phases, 1):
            if name in ph.steps:
                return i
        for i, ph in enumerate(self.phases, 1):
            if kind in ph.steps and ' ' in name:
                return i
        return None

    def enter(self, n):
        c = self.c
        while self.index < n:
            self.leave()
            self.index += 1
            ph = self.phases[self.index - 1]
            note = 'done in the earlier attempt' if self.index < n and self.resumed else ph.note
            c.step(ph.title, note=note, quiet=False)
            self.phase_started = time.monotonic()
            self.pace()

    def finish(self, ok=True):
        """End the line on screen; a recipe's line is not kept (its pack's line follows)."""
        t, self.task = self.task, None
        if t is None:
            return
        if self.recipe_line and ok and not self.c.at('files'):
            t.drop()
        else:
            t.end(ok)

    def flush(self):
        """The closing lines of the recipes so far: one per pack (Apply packs), one for the post recipes."""
        self.finish()
        for pack, names in self.packs.items():
            self.c.item('%s %s' % (self.c.paint('bold', '%-22s' % pack_name(pack)),
                                   '%d recipe%s' % (len(names), '' if len(names) == 1 else 's')), ok=True,
                        ev='pack.applied', pack=pack, recipes=names)
        self.packs = collections.OrderedDict()
        if self.posts:
            self.c.item('%s  %d recipes' % (SAY['posts'], len(self.posts)), ok=True, ev='posts.applied',
                        recipes=self.posts)
            self.posts = []

    def leave(self):
        self.flush()

    # -- the --quiet bar
    def pace(self):
        if self.c.level != 'quiet':
            return
        total = float(sum(p.seconds for p in self.phases))
        before = sum(p.seconds for p in self.phases[:max(self.index - 1, 0)])
        ph = self.phases[self.index - 1] if self.index else None
        within = 0
        if ph:
            within = min(0.95, (time.monotonic() - self.phase_started) / float(ph.seconds)) * ph.seconds
        title = ph.title.lower() if ph else 'preparing'
        if self.bar is None:
            self.bar = self.c.task('Installing macOS 27', 'quiet', total=1000, unit='%')
        self.bar.update(done=int(1000 * (before + within) / total), tail=title[0].upper() + title[1:] + '…')

    # -- the backend's lines
    def start(self):
        self.c.steps(len(self.phases))
        self.enter(1)
        self.task = self.c.task('  ' + SAY['tools'])

    def step(self, name):
        if name == self.last:          # golden-pristine.sh names the step golden-image.py has just started
            return
        self.last = name
        n = self.phase_of(name)
        if n is not None and n > self.index:
            self.enter(n)
        elif n is None and name in SAY and self.task and not self.recipe_line:
            self.task.update(tail=SAY[name])     # a sub-step of the line on screen (golden-pristine.sh's)
            return
        if name in ('recipes', 'posts'):
            return
        kind, _, recipe = name.partition(' ')
        if recipe and kind in ('recipe', 'overlay', 'post') and (self.index >= 5 or kind == 'post'):
            self.recipe(kind, recipe)
            return
        self.flush()
        self.recipe_line = False
        self.task = self.c.task('  ' + (SAY.get(name) or name))

    def recipe(self, kind, recipe):
        """One recipe of Apply packs, or a post recipe: its line shows its pack (Apply packs) or what posts do;
        the closing line per pack comes when the phase ends."""
        self.finish()
        self.recipe_line = True
        if self.c.at('files'):
            label = '%s %s' % (self.c.paint('bold', '%-22s' % pack_name(self.r.pack_of(recipe))), recipe)
        elif kind == 'post':
            label = '%s  %s' % (SAY['posts'], 'recipe %d' % (len(self.posts) + 1))
        else:
            label = '%s %s' % (self.c.paint('bold', '%-22s' % pack_name(self.r.pack_of(recipe))),
                               SAY.get('recipe ' + recipe, 'recipe %d' % (sum(map(len, self.packs.values())) + 1)))
        if kind == 'post':
            self.posts.append(recipe)
        else:
            self.packs.setdefault(self.r.pack_of(recipe), []).append(recipe)
        self.task = self.c.task(('    ' if self.c.at('files') else '  ') + label)

    def command(self, cmd):
        pass

    def progress(self, done, total, unit):
        if self.task:
            self.task.unit = unit
            self.task.update(done=done, total=total)

    def tick(self):
        if self.task:
            self.task.update()
        self.pace()

    def end(self, rc):
        if rc == 0:
            self.flush()
            if self.bar:
                self.bar.update(done=1000, tail='Done')
                self.bar.end(True)
            return
        self.finish(False)
        if self.bar:
            self.bar.end(False)

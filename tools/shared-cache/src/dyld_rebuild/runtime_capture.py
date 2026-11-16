"""Keep a native constructor failure explicit, then retry in a fresh worker.

Never resume inside a faulted Swift runtime: its metadata locks and singleton
state may be incomplete. The successful attempt supplies every exported address.
"""
import json
import os
import shutil
import signal
import subprocess

from .swift_metadata import write_json


FAULTS = {signal.SIGSEGV, signal.SIGBUS, signal.SIGILL, signal.SIGABRT,
          signal.SIGFPE, signal.SIGALRM}


def interrupted_constructor(path):
    active = None
    with path.open() as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                if not line.endswith('\n'):
                    break  # A signal may interrupt the last output write.
                raise
            if 'constructor_begin' in event:
                active = event['constructor_begin']
            elif 'constructor' in event or 'root' in event or event.get('complete'):
                active = None
    return active


def capture(runner, worker, raw, execute):
    """Use one address space for the final capture; retain every failed attempt."""
    original = (worker/'names.tsv').read_text().split('\n')
    definitions = {int(line.split('\t', 2)[1]) for line in original
                   if line.startswith(('@type\t', '@generic\t', '@opaque\t', '@reference\t'))}
    failed, attempts = {}, []
    while True:
        bundle = raw.parent/'capture-attempts'/str(len(attempts))
        bundle.mkdir(parents=True)
        os.link(worker/'swift-capture', bundle/'swift-capture')
        lines = []
        for line in original:
            if line.startswith(('@type\t', '@generic\t', '@opaque\t', '@reference\t')):
                number = int(line.split('\t', 2)[1])
                if number in failed:
                    line = f'@unavailable\t{number}\t{failed[number]}'
            lines.append(line)
        (bundle/'names.tsv').write_text('\n'.join(lines))
        output = bundle/'capture.jsonl'
        try:
            execute(runner, 'capture', bundle, output)
        except subprocess.CalledProcessError as error:
            signum = -error.returncode if error.returncode < 0 else error.returncode-128
            constructor = interrupted_constructor(output)
            attempt = dict(directory=str(bundle), exit_code=error.returncode,
                           active_constructor=constructor)
            attempts.append(attempt)
            write_json(raw.parent/'capture-attempts.json', attempts)
            # Transport failures, kills and failures outside construction remain
            # terminal. Only a native fault attributed by the worker can recover.
            if signum not in FAULTS or constructor not in definitions or constructor in failed:
                raise
            failed[constructor] = signum
            print(json.dumps(dict(constructor=constructor, signal=signal.Signals(signum).name,
                                  action='record unresolved and restart native worker')), flush=True)
            continue
        attempts.append(dict(directory=str(bundle), exit_code=0))
        write_json(raw.parent/'capture-attempts.json', attempts)
        shutil.copyfile(output, raw)
        shutil.copyfile(output.with_suffix('.stderr'), raw.with_suffix('.stderr'))
        return [dict(constructor=number, signal=signum) for number, signum in sorted(failed.items())]

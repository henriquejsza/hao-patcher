"""Disk guard for a producer run: refuse to start without room, and remove the intermediates afterwards.

A 26B131 fold-in run writes about 21 GB of intermediates under WORK (plus the whole disk image when it reads an image
repository) and a 7 GB family. Before anything is written,
`check` refuses when the volume of WORK or OUTPUT has less than NEED_GB free (the two may share a volume; the larger
need counts then). SHARED_CACHE_DISK_CHECK may name a site command that decides as well; it is run as
`COMMAND check --need GB --who shared-cache --what TEXT` and a non-zero exit refuses the run.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess

from .exports import Refusal

WORK_GB = 22      # intermediates of a 26B131 fold-in run
FAMILY_GB = 8     # the family itself


def existing(path):
    path = Path(path).resolve()
    while not path.exists():
        path = path.parent
    return path


def free_gb(path):
    return shutil.disk_usage(existing(path)).free / 1e9


def check(work, output, what, work_gb=WORK_GB, family_gb=FAMILY_GB, free=free_gb, run=subprocess.run,
          command=None):
    """Refusal unless WORK's and OUTPUT's volumes have room for this run."""
    need = {}                                 # volume -> [a path on it, GB needed there]
    for path, gb in ((work, work_gb), (output, family_gb)):
        need.setdefault(os.stat(existing(path)).st_dev, [path, 0])[1] += gb
    for path, gb in need.values():
        have = free(path)
        if have < gb:
            raise Refusal(f'disk: {have:.0f} GB free on the volume of {path}, this run needs {gb} GB; free space first')
    command = os.environ.get('SHARED_CACHE_DISK_CHECK') if command is None else command
    if command:
        total = sum(gb for _, gb in need.values())
        result = run([*shlex.split(command), 'check', '--need', str(total), '--who', 'shared-cache', '--what', what])
        if result.returncode != 0:
            raise Refusal(f'disk: {command} refused the run (exit {result.returncode})')


def remove_intermediates(work):
    """Remove WORK's build folder and an exported source.img once the family is written; selection.json stays."""
    build = Path(work) / 'build'
    if build.is_dir():
        shutil.rmtree(build)
    (Path(work) / 'source.img').unlink(missing_ok=True)

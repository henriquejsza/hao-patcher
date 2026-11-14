"""Take this Mac off 27.x's unsupported-model lists for Sidecar, AirPlay to Mac and Continuity Camera.

Each image in src/model-gates.json keeps a list of unsupported Mac models as consecutive C strings in its __TEXT
(__cstring in CMCapture, __const in SidecarCore and AirPlaySupport). This planner renames this Mac's entry in place
(same length, one byte), so the feature's model check no longer finds it; nothing else in the image changes. The
image must hold the model exactly once in those sections, NUL-delimited, with Mac model names on both sides;
anything else refuses the build.
This replaces acidanthera's FeatureUnlock (which renames the same strings in every validated page at run time):
the edit is made once, in the cache, and only in the listed images.
The caller re-signs changed cache files before sealing the cryptex.
"""
import json
import re
from pathlib import Path

from legacy_trackpad import image_layout, plan_cache_family as plan_family

DATA = json.loads(Path(__file__).with_name('model-gates.json').read_text())
SECTIONS = (b'__cstring', b'__const')   # where the lists are: CMCapture's in __cstring, the others' in __const
MODEL = re.compile(rb'(?:MacBook(?:Air|Pro)?|iMac(?:Pro)?|Macmini|MacPro)\d+,\d+')


def checker(model, renamed):
    model, renamed = model.encode(), renamed.encode()
    if len(model) != len(renamed) or not MODEL.fullmatch(model):
        raise ValueError('model gates: the renamed model must be a Mac model name of the same length')

    def checked_edits(read, address):
        _, sections = image_layout(read, address)
        hits = []
        for name in SECTIONS:
            if name in sections:
                start, size = sections[name]
                strings = read(start, size)
                hits += [(start, strings, m.start() + 1)
                         for m in re.finditer(re.escape(b'\0' + model + b'\0'), strings)]
        if len(hits) != 1:
            raise ValueError('MISSING/unsupported: model gate: expected %s once in __TEXT __cstring/__const, found %d'
                             % (model.decode(), len(hits)))
        (start, strings, at), = hits
        before = strings[:at - 1].rsplit(b'\0', 1)[-1]
        after = strings[at + len(model) + 1:].split(b'\0', 1)[0]
        if not (MODEL.fullmatch(before) and MODEL.fullmatch(after)):
            raise ValueError('MISSING/unsupported: model gate: %s is not inside a model list' % model.decode())
        return [(start + at, model, renamed, 'take %s off the unsupported-model list' % model.decode())]
    return checked_edits


def plan_cache_family(directory, data=DATA):
    """{cache file: [(offset, original, replacement, reason)]} for every listed image."""
    plan = {}
    edits = checker(data['model'], data['renamed'])
    for image in data['images']:
        for path, changes in plan_family(directory, image['path'].encode(), edits).items():
            plan.setdefault(path, []).extend(
                (offset, original, replacement, '%s: %s' % (image['feature'], reason))
                for offset, original, replacement, reason in changes)
    return plan

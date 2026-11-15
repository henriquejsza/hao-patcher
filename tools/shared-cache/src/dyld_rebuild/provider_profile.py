"""Selected provider paths, carried as build data rather than fixed-build pins."""
import json
from pathlib import Path

def select(name=None, build=None):
    value = json.loads(Path(name).read_text()) if name else {'providers': {}}
    return dict(value['providers']), value, {}

def authenticated(reference=None, build=None):
    value = reference or {'providers': {}}
    return dict(value['providers']), value, {}

def check_inventory(paths, reference=None, build=None):
    return authenticated(reference, build)[0]

def check_records(records, reference=None, build=None):
    return authenticated(reference, build)[0]

def documents(pins, provenance, build):
    return dict(pins['providers'])

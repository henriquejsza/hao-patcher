"""Demand-driven LC_RPATH lookup without splitting literal Mach-O strings.

Apple Loader::forEachResolvedAtPathVar walks the rpath stack only for an
@rpath dependency and stops after the first selected candidate. Relative rpaths
need process security/current-directory context that this offline stage does
not supply; reaching one therefore refuses instead of skipping or guessing it.
"""
from collections import namedtuple
import posixpath

from .exports import require

RPath = namedtuple('RPath', ('literal', 'loader'))


def expand_path(path, loader, main):
    if path.startswith('@loader_path/') or path == '@loader_path':
        return posixpath.normpath(posixpath.dirname(loader) + path[len('@loader_path'):])
    if path.startswith('@executable_path/') or path == '@executable_path':
        return posixpath.normpath(posixpath.dirname(main) + path[len('@executable_path'):])
    return posixpath.normpath(path) if path.startswith('/') else None


def rpath_stack(rpaths, loader, inherited):
    """Preserve each LC_RPATH literal and the image that owns @loader_path."""
    return tuple(dict.fromkeys([RPath(path, loader) for path in rpaths] + list(inherited)))


def dependency_candidates(dependency, loader, main, stack):
    """Yield candidates in lookup order; validate only rpath entries reached."""
    if dependency.startswith('@rpath/'):
        require(stack, 'unsupported/unresolved load path: ' + dependency)
        for entry in stack:
            expanded = expand_path(entry.literal, entry.loader, main)
            require(expanded is not None, 'unsupported reached current LC_RPATH: ' + entry.literal)
            yield posixpath.normpath(expanded + '/' + dependency[7:])
    else:
        expanded = expand_path(dependency, loader, main)
        require(expanded is not None, 'unsupported/unresolved load path: ' + dependency)
        yield expanded

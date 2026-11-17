"""The installed iCBE wrapper reads no path from the environment; only a --diagnostics build has the harness switches."""
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SRC = HERE.parent/'src/compiler'
SWITCHES = (b'ICBE_WRAP_DUMP', b'ICBE_WRAP_INJECT_DIR', b'ARGBUF_IR_DUMP_DIR', b'ARGBUF_LLVM_OPTIONS')


def build(work, *flags):
    # The wrapper's own code without the iCBE re-export: undefined iCBE symbols stay unresolved.
    out = work/('wrap%s.dylib' % len(flags))
    subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-mmacosx-version-min=11.7', *flags, '-O1', '-Wall', '-Werror',
                    '-dynamiclib', '-undefined', 'dynamic_lookup', str(SRC/'icbe_wrap.c'), str(SRC/'igil_rewrite.c'),
                    str(SRC/'air_hook.c'), str(SRC/'air_pass.c'), '-o', str(out)], check=True, capture_output=True)
    return out.read_bytes()


class ReleaseSwitches(unittest.TestCase):
    def test_release_has_none_diagnostics_has_all(self):
        with tempfile.TemporaryDirectory(prefix='argbuf-switches-') as work:
            release = build(Path(work))
            diagnostics = build(Path(work), '-DARGBUF_DIAGNOSTICS=1')
        for name in SWITCHES:
            self.assertNotIn(name, release)
            self.assertIn(name, diagnostics)


if __name__ == '__main__':
    unittest.main()

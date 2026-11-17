"""The installed library takes no library path from the environment (the LLVM it lowers with is the stack's own)."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SRC = Path(__file__).resolve().parents[1]/'src'


class NoEnvironmentPaths(unittest.TestCase):
    def test_frontend_reads_no_environment(self):
        with tempfile.TemporaryDirectory(prefix='fb-env-') as work:
            obj = Path(work)/'frontend.o'
            subprocess.run(['xcrun', 'clang++', '-std=c++17', '-arch', 'x86_64', '-mmacosx-version-min=13.0',
                            '-fobjc-arc', '-c', str(SRC/'frontend.mm'), '-o', str(obj)], check=True, capture_output=True)
            data = obj.read_bytes()
            symbols = subprocess.run(['nm', '-u', str(obj)], check=True, capture_output=True, text=True).stdout.split()
        self.assertNotIn(b'METAL_FRAMEBUFFER_LLVM', data)
        self.assertNotIn('_getenv', symbols)


if __name__ == '__main__':
    unittest.main()

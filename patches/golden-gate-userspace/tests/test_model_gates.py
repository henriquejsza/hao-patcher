"""src/model_gates.py on a synthetic cache image (no Apple bytes).
python3.14 -I -B -m unittest discover -s patches/golden-gate-userspace/tests -k test_model_gates
The real cache's sites are checked by test_edits (RealCaches, USERSPACE_X86_CACHE)."""
import struct
import sys
import json
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import model_gates  # noqa: E402

BASE = 0x7ff900000000


def image(const, cstring=b'\0'):
    """A thin x86_64 Mach-O at BASE: __TEXT with __text, __const and __cstring; read(address, size) over it."""
    sections = [(b'__text', b'\xc3' * 16), (b'__const', const), (b'__cstring', cstring)]
    header_size = 32 + 72 + 80 * len(sections)
    at, rows, body = header_size, b'', b''
    for name, data in sections:
        rows += struct.pack('<16s16sQQIIIIIIII', name, b'__TEXT', BASE + at, len(data), at, 0, 0, 0, 0, 0, 0, 0)
        body += data
        at += len(data)
    command = struct.pack('<II16sQQQQiiII', 0x19, 72 + 80 * len(sections), b'__TEXT', BASE, at, 0, at, 5, 5,
                          len(sections), 0) + rows
    blob = struct.pack('<IiiIIIII', 0xfeedfacf, 0x1000007, 3, 6, 1, len(command), 0, 0) + command + body

    def read(address, size):
        return blob[address - BASE:address - BASE + size]
    return blob, read


LIST = b'\0MacBookAir7,2\0MacBookPro9,1\0MacBookPro9,2\0MacBookPro10,1\0'


class Planner(unittest.TestCase):
    def setUp(self):
        self.check = model_gates.checker('MacBookPro9,2', 'NacBookPro9,2')

    def test_renames_the_one_entry_in_a_model_list(self):
        blob, read = image(LIST)
        (address, before, after, reason), = self.check(read, BASE)
        self.assertEqual((before, after), (b'MacBookPro9,2', b'NacBookPro9,2'))
        self.assertEqual(read(address, 13), b'MacBookPro9,2')
        self.assertIn('unsupported-model list', reason)

    def test_finds_it_in_cstring_too(self):
        _, read = image(b'\0', LIST)
        self.assertEqual(len(self.check(read, BASE)), 1)

    def test_refuses_when_absent_twice_or_outside_a_list(self):
        for const in (b'\0MacBookPro9,1\0MacBookPro10,1\0', LIST + LIST[1:],
                      b'\0hello\0MacBookPro9,2\0MacBookPro10,1\0', b'\0MacBookPro9,22\0'):
            _, read = image(const)
            with self.assertRaises(ValueError, msg=const):
                self.check(read, BASE)

    def test_a_longer_model_is_not_matched(self):
        _, read = image(b'\0MacBookPro9,1\0MacBookPro9,23\0MacBookPro10,1\0')
        with self.assertRaises(ValueError):
            self.check(read, BASE)

    def test_the_rename_must_keep_the_length(self):
        with self.assertRaises(ValueError):
            model_gates.checker('MacBookPro9,2', 'MacBookPro9,22')

    def test_data_names_three_images_and_no_mac(self):
        self.assertEqual(len(model_gates.DATA['images']), 3)
        self.assertNotIn('model', model_gates.DATA)          # the Mac is the target's (platform_data model_gates)
        self.assertNotIn('MacBook', json.dumps(model_gates.DATA))

    def test_the_gates_come_from_the_target(self):
        self.assertEqual(model_gates.target_gates('MacBookPro9,2', {'model_gates': {'renamed': 'NacBookPro9,2'}}),
                         ('MacBookPro9,2', 'NacBookPro9,2'))
        self.assertIsNone(model_gates.target_gates('iMac20,1', {}))                 # e.g. the generic image
        with self.assertRaises(ValueError):
            model_gates.target_gates('', {'model_gates': {'renamed': 'X'}})
        self.assertEqual(model_gates.plan_cache_family('/nonexistent', gates=()), {})  # no gates: nothing planned

    def test_the_mbp92_target_carries_its_gates(self):
        top = Path(__file__).resolve().parents[3]
        target = json.loads((top/'pipeline/targets/mbp92.json').read_text())
        model, renamed = model_gates.target_gates(target['model'], target['platform_data'])
        self.assertEqual(len(model), len(renamed))
        model_gates.checker(model, renamed)                    # a Mac model name of the same length


if __name__ == '__main__':
    unittest.main()

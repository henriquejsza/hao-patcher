from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.canonical_inputs import extend_pool
from dyld_rebuild.exports import Refusal


class CanonicalInputTests(unittest.TestCase):
    def test_append_preserves_old_addresses_and_bytes(self):
        old=b'first\0second\0'
        blob,names=extend_pool(old,0x1000,64,{'first':0x1000,'second':0x1006},['zebra','alpha'])
        self.assertEqual(blob[:len(old)],old)
        self.assertEqual(names['first'],0x1000);self.assertEqual(names['second'],0x1006)
        self.assertEqual(names['alpha'],0x1000+len(old))
        self.assertEqual(blob[len(old):],b'alpha\0zebra\0')

    def test_no_additions_is_byte_exact(self):
        self.assertEqual(extend_pool(b'old\0',4,8,{'old':4},[]),(b'old\0',{'old':4}))

    def test_existing_pool_identity_drift_and_overlap_refuse(self):
        for names in ({'wrong':0x1000},{'old':0x1001},{'old':0xfff},{'old':0x1000,'ld':0x1001}):
            with self.subTest(names=names),self.assertRaises(Refusal):extend_pool(b'old\0',0x1000,32,names,[])

    def test_invalid_duplicate_or_reused_additions_refuse(self):
        for names in (['a','a'],['old'],[''],['bad\0name']):
            with self.subTest(names=names),self.assertRaises(Refusal):extend_pool(b'old\0',0x1000,32,{'old':0x1000},names)

    def test_reservation_overflow_refuses(self):
        with self.assertRaisesRegex(Refusal,'exceed reservation'):extend_pool(b'old\0',0x1000,5,{'old':0x1000},['new'])
        with self.assertRaises(Refusal):extend_pool(b'old\0',0x1000,3,{'old':0x1000},[])


if __name__=='__main__':unittest.main()

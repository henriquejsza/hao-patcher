import copy
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.swift_dependencies import recover
from dyld_rebuild.swift_metadata import recipe_text

UUID = '00000000-0000-0000-0000-000000000000'


class FakeFamily:
    main = SimpleNamespace(data=bytes(128), mappings=[SimpleNamespace(address=0x1000)])

    def read(self, address, size):
        for desc, kind, params, count in [(0x1100,17,1,1), (0x1200,18,1,2), (0x1300,16,1,1)]:
            if address == desc and size == 4:
                return struct.pack('<I', 0x80 | kind)
            if address == desc+36 and size == 8:
                return struct.pack('<4H', params, 0, count, 0)
        raise AssertionError((address,size))


class FakeReferences:
    def __init__(self, family):
        pass

    def encode(self, address):
        if address not in [0x1100,0x1200,0x1300,0x1500]:
            raise Refusal('not a file-backed section')
        return dict(image='/Swift', segment='__DATA', section='__const', image_uuid=UUID,
                    offset=address-0x1000, executable=False)


class DependenciesTests(unittest.TestCase):
    def setUp(self):
        self.profile = dict(cache_uuid=UUID, cache_base=0x1000,
                            catalog=[dict(name='KnownDependency',metadata=0x2000)])
        self.runtime = dict(complete=True, errors=[], identities=[dict(cache_uuid=UUID,slide=0x10000)], requests=[])

    def request(self, descriptor, arguments, outcome='miss', slide=0x10000):
        return dict(descriptor=descriptor+slide, arguments=[a+slide for a in arguments], outcome=outcome)

    def recover(self, runtime=None):
        with patch('dyld_rebuild.swift_dependencies.References', FakeReferences):
            return recover(FakeFamily(), self.profile, runtime or self.runtime)

    def test_exact_keys_bypass_name_resolution_and_deduplicate(self):
        row=self.request(0x1100,[0x2000])
        self.runtime['requests']=[row,row,self.request(0x1100,[0x1500],'hit')]
        recipe,report=self.recover()
        self.assertEqual(report['missed_requests'],2)
        self.assertEqual(report['distinct_missed_keys'],1)
        self.assertEqual(report['categories'],{'exact_key_replay':1})
        self.assertEqual(recipe['records'][0]['key'],[0x100,0x1000])
        text=recipe_text(recipe,True)
        self.assertIn('@cache\t'+UUID,text)
        self.assertEqual(recipe['installed_metadata'],[0x1000])
        self.assertIn('@metadata\t1000\n',text)
        self.assertIn('\t/Swift\t100,1000\n',text)
        self.assertEqual(recipe['loads'],['/Swift'])

    def test_selected_identity_does_not_change_with_slide(self):
        self.runtime['requests']=[self.request(0x1100,[0x1500])]
        first,_=self.recover()
        other=copy.deepcopy(self.runtime)
        other['identities'][0]['slide']=0x20000
        other['requests']=[self.request(0x1100,[0x1500],slide=0x20000)]
        second,_=self.recover(other)
        self.assertEqual(first,second)

    def test_blocked_dependencies_and_classes_stay_out_of_recipe(self):
        self.runtime['requests']=[self.request(0x1100,[0x6000]),
                                  self.request(0x1200,[0x1500,0x6000]),
                                  self.request(0x1300,[0x1500]),
                                  self.request(0x1100,[0x1500,0x1500])]
        recipe,report=self.recover()
        self.assertEqual(recipe['records'],[])
        self.assertEqual(report['categories'],dict(needs_live_dependencies=2,
                         needs_class_metadata_support=1,unsupported_key_layout=1))
        self.assertEqual(report['blocked_roles'],dict(type_metadata=1,protocol_witness=1))
        self.assertEqual(len(report['entries']),4)

    def test_wrong_cache_and_incomplete_trace_do_not_make_a_recipe(self):
        bad=copy.deepcopy(self.runtime);bad['identities'][0]['cache_uuid']='wrong'
        with self.assertRaises(Refusal):self.recover(bad)
        bad=copy.deepcopy(self.runtime);bad['complete']=False
        with self.assertRaises(Refusal):self.recover(bad)


if __name__=='__main__':unittest.main()

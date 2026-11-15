import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.swift_live import Identities, normalize, ROOT


class References:
    images = {'/cached'}
    def encode(self, address):
        if 0x5000 <= address < 0x6000:
            return dict(image='/cached', image_uuid='fixture-uuid', section='__const', offset=address-0x5000)
        raise Refusal('outside section')


def capture(slide=0):
    return [dict(pid=123, cache_uuid='cache', cache_slide=slide),
            dict(root=1, metadata=0x9000+slide, type=1, descriptor=0x5100+slide, instance_fields=[]),
            dict(node=1, name='Box', kind=4, size=8, arguments=[2], fields=[]),
            dict(node=2, name='Child', kind=0, size=0, arguments=[], fields=[]),
            dict(complete=True, roots=1, nodes=2)]


def inventory(slide=0):
    return [dict(pid=123, metadata=[dict(address=0x9000+slide, name='Box')])]


class LiveTests(unittest.TestCase):
    def test_unknown_child_stays_in_graph_without_claiming_generation(self):
        r = normalize(capture(), inventory(), References())
        self.assertEqual(r['nodes'][1]['dependencies'], [2])
        self.assertEqual(r['nodes'][2]['unresolved'], ['layout_unavailable'])
        self.assertEqual(r['roots'][0]['generation_status'], 'not_tested')
        self.assertEqual(r['roots'][0]['adoption_status'], 'not_tested')

    def test_private_identity_is_slide_independent_and_unmapped_is_not_merged(self):
        values=[]
        for slide in (0x100000, 0x200000):
            ids=Identities(References(), dict(cache_slide=slide), [])
            token=f'${0x5100+slide:x}'
            values.append(ids.name(f'Box{len(token)}{token}LL'))
        self.assertEqual(values[0], values[1])
        self.assertEqual(Identities(References(), dict(cache_slide=0), []).name('Box7$abcdefLL'),
                         (None, ['process_local_context']))

    def test_app_context_has_uuid_identity_but_cache_zero_fill_does_not(self):
        images=[dict(path='/app',uuid='app-uuid',segments=[dict(start=0x10000,size=4096,name='__TEXT')]),
                dict(path='/cached',uuid='cache-uuid',segments=[dict(start=0x20000,size=4096,name='__DATA')])]
        ids=Identities(References(),dict(cache_slide=0),images)
        self.assertEqual(ids.reference(0x10008)['image_uuid'],'app-uuid')
        self.assertIsNone(ids.reference(0x20008))

    def test_missing_root_and_conformance_error_remain_explicit(self):
        rows=capture();rows[1]['type']=0;rows.insert(-1,dict(conformance_error='unsupported'))
        r=normalize(rows,inventory(),References())
        self.assertEqual(r['summary']['unresolved_roots'],1)
        self.assertEqual(r['summary']['conformance_errors'],['unsupported'])

    def test_truncated_capture_or_wrong_inventory_is_not_complete(self):
        with self.assertRaisesRegex(Refusal,'incomplete'):
            normalize(capture()[:-1],inventory(),References())
        with self.assertRaisesRegex(Refusal,'differ from inventory'):
            normalize(capture(),inventory(1),References())

    def test_class_fields_and_canonical_variants_are_retained(self):
        rows=capture();rows[1]['instance_fields']=[dict(type=2,name='value')]
        rows[1]['instance_kind']=17;rows[2]['kind']=13;rows[2]['arguments']=[]
        rows.insert(2,dict(rows[1],root=2,metadata=0x9008));rows[-1]['roots']=2
        inv=inventory();inv[0]['metadata'].append(dict(address=0x9008,name='Box'))
        r=normalize(rows,inv,References())
        self.assertEqual(len(r['roots']),2)
        self.assertEqual(r['roots'][0]['instance_dependencies'],[2])
        self.assertEqual(r['roots'][1]['type'],r['roots'][0]['type'])
        self.assertEqual(r['nodes'][1]['dependencies'],[2])
        self.assertNotIn('class_instance_not_observed',r['nodes'][1]['unresolved'])

    @unittest.skipUnless(sys.platform=='darwin' and shutil.which('xcrun'), 'requires Apple Swift reflection runtime')
    def test_upstream_reflects_native_values_classes_tuples_functions_and_enums(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp);sdk=subprocess.check_output(['xcrun','--show-sdk-path'],text=True).strip()
            subprocess.run(['xcrun','clang','-O2','-Wall','-Wextra','-Werror',
                            '-Dmain=reflection_main','-I',str(ROOT/'vendor/swift-remote-mirror'),
                            '-c',str(ROOT/'tools/swift-reflection-reader.c'),'-o',str(tmp/'reader.o')],check=True)
            subprocess.run(['xcrun','swiftc',str(ROOT/'tests/swift-reflection.swift'),str(tmp/'reader.o'),
                            '-L'+sdk+'/usr/lib/swift','-lswiftRemoteMirror','-o',str(tmp/'fixture')],check=True)
            subprocess.run(['codesign','-s','-',str(tmp/'fixture')],check=True,capture_output=True)
            run=subprocess.run([str(tmp/'fixture')],text=True,capture_output=True,check=True,timeout=60)
            rows=[json.loads(line) for line in run.stdout.splitlines()]
            roots=[r for r in rows if 'root' in r];nodes={r['node']:r for r in rows if 'node' in r}
            self.assertEqual(len(roots),6)
            self.assertTrue(all(r['type'] in nodes for r in roots))
            self.assertEqual([nodes[r['type']]['kind'] for r in roots],[4,13,6,3,8,6])
            self.assertEqual(roots[1]['instance_kind'],17)
            self.assertIn('value',[f['name'] for f in roots[1]['instance_fields']])
            self.assertTrue(rows[-1]['complete'])
            self.assertFalse(any('conformance_error' in r for r in rows))
            self.assertNotIn('symbol unavailable',run.stderr)

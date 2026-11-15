import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.metadata_inventory import inputs, plan, type_constraints
from dyld_rebuild.metadata_expand import main
from dyld_rebuild.swift_metadata import recipe_rows


class InventoryBatchTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('SWIFT_TYPE_GRAPH_JSON'), 'set SWIFT_TYPE_GRAPH_JSON to upstream reader')
    def test_observed_jet_dependency_name_requires_context(self):
        # This inventory spelling aborts the target runtime with "Expected a
        # metadata pack but got metadata" when submitted without its context.
        name='s15LazyMapSequenceVySay9JetEngine15_DependencyRule_pmGAcD_px7_OutputAcDPRtz_XPmmSgG'
        toolchain=Path(os.environ['SWIFT_TYPE_GRAPH_JSON']).resolve().parent.parent
        blocked=type_constraints([name, 'SiSg'], toolchain)
        self.assertNotIn('SiSg', blocked)
        self.assertIn('DependentGenericParamType', blocked[name]['details'])

    def test_union_discards_process_addresses_and_retains_private_blockers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root/'first.json', root/'second.json'
            first.write_text(json.dumps([dict(metadata=[dict(name='$sSiSg', address=123),
                dict(name='7Example13$1234abcdyXZ4TypeVSg', address=456)])]))
            second.write_text(json.dumps({'SiSg': ['/App'], 'SSSg': ['/Other']}))
            with patch('dyld_rebuild.metadata_inventory.framework_owners',
                       return_value={'Swift': ['/usr/lib/swift/libswiftCore.dylib']}), \
                 patch('dyld_rebuild.metadata_inventory.type_constraints', return_value={}):
                graph = plan(None, [first, second], [], {'loads': ['/Framework']}, root)
            requests = graph.document['requests']
            self.assertEqual(len(requests), 3)
            candidate = [r for r in requests if 'constructor' in r]
            self.assertEqual({r['name'] for r in candidate}, {'SiSg', 'SSSg'})
            # The all-observed resolver must supply the worker's load image;
            # a missing owner previously failed before native generation began.
            recipe_rows(dict(schema=1, records=candidate))
            self.assertTrue(all(r['owner']=='/usr/lib/swift/libswiftCore.dylib' for r in candidate))
            self.assertEqual(next(r for r in requests if 'unresolved' in r)['facts'], ['requested', 'unresolved'])
            self.assertEqual(next(r for r in candidate if r['name']=='SiSg')['source'], ['/App'])
            before = inputs([first, second], [])
            second.write_text('{}')
            self.assertNotEqual(before, inputs([first, second], []))

    def test_inventory_mode_does_not_require_binary_discovery(self):
        with patch('dyld_rebuild.metadata_expand.expand') as expand:
            self.assertEqual(main(['--cache','cache','--catalog','catalog','--toolchain','tools',
                '--dyld-toolchain','dyld','--devkit','devkit','--llvm','llvm','--output','out',
                '--inventory','first.json','--inventory','second.json',
                '--reflection-graph','reflection.json','--runner','runner']), 0)
        self.assertEqual(expand.call_args.args[0].binary, [])
        self.assertEqual(expand.call_args.args[0].inventory, [Path('first.json'), Path('second.json')])


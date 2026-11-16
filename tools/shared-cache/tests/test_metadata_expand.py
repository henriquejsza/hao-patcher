"""Execution adapters must fail explicitly and never imply installed acceptance."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.metadata_expand import execute, main, binary_inputs, reused_graph
from dyld_rebuild.metadata_graph import MetadataGraph
from dyld_rebuild.exports import Refusal


class ExpansionTests(unittest.TestCase):
    def test_adapter_receives_phase_and_bundle_and_preserves_failure_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            runner = root/'runner'
            runner.write_text('#!/bin/sh\nprintf \'{"phase":"%s","bundle":"%s"}\\n\' "$1" "$2"\n'
                              'echo "adapter diagnostic" >&2\nexit 7\n')
            runner.chmod(0o755)
            out = root/'capture.jsonl'
            with self.assertRaises(subprocess.CalledProcessError) as failure:
                execute(runner, 'capture', root/'bundle', out)
            self.assertEqual(failure.exception.returncode, 7)
            self.assertEqual(json.loads(out.read_text()), dict(phase='capture', bundle=str((root/'bundle').resolve())))
            self.assertEqual(out.with_suffix('.stderr').read_text(), 'adapter diagnostic\n')
            # Verification consumes the failed adapter's events before refusing
            # the result, so the graph and coverage can retain the failure.
            verified=root/'verification.jsonl'
            result=execute(runner,'verify',root/'bundle',verified,check=False)
            self.assertEqual(result.returncode,7)
            self.assertEqual(json.loads(verified.read_text())['phase'],'verify')

    def test_saved_capture_cannot_be_relabelled_for_another_cache(self):
        from test_swift_graph import SwiftGraphTests
        fixture = SwiftGraphTests()
        fixture.setUp()
        graph = MetadataGraph.from_plan([], fixture.recipe['records'])
        graph.import_catalog(fixture.base)
        fixture.capture[0]['cache_uuid'] = '11111111-1111-1111-1111-111111111111'
        with patch('dyld_rebuild.swift_metadata.References', return_value=fixture.refs), \
             self.assertRaisesRegex(Refusal, 'did not run with the supplied cache'):
            graph.record_capture(fixture.family, fixture.capture)
        self.assertIsNone(graph.coverage()['generation'])
        self.assertIsNone(graph.coverage()['installed'])

    def test_command_requires_an_explicit_execution_adapter(self):
        with patch('sys.stderr'), self.assertRaises(SystemExit) as failure:
            main(['--cache','cache','--catalog','catalog','--toolchain','tools',
                  '--dyld-toolchain','dyld','--devkit','devkit','--llvm','llvm',
                  '--output','out','--binary','app'])
        self.assertEqual(failure.exception.code, 2)

    def test_saved_capture_can_use_a_native_verification_adapter(self):
        with patch('dyld_rebuild.metadata_expand.expand') as expand:
            self.assertEqual(main(['--cache','cache','--catalog','catalog','--toolchain','tools',
                '--dyld-toolchain','dyld','--devkit','devkit','--llvm','llvm',
                '--output','out','--binary','app','--saved-capture','capture.jsonl',
                '--runner','runner']),0)
        args=expand.call_args.args[0]
        self.assertEqual(args.saved_capture,Path('capture.jsonl'))
        self.assertEqual(args.runner,Path('runner').resolve())

    def test_component_expansion_accepts_incremental_analysis(self):
        arguments=['--cache','cache','--catalog','catalog','--toolchain','tools',
            '--dyld-toolchain','dyld','--devkit','devkit','--llvm','llvm',
            '--output','out','--binary','app','--runner','runner',
            '--reuse-expansion','previous']
        with patch('sys.stderr'), self.assertRaises(SystemExit):
            main(arguments)
        with patch('dyld_rebuild.metadata_expand.expand') as expand:
            self.assertEqual(main(arguments+['--dependencies']),0)
        self.assertEqual(expand.call_args.args[0].reuse_expansion,Path('previous'))


class BinaryIdentityTests(unittest.TestCase):
    def test_saved_requests_require_the_analyzed_binary_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root/'app'
            binary.write_bytes(b'original')
            document = MetadataGraph().document
            document['inputs'] = binary_inputs([binary])
            graph = root/'graph.json'
            graph.write_text(json.dumps(document))
            self.assertEqual(reused_graph(graph, [binary]).document, document)
            binary.write_bytes(b'changed')
            with self.assertRaisesRegex(Refusal, 'renew analysis'):
                reused_graph(graph, [binary])
            document.pop('inputs')
            graph.write_text(json.dumps(document))
            with self.assertRaisesRegex(Refusal, 'missing'):
                reused_graph(graph, [binary])

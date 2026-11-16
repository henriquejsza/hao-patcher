"""Dependency coverage needs library paths and service connections, not only PPIDs."""
import json
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild import component_graph as graph
from dyld_rebuild.component_metadata import (component_inputs, component_identity, generation_results,
                                            attribute_results, reuse_frontends)
from dyld_rebuild.metadata_graph import MetadataGraph
from dyld_rebuild.exports import Image
from dyld_rebuild.cache_exports import CacheDependency


def command(kind, prefix, name):
    raw = prefix+name.encode()+b'\0'
    raw += bytes((-len(raw)-8)%8)
    return struct.pack('<II',kind,8+len(raw))+raw


def macho(deps=(), rpaths=(), literals=()):
    commands = [struct.pack('<II',0x1b,24)+bytes(range(16))]
    commands += [command(0xc,struct.pack('<4I',24,0,0,0),d) for d in deps]
    commands += [command(0x8000001c,struct.pack('<I',12),r) for r in rpaths]
    return struct.pack('<8I',0xfeedfacf,0x1000007,3,2,len(commands),sum(map(len,commands)),0,0)+b''.join(commands)+b'\0'+b'\0'.join(s.encode() for s in literals)+b'\0'


class ComponentsTests(unittest.TestCase):
    def test_libraries_bundled_xpc_and_launchd_connection_are_distinct(self):
        images = {'/System/lib/One':Image('/System/lib/One',[CacheDependency('/System/lib/Two',0xc)],{}),
                  '/System/lib/Two':Image('/System/lib/Two',[CacheDependency('/System/lib/One',0xc)],{})}
        class Cache:
            def __init__(self,*args):pass
            def canonical(self,path):return path if path in images else None
            def image(self,path):return path,images[path]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            main='/Apps/Main.app/Contents/MacOS/Main'
            files={main:macho(['/System/lib/One','@rpath/Local'],['@executable_path/../Frameworks'],['com.fixture.static']),
                '/Apps/Main.app/Contents/Frameworks/Local':macho(['/System/lib/One']),
                '/Apps/Main.app/Contents/XPCServices/Helper.xpc/Contents/MacOS/Helper':macho(),
                '/usr/libexec/StaticService':macho(),'/usr/libexec/DynamicService':macho()}
            for name,data in files.items():
                p=root/name.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            p=root/'Apps/Main.app/Contents/XPCServices/Helper.xpc/Contents/Info.plist'
            p.write_bytes(plistlib.dumps(dict(CFBundleExecutable='Helper',CFBundleIdentifier='com.fixture.helper')))
            for kind in ('Static','Dynamic'):
                p=root/f'System/Library/LaunchAgents/{kind}.plist';p.parent.mkdir(parents=True,exist_ok=True)
                p.write_bytes(plistlib.dumps(dict(Label='com.fixture.'+kind.lower(),
                    Program='/usr/libexec/'+kind+'Service',MachServices={'com.fixture.'+kind.lower():True})))
            family=SimpleNamespace(images=list(zip(images,(0x1000,0x2000))))
            event=dict(kind='xpc-connection',source=main,service='com.fixture.dynamic',pid=123,service_pid=987,ppid=1)
            request=dict(kind='xpc-connection',source=main,service='com.fixture.dynamic',
                         status='activation-request',observed=False)
            with patch.object(graph,'FinalGraph',Cache),patch.object(graph,'commands',return_value=[]):
                doc,_=graph.discover(family,[root/main.lstrip('/')],[root],dict(events=[event,request]))
            self.assertEqual(len(doc['components']),7)
            self.assertFalse(doc['unresolved'])
            edges=doc['edges']
            self.assertTrue(any(e['relation']=='bundled-component' and e['target'].endswith('/Helper') for e in edges))
            static=next(e for e in edges if e['relation']=='service-name-reference')
            self.assertEqual(static['target'],'/usr/libexec/StaticService')
            self.assertFalse(static['observed'])
            observed=next(e for e in edges if e['relation']=='xpc-connection' and e['observed'])
            self.assertTrue(observed['observed'])
            self.assertEqual(observed['source'],main)
            self.assertEqual(observed['target'],'/usr/libexec/DynamicService')
            self.assertEqual(observed['evidence']['ppid'],1)
            requested=next(e for e in edges if e['relation']=='xpc-connection' and not e['observed'])
            self.assertEqual(requested['evidence']['status'],'activation-request')
            self.assertEqual(len({json.dumps(e,sort_keys=True) for e in edges}),len(edges))
            self.assertTrue(all(c['image_uuid'] for c in doc['components'] if c['kind']=='disk-image'))

    def test_target_absolute_symlinks_never_use_host_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);a=root/'a';b=root/'b';a.mkdir();b.mkdir()
            (a/'link').symlink_to('/target')
            (b/'target').mkdir();(b/'target/value').write_text('target')
            roots=graph.Roots([a,b])
            self.assertEqual(roots.find('/link/value'),(b/'target/value').resolve())
            (a/'cycle').symlink_to('/cycle')
            with self.assertRaisesRegex(ValueError,'cycle'):roots.find('/cycle')
            self.assertIsNone(roots.find('/etc/passwd'))

    def test_cryptex_mapping_and_bundle_links_resolve_inside_target_views(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);system=root/'system';app=root/'app';system.mkdir();app.mkdir()
            prefix='/System/Volumes/Preboot/Cryptexes/App'
            (system/'Applications').mkdir()
            (system/'Applications/Browser.app').symlink_to(prefix+'/Applications/Browser.app')
            bundle=app/'Applications/Browser.app';(bundle/'Contents/MacOS').mkdir(parents=True)
            (bundle/'Contents/MacOS/Browser').write_bytes(macho())
            (bundle/'Contents/MacOS/Helper').symlink_to('/usr/libexec/Helper')
            (system/'usr/libexec').mkdir(parents=True);(system/'usr/libexec/Helper').write_bytes(macho())
            roots=graph.Roots([system],[(prefix,app),('/System/Cryptexes/App',app)])
            physical=(bundle/'Contents/MacOS/Browser').resolve()
            self.assertEqual(roots.find('/Applications/Browser.app/Contents/MacOS/Browser'),physical)
            self.assertEqual(roots.find('/System/Cryptexes/App/Applications/Browser.app/Contents/MacOS/Browser'),physical)
            self.assertEqual(roots.logical(physical),prefix+'/Applications/Browser.app/Contents/MacOS/Browser')
            self.assertEqual(graph.bundle_executable(bundle,dict(CFBundleExecutable='Helper'),roots),
                             (system/'usr/libexec/Helper').resolve())
            # A missing mapped input must not fall through to an unrelated overlay.
            wrong=system/prefix.lstrip('/')/'missing';wrong.parent.mkdir(parents=True);wrong.write_text('wrong')
            self.assertIsNone(roots.find(prefix+'/missing'))

    def test_inherited_rpaths_survive_cached_libraries_for_each_executable(self):
        images={'/Cached':Image('/Cached',[CacheDependency('/Plugin',0xc)],{})}
        class Cache:
            def __init__(self,*args):pass
            def canonical(self,path):return path if path in images else None
            def image(self,path):return path,images[path]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            files={'/Plugin':macho(['@rpath/Leaf']),
                '/One/Main':macho(['/Cached'],['@executable_path/Libs']),
                '/Two/Main':macho(['/Cached'],['@executable_path/Libs']),
                '/One/Libs/Leaf':macho(),'/Two/Libs/Leaf':macho()}
            for name,data in files.items():
                p=root/name.lstrip('/');p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
            family=SimpleNamespace(images=[('/Cached',0x1000)])
            with patch.object(graph,'FinalGraph',Cache),patch.object(graph,'commands',return_value=[]):
                doc,_=graph.discover(family,[root/'One/Main',root/'Two/Main'],[root])
            self.assertFalse(doc['unresolved'])
            self.assertEqual({e['target'] for e in doc['edges'] if e['source']=='/Plugin'},
                             {'/One/Libs/Leaf','/Two/Libs/Leaf'})

    def test_component_results_keep_generated_retained_and_unresolved_separate(self):
        c=dict(path='/App',kind='disk-image',sha256='a',image_uuid='b')
        d=dict(components=[c]);g=MetadataGraph();key=g.constructor('resolve',name='SaySiG')
        g.request('SaySiG','/Swift',key,source={'input':component_identity(c)})
        g.document['requests'][0]['facts']=['requested','retained']
        result=generation_results(d,g)['components'][0]
        self.assertEqual(result['generation'],dict(state='evaluated',requests=1,retained=1))
        self.assertFalse(result['installed'])
        before=component_inputs(d);c['sha256']='changed'
        self.assertNotEqual(before,component_inputs(d))

    def test_existing_results_match_binary_identity_and_do_not_mark_missing_components_analyzed(self):
        shared=dict(path='/Shared',kind='cache-image',image_uuid='one',
                    analysis=dict(state='analyzed'),generation=dict(state='evaluated',requests=4,generated=2,retained=1,unresolved=1))
        disk=dict(path='/App',kind='disk-image',image_uuid='app',sha256='old')
        discovery=dict(roots=['/App'],components=[dict(shared),dict(disk,sha256='new'),
                       dict(shared,path='/SameNameDifferentBinary',image_uuid='two')])
        coverage=dict(verification=dict(executed=True,installed=False,result=dict(complete=True)))
        report=attribute_results(discovery,dict(components=[shared,disk]),coverage)
        self.assertEqual(report['summary'],dict(discovered=3,matched=1,not_analyzed=2,
            request_facts=dict(requests=4,generated=2,retained=1,unresolved=1)))
        self.assertEqual([r['generation']['state'] for r in report['components']],['evaluated','pending','pending'])
        self.assertIsNone(report['installed'])
        self.assertIsNone(report['observed_application_use'])
        report['components'][0]['generation']['generated']=99
        self.assertEqual(shared['generation']['generated'],2)

    def test_results_command_preserves_discovery_reference_without_duplicating_edges(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'expansion';source.mkdir()
            component=dict(path='/App',kind='disk-image',image_uuid='uuid',sha256='same',
                analysis=dict(state='reused'),generation=dict(state='evaluated',requests=1,retained=1))
            discovery=dict(roots=['/App'],components=[component],edges=[dict(source='/App',target='/Library')])
            manifest=root/'components.json';manifest.write_text(json.dumps(discovery))
            for name,value in [('components.json',discovery),('build.json',{}),
                ('coverage.json',dict(verification=dict(executed=True,installed=False,result=dict(complete=True))))]:
                (source/name).write_text(json.dumps(value))
            out=root/'results'
            with patch('builtins.print'):
                self.assertEqual(graph.main(['--manifest',str(manifest),'--generation',str(source),'--output',str(out)]),0)
            result=json.loads((out/'component-results.json').read_text())
            self.assertEqual(result['summary']['matched'],1)
            self.assertEqual(result['discovery']['path'],str(manifest.resolve()))
            self.assertNotIn('edges',result)
            self.assertEqual(json.loads((out/'build.json').read_text())['operation'],'application-component-generation')

    def test_incremental_frontends_keep_unchanged_requests_and_constructor_dependencies(self):
        shared=dict(path='/Shared',kind='cache-image',image_uuid='shared',analysis=dict(state='analyzed'))
        old=dict(path='/App',kind='disk-image',image_uuid='app',sha256='old',analysis=dict(state='reused'))
        keep=dict(path='/Helper',kind='disk-image',image_uuid='helper',sha256='same',analysis=dict(state='analyzed'))
        removed=dict(path='/Removed',kind='disk-image',image_uuid='gone',sha256='gone',analysis=dict(state='analyzed'))
        previous=dict(components=[shared,old,keep,removed])
        current=dict(components=[shared,dict(shared,path='/Additional',image_uuid='additional'),
                                dict(old,sha256='changed'),keep,
                                dict(old,path='/New',sha256='new')])
        g=MetadataGraph()
        argument=g.constructor('resolve',name='Si')
        parent=g.constructor('generic',descriptor={'fixture':True},arguments=[argument])
        dropped=g.constructor('resolve',name='OldAppType')
        g.request('SharedType','/Shared',parent,source={'input':component_identity(shared),'declaration':'field'})
        g.request('OldAppType','/Shared',dropped,source={'input':component_identity(old)})
        g.request('RemovedType','/Shared',dropped,source={'input':component_identity(removed)})
        g.request('Unresolved',source={'input':component_identity(keep)},unresolved={'state':'missing'})
        first=g.document['requests'][0]
        first.update(facts=['requested','generated'],object='old-object',outcome={'status':'included'})
        g.document['objects']={'old-object':{'facts':['generated']}}
        g.document['loads']=['/Shared']
        g.document['inputs']=component_inputs(previous)
        g.document['evidence']={'frontends':[{'component':c['path'],'report':{}} for c in previous['components']],
                                'isolated_replay':{'complete':True}}
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            for name,value in [('requests.json',g.document),('components.json',previous),
                               ('build.json',{'cache_uuid':'cache'})]:
                (p/name).write_text(json.dumps(value))
            result,reused,files,reason=reuse_frontends(p,current,'cache')
        self.assertIsNone(reason)
        self.assertEqual(set(reused),{component_identity(shared),component_identity(keep)})
        self.assertEqual(set(result.document['constructors']),{argument,parent})
        self.assertEqual([r['name'] for r in result.document['requests']],['SharedType','Unresolved'])
        self.assertEqual(result.document['requests'][0]['facts'],['requested'])
        self.assertNotIn('object',result.document['requests'][0])
        self.assertNotIn('outcome',result.document['requests'][0])
        self.assertEqual(result.document['requests'][1]['facts'],['requested','unresolved'])
        self.assertEqual(result.document['objects'],{})
        self.assertNotIn('isolated_replay',result.document['evidence'])
        self.assertEqual({r['component'] for r in result.document['evidence']['frontends']},{'/Shared','/Helper'})
        self.assertEqual(result.document['loads'],['/Shared'])
        self.assertEqual({p.name for p in files},{'requests.json','components.json','build.json'})

    def test_changed_cache_context_renews_frontends_instead_of_reusing_old_resolution(self):
        component=dict(path='/Shared',kind='cache-image',image_uuid='old',analysis=dict(state='analyzed'))
        previous=dict(components=[component]);g=MetadataGraph()
        g.document['inputs']=component_inputs(previous)
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)
            for name,value in [('requests.json',g.document),('components.json',previous),
                               ('build.json',{'cache_uuid':'old-cache'})]:
                (p/name).write_text(json.dumps(value))
            for current,cache_uuid in [(previous,'new-cache'),
                    (dict(components=[dict(component,image_uuid='changed')]),'old-cache')]:
                result,reused,files,reason=reuse_frontends(p,current,cache_uuid)
                self.assertEqual(result.document,MetadataGraph().document)
                self.assertEqual(reused,{})
                self.assertEqual(reason,'cache binaries changed')


if __name__=='__main__':unittest.main()

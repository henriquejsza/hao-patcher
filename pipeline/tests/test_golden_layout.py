"""Protected metadata/grouping logic with syscalls and mutation mocked on the host."""
import errno
import os
import stat
import importlib.util
from pathlib import Path
import tempfile
import shutil
import subprocess
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('golden_layout',Path(__file__).resolve().parents[1]/'stages/golden-layout.py')
layout=importlib.util.module_from_spec(spec);spec.loader.exec_module(layout)
LINK='../../System/Volumes/Preboot/Cryptexes/OS'
VALUE=b'/System/Volumes/Preboot/Cryptexes/Incoming/OS'


def state(group=None):
    return dict(container='disk9',system='disk9s1',volumes={
        'disk9s1':dict(uuid='SYSTEM',group=group,role='System'),
        'disk9s2':dict(uuid='DATA',group=group,role='Data')})


class GoldenLayoutTests(unittest.TestCase):
    def test_image_binding_refuses_running_container_before_any_disk_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            image=Path(temporary)/'image';image.write_bytes(b'fixture')
            with patch.object(layout,'plist',return_value=dict(APFSContainerReference='disk9')):
                with self.assertRaisesRegex(ValueError,'maintenance container'):
                    layout.bound_container(image,'disk9')

    def test_image_binding_refuses_a_container_outside_declared_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            image=Path(temporary)/'image';image.write_bytes(b'fixture')
            replies=iter([dict(APFSContainerReference='disk1'),
                dict(Containers=[dict(PhysicalStores=[dict(DeviceIdentifier='disk8s2')])]),
                dict(images=[{'image-path':str(image),'writeable':True,
                              'system-entities':[{'dev-entry':'/dev/disk2'}]}])])
            with patch.object(layout,'plist',side_effect=lambda *a:next(replies)):
                with self.assertRaisesRegex(ValueError,'do not belong'):
                    layout.bound_container(image,'disk9')

    def test_group_preserves_altlink_identity_and_reads_back_data_uuid(self):
        observed=iter([state(),state('DATA')]);calls=[]
        original=dict(inode=5,device=6,target=LINK,altlink_hex=VALUE.hex())
        result=layout.group('/image','/system','disk9s2',observe=lambda *a:next(observed),
                            read=lambda *a:original,mutate=lambda c,i:calls.append((c,i)) or 'DATA')
        self.assertEqual(calls,[('disk9',[1,2])])
        self.assertEqual(result['group_uuid'],'DATA')
        self.assertEqual(result['altlink'],original)

    def test_group_refuses_changed_node_after_grouping(self):
        observed=iter([state(),state('DATA')]);reads=iter([{'inode':5},{'inode':9}])
        with self.assertRaisesRegex(ValueError,'inode'):
            layout.group('/image','/system','disk9s2',observe=lambda *a:next(observed),
                         read=lambda *a:next(reads),mutate=lambda *a:'DATA')

    def test_preexisting_group_never_reaches_mutation(self):
        with self.assertRaisesRegex(ValueError,'ungrouped'):
            layout.group('/image','/system','disk9s2',observe=lambda *a:state('EXISTING'),
                         mutate=lambda *a:self.fail('must not mutate'))

    def test_wrong_returned_group_refuses(self):
        with self.assertRaisesRegex(ValueError,'different Data UUID'):
            layout.group('/image','/system','disk9s2',observe=lambda *a:state(),read=lambda *a:{},
                         mutate=lambda *a:'WRONG')

    def test_seed_sets_only_missing_attribute_and_preserves_existing_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/layout.ALT_PATH
            path.parent.mkdir(parents=True);path.symlink_to(LINK);inode=path.lstat().st_ino
            values={}
            def get(p):
                if p not in values:raise OSError(errno.ENOATTR,'missing')
                return values[p]
            def put(p,value):values[p]=value
            sole=dict(container='disk9',system='disk9s1',volumes={'disk9s1':dict(uuid='SYSTEM',role='System',group=None)})
            with patch.object(layout,'read_xattr',side_effect=get),patch.object(layout,'write_xattr',side_effect=put) as setter:
                first=layout.seed('/image',root,LINK,VALUE,observe=lambda *a:sole)
                second=layout.seed('/image',root,LINK,VALUE,observe=lambda *a:sole)
                self.assertEqual(first,second)
                self.assertEqual(first['inode'],inode)
                self.assertEqual(setter.call_count,1)

    def test_seed_does_not_waive_permission_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            sole=dict(volumes={'disk9s1':dict(group=None)})
            with patch.object(layout,'read_xattr',side_effect=PermissionError(errno.EPERM,'denied')):
                with self.assertRaises(PermissionError):layout.seed('/image',Path(temporary),LINK,VALUE,observe=lambda *a:sole)


class GoldenSystemCopyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.source=Path(self.temp.name)/'source';self.target=Path(self.temp.name)/'target';self.source.mkdir()
        (self.source/'usr/share').mkdir(parents=True)
        (self.source/'usr/share/firmlinks').write_text('/Library\tLibrary\n/Absent\tAbsent\n/usr/local\tusr/local\n')
        (self.source/'Library').mkdir();(self.source/'usr/local').mkdir()
        (self.source/'System/ordinary').mkdir(parents=True);(self.source/'System/ordinary/file').write_bytes(b'Golden bytes')
        (self.source/'etc').symlink_to('private/etc')
        self.commands=[];self.metadata=[]

    def command(self,args,check=True):
        self.commands.append(args)
        source,target=map(Path,args[-2:])
        if source.is_dir():shutil.copytree(source,target,symlinks=True,dirs_exist_ok=True)
        else:shutil.copy2(source,target,follow_symlinks=False)

    def copy_metadata(self,source,target,firmlink):
        self.metadata.append((source.relative_to(self.source).as_posix(),firmlink))

    def test_copy_excludes_only_firmlink_object_metadata_and_keeps_other_subtrees(self):
        result=layout.copy_system_tree(self.source,self.target,self.copy_metadata,self.command)
        self.assertEqual(result['firmlink_anchors'],['Library','usr/local'])
        self.assertTrue((self.target/'Library').is_dir());self.assertEqual(list((self.target/'Library').iterdir()),[])
        self.assertEqual((self.target/'System/ordinary/file').read_bytes(),b'Golden bytes')
        self.assertEqual((self.target/'etc').readlink(),Path('private/etc'))
        self.assertEqual([x for x in self.metadata if x[1]],[('Library',True),('usr/local',True)])
        copied=[Path(c[-2]).relative_to(self.source).as_posix() for c in self.commands]
        self.assertIn('System',copied);self.assertNotIn('Library',copied);self.assertNotIn('usr/local',copied)
        self.assertEqual(self.metadata[-1],('.',False))

    def test_ordinary_copy_error_is_fatal(self):
        def fail(args,check):raise subprocess.CalledProcessError(19,args)
        with self.assertRaises(subprocess.CalledProcessError):layout.copy_system_tree(self.source,self.target,self.copy_metadata,fail)

    def test_unexpected_anchor_contents_are_not_discarded(self):
        (self.source/'Library/unexpected').write_bytes(b'must not lose')
        with self.assertRaisesRegex(ValueError,'anchor has source contents'):
            layout.copy_system_tree(self.source,self.target,self.copy_metadata,self.command)

    def test_invalid_anchor_path_cannot_escape_source(self):
        (self.source/'usr/share/firmlinks').write_text('/../escape\tescape\n')
        with self.assertRaisesRegex(ValueError,'invalid firmlink source'):
            layout.copy_system_tree(self.source,self.target,self.copy_metadata,self.command)

    def test_firmlink_flag_deferred_but_other_flags_and_compression_kept(self):
        self.assertEqual(layout.metadata_flags(0x900020,0,True),0x100000)
        self.assertEqual(layout.metadata_flags(0x880000,0x20,True),0x80020)
        self.assertEqual(layout.metadata_flags(0x900000,0,False),0x900000)


if __name__=='__main__':unittest.main()


class SetIDTests(unittest.TestCase):
    """diag#0057: ditto from an image attached off the USB installer (nosuid) drops set-ID bits; copy-system puts every
    one back from the source and records them for golden-image's pre-seal check."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.source=Path(self.temp.name)/'source';self.target=Path(self.temp.name)/'target'
        (self.source/'usr/share').mkdir(parents=True);(self.source/'usr/share/firmlinks').write_text('')
        (self.source/'usr/bin').mkdir()
        for name,mode in (('login',0o4555),('sudo',0o4511),('newgrp',0o2555),('ls',0o755)):
            (self.source/'usr/bin'/name).write_bytes(name.encode());os.chmod(self.source/'usr/bin'/name,mode)
        (self.source/'usr/bin/link').symlink_to('login')
        (self.source/'sbin').mkdir();(self.source/'sbin/ping').write_bytes(b'p');os.chmod(self.source/'sbin/ping',0o4555)

    def nosuid_ditto(self,args,check=True):
        """A copy that clears set-ID bits, as ditto does from a nosuid source volume."""
        source,target=map(Path,args[-2:])
        if source.is_dir():shutil.copytree(source,target,symlinks=True,dirs_exist_ok=True)
        else:shutil.copy2(source,target,follow_symlinks=False)
        for p in [target]+list(target.rglob('*')):
            if not p.is_symlink():os.chmod(p,stat.S_IMODE(p.lstat().st_mode)&~(stat.S_ISUID|stat.S_ISGID))

    def test_every_set_id_mode_survives_the_copy(self):
        result=layout.copy_system_tree(self.source,self.target,lambda *a:None,self.nosuid_ditto)
        for rel,mode in (('usr/bin/login',0o4555),('usr/bin/sudo',0o4511),('usr/bin/newgrp',0o2555),('usr/bin/ls',0o755),
                         ('sbin/ping',0o4555)):
            self.assertEqual(stat.S_IMODE((self.target/rel).lstat().st_mode),mode,rel)
        recorded={r[0]:r[1] for r in result['set_id']}
        self.assertEqual(recorded,{'usr/bin/login':0o4555,'usr/bin/sudo':0o4511,'usr/bin/newgrp':0o2555,'sbin/ping':0o4555})
        uid=os.getuid()
        self.assertTrue(all(r[2]==uid for r in result['set_id']))

    def test_symlinks_are_not_set_id_files(self):
        self.assertNotIn('usr/bin/link',[r[0] for r in layout.set_id_files(self.source)])

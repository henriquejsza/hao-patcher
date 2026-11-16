"""Pinned UID0 read-only exports for the one observed unreadable factory program."""
import errno
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess

from .exports import require
from .run_inputs import pin
from .loader_generation import verify_file,executable

ALLOWED=frozenset(['/usr/sbin/visudo'])
STAT_FIELDS=('mode','uid','gid','size','inode','mtime_ns','flags')


def original_stat(path):
    info=Path(path).lstat()
    return dict(mode=info.st_mode,uid=info.st_uid,gid=info.st_gid,size=info.st_size,
                inode=info.st_ino,mtime_ns=info.st_mtime_ns,flags=info.st_flags)


def read_plist(*command):
    return plistlib.loads(subprocess.check_output(command))


def observe_snapshot(system,image,snapshot):
    """A manual named-snapshot mount need not publish a diskutil mount device."""
    lines=subprocess.check_output(['/sbin/mount'],text=True).splitlines()
    selected=[]
    for line in lines:
        match=re.fullmatch(r'(.+) on (.+) \(([^)]*)\)',line)
        if match and match[2]==str(system):selected.append(match)
    require(len(selected)==1,'privileged input System is not one explicit mount')
    mounted=selected[0];options={part.strip() for part in mounted[3].split(',')}
    require('read-only' in options,'privileged input System mount is not read-only')
    source=re.fullmatch(re.escape(snapshot['snapshot_name'])+r'@(/dev/disk[0-9]+s[0-9]+)',mounted[1])
    require(source is not None,'System is not the exact named snapshot mount')
    device=source[1]
    underlying=read_plist('/usr/sbin/diskutil','info','-plist',device)
    require(underlying.get('VolumeUUID')==snapshot['volume_uuid'],'privileged input System volume UUID differs')
    snapshots=read_plist('/usr/sbin/diskutil','apfs','listSnapshots','-plist',device)
    rows=[row for row in snapshots.get('Snapshots',[]) if row.get('SnapshotUUID')==snapshot['snapshot_uuid']]
    require(len(rows)==1 and rows[0].get('SnapshotName')==snapshot['snapshot_name'] and rows[0].get('RootTo') is True,
            'privileged input frozen RootTo snapshot differs')
    container=underlying.get('APFSContainerReference')
    require(isinstance(container,str) and re.fullmatch(r'disk[0-9]+',container),'source container absent')
    images=read_plist('/usr/bin/hdiutil','info','-plist').get('images',[])
    images=[row for row in images if row.get('image-path')==str(image)]
    require(len(images)==1 and images[0].get('writeable') is False,'source image not attached exactly once read-only')
    entities={row.get('dev-entry') for row in images[0].get('system-entities',[])}
    require('/dev/'+container in entities and device in entities,'snapshot System is not from the pinned image attachment')
    return dict(source_snapshot=snapshot,noowners='noowners' in options,device=device,container=container)


def codesign_hash(path):
    subprocess.run(['/usr/bin/codesign','--verify','--strict',str(path)],check=True,capture_output=True)
    process=subprocess.run(['/usr/bin/codesign','-d','--arch','x86_64','--verbose=4',str(path)],
                           check=True,capture_output=True,text=True)
    matches=re.findall(r'^CDHash=([0-9a-f]{40})$',process.stdout+process.stderr,re.M)
    require(len(matches)==1,'privileged export has no unique signed x86_64 CDHash')
    executable(Path(path).read_bytes(),'/usr/sbin/visudo')
    return matches[0]


def regular_pin(path):
    path=Path(path)
    require(path.is_absolute() and not path.is_symlink() and path.is_file()
            and stat.S_ISREG(path.lstat().st_mode),'privileged input is not an absolute regular file')
    return pin(path)


class PrivilegedInputs:
    def __init__(self,path,digest,system,build,*,observer=None,signature=None,image_pinner=None):
        self.system=Path(system).resolve(strict=True)
        self.observer=observer or observe_snapshot;self.signature=signature or codesign_hash
        self.image_pinner=image_pinner or regular_pin
        self.manifest_pin=regular_pin(path)
        require(self.manifest_pin['sha256']==digest,'privileged input manifest hash differs')
        raw=Path(path).read_bytes();value=json.loads(raw)
        require(regular_pin(path)==self.manifest_pin,'privileged input manifest changed')
        require(value.get('schema')==1 and value.get('kind')=='dyld-cache-privileged-input-export'
                and value.get('build')==build and value.get('result')=='PASS','unsupported privileged input export')
        self.value=value;self.snapshot=value['source_snapshot']
        require(set(self.snapshot)=={'volume_uuid','snapshot_uuid','snapshot_name','readonly'}
                and self.snapshot['readonly'] is True,'privileged export has no exact read-only snapshot identity')
        require(all(isinstance(self.snapshot[key],str) and self.snapshot[key] for key in ('volume_uuid','snapshot_uuid','snapshot_name')),
                'invalid privileged export snapshot identity')
        guest=value['guest'];require(type(guest.get('uid')) is int and type(guest.get('euid')) is int
                and guest['uid']==guest['euid']==0,'privileged export was not UID0')
        require(value.get('cleanup')==dict(mount_absent=True,device_absent=True),'privileged export cleanup not complete')
        observed=guest.get('source_snapshot_observation',{})
        underlying=observed.get('underlying',{})
        require(underlying.get('VolumeUUID')==self.snapshot['volume_uuid'],'UID0 source volume UUID differs')
        guest_device=underlying.get('DeviceNode')
        require(isinstance(guest_device,str) and re.fullmatch(r'/dev/disk[0-9]+s[0-9]+',guest_device),
                'UID0 source device absent')
        mounted=re.fullmatch(re.escape(self.snapshot['snapshot_name']+'@'+guest_device)+r' on (.+) \(([^)]*)\)',observed.get('mount_entry',''))
        require(mounted is not None and 'read-only' in {p.strip() for p in mounted[2].split(',')},
                'UID0 named snapshot mount is not read-only')
        snapshots=[row for row in observed.get('snapshots',{}).get('Snapshots',[])
                   if row.get('SnapshotUUID')==self.snapshot['snapshot_uuid']]
        require(len(snapshots)==1 and snapshots[0].get('SnapshotName')==self.snapshot['snapshot_name']
                and snapshots[0].get('RootTo') is True,'UID0 RootTo snapshot differs')

        self.input_pins=[self.manifest_pin]
        for key in ('vm_receipt','collector'):
            record=value[key];actual=regular_pin(record['path'])
            require(actual['sha256']==record['sha256'] and actual['size']==record.get('size',actual['size']),
                    'privileged export evidence pin differs: '+key)
            self.input_pins.append(actual)
        receipt=json.loads(Path(value['vm_receipt']['path']).read_text())
        for key in ('schema','kind','build','result','source_snapshot','guest','files','cleanup'):
            require(receipt.get(key)==value.get(key),'privileged export differs from pinned VM receipt: '+key)
        require(receipt.get('collector',{}).get('sha256')==value['collector']['sha256'],
                'privileged export collector differs from UID0 receipt')
        image=value['source_image'];self.image=Path(image['path'])
        require(all(receipt.get('source_image',{}).get(key)==image.get(key) for key in ('path','size','sha256')),
                'privileged image differs from VM receipt')
        actual=self.image_pinner(self.image)
        require(all(actual[key]==image[key] for key in ('path','size','sha256')),'privileged source image pin differs')
        self.input_pins.append(actual);self.image_stat=original_stat(self.image)
        self.observation=self.observer(self.system,self.image,self.snapshot)
        rows=value.get('files');require(isinstance(rows,list) and len(rows)==len(ALLOWED)
                and {row.get('logical_path') for row in rows}==ALLOWED,'privileged export path allowlist differs')
        self.files={}
        for row in rows:
            require(row.get('view')=='system' and row.get('export_file')=='visudo','unsafe privileged export location')
            components=row.get('components',[])
            require([entry.get('relative_path') for entry in components]==['usr','usr/sbin','usr/sbin/visudo'],
                    'privileged source component proof differs')
            require(all(type(entry.get('mode')) is int and type(entry.get('inode')) is int for entry in components)
                    and all(stat.S_ISDIR(entry['mode']) for entry in components[:-1])
                    and stat.S_ISREG(components[-1]['mode']),'privileged source component proof is not directory/file only')

            expected=row['original_stat']
            require(set(expected)==set(STAT_FIELDS) and all(type(expected[key]) is int for key in STAT_FIELDS)
                    and expected==row.get('after_stat'),'privileged source stat changed during export')
            require(stat.S_ISREG(expected['mode']) and expected['mode']&0o7777==0o111
                    and expected['uid']==expected['gid']==0,'privileged source metadata differs from exact factory executable')
            exported=Path(path).parent/row['export_file']
            actual=regular_pin(exported)
            require(exported.resolve().parent==Path(path).resolve().parent and actual['size']==row['size']==expected['size']
                    and actual['sha256']==row['sha256'],'privileged export byte pin differs')
            require(self.signature(exported)==row['cdhash'],'privileged export signed CDHash differs from VM source')
            self.input_pins.append(actual);self.files[row['logical_path']]=dict(row,export=actual)
            self.select(row['logical_path'],'system',self.system/row['logical_path'].lstrip('/'))
        self.factory_verified=False

    def verify_factory(self,original):
        for path,row in self.files.items():
            require(path in original and original[path]['check_cdhash'] is True
                    and original[path]['cdhash']==row['cdhash'],'privileged export CDHash differs from current factory program')
        self.factory_verified=True

    def select(self,logical,view,physical):
        if logical not in self.files:return None
        require(view=='system' and Path(physical)==self.system/logical.lstrip('/'),'privileged source view/path differs')
        require(original_stat(self.image)==self.image_stat,'privileged source image changed')
        require(self.observer(self.system,self.image,self.snapshot)==self.observation,'privileged source snapshot mount changed')
        current=self.system
        for part,component in zip(Path(logical).parts[1:],self.files[logical]['components']):
            current/=part;info=current.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_mode==component['mode'] and info.st_ino==component['inode'],
                    'privileged source component identity differs')
        actual=original_stat(current);expected=self.files[logical]['original_stat']
        keys=('mode','size','inode','mtime_ns','flags') if self.observation['noowners'] else STAT_FIELDS
        require(all(actual[key]==expected[key] for key in keys),'privileged source file identity changed')
        try:
            with current.open('rb') as stream:stream.read(1)
        except PermissionError as error:
            require(error.errno==errno.EACCES,'privileged source refusal is not EACCES')
        else:raise ValueError('privileged export cannot replace a readable source file')
        exported=self.files[logical]['export']
        verify_file(exported['path'],exported)
        return dict(view='privileged-export',path=exported['path'],original_view=view,
                    original_path=str(current),original_stat=actual,export_manifest=self.manifest_pin)

    def provenance(self):
        return dict(manifest=self.manifest_pin,source_image=self.value['source_image'],
                    source_snapshot=self.snapshot,host_observation=self.observation,
                    files=self.files,inputs=self.input_pins)

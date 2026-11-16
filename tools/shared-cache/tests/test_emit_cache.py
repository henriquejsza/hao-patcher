import hashlib
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild import codesign
from dyld_rebuild.emit_cache import emit_slide_chains, sign_with_uuid, write_image_lists
from dyld_rebuild.exports import Refusal

BASE = 0x7ff800000000


def chains():
    fields = [(0,BASE+0x1234),(16,0),(4088,BASE+0x4000),(8192,BASE+0x9000)]
    data = bytearray(b'\x77'*16384)
    mapping = dict(address=BASE+0x10000,size=12288,file_offset=0,
                   slide_info=dict(version=2,page_size=4096,page_count=3,size=46,
                                   page_starts=[0,0x4000,0],delta_mask=0x00ffff0000000000,
                                   value_add=BASE,file_offset=12288))
    fixups = dict(rebase_columns=['source_file_offset','file_offset','address','mapping_index','source_target','target'],
                  bind_columns=['source_file_offset','file_offset','address','mapping_index','binding_index'],
                  rebase_rows=[[offset,offset,mapping['address']+offset,0,target,target] for offset,target in fields],
                  bind_rows=[],bindings=[])
    provider = dict(pointer_fixups=fixups,placement=dict(mappings=[mapping],uniform_slide=0),
                    geometry=dict(slide_info_start=12288,signature=dict(offset=16384)))
    return data,provider,fields


class EmitterTests(unittest.TestCase):
    def test_new_chains_null_empty_page_last_slot_and_untouched_bytes(self):
        data,provider,fields = chains()
        before = bytes(data)
        self.assertEqual(emit_slide_chains(data,provider),4)
        # Independent kernel-equivalent bit operation, including a runtime slide.
        for offset,target in fields:
            raw = struct.unpack_from('<Q',data,offset)[0]
            value = raw & 0xff0000ffffffffff
            for slide in (0,4096,0x19800000):
                actual = (value+BASE+slide)&((1<<64)-1) if value else 0
                self.assertEqual(actual,target+slide if target else 0)
        changes = {i for offset,_ in fields for i in range(offset,offset+8)} | set(range(12288,12334))
        self.assertTrue(all(a==b or i in changes for i,(a,b) in enumerate(zip(before,data))))

    def test_refuse_mislocated_duplicated_and_unrepresentable_pointer(self):
        for mode in ('file_offset','duplicate','target','cross_page','starts'):
            data,p,_ = chains()
            if mode=='file_offset': p['pointer_fixups']['rebase_rows'][0][1] = 8
            if mode=='duplicate': p['pointer_fixups']['rebase_rows'].append(p['pointer_fixups']['rebase_rows'][0])
            if mode=='target': p['pointer_fixups']['rebase_rows'][0][4:] = [0xbad4007]*2
            if mode=='cross_page':
                p['pointer_fixups']['rebase_rows'][2][1:3] = [4092,BASE+0x10000+4092]
            if mode=='starts': p['placement']['mappings'][0]['slide_info']['page_starts'][1]=0
            with self.subTest(mode=mode),self.assertRaises(Refusal): emit_slide_chains(data,p)

    def test_image_lists_round_trip_and_capacity_refusal(self):
        rows = [dict(path='/a',address=BASE+4096,mtime=0,inode=0,uuid='11'*16,text_size=4096),
                dict(path='/long/path',address=BASE+8192,mtime=1,inode=2,uuid='22'*16,text_size=8192)]
        data = bytearray(8192)
        end = write_image_lists(data,rows,1024,1088,1152,len(data))
        self.assertEqual(end,1166)
        for i,row in enumerate(rows):
            address,mtime,inode,pathoff,pad=struct.unpack_from('<3Q2I',data,1024+32*i)
            uuid,textaddr,size,otherpath=struct.unpack_from('<16sQ2I',data,1088+32*i)
            self.assertEqual((address,textaddr,pathoff,pad),(row['address'],row['address'],otherpath,0))
            self.assertEqual(data[pathoff:data.index(0,pathoff)].decode(),row['path'])
        with self.assertRaisesRegex(Refusal,'exceed reserved prefix'):
            write_image_lists(data,rows,1024,1088,1152,1153)

    def test_content_derived_uuid_and_signature(self):
        data=bytearray(8192+16384)
        data[:16]=b'dyld_v1  x86_64\0'
        struct.pack_into('<I',data,16,552)
        struct.pack_into('<QQ',data,40,8192,16384)
        struct.pack_into('<Q',data,560,4096)
        first=codesign.emit(data,8192,'test',4096)
        length=struct.unpack_from('>I',first,40)[0]
        expected=bytearray(hashlib.sha256(first[36:36+length]).digest()[:16])
        expected[6]=(expected[6]&15)|0x30; expected[8]=(expected[8]&63)|0x80
        report=sign_with_uuid(data,'test',4096)
        self.assertEqual(data[88:104],expected)
        self.assertEqual(codesign.inspect(data)['cdhash'],report['cdhash'])
        with self.assertRaisesRegex(Refusal,'unset UUID'): sign_with_uuid(data,'test',4096)
        data[7000]^=1
        with self.assertRaisesRegex(Refusal,'page hash'): codesign.inspect(data)


if __name__=='__main__': unittest.main()


class SymbolSectionTests(unittest.TestCase):
    def test_preserve_valid_and_repair_unique_extracted_section(self):
        from dyld_rebuild.emit_cache import symbol_section
        rows=[dict(address=100,size=20),dict(address=200,size=20)]
        self.assertEqual(symbol_section(rows,1,110),1)
        self.assertEqual(symbol_section(rows,1,210),2)
        self.assertEqual(symbol_section(rows,1,120),1)
        for value in (0,150,230):
            with self.assertRaises(Refusal):symbol_section(rows,1,value)
        with self.assertRaises(Refusal):symbol_section(rows+[dict(address=205,size=10)],1,210)


class CompactPathTests(unittest.TestCase):
    def test_suffix_sharing_preserves_image_order_and_exact_paths(self):
        paths=['/System/A','/System/iOSSupport/System/A','/other/A']
        rows=[dict(path=p,address=BASE+4096*i,mtime=0,inode=0,uuid='11'*16,text_size=4096) for i,p in enumerate(paths)]
        data=bytearray(4096);end=write_image_lists(data,rows,1024,1120,1216,4096,compact_paths=True)
        offsets=[]
        for i,path in enumerate(paths):
            off=struct.unpack_from('<I',data,1024+32*i+24)[0];offsets.append(off)
            self.assertEqual(bytes(data[off:data.index(0,off)]).decode(),path)
        self.assertEqual(offsets[0],offsets[1]+len('/System/iOSSupport'))
        self.assertEqual(end-1216,sum(len(p)+1 for p in paths)-(len(paths[0])+1))
        with self.assertRaises(Refusal):write_image_lists(bytearray(4096),rows,1024,1120,1216,1220,compact_paths=True)


class CachedCommandTests(unittest.TestCase):
    def test_bundle_type_is_preserved_and_unknown_type_refused(self):
        from dyld_rebuild.cache import commands
        from types import SimpleNamespace
        for kind in (6,7,8,2):
            data=struct.pack('<8I',0xfeedfacf,0x1000007,3,kind,0,0,0,0)
            family=SimpleNamespace(read=lambda address,size:data[address:address+size])
            if kind==2:
                with self.assertRaisesRegex(Refusal,'unexpected cached Mach-O'):commands(family,0)
            else:self.assertEqual(commands(family,0),[])

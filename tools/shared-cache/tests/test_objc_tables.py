import struct
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.objc_tables import (NameEntry,read_table,writer_fixture,rewrite_objects,
                                     decode_header_info,emit_header_info,relative_list_index_edits,template_class_objects,optimization_roots,checked_loader_addresses)


class ObjCTables(unittest.TestCase):
    base=0x100000000
    address=0x100001000

    def fixture(self,kind='class'):
        cap=4;mask=3;prefix=1056+4+20
        b=bytearray(prefix)
        struct.pack_into('<5I',b,0,0,cap,2,62,mask)
        for bucket,offset,name in ((0,-100,b'Alpha'),(2,200,b'Beta')):
            b[1060+bucket]=((name[0]&7)<<5)|(len(name)&31)
            struct.pack_into('<i',b,1064+bucket*4,offset)
        if kind!='selector':
            b+=struct.pack('<4QI2Q',(3<<48)|(0x800<<1),0,(2<<48)|1,0,2,
                           (4<<48)|(0x900<<1),(7<<48)|(0xa00<<1))
        strings={self.address-100:b'Alpha',self.address+200:b'Beta'}
        def read(a,n):
            self.assertGreaterEqual(a,self.address)
            if a+n>self.address+len(b):raise Refusal('truncated')
            return bytes(b[a-self.address:a-self.address+n])
        return b,strings,read

    def test_full_object_decode_and_fixture_order(self):
        b,names,read=self.fixture();t=read_table(read,names.__getitem__,self.address,'class',self.base)
        self.assertEqual(t.object_order,(b'Beta',b'Alpha'))
        self.assertEqual(t.entries[1].objects,((self.base+0x900,4),(self.base+0xa00,7)))
        output=writer_fixture(t.entries,'class',self.base,self.address,len(b),t.object_order)
        self.assertEqual(output[:4],b'OTW1')
        self.assertEqual(struct.unpack_from('<II',output,8),(2,3))
        # The source format permits repeated protocol object/owner pairs.
        entries=(NameEntry(b'P',self.address+200,((self.base+32,1),)*2),)
        writer_fixture(entries,'protocol',self.base,self.address,2048)

    def test_table_corruption_refused(self):
        mutations=[(0,'<I',1),(8,'<I',3),(12,'<I',63),(16,'<I',2),
                   (1064+4,'<i',-100),(1080+16,'<Q',(3<<48)|1),
                   (1080+16,'<Q',(2<<48)|3),(1080+32+4,'<Q',3)]
        for offset,fmt,value in mutations:
            with self.subTest(offset=offset,value=value):
                b,names,read=self.fixture();struct.pack_into(fmt,b,offset,value)
                with self.assertRaises((Refusal,KeyError)):read_table(read,names.__getitem__,self.address,'class',self.base)
        b,names,read=self.fixture();b[1060]^=1
        with self.assertRaises(Refusal):read_table(read,names.__getitem__,self.address,'class',self.base)
        b,names,read=self.fixture();del b[-1]
        with self.assertRaises(Refusal):read_table(read,names.__getitem__,self.address,'class',self.base)

    def test_relative_ranges_and_explicit_inputs(self):
        valid=NameEntry(b'X\xff',self.address-(1<<31),((self.base+1,65535),))
        writer_fixture((valid,),'class',self.base,self.address,2048)
        for entry in (NameEntry(b'A',self.address+(1<<31),valid.objects),
                      NameEntry(b'A',self.address,valid.objects),
                      NameEntry(b'A\0B',self.address+200,valid.objects),
                      NameEntry(b'A',self.address+200,((self.base+(1<<47),1),)),
                      NameEntry(b'A',self.address+200,((self.base+1,65536),))):
            with self.assertRaises(Refusal):writer_fixture((entry,),'class',self.base,self.address,2048)
        with self.assertRaises(Refusal):writer_fixture((valid,valid),'class',self.base,self.address,2048)
        with self.assertRaises(Refusal):writer_fixture((valid,),'selector',self.base,self.address,2048)
        with self.assertRaises(Refusal):writer_fixture((valid,),'class',self.base,self.address,2048,())

    def test_membership_replacement_preserves_lookup_order(self):
        b,names,read=self.fixture();t=read_table(read,names.__getitem__,self.address,'class',self.base)
        original=[f'/{i}' for i in range(8)];final=list(reversed(original))+['/new']
        additions=[(b'Beta',self.address+200,self.base+0xb00,'/new')]
        rows,order=rewrite_objects(t,original,final,{'/4'},additions)
        byname={r.name:r for r in rows}
        self.assertEqual(byname[b'Beta'].objects,((self.base+0xa00,0),(self.base+0xb00,8)))
        self.assertEqual(order,(b'Beta',b'Alpha'))
        with self.assertRaises(Refusal):rewrite_objects(t,original,final,{'/4'},[(b'Beta',self.address+201,self.base+0xb00,'/new')])
        with self.assertRaises(Refusal):rewrite_objects(t,original,final,{'/4'},[(b'Beta',self.address+200,self.base+0xb00,'/absent')])

    def test_header_info_roundtrip_and_missing_loader_refusal(self):
        rows=((self.base+0x1000,struct.pack('<II',0,8),self.base+0x9000),
              (self.base+0x3000,struct.pack('<II',0,9),self.base+0xa000))
        ro,rw,info=self.base+0x5000,self.base+0x6000,self.base+0x7000
        result=emit_header_info(rows,ro,rw,info)
        blobs=((ro,result['ro']),(rw,result['rw']),(info,result['imageinfo']))
        def read(a,n):
            for start,data in blobs:
                if start<=a and a+n<=start+len(data):return data[a-start:a-start+n]
            raise Refusal('unmapped')
        self.assertEqual(decode_header_info(read,ro,rw),((rows[0][0],info,rows[0][2]),(rows[1][0],info+8,rows[1][2])))
        for invalid in ((rows[1],rows[0]),((rows[0][0],rows[0][1],0),),
                        ((rows[0][0],struct.pack('<II',0,0),rows[0][2]),)):
            with self.assertRaises(Refusal):emit_header_info(invalid,ro,rw,info)
        with self.assertRaises(Refusal):emit_header_info(rows,ro+1,rw,info)

    def test_legacy_and_global_roots_preserve_flags_and_selector_extent(self):
        legacy=self.base+0x1000
        original=[2,6,0x3000,0x4000,0x5000,0x6000,0x7000,0x8000,999,0]
        old=[16,6,0x4000,0x2000,0,0,0x3000,0,0x5000,0x6000,0x7000]
        a=struct.pack('<II8Q',*original);b=struct.pack('<II8iq',*old)
        targets={k:self.base+0x9000+0x1000*i for i,k in enumerate(('ro','rw','selector','class','protocol'))}
        out,newlegacy=optimization_roots(a,b,self.base,legacy,targets)
        values=struct.unpack('<II8Q',out)
        self.assertEqual(values[:2],(2,6));self.assertEqual(values[7:],tuple(original[7:]))
        self.assertEqual(struct.unpack('<II8iq',newlegacy)[10],old[10])
        bad=dict(targets);bad['class']=legacy+(1<<31)
        with self.assertRaises(Refusal):optimization_roots(a,b,self.base,legacy,bad)
        mutated=bytearray(b);struct.pack_into('<i',mutated,8,123)
        with self.assertRaises(Refusal):optimization_roots(a,mutated,self.base,legacy,targets)

    def test_bootstrap_headers_require_explicit_mode_and_zero_pbl_fields(self):
        ro,rw,info=self.base+0x5000,self.base+0x6000,self.base+0x7000
        rows=((self.base+0x1000,struct.pack('<II',0,8),0),)
        result=emit_header_info(rows,ro,rw,info,bootstrap_only=True)
        blobs=((ro,result['ro']),(rw,result['rw']),(info,result['imageinfo']))
        def read(a,n):
            for start,data in blobs:
                if start<=a and a+n<=start+len(data):return data[a-start:a-start+n]
            raise Refusal('unmapped')
        self.assertEqual(result['ro'][24:32],b'\0'*8)
        self.assertEqual(decode_header_info(read,ro,rw,bootstrap_only=True),((rows[0][0],info,0),))
        with self.assertRaises(Refusal):decode_header_info(read,ro,rw)
        with self.assertRaises(Refusal):emit_header_info(rows,ro,rw,info)
        with self.assertRaises(Refusal):emit_header_info(((rows[0][0],rows[0][1],self.base+0x9000),),ro,rw,info,bootstrap_only=True)
        with self.assertRaises(Refusal):emit_header_info(((rows[0][0],rows[0][1],ro+24),),ro,rw,info)

    def test_loader_addresses_bound_to_actual_blob_and_order(self):
        import copy
        rows=[dict(index=0,path='/a',offset=100),dict(index=1,path='/b',offset=200)]
        document=dict(base=self.base,alignment=8,size=300,sha256='digest',loaders=[dict(r,address=self.base+r['offset']) for r in rows])
        expected={'/a':self.base+100,'/b':self.base+200}
        self.assertEqual(checked_loader_addresses(document,rows,self.base,300,'digest'),expected)
        self.assertEqual(checked_loader_addresses(expected,rows,self.base,300,'digest'),expected)
        for field,value in [('base',self.base+8),('size',301),('sha256','other'),('alignment',4)]:
            bad=copy.deepcopy(document);bad[field]=value
            with self.assertRaises(Refusal):checked_loader_addresses(bad,rows,self.base,300,'digest')
        for field,value in [('path','/a'),('index',0),('offset',201),('address',self.base+201)]:
            bad=copy.deepcopy(document);bad['loaders'][1][field]=value
            with self.assertRaises(Refusal):checked_loader_addresses(bad,rows,self.base,300,'digest')
        with self.assertRaises(Refusal):checked_loader_addresses({'/a':self.base+100},rows,self.base,300,'digest')

    def test_conditional_list_owner_remap_preserves_signed_target(self):
        base=0x100000;data=bytearray(0x2000)
        struct.pack_into('<6I',data,0,0xfeedfacf,0x1000007,3,6,1,152)
        struct.pack_into('<II',data,32,0x19,152)
        struct.pack_into('<I',data,32+64,1)
        at=32+72;data[at:at+16]=b'__objc_classlist';data[at+16:at+32]=b'__DATA'+b'\0'*10
        struct.pack_into('<QQ',data,at+32,base+0x500,8)
        for offset,value in [(0x500,base+0x600),(0x600,base+0x640),(0x620,base+0x700),
                             (0x660,base+0x780),(0x720,base+0x901),(0x7a0,base+0x901)]:
            struct.pack_into('<Q',data,offset,value)
        struct.pack_into('<II',data,0x900,8,2)
        for field,index,target in [(0x908,1,0x880),(0x910,2,0xa00)]:
            struct.pack_into('<Q',data,field,(((target-field)&((1<<48)-1))<<16)|index)
        class Family:
            images=[('/image',base)]
            def read(self,a,n):
                if not base<=a<=a+n<=base+len(data):raise Refusal('range')
                return bytes(data[a-base:a-base+n])
        family=Family();pointer=lambda a:struct.unpack('<Q',family.read(a,8))[0]
        result=relative_list_index_edits(family,pointer,{1:5,2:0})
        self.assertEqual((result['class_and_metaclass_objects'],result['lists'],result['entries']),(2,1,2))
        for e in result['edits']:
            before=int.from_bytes(bytes.fromhex(e['expected']),'little')
            after=int.from_bytes(bytes.fromhex(e['replacement']),'little')
            self.assertEqual(before>>16,after>>16)
        with self.assertRaises(Refusal):relative_list_index_edits(family,pointer,{1:5})
        struct.pack_into('<I',data,0x900,16)
        with self.assertRaises(Refusal):relative_list_index_edits(family,pointer,{1:5,2:0})

    def test_swift_template_lists_outside_classlists_are_remapped(self):
        # Image with an empty classlist; a Swift class template at 0x400 (data -> RO 0x700)
        # whose baseMethods (+32) is a tagged list-list at 0x900. A decoy tagged pointer
        # to a list-list-shaped blob (0xa80) has no class RO around it.
        base=0x100000;data=bytearray(0x2000)
        struct.pack_into('<6I',data,0,0xfeedfacf,0x1000007,3,6,1,152)
        struct.pack_into('<II',data,32,0x19,152)
        struct.pack_into('<I',data,32+64,1)
        at=32+72;data[at:at+16]=b'__objc_classlist';data[at+16:at+32]=b'__DATA'+b'\0'*10
        struct.pack_into('<QQ',data,at+32,base+0x500,0)
        data[0xc00:0xc1b]=b'_TtC4Demo14TemplateClient\0'
        slots={0x420:base+0x700,0x718:base+0xc00,0x720:base+0x901,0xb20:base+0xa81}
        for offset,value in slots.items():struct.pack_into('<Q',data,offset,value)
        struct.pack_into('<II',data,0x900,8,1);struct.pack_into('<II',data,0xa80,8,1)
        for field,index,target in [(0x908,1,0x880),(0xa88,1,0x880)]:
            struct.pack_into('<Q',data,field,(((target-field)&((1<<48)-1))<<16)|index)
        class Family:
            images=[('/image',base)]
            def read(self,a,n):
                if not base<=a<=a+n<=base+len(data):raise Refusal('range')
                return bytes(data[a-base:a-base+n])
        class Mapping:address=base;size=len(data)
        class Slide:
            starts=(0,)
            def page(self,index):return {o:struct.unpack_from('<Q',data,o)[0] for o in slots}
            def decode(self,raw):return raw
            def pointer(self,offset):
                if offset not in slots:raise Refusal('not a slide pointer')
                return {'target':struct.unpack_from('<Q',data,offset)[0]}
        family=Family();pointer=lambda a:struct.unpack('<Q',family.read(a,8))[0]
        slides=[(None,Mapping,Slide())]
        templates=template_class_objects(family,slides)
        self.assertEqual(templates,{base+0x400:base+0x700})
        # The classlist-only route (previous behaviour) never sees the template's list.
        self.assertEqual(relative_list_index_edits(family,pointer,{1:7})['lists'],0)
        result=relative_list_index_edits(family,pointer,{1:7},templates)
        self.assertEqual((result['template_objects'],result['lists'],result['entries'],result['changed_entries']),(1,1,1,1))
        edit=result['edits'][0];self.assertEqual(edit['address'],base+0x908)
        after=int.from_bytes(bytes.fromhex(edit['replacement']),'little')
        self.assertEqual((after&0xffff,after>>16),(7,struct.unpack_from('<Q',data,0x908)[0]>>16))
        # Without an identifier name at RO+24 the candidate is refused, not guessed.
        data[0xc00]=0
        self.assertEqual(template_class_objects(family,slides),{})

if __name__=='__main__':unittest.main()

import hashlib,struct,unittest
from dyld_rebuild.graphics_identity import normalize_graphics,inspect_graphics
from dyld_rebuild.exports import Refusal

def fixture(kind=6):
    def namecmd(cmd,s):
        name=s.encode()+b'\0';n=(24+len(name)+7)&~7;return struct.pack('<6I',cmd,n,24,0,1,1)+name+bytes(n-24-len(name))
    segment=struct.pack('<II16s4Q4I',0x19,152,b'__TEXT',0,4096,0,4096,7,5,1,0)
    section=struct.pack('<16s16sQQ8I',b'__text',b'__TEXT',1024,64,1024,0,0,0,0,0,0,0)
    cmds=segment+section+namecmd(0xd,'Wrapped/old.dylib')+namecmd(0xc,'System/helper.dylib')+struct.pack('<4I',0x1d,16,4000,32)
    return struct.pack('<8I',0xfeedfacf,0x1000007,3,kind,4,len(cmds),0,0)+cmds+bytes(1024-32-len(cmds))+b'X'*64+bytes(4000-1088)+b'S'*32+bytes(64)
class Tests(unittest.TestCase):
    def test_grow_shrink_and_payload_scope(self):
        a=fixture();b,r=normalize_graphics(a,hashlib.sha256(a).hexdigest(),'Wrapped/old.dylib','/System/Library/very-long-name.dylib',{'System/helper.dylib':'/System/helper.dylib'});self.assertEqual(a[1024:],b[1024:]);self.assertTrue(r['payload_unchanged']);self.assertEqual(inspect_graphics(b)['identity']['name'],'/System/Library/very-long-name.dylib')
    def test_source_hash_refuses(self):
        with self.assertRaises(Refusal):normalize_graphics(fixture(),'0'*64,'Wrapped/old.dylib','/x')
    def test_bundle_refuses(self):
        a=fixture(8)
        with self.assertRaises(Refusal):normalize_graphics(a,hashlib.sha256(a).hexdigest(),'Wrapped/old.dylib','/x')
    def test_missing_dependency_refuses(self):
        a=fixture()
        with self.assertRaises(Refusal):normalize_graphics(a,hashlib.sha256(a).hexdigest(),'Wrapped/old.dylib','/x',{'missing':'/x'})
    def test_nonzero_padding_refuses(self):
        a=bytearray(fixture());a[900]=1
        self.assertEqual(inspect_graphics(a)['padding_end'],900)
        b,_=normalize_graphics(a,hashlib.sha256(a).hexdigest(),'Wrapped/old.dylib','/x')
        self.assertEqual(b[900:],a[900:])
        with self.assertRaises(Refusal):normalize_graphics(a,hashlib.sha256(a).hexdigest(),'Wrapped/old.dylib','/'+('x'*700))
    def test_insufficient_padding_refuses(self):
        a=fixture()
        with self.assertRaises(Refusal):normalize_graphics(a,hashlib.sha256(a).hexdigest(),'Wrapped/old.dylib','/'+('x'*2000))

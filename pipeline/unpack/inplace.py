#!/usr/bin/env python3
"""inplace.py: read a macOS InstallAssistant.pkg in place, from disk or by URL, and extract only selected items.

The flat package stores SharedSupport.dmg uncompressed, and that image's volume uses raw
UDIF chunks, so every byte of the asset zip inside it sits at a computable offset of the
.pkg. This reads the zip directly from the .pkg: no SharedSupport.dmg copy, no attach, and over
HTTP(S) only the byte ranges it needs (ranged.py).

  inplace.py members PKG                         list the asset zip's members
  inplace.py cat PKG MEMBER [OUT]                copy one member (stdout or OUT)
  inplace.py payload PKG INCLUDE_LIST OUT.aa     decode the payload chunks and keep only
                                                 entries under INCLUDE_LIST (aa convert)
  inplace.py pbzx PKG MEMBER OUT                 decode one pbzx member to a file
  inplace.py verify PKG                          check SharedSupport.dmg against the TOC SHA-1 (whole local file)
  inplace.py signature PKG                       Apple's signature over the package TOC (its RSA signature and
                                                 certificate chain to Apple Root CA; a few KB read)
  inplace.py pins PKG MEMBER...                  {"toc_sha256", "members": {MEMBER: {size, sha256}}} of a local copy

PKG is a path or an http(s) URL. --pins FILE (any command) checks every member read against the release's pins and
the TOC against its toc_sha256, and refuses an unpinned member; a URL is read only with --pins.
"""
import hashlib, io, lzma, os, plistlib, re, struct, subprocess, sys, tempfile, zipfile, zlib
import xml.etree.ElementTree as ET
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ranged  # noqa: E402

ASSET_DIR = 'com_apple_MobileAsset_MacSoftwareUpdate'
SECTOR = 512


def source(pkg):
    return pkg if isinstance(pkg, ranged.Source) else ranged.open_source(pkg)


def xar_toc(src, toc_sha256=None):
    """(TOC element, heap start, compressed TOC bytes). The TOC's own SHA-1 (first bytes of the heap) must match it,
    and with TOC_SHA256 (a release pin) the compressed TOC must hash to that."""
    head = src.read_at(0, 28)
    magic, hsize, _, tcomp, _, _ = struct.unpack('>IHHQQI', head)
    if magic != 0x78617221:
        raise ranged.PinError('not a xar package')
    comp = src.read_at(hsize, tcomp)
    if toc_sha256 is not None and hashlib.sha256(comp).hexdigest() != toc_sha256:
        raise ranged.PinError('package TOC: sha256 %s; pinned %s' % (hashlib.sha256(comp).hexdigest(), toc_sha256))
    toc = ET.fromstring(zlib.decompress(comp)).find('toc')
    ck = toc.find('checksum')
    if ck is None or ck.get('style') != 'sha1':
        raise ranged.PinError('package TOC has no SHA-1 checksum')
    stored = src.read_at(hsize + tcomp + int(ck.findtext('offset')), int(ck.findtext('size')))
    if hashlib.sha1(comp).digest() != stored:
        raise ranged.PinError('package TOC does not match its checksum')
    return toc, hsize + tcomp, comp


def xar_member(pkg, name='SharedSupport.dmg', toc_sha256=None):
    src = source(pkg)
    toc, heap, _ = xar_toc(src, toc_sha256)
    for f in toc.iter('file'):
        if f.findtext('name') != name or f.find('data') is None:
            continue
        data = f.find('data')
        enc = data.find('encoding').get('style')
        if enc != 'application/octet-stream':
            raise SystemExit('%s is stored with %s; in-place reading needs it uncompressed' % (name, enc))
        ext = data.find('extracted-checksum')
        return dict(start=heap + int(data.findtext('offset')), length=int(data.findtext('length')),
                    checksum=(ext.get('style'), ext.text.strip()) if ext is not None else None)
    raise SystemExit('%s not found in the package' % name)


def check_signature(pkg, toc_sha256=None):
    """Apple's signature of the package: the RSA signature in the heap over the TOC's SHA-1, by the first certificate
    of the TOC, whose chain (the TOC's other certificates) must end at an Apple Root CA of this Mac's system roots
    (openssl verify). This is what pkgutil checks first; pkgutil itself also hashes every member whole, which a
    ranged read cannot, so the members read are checked against the release's pins instead. Returns the signer's
    subject; raises PinError otherwise."""
    import base64, textwrap
    src = source(pkg)
    toc, heap, comp = xar_toc(src, toc_sha256)
    sig = toc.find('signature')
    if sig is None or sig.get('style') != 'RSA':
        raise ranged.PinError('the package carries no RSA signature')
    certs = [c.text.replace('\n', '').strip() for c in sig.iter('{http://www.w3.org/2000/09/xmldsig#}X509Certificate')]
    if len(certs) < 2:
        raise ranged.PinError('the package signature has no certificate chain')

    def run(*cmd):
        return subprocess.run(list(cmd), capture_output=True, text=True, cwd=d)
    with tempfile.TemporaryDirectory(prefix='pkgsig-') as d:
        for i, c in enumerate(certs):
            base64.b64decode(c, validate=True)
            with open(os.path.join(d, 'cert%d.pem' % i), 'w') as f:
                f.write('-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' % '\n'.join(textwrap.wrap(c, 64)))
        with open(os.path.join(d, 'chain.pem'), 'w') as f:
            f.write(''.join(open(os.path.join(d, 'cert%d.pem' % i)).read() for i in range(1, len(certs))))
        with open(os.path.join(d, 'sig.bin'), 'wb') as f:
            f.write(src.read_at(heap + int(sig.findtext('offset')), int(sig.findtext('size'))))
        with open(os.path.join(d, 'digest.bin'), 'wb') as f:
            f.write(hashlib.sha1(comp).digest())
        roots = run('/usr/bin/security', 'find-certificate', '-a', '-c', 'Apple Root CA', '-p',
                    '/System/Library/Keychains/SystemRootCertificates.keychain')
        with open(os.path.join(d, 'roots.pem'), 'w') as f:
            f.write(roots.stdout)
        chain = run('/usr/bin/openssl', 'verify', '-CAfile', 'roots.pem', '-untrusted', 'chain.pem', 'cert0.pem')
        if chain.returncode or chain.stdout.strip() != 'cert0.pem: OK':
            raise ranged.PinError('the package signer does not chain to Apple Root CA: %s' % ' '.join(
                (chain.stdout + chain.stderr).split())[:300])
        subject = run('/usr/bin/openssl', 'x509', '-in', 'cert0.pem', '-noout', '-subject').stdout.strip()
        if '/O=Apple Inc.' not in subject:
            raise ranged.PinError('the package is signed by %s, not Apple' % subject)
        with open(os.path.join(d, 'pub.pem'), 'w') as f:
            f.write(run('/usr/bin/openssl', 'x509', '-in', 'cert0.pem', '-pubkey', '-noout').stdout)
        v = run('/usr/bin/openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', 'pub.pem', '-sigfile', 'sig.bin',
                '-in', 'digest.bin', '-pkeyopt', 'digest:sha1')
        if v.returncode or 'Signature Verified Successfully' not in v.stdout:
            raise ranged.PinError('the package signature does not match its TOC')
    return subject


class Partition:
    """The Apple_HFS partition of a raw-chunk UDIF image embedded at `start` in `path`."""
    def __init__(self, src, start, length):
        self.src = src; koly = src.read_at(start + length - 512, 512)
        if koly[:4] != b'koly':
            raise SystemExit('no UDIF trailer')
        data_fork = struct.unpack('>Q', koly[0x18:0x20])[0]
        xml_off, xml_len = struct.unpack('>QQ', koly[0xD8:0xE8])
        plist = plistlib.loads(src.read_at(start + xml_off, xml_len))
        parts = [b for b in plist['resource-fork']['blkx'] if 'Apple_HFS' in b.get('Name', '')]
        if len(parts) != 1:
            raise SystemExit('expected one Apple_HFS partition, found %d' % len(parts))
        mish = parts[0]['Data']; data_off = struct.unpack('>Q', mish[24:32])[0]
        count = struct.unpack('>I', mish[200:204])[0]
        self.runs = []
        for i in range(count):
            typ, _, sec, nsec, coff, clen = struct.unpack('>IIQQQQ', mish[204 + 40 * i:244 + 40 * i])
            if typ == 0xFFFFFFFF:
                break
            if typ in (0x7FFFFFFE,):
                continue  # comment
            if typ not in (0, 1, 2):
                raise SystemExit('chunk type %#x is compressed; in-place reading needs raw chunks' % typ)
            self.runs.append((sec * SECTOR, nsec * SECTOR, typ, start + data_fork + data_off + coff))
        self.size = sum(r[1] for r in self.runs)

    def read(self, off, n):
        out = bytearray()
        for base, ln, typ, foff in self.runs:
            if n <= 0:
                break
            if off >= base + ln or off + n <= base:
                continue
            a = max(off, base); b = min(off + n, base + ln)
            if typ == 1:
                out += self.src.read_at(foff + (a - base), b - a)
            else:
                out += bytes(b - a)
        return bytes(out)


class HFS:
    def __init__(self, part):
        self.p = part; vh = part.read(1024, 512)
        if vh[:2] not in (b'H+', b'HX'):
            raise SystemExit('not an HFS+ volume')
        self.bs = struct.unpack('>I', vh[0x28:0x2C])[0]
        self.extents_fork = self.fork(vh[0xC0:0x110]); self.catalog_fork = self.fork(vh[0x110:0x160])

    @staticmethod
    def fork(b):
        size, _, blocks = struct.unpack('>QII', b[:16])
        ext = [struct.unpack('>II', b[16 + 8 * i:24 + 8 * i]) for i in range(8)]
        return dict(size=size, blocks=blocks, extents=[e for e in ext if e[1]])

    def fork_read(self, extents, off, n):
        out = bytearray(); pos = 0
        for start, count in extents:
            ln = count * self.bs
            if off < pos + ln and off + n > pos:
                a = max(off, pos); b = min(off + n, pos + ln)
                out += self.p.read(start * self.bs + (a - pos), b - a)
            pos += ln
        return bytes(out)

    def leaves(self, fork):
        ext = fork['extents']; head = self.fork_read(ext, 0, 512)
        node_size = struct.unpack('>H', head[32:34])[0]; leaf = struct.unpack('>I', head[24:28])[0]
        while leaf:
            node = self.fork_read(ext, leaf * node_size, node_size)
            flink, _, kind, _, nrec = struct.unpack('>IIbBH', node[:12])
            offs = [struct.unpack('>H', node[node_size - 2 * (i + 1):node_size - 2 * i])[0] for i in range(nrec)]
            for o in offs:
                yield node, o
            leaf = flink

    def catalog(self):
        for node, o in self.leaves(self.catalog_fork):
            klen, parent, nlen = struct.unpack('>HIH', node[o:o + 8])
            name = node[o + 8:o + 8 + 2 * nlen].decode('utf-16-be')
            rec = node[o + 2 + klen:]
            yield parent, name, struct.unpack('>h', rec[:2])[0], rec

    def find_file(self, folder, suffix):
        folder_id = None; files = []
        for parent, name, typ, rec in self.catalog():
            if typ == 1 and parent == 2 and name == folder:
                folder_id = struct.unpack('>I', rec[8:12])[0]
            elif typ == 2:
                files.append((parent, name, rec))
        hits = [(n, r) for p, n, r in files if p == folder_id and n.endswith(suffix)]
        if len(hits) != 1:
            raise SystemExit('expected one %s/*%s, found %d' % (folder, suffix, len(hits)))
        name, rec = hits[0]; file_id = struct.unpack('>I', rec[8:12])[0]; fork = self.fork(rec[88:168])
        have = sum(c for _, c in fork['extents'])
        if have < fork['blocks']:
            more = []
            for node, o in self.leaves(self.extents_fork):
                _, ftype, _, fid, sb = struct.unpack('>HBBII', node[o:o + 12])
                if fid == file_id and ftype == 0:
                    more.append((sb, [struct.unpack('>II', node[o + 12 + 8 * i:o + 20 + 8 * i]) for i in range(8)]))
            for _, ext in sorted(more):
                fork['extents'] += [e for e in ext if e[1]]
        if sum(c for _, c in fork['extents']) < fork['blocks']:
            raise SystemExit('incomplete extents for ' + name)
        return name, fork


class ForkFile(io.RawIOBase):
    def __init__(self, hfs, fork):
        self.h, self.fork, self.pos = hfs, fork, 0

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else self.fork['size'] + off
        return self.pos

    def readinto(self, b):
        n = min(len(b), max(0, self.fork['size'] - self.pos))
        data = self.h.fork_read(self.fork['extents'], self.pos, n); b[:len(data)] = data; self.pos += len(data)
        return len(data)


def open_zip(pkg, toc_sha256=None):
    src = source(pkg)
    m = xar_member(src, toc_sha256=toc_sha256); hfs = HFS(Partition(src, m['start'], m['length']))
    name, fork = hfs.find_file(ASSET_DIR, '.zip')
    return name, zipfile.ZipFile(io.BufferedReader(ForkFile(hfs, fork), 1 << 20))


def load_pins(path):
    """(Pins over the asset zip's members, the TOC pin) from a pins file, or unchecked for None."""
    if not path:
        return ranged.Pins(None, 'installer member'), None
    import json
    doc = json.load(open(path))
    return ranged.Pins(doc['members'], 'installer member'), doc['toc_sha256']


def pbzx_bytes(stream):
    if stream.read(4) != b'pbzx':
        raise SystemExit('not pbzx')
    stream.read(8); out = []
    while True:
        hdr = stream.read(16)
        if not hdr:
            break
        usize, csize = struct.unpack('>QQ', hdr); data = stream.read(csize)
        out.append(data if csize == usize else lzma.decompress(data, format=lzma.FORMAT_XZ))
    return b''.join(out)


_ZIP = {}


def _decode_member(args):
    pkg, member, pins_path = args
    if pkg not in _ZIP:                    # one zip per worker process: the TOC, UDIF and HFS are read once
        pins, toc = load_pins(pins_path)
        _ZIP[pkg] = (open_zip(pkg, toc)[1], pins)
    z, pins = _ZIP[pkg]
    with pins.open(z, member) as s:
        return pbzx_bytes(s)


def payload_members(z):
    return sorted(n for n in z.namelist() if re.fullmatch(r'AssetData/payloadv2/payload\.\d{3}', n))


def decode_window():
    """Chunks decoded at once: each holds a decoded chunk (up to about 1.5 GB) in memory, so about one per 3 GB of
    this Mac's memory, 2 to 10 (10 on a 32 GB Mac measured a 17.6 GB peak)."""
    try:
        mem = int(subprocess.run(['/usr/sbin/sysctl', '-n', 'hw.memsize'], capture_output=True, text=True).stdout)
    except ValueError:
        return 2
    return max(2, min(10, mem // (3 << 30)))


def payload(pkg, include_list, out_aa, pins_path=None, window=None):
    window = window or decode_window()
    _, z = open_zip(pkg, load_pins(pins_path)[1])
    members = payload_members(z)
    conv = subprocess.Popen(['/usr/bin/aa', 'convert', '-a', 'raw', '-include-path-list', include_list,
                             '-o', out_aa], stdin=subprocess.PIPE)
    with ProcessPoolExecutor(max_workers=window) as ex:
        futures = [ex.submit(_decode_member, (pkg, m, pins_path)) for m in members[:window]]
        nxt = window
        for i in range(len(members)):
            conv.stdin.write(futures[i].result()); futures[i] = None
            if nxt < len(members):
                futures.append(ex.submit(_decode_member, (pkg, members[nxt], pins_path))); nxt += 1
            print('payload chunk %d/%d' % (i + 1, len(members)), file=sys.stderr, flush=True)
    conv.stdin.close()
    if conv.wait():
        raise SystemExit('aa convert failed')


def main():
    argv = sys.argv[1:]
    pins_path = None
    if '--pins' in argv:
        i = argv.index('--pins'); pins_path = argv[i + 1]; del argv[i:i + 2]
    cmd, pkg = argv[0], argv[1]
    if pkg.startswith(('http://', 'https://')) and not pins_path:
        raise SystemExit('inplace.py: a URL is read only with --pins')
    pins, toc_pin = load_pins(pins_path)
    if cmd == 'verify':
        m = xar_member(pkg, toc_sha256=toc_pin); algo, want = m['checksum']; h = hashlib.new(algo.replace('-', ''))
        with open(pkg, 'rb') as f:
            f.seek(m['start']); left = m['length']
            while left:
                b = f.read(min(left, 64 << 20)); h.update(b); left -= len(b)
        print('SharedSupport.dmg', algo, h.hexdigest(), 'OK' if h.hexdigest() == want else 'MISMATCH (TOC %s)' % want)
        sys.exit(0 if h.hexdigest() == want else 1)
    if cmd == 'signature':
        print(check_signature(pkg, toc_pin))
        return
    if cmd == 'payload':
        payload(pkg, argv[2], argv[3], pins_path)
        return
    name, z = open_zip(pkg, toc_pin)
    if cmd == 'members':
        print('#', name)
        for i in z.infolist():
            print('%d\t%d\t%s' % (i.file_size, i.compress_type, i.filename))
    elif cmd == 'pins':
        import json
        src = source(pkg); toc_sha = hashlib.sha256(xar_toc(src)[2]).hexdigest()
        members = argv[2:] or [n for n in z.namelist() if not n.endswith('/')]
        print(json.dumps(dict(toc_sha256=toc_sha, members=ranged.pins_for(z, members, 'installer member')),
                         indent=1, sort_keys=True))
    elif cmd == 'cat':
        out = open(argv[3], 'xb') if len(argv) > 3 else sys.stdout.buffer
        with pins.open(z, argv[2]) as s:
            while chunk := s.read(16 << 20):
                out.write(chunk)
    elif cmd == 'pbzx':
        with pins.open(z, argv[2]) as s:
            data = pbzx_bytes(s)
        with open(argv[3], 'xb') as o:
            o.write(data)
    else:
        raise SystemExit(__doc__)


if __name__ == '__main__':
    main()

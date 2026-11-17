"""Release signatures (src/signing.py): RFC 8032's vectors, minisign 0.12's own files, and the refusals: a changed
file, a changed trusted comment, another file's signature, an unknown key, a missing signature, and hao fetch /
create-installer / install stopping with exit 4 before anything is read or written.

fixtures/signing: release.json and release.json.minisig made by `minisign -S -t "hao release test"` with a throwaway
key whose public half is test-key.pub (its secret half was never kept)."""
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
FIX = HERE / 'fixtures' / 'signing'
sys.path.insert(0, str(TOOL / 'src'))
import signing as SIGN    # noqa: E402

VECTORS = [   # RFC 8032 section 7.1, tests 1-3: secret, public, message, signature
    ('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
     'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
     'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
    ('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
     '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
     '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
    ('c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
     'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
     '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'),
]


def minisign_files(secret, data, comment='hao release test', kid=b'12345678'):
    """(public key file, signature file) as minisign writes them, made with SECRET (for tests' own keys)."""
    pub = SIGN.secret_to_public(secret)
    sig = SIGN.sign(secret, hashlib.blake2b(data, digest_size=64).digest())
    gsig = SIGN.sign(secret, sig + comment.encode())
    b = lambda x: base64.b64encode(x).decode()     # noqa: E731
    return ('untrusted comment: minisign public key\n%s\n' % b(b'Ed' + kid + pub),
            'untrusted comment: test\n%s\ntrusted comment: %s\n%s\n' % (b(b'ED' + kid + sig), comment, b(gsig)))


class Ed25519(unittest.TestCase):
    def test_rfc8032_vectors(self):
        for sk, pk, m, sg in VECTORS:
            sk, pk, m, sg = map(bytes.fromhex, (sk, pk, m, sg))
            self.assertEqual(SIGN.secret_to_public(sk), pk)
            self.assertEqual(SIGN.sign(sk, m), sg)
            self.assertTrue(SIGN.ed25519_verify(pk, m, sg))
            self.assertFalse(SIGN.ed25519_verify(pk, m + b'x', sg))

    def test_malformed_signatures_fail(self):
        sk, pk, m, sg = map(bytes.fromhex, VECTORS[1])
        s = int.from_bytes(sg[32:], 'little')
        self.assertFalse(SIGN.ed25519_verify(pk, m, sg[:32] + int.to_bytes(s + SIGN.q, 32, 'little')))  # S >= L
        self.assertFalse(SIGN.ed25519_verify(pk, m, b'\xff' * 32 + sg[32:]))      # R does not decode
        self.assertFalse(SIGN.ed25519_verify(b'\xff' * 32, m, sg))                  # A does not decode
        self.assertFalse(SIGN.ed25519_verify(pk, m, sg[:63]))


class Minisign(unittest.TestCase):
    def setUp(self):
        self.keys = SIGN.load_keys(FIX / 'test-key.pub')
        self.data = (FIX / 'release.json').read_bytes()
        self.sig = (FIX / 'release.json.minisig').read_text()

    def test_minisign_made_signature_verifies(self):
        kid, comment = SIGN.verify(self.data, self.sig, self.keys)
        self.assertEqual(comment, 'hao release test')
        self.assertEqual(len(kid), 16)

    def test_refusals(self):
        lines = self.sig.splitlines()
        other = SIGN.parse_keys(minisign_files(b'\1' * 32, b'')[0])
        for why, data, sig, keys in (
                ('changed file', self.data + b' ', self.sig, self.keys),
                ('changed comment', self.data, self.sig.replace('hao release test', 'hao release tesT'), self.keys),
                ('unknown key', self.data, self.sig, other),
                ('not minisign', self.data, 'hello', self.keys),
                ('legacy Ed', self.data, '\n'.join([lines[0], base64.b64encode(b'Ed' + base64.b64decode(lines[1])[2:])
                                                    .decode()] + lines[2:]), self.keys),
                ('bad base64', self.data, '\n'.join([lines[0], '!!!'] + lines[2:]), self.keys)):
            with self.assertRaises(SIGN.SignatureError, msg=why):
                SIGN.verify(data, sig, keys)

    def test_no_keys_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(SIGN.SignatureError):
                SIGN.load_keys(Path(d) / 'none.pub')
            (Path(d) / 'empty.pub').write_text('untrusted comment: nothing\n')
            with self.assertRaises(SIGN.SignatureError):
                SIGN.load_keys(Path(d) / 'empty.pub')

    def test_verified_release_reads_once_and_keeps_a_private_copy(self):
        with tempfile.TemporaryDirectory() as d:
            for n in ('release.json', 'release.json.minisig'):
                (Path(d) / n).write_bytes((FIX / n).read_bytes())
            copy, kid, comment = SIGN.verified_release(Path(d) / 'release.json', self.keys)
            self.assertNotEqual(copy.parent, Path(d))
            self.assertEqual(copy.read_bytes(), self.data)
            self.assertEqual(oct(copy.parent.stat().st_mode & 0o777), '0o700')
            self.assertTrue(SIGN.signature_of(copy).is_file())
            (Path(d) / 'release.json.minisig').unlink()
            with self.assertRaises(SIGN.SignatureError):
                SIGN.verified_release(Path(d) / 'release.json', self.keys)
            (Path(d) / 'release.json.minisig').symlink_to(FIX / 'release.json.minisig')
            with self.assertRaises(SIGN.SignatureError):     # not through a symlink
                SIGN.verified_release(Path(d) / 'release.json', self.keys)


class Commands(unittest.TestCase):
    def hao(self, *argv, env=None):
        return subprocess.run([sys.executable, '-I', '-B', str(TOOL / 'hao')] + list(argv), capture_output=True,
                              text=True, env=dict(os.environ, **(env or {})))

    def release(self, d, sign=True):
        rel = Path(d) / 'release.json'
        rel.write_text(json.dumps({'downloads': [{'name': 'a.bin', 'url': 'file:///nonexistent', 'size': 1,
                                                  'sha256': '0' * 64}]}))
        if sign:
            (Path(d) / 'release.json.minisig').write_text(minisign_files(b'\2' * 32, rel.read_bytes())[1])
        return rel

    def test_fetch_refuses_an_unsigned_release_with_exit_4(self):
        with tempfile.TemporaryDirectory() as d:
            rel = self.release(d, sign=False)
            r = self.hao('fetch', str(rel), '--cache', d + '/cache', env={'HAO_LOGS': d})
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
            self.assertIn('not signed by hao', r.stdout + r.stderr)
            self.assertFalse((Path(d) / 'cache').exists())

    def test_fetch_refuses_a_release_signed_by_another_key(self):
        with tempfile.TemporaryDirectory() as d:
            rel = self.release(d)
            r = self.hao('fetch', str(rel), '--cache', d + '/cache', env={'HAO_LOGS': d})
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
            self.assertFalse((Path(d) / 'cache').exists())

    def test_create_installer_refuses_an_unsigned_release(self):
        with tempfile.TemporaryDirectory() as d:
            rel = self.release(d, sign=False)
            r = self.hao('create-installer', '--dry-run', '--release', str(rel), env={'HAO_LOGS': d})
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)

    def test_install_checks_the_drive(self):
        with tempfile.TemporaryDirectory() as d:
            self.release(d, sign=False)
            (Path(d) / 'stick.json').write_text(json.dumps({'release_sha256': 'f' * 64}))
            r = self.hao('install', '--dry-run', env={'HAO_STICK': d, 'HAO_LOGS': d, 'HAO_ANYWHERE': '1'})
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
            (Path(d) / 'release.json').unlink()
            r = self.hao('install', '--dry-run', env={'HAO_STICK': d, 'HAO_LOGS': d, 'HAO_ANYWHERE': '1'})
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
            self.assertIn('is gone', r.stdout + r.stderr)

    def test_signed_release_accepts_the_owners_key_in_process(self):
        hao = runpy.run_path(str(TOOL / 'hao'), run_name='hao_module')
        import console as CON
        with tempfile.TemporaryDirectory() as d:
            rel = self.release(d, sign=False)
            pub, sig = minisign_files(b'\3' * 32, rel.read_bytes())
            (Path(d) / 'release.json.minisig').write_text(sig)
            (Path(d) / 'keys.pub').write_text(pub)
            keys = hao['SIGN'].KEYS
            hao['SIGN'].KEYS = Path(d) / 'keys.pub'
            try:
                import argparse
                c = CON.Console('quiet', env={})
                copy = hao['signed_release'](argparse.Namespace(unsigned=False), c, rel)
            finally:
                hao['SIGN'].KEYS = keys
            self.assertEqual(Path(copy).read_bytes(), rel.read_bytes())

    def test_unsigned_is_for_a_checkout_only(self):
        hao = runpy.run_path(str(TOOL / 'hao'), run_name='hao_module')
        import argparse
        import console as CON
        with tempfile.TemporaryDirectory() as d:
            rel = self.release(d, sign=False)
            c = CON.Console('quiet', env={})
            hao['signed_release'].__globals__['REPO'] = Path(d)          # no .git there: a release
            with self.assertRaises(CON.Stopped) as x:
                hao['signed_release'](argparse.Namespace(unsigned=True), c, rel)
            self.assertEqual(x.exception.code, 5)


if __name__ == '__main__':
    unittest.main()

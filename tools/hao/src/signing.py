"""Release signatures: minisign files (Ed25519, prehashed with BLAKE2b-512) checked against the keys hao carries.

The owner signs each release offline with minisign (https://jedisct1.github.io/minisign/):
    minisign -S -s KEY -m release.json SHA256SUMS -t "hao release NAME"
which writes release.json.minisig and SHA256SUMS.minisig. hao verifies release.json.minisig against
tools/hao/data/release-keys.pub before it reads anything in release.json, then works only from the verified bytes
(a private copy), so the file cannot change between the check and its use.

  load_keys(path)          {key id: public key} from minisign public key lines (more than one for a key change)
  verify(data, sig, keys)  (key id, trusted comment) when SIG signs DATA with one of KEYS, else SignatureError
  verified_release(path)   the release's bytes checked, copied to a new private folder: (copy, key id, comment)

Ed25519 verification is RFC 8032 section 6's reference code (Simplified BSD, IETF Trust; see NOTICE.md) with the
same checks: a point that does not decode, or S >= L, fails. Verification uses no secret, so it need not run in
constant time. `sign`/`secret_to_public` are there for the tests' own keys only.
"""
import base64
import hashlib
import os
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent
KEYS = HERE.parent / 'data' / 'release-keys.pub'
SIG_LIMIT = 4096
RELEASE_LIMIT = 16 << 20


class SignatureError(Exception):
    pass


# --- RFC 8032 section 6 (Ed25519), unchanged in substance -----------------------------------------------------------
# Copyright (c) 2017 IETF Trust and the persons identified as the document authors (S. Josefsson, I. Liusvaara).
# All rights reserved. Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met: Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
# provided with the distribution. Neither the name of Internet Society, IETF or IETF Trust, nor the names of specific
# contributors, may be used to endorse or promote products derived from this software without specific prior written
# permission. THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
p = 2 ** 255 - 19
q = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, p - 2, p)


d = -121665 * _inv(121666) % p
_SQRT_M1 = pow(2, (p - 1) // 4, p)


def _sha512_modq(s):
    return int.from_bytes(hashlib.sha512(s).digest(), 'little') % q


def _add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % p, (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p
    E, F, G_, H = B - A, D - C, D + C, B + A
    return (E * F, G_ * H, F * G_, E * H)


def _mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(d * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _SQRT_M1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_GY = 4 * _inv(5) % p
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % p)


def _compress(P):
    zi = _inv(P[2])
    x, y = P[0] * zi % p, P[1] * zi % p
    return int.to_bytes(y | ((x & 1) << 255), 32, 'little')


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


def _expand(secret):
    h = hashlib.sha512(secret).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def secret_to_public(secret):
    return _compress(_mul(_expand(secret)[0], G))


def sign(secret, msg):
    a, prefix = _expand(secret)
    A = _compress(_mul(a, G))
    r = _sha512_modq(prefix + msg)
    Rs = _compress(_mul(r, G))
    s = (r + _sha512_modq(Rs + A + msg) * a) % q
    return Rs + int.to_bytes(s, 32, 'little')


def ed25519_verify(public, msg, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    R = _decompress(signature[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(signature[32:], 'little')
    if s >= q:
        return False
    h = _sha512_modq(signature[:32] + public + msg)
    return _equal(_mul(s, G), _add(R, _mul(h, A)))


# --- minisign files -----------------------------------------------------------------------------------------------
def key_id_text(kid):
    return kid[::-1].hex().upper()


def _b64(line, size, what):
    try:
        raw = base64.b64decode(line.strip(), validate=True)
    except ValueError:
        raise SignatureError('%s is not base64' % what)
    if len(raw) != size:
        raise SignatureError('%s has %d bytes, not %d' % (what, len(raw), size))
    return raw


def parse_keys(text):
    """{key id (8 bytes): public key (32 bytes)} from minisign public key files (comment lines and key lines)."""
    keys = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('untrusted comment:') or line.startswith('#'):
            continue
        raw = _b64(line, 42, 'a public key')
        if raw[:2] != b'Ed':
            raise SignatureError('a public key is not an Ed25519 minisign key')
        keys[raw[2:10]] = raw[10:]
    return keys


def load_keys(path=None):
    path = path or KEYS
    try:
        text = Path(path).read_text()
    except OSError:
        raise SignatureError('this hao carries no release key (%s)' % path)
    keys = parse_keys(text)
    if not keys:
        raise SignatureError('this hao carries no release key (%s is empty)' % path)
    return keys


def verify(data, sig_text, keys):
    """(key id text, trusted comment) when SIG_TEXT (a .minisig file) signs DATA with one of KEYS."""
    lines = sig_text.splitlines()
    if len(lines) < 4 or not lines[0].startswith('untrusted comment:') or \
            not lines[2].startswith('trusted comment: '):
        raise SignatureError('the signature file is not a minisign signature')
    raw = _b64(lines[1], 74, 'the signature')
    if raw[:2] != b'ED':
        raise SignatureError('the signature is not a prehashed (BLAKE2b) minisign signature')
    kid, sig = raw[2:10], raw[10:]
    if kid not in keys:
        raise SignatureError('signed with key %s, which this hao does not trust' % key_id_text(kid))
    comment = lines[2][len('trusted comment: '):]
    gsig = _b64(lines[3], 64, 'the trusted comment signature')
    if not ed25519_verify(keys[kid], hashlib.blake2b(data, digest_size=64).digest(), sig):
        raise SignatureError('the signature does not match the file (changed after signing, or not signed by hao)')
    if not ed25519_verify(keys[kid], sig + comment.encode(), gsig):
        raise SignatureError('the trusted comment was changed after signing')
    return key_id_text(kid), comment


def _read(path, limit, what):
    """PATH's bytes: a regular file that is not a symlink, at most LIMIT bytes, read through the checked descriptor."""
    import stat
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0))
    except FileNotFoundError:
        raise SignatureError('there is no %s (%s)' % (what, path))
    except OSError as x:
        raise SignatureError('%s cannot be read: %s' % (path, x.strerror))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            raise SignatureError('%s is not a plain file of at most %d bytes' % (path, limit))
        with os.fdopen(fd, 'rb', closefd=False) as f:
            return f.read(limit + 1)
    finally:
        os.close(fd)


def signature_of(path):
    return Path(str(path) + '.minisig')


def verified_release(path, keys=None):
    """(private copy of PATH, key id, trusted comment): PATH and PATH.minisig read once, verified, and the same bytes
    written with the signature into a new 0700 folder, which every later step reads instead of PATH."""
    path = Path(path)
    data = _read(path, RELEASE_LIMIT, 'release file')
    sig = _read(signature_of(path), SIG_LIMIT, 'signature beside %s (%s.minisig)' % (path.name, path.name))
    kid, comment = verify(data, sig.decode('utf-8', errors='replace'), load_keys() if keys is None else keys)
    import safety as SAFE
    folder = Path(tempfile.mkdtemp(prefix='hao-release-'))
    import atexit
    import shutil
    atexit.register(shutil.rmtree, str(folder), True)
    copy = SAFE.create(folder / path.name, data, 0o644)
    SAFE.create(signature_of(copy), sig, 0o644)
    return copy, kid, comment

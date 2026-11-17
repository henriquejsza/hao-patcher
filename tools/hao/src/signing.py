"""Release signatures: SSH signatures (SSHSIG, `ssh-keygen -Y sign`) by an Ed25519 key, checked against the keys hao
carries, in pure Python (no ssh-keygen needed: the Recovery has none).

The owner signs each release offline, with a key file or a hardware wallet through its SSH agent (trezor-agent,
ledger-agent), in the folder release-cut staged:
    ssh-keygen -Y sign -f OWNER.pub -n hao-release release.json SHA256SUMS
which writes release.json.sig and SHA256SUMS.sig. hao verifies release.json.sig against tools/hao/data/release-keys.pub
(OpenSSH public key lines, `ssh-ed25519 AAAA... comment`) before it reads anything in release.json, then works only from
the verified bytes (a private copy), so the file cannot change between the check and its use.

  load_keys(path)          {public key (32 bytes): fingerprint} from ssh-ed25519 lines (more than one for a key change)
  verify(data, sig, keys)  (fingerprint, hash) when SIG (an armored SSHSIG) signs DATA in NAMESPACE with one of KEYS
  verified_release(path)   the release's bytes checked, copied to a new private folder: (copy, fingerprint, hash)

The format is OpenSSH's PROTOCOL.sshsig, parsed strictly: version 1, namespace hao-release, empty reserved field,
sha512 or sha256, ssh-ed25519 key and signature, nothing left over. Ed25519 verification is RFC 8032 section 6's
reference code (Simplified BSD, IETF Trust; see NOTICE.md) with the same checks: a point that does not decode, or
S >= L, fails. Verification uses no secret, so it need not run in constant time. `sign`/`secret_to_public` are there for
the tests' own keys only.
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


# --- SSH signatures (OpenSSH PROTOCOL.sshsig) -------------------------------------------------------------------
NAMESPACE = 'hao-release'
MAGIC = b'SSHSIG'
HASHES = {'sha512': hashlib.sha512, 'sha256': hashlib.sha256}
BEGIN, END = '-----BEGIN SSH SIGNATURE-----', '-----END SSH SIGNATURE-----'


def _string(b):
    return len(b).to_bytes(4, 'big') + b


class _Reader:
    def __init__(self, data, what):
        self.data, self.at, self.what = data, 0, what

    def take(self, n):
        if self.at + n > len(self.data):
            raise SignatureError('%s is cut short' % self.what)
        out = self.data[self.at:self.at + n]
        self.at += n
        return out

    def string(self):
        return self.take(int.from_bytes(self.take(4), 'big'))

    def end(self):
        if self.at != len(self.data):
            raise SignatureError('%s has bytes after its end' % self.what)


def _ed25519_blob(blob, what, size):
    r = _Reader(blob, what)
    kind = r.string()
    if kind != b'ssh-ed25519':
        raise SignatureError('%s is %s, not ssh-ed25519' % (what, kind.decode('ascii', 'replace')[:40]))
    value = r.string()
    r.end()
    if len(value) != size:
        raise SignatureError('%s has %d bytes, not %d' % (what, len(value), size))
    return value


def fingerprint(public):
    """SHA256:... as ssh-keygen -l shows it."""
    blob = _string(b'ssh-ed25519') + _string(public)
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def parse_keys(text):
    """{public key: fingerprint} from OpenSSH public key lines; blank and # lines are skipped, any other line must be
    an ssh-ed25519 key."""
    keys = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) < 2 or parts[0] != 'ssh-ed25519':
            raise SignatureError('a release key is not an ssh-ed25519 public key line')
        try:
            blob = base64.b64decode(parts[1], validate=True)
        except ValueError:
            raise SignatureError('a release key is not base64')
        pub = _ed25519_blob(blob, 'a release key', 32)
        keys[pub] = fingerprint(pub)
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


def armored(text):
    """The SSHSIG blob inside -----BEGIN/END SSH SIGNATURE----- (nothing else in the file but blank lines)."""
    lines = [x.strip() for x in text.strip().splitlines()]
    if len(lines) < 3 or lines[0] != BEGIN or lines[-1] != END:
        raise SignatureError('the signature file is not an SSH signature')
    try:
        return base64.b64decode(''.join(lines[1:-1]), validate=True)
    except ValueError:
        raise SignatureError('the signature is not base64')


def signed_data(namespace, hash_name, data):
    return (MAGIC + _string(namespace.encode()) + _string(b'') + _string(hash_name.encode())
            + _string(HASHES[hash_name](data).digest()))


def verify(data, sig_text, keys, namespace=NAMESPACE):
    """(fingerprint, hash name) when SIG_TEXT (an armored SSHSIG) signs DATA for NAMESPACE with one of KEYS."""
    r = _Reader(armored(sig_text), 'the signature')
    if r.take(6) != MAGIC:
        raise SignatureError('the signature is not an SSH signature')
    if int.from_bytes(r.take(4), 'big') != 1:
        raise SignatureError('the signature is not SSH signature version 1')
    public = _ed25519_blob(r.string(), 'the signing key', 32)
    ns, reserved, hash_name = r.string(), r.string(), r.string()
    sig = _ed25519_blob(r.string(), 'the signature', 64)
    r.end()
    if ns != namespace.encode():
        raise SignatureError('the signature is for "%s", not "%s"' % (ns.decode('ascii', 'replace')[:40], namespace))
    if reserved:
        raise SignatureError('the signature\'s reserved field is not empty')
    hash_name = hash_name.decode('ascii', 'replace')
    if hash_name not in HASHES:
        raise SignatureError('the signature uses hash %s, not sha512 or sha256' % hash_name[:20])
    if public not in keys:
        raise SignatureError('signed with key %s, which this hao does not trust' % fingerprint(public))
    if not ed25519_verify(public, signed_data(namespace, hash_name, data), sig):
        raise SignatureError('the signature does not match the file (changed after signing, or not signed by hao)')
    return keys[public], hash_name


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
    return Path(str(path) + '.sig')


def verified_release(path, keys=None):
    """(private copy of PATH, fingerprint, hash): PATH and PATH.sig read once, verified, and the same bytes
    written with the signature into a new 0700 folder, which every later step reads instead of PATH."""
    path = Path(path)
    data = _read(path, RELEASE_LIMIT, 'release file')
    sig = _read(signature_of(path), SIG_LIMIT, 'signature beside %s (%s.sig)' % (path.name, path.name))
    kid, hashed = verify(data, sig.decode('utf-8', errors='replace'), load_keys() if keys is None else keys)
    import safety as SAFE
    folder = Path(tempfile.mkdtemp(prefix='hao-release-'))
    import atexit
    import shutil
    atexit.register(shutil.rmtree, str(folder), True)
    copy = SAFE.create(folder / path.name, data, 0o644)
    SAFE.create(signature_of(copy), sig, 0o644)
    return copy, kid, hashed

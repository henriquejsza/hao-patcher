"""ranged.py: read a large file by byte ranges, from disk or over HTTP(S), and check what is read against pins.

A release pins the bytes the build uses, not whole downloads: each zip member it reads (an IPSW's disk images, the
installer's asset zip members) has its size and sha256 in release.json, and a member is hashed while it streams and
refused at its end if it differs. Nothing read from a source counts until its pin is checked.

  open_source(PATH_OR_URL)   -> Source: .size, .read_at(off, n), .reader() (seekable file object), .fetched
  Pins(DICT, what)            {member: {"size": N, "sha256": HEX}}: .open(zipfile, member) -> a stream that raises
                              PinError at its end when the bytes differ (and at once when the member is not pinned)

  ranged.py pins ZIP MEMBER...   the pins of MEMBERs of a trusted local zip (an IPSW), as JSON
"""
import hashlib
import http.client
import io
import os
import time
import urllib.parse
import zipfile

WINDOW = 16 << 20          # a remote read fetches at least this much (sequential zip reads are many small reads)
RETRIES = 5


class PinError(Exception):
    """Bytes that are not the pinned ones: never used."""


class Source:
    fetched = 0

    def reader(self, window=WINDOW):
        return io.BufferedReader(_Raw(self), window)


class FileSource(Source):
    def __init__(self, path):
        self.path = str(path)
        self.f = open(self.path, 'rb')
        self.size = os.fstat(self.f.fileno()).st_size

    def read_at(self, off, n):
        self.f.seek(off)
        b = self.f.read(n)
        self.fetched += len(b)
        return b


class HTTPSource(Source):
    """A URL read with Range requests over one kept-alive connection; a short or wrong reply is retried, then
    refused. A redirect is followed once per connection (Apple's CDNs and GitHub's release downloads redirect)."""

    def __init__(self, url, window=WINDOW):
        self.url, self.window, self.conn = url, window, None
        self.cache_off, self.cache = 0, b''
        self.size = self._size()

    def _connect(self, url):
        u = urllib.parse.urlsplit(url)
        cls = http.client.HTTPSConnection if u.scheme == 'https' else http.client.HTTPConnection
        self.conn, self.host, self.target = cls(u.netloc, timeout=60), u.netloc, (u.path or '/') + (
            '?' + u.query if u.query else '')

    def _request(self, start, end):
        url = self.url
        for _ in range(5):
            if self.conn is None:
                self._connect(url)
            self.conn.request('GET', self.target, headers={'Range': 'bytes=%d-%d' % (start, end),
                                                           'User-Agent': 'hao-ranged/1'})
            r = self.conn.getresponse()
            if r.status in (301, 302, 303, 307, 308):
                r.read(); self.conn.close(); self.conn = None
                url = urllib.parse.urljoin(url, r.getheader('Location'))
                continue
            return r
        raise OSError('%s: too many redirects' % self.url)

    def _size(self):
        r = self._request(0, 0)
        body = r.read()
        rng = r.getheader('Content-Range') or ''
        if r.status != 206 or not rng.startswith('bytes 0-0/'):
            raise OSError('%s does not serve byte ranges (HTTP %d)' % (self.url, r.status))
        return int(rng.split('/')[1])

    def _get(self, off, n):
        end = min(off + n, self.size) - 1
        err = None
        for attempt in range(RETRIES):
            try:
                r = self._request(off, end)
                body = r.read()
                if r.status != 206 or not (r.getheader('Content-Range') or '').startswith('bytes %d-%d/' % (off, end)):
                    raise OSError('HTTP %d, Content-Range %r for bytes %d-%d' % (r.status, r.getheader('Content-Range'),
                                                                               off, end))
                if len(body) != end - off + 1:
                    raise OSError('short reply: %d of %d bytes' % (len(body), end - off + 1))
                self.fetched += len(body)
                return body
            except (OSError, http.client.HTTPException) as x:
                err = x
                if self.conn:
                    self.conn.close()
                self.conn = None
                time.sleep(min(2 ** attempt, 20))
        raise OSError('%s: bytes %d-%d: %s' % (self.url, off, end, err))

    def read_at(self, off, n):
        if off >= self.size or n <= 0:
            return b''
        n = min(n, self.size - off)
        c0, c1 = self.cache_off, self.cache_off + len(self.cache)
        if c0 <= off and off + n <= c1:
            return self.cache[off - c0:off - c0 + n]
        if n >= self.window:
            return self._get(off, n)
        self.cache_off, self.cache = off, self._get(off, self.window)
        return self.cache[:n]


def open_source(where):
    w = str(where)
    return HTTPSource(w) if w.startswith(('http://', 'https://')) else FileSource(w)


class _Raw(io.RawIOBase):
    def __init__(self, src):
        self.src, self.pos = src, 0

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.pos

    def seek(self, off, whence=0):
        self.pos = off if whence == 0 else self.pos + off if whence == 1 else self.src.size + off
        return self.pos

    def readinto(self, b):
        data = self.src.read_at(self.pos, len(b))
        b[:len(data)] = data
        self.pos += len(data)
        return len(data)


class Hashed(io.RawIOBase):
    """STREAM read through sha256; at its end the size and digest must equal the pin, else PinError."""

    def __init__(self, stream, name, pin, what):
        self.s, self.name, self.pin, self.what = stream, name, pin, what
        self.h, self.n, self.checked = hashlib.sha256(), 0, False

    def readable(self): return True

    def readinto(self, b):
        try:
            data = self.s.read(len(b))
        except zipfile.BadZipFile as x:          # the zip's own CRC-32 saw it first: the same refusal
            raise PinError('%s %s: %s' % (self.what, self.name, x)) from None
        if data:
            self.h.update(data); self.n += len(data)
            if self.n > self.pin['size']:
                raise PinError('%s %s: more than the pinned %d bytes' % (self.what, self.name, self.pin['size']))
        else:
            self.check()
        b[:len(data)] = data
        return len(data)

    def check(self):
        if self.checked:
            return
        if self.n != self.pin['size'] or self.h.hexdigest() != self.pin['sha256']:
            raise PinError('%s %s: got %d bytes, sha256 %s; pinned %d, %s' % (
                self.what, self.name, self.n, self.h.hexdigest(), self.pin['size'], self.pin['sha256']))
        self.checked = True

    def close(self):
        self.s.close()
        super().close()


class Pins:
    """{member: {"size", "sha256"}} for one source; None checks nothing (a local file a maintainer trusts)."""

    def __init__(self, pins, what):
        self.pins, self.what, self.used = pins, what, set()

    def open(self, z, member):
        self.used.add(member)                  # the members a run reads: what a release must pin
        s = z.open(member)
        if self.pins is None:
            return s
        pin = self.pins.get(member)
        if pin is None:
            s.close()
            raise PinError('%s %s is not pinned by the release; it is not read' % (self.what, member))
        return io.BufferedReader(Hashed(s, member, pin, self.what), 8 << 20)

    def read(self, z, member):
        with self.open(z, member) as s:
            return s.read()


def pins_for(zipfile_obj, members, what):
    """{member: {"size", "sha256"}} computed from a trusted local copy (release-cut writes these into release.json)."""
    out = {}
    for m in members:
        h, n = hashlib.sha256(), 0
        with zipfile_obj.open(m) as s:
            for b in iter(lambda: s.read(8 << 20), b''):
                h.update(b); n += len(b)
        out[m] = dict(size=n, sha256=h.hexdigest())
    return out


if __name__ == '__main__':
    import json, sys, zipfile
    if len(sys.argv) < 4 or sys.argv[1] != 'pins':
        raise SystemExit(__doc__)
    print(json.dumps(pins_for(zipfile.ZipFile(sys.argv[2]), sys.argv[3:], 'member'), indent=1, sort_keys=True))

"""S25 for `ssdimg push`: write only what changed, verify everything, fall back to a full write on a mismatch.

Runs the real host side (cli + push.py) against the real agent (built here with HOST_ONLY=1 into a temporary
folder) on `local:` file targets in temporary folders; never a device. The images are synthetic: a GPT with two
non-APFS partitions of random data (ssdimg keeps non-APFS partitions whole), so no hdiutil is needed.

    python3.14 -I -B -m unittest discover -s tools/ssdimg/tests
"""
import argparse
import io
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import zlib
from pathlib import Path
from contextlib import redirect_stderr, redirect_stdout

TOOLS = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, TOOLS)

from ssdimg import cli, gpt, push  # noqa: E402

ZSTD_CANDIDATES = [os.environ.get("SSDPUSH_ZSTD", ""),
                   os.path.join(os.path.dirname(TOOLS), "store/cache/zstd/zstd-1.5.7")]
SECTOR = 512
CS = 64 << 10                       # repository chunk size of the test images
IMAGE = (16 << 20) + (32 << 10)     # 16 MiB + 32 KiB: the last chunk is partial
TARGET = 20 << 20                   # larger than the image: the backup GPT is relocated
TIMES = {}
AGENT = None
SKIP = None
TMP = None
RUN = ("import sys; sys.path.insert(0, sys.argv[1]); from ssdimg.cli import main; main(sys.argv[2:])")
SUMMARY = re.compile(r"push summary: mode='([^']*)' queried=(\d+) matched=(\d+) written=(\d+) bytes=(\d+) "
                     r"fallback=(\d)")


def setUpModule():
    global AGENT, SKIP, TMP
    TMP = tempfile.mkdtemp(prefix="ssdimg-s25-")
    zstd_src = next((z for z in ZSTD_CANDIDATES if z and os.path.isfile(os.path.join(z, "lib/zstd.h"))), None)
    if not zstd_src:
        SKIP = "no zstd 1.5.x source (SSDPUSH_ZSTD or store/cache/zstd/zstd-1.5.7) to build ssdpush-agent"
        return
    build = os.path.join(TOOLS, "ssdpush", "build.sh")
    t0 = time.time()
    r = subprocess.run(["zsh", build, zstd_src, TMP], env={**os.environ, "HOST_ONLY": "1"},
                       capture_output=True, text=True)
    TIMES["agent build"] = time.time() - t0
    agent = os.path.join(TMP, "ssdpush-agent-macos")
    if r.returncode or not os.path.isfile(agent):
        SKIP = f"ssdpush-agent did not build: {(r.stderr or r.stdout).strip()[-300:]}"
        return
    AGENT = agent


def tearDownModule():
    if TMP:
        shutil.rmtree(TMP, ignore_errors=True)
    if TIMES:
        print("\nS25 test timings:", file=sys.stderr)
        for k, v in TIMES.items():
            print(f"  {k:<48} {v:6.2f} s", file=sys.stderr)


# ---------------------------------------------------------------- synthetic images

def gpt_image(path, size, seed, parts=((2048, 4 << 20), (12288, 6 << 20))):
    """Raw image with a protective MBR, primary and backup GPT and `parts` = [(first LBA, bytes)] partitions of
    random data (EFI and HFS+ types: kept whole by ssdimg). The space between them is zeros."""
    rnd = random.Random(seed)
    sectors = size // SECTOR
    entries = bytearray(128 * 128)
    types = [gpt.TYPE_EFI, gpt.TYPE_HFS]
    for k, (first, n) in enumerate(parts):
        struct.pack_into("<16s16sQQQ72s", entries, k * 128, types[k % 2].bytes_le,
                         uuid.UUID(int=rnd.getrandbits(128)).bytes_le, first, first + n // SECTOR - 1, 0,
                         f"part{k + 1}".encode("utf-16-le"))
    ecrc = zlib.crc32(entries)
    guid = uuid.UUID(int=rnd.getrandbits(128)).bytes_le

    def header(my, alt, elba):
        h = bytearray(struct.pack(gpt.HDR_FMT, b"EFI PART", 0x10000, 92, 0, 0, my, alt, 34, sectors - 34, guid,
                                  elba, 128, 128, ecrc))
        h[16:20] = struct.pack("<I", zlib.crc32(h))
        return bytes(h).ljust(SECTOR, b"\0")

    mbr = bytearray(SECTOR)
    struct.pack_into("<BBBBBBBBII", mbr, 446, 0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF, 1, min(sectors - 1, 0xFFFFFFFF))
    mbr[510:512] = b"\x55\xaa"
    with open(path, "wb") as f:
        f.truncate(size)
        f.seek(0)
        f.write(mbr + header(1, sectors - 1, 2) + entries)
        for first, n in parts:
            f.seek(first * SECTOR)
            f.write(rnd.randbytes(n))
        f.seek((sectors - 33) * SECTOR)
        f.write(entries + header(sectors - 1, 1, sectors - 33))
    return path


def file_reader(path):
    with open(path, "rb") as f:
        data = f.read()
    return lambda off, n: data[off:off + n]


def present_chunks(path, cs=CS):
    size = os.path.getsize(path)
    read = file_reader(path)
    with redirect_stdout(io.StringIO()):
        _g, keep = cli.keep_ranges(read, size, SECTOR)
    return sorted(cli.chunk_masks(keep, size, cs))


def make_repo(root, seed):
    """An ssdimg repository with one commit of a synthetic image."""
    with redirect_stdout(io.StringIO()):
        repo = cli.Repo.init(root, chunk_size=CS)
    gpt_image(repo.work, IMAGE, seed)
    m = repo.meta()
    m.update(size=IMAGE, sector_size=SECTOR)
    repo.save_meta(m)
    r = run_ssdimg("-C", root, "commit", "-m", "synthetic")
    assert r.returncode == 0, r.stdout + r.stderr
    return repo


def run_ssdimg(*args, fault=None):
    env = {k: v for k, v in os.environ.items() if k != "SSDPUSH_TEST_FAULT"}
    env["SSDPUSH_LOCAL_AGENT"] = AGENT or ""
    if fault:
        env["SSDPUSH_TEST_FAULT"] = fault
    return subprocess.run([sys.executable, "-I", "-B", "-c", RUN, TOOLS, *args], capture_output=True, text=True,
                          env=env, stdin=subprocess.DEVNULL)


def blank_target(path, size=TARGET, fill=None):
    with open(path, "wb") as f:
        if fill is None:
            f.truncate(size)
        else:
            f.write(fill(size))
    return path


def summary(r):
    m = SUMMARY.search(r.stdout)
    assert m, r.stdout + r.stderr
    mode, *n = m.groups()
    return {"mode": mode, **dict(zip(("queried", "matched", "written", "bytes", "fallback"), map(int, n)))}


class Base(unittest.TestCase):
    def setUp(self):
        if SKIP:
            self.skipTest(SKIP)
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.t0 = time.time()

    def tearDown(self):
        TIMES[self.id().split(".", 1)[1]] = time.time() - self.t0
        shutil.rmtree(self.dir, ignore_errors=True)

    def assertPresentEqual(self, image, target):
        """Every present chunk of the image is on the target, except where the relocated GPT goes."""
        with open(image, "rb") as f:
            img = f.read()
        with open(target, "rb") as f:
            tgt = f.read()
        size = len(img)
        g = gpt.GPT(lambda off, n: img[off:off + n], SECTOR)
        raw = g.relocated(len(tgt) // SECTOR)
        for i in present_chunks(image):
            lo, hi = i * CS, min((i + 1) * CS, size)
            want = push._overlay(lo, img[lo:hi], raw)
            self.assertEqual(tgt[lo:hi], want, f"chunk {i} differs")
        for off, data in raw:
            self.assertEqual(tgt[off:off + len(data)], data, f"relocated GPT piece at {off} differs")


class RepoPush(Base):
    """(a)-(d): a repository commit pushed to a file."""

    def setUp(self):
        super().setUp()
        self.repo = make_repo(os.path.join(self.dir, "repo"), seed=1)
        self.image = self.repo.work
        self.target = blank_target(os.path.join(self.dir, "target.img"))

    def push(self, *extra, fault=None):
        return run_ssdimg("-C", self.repo.root, "push", "local:" + self.target, "--yes", "--no-check", *extra,
                          fault=fault)

    def pushed_ok(self, *extra, fault=None):
        r = self.push(*extra, fault=fault)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r, summary(r)

    def corrupt(self, chunks):
        with open(self.target, "r+b") as f:
            for i in chunks:
                f.seek(i * CS + 100)
                f.write(os.urandom(64))

    def test_a_fresh_full_push(self):
        r, s = self.pushed_ok("--full")
        self.assertEqual(s["mode"], "full")
        self.assertEqual(s["written"], len(present_chunks(self.image)))
        self.assertIn("all match", r.stdout)
        self.assertPresentEqual(self.image, self.target)
        v = run_ssdimg("-C", self.repo.root, "verify", "local:" + self.target)
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)

    def test_b_delta_writes_only_corrupted_chunks(self):
        self.pushed_ok("--full")
        _r, s0 = self.pushed_ok()                       # holds the image: only the partial last chunk is written
        self.assertEqual(s0["mode"], "delta")
        self.assertEqual(s0["written"], 1)
        n = len(present_chunks(self.image))
        self.assertEqual(s0["queried"], n - 1)
        self.assertEqual(s0["matched"], n - 1)
        bad = [20, 77, 150]
        self.corrupt(bad)
        r, s = self.pushed_ok()
        self.assertEqual(s["mode"], "delta", r.stdout)
        self.assertEqual(s["written"], s0["written"] + len(bad))
        self.assertEqual(s["matched"], n - 1 - len(bad))
        self.assertEqual(s["fallback"], 0)
        self.assertIn("all match", r.stdout)
        self.assertPresentEqual(self.image, self.target)

    def test_c_random_target_gets_a_full_write(self):
        blank_target(self.target, fill=os.urandom)
        r, s = self.pushed_ok()
        self.assertIn("target does not match the image (its primary GPT differs): full write", r.stdout)
        self.assertEqual(s["mode"], "full (target does not match)")
        self.assertEqual(s["queried"], 0)                # no hash query when the GPT already differs
        self.assertEqual(s["written"], len(present_chunks(self.image)))
        self.assertPresentEqual(self.image, self.target)

    def test_c_other_image_same_layout_gets_a_full_write(self):
        other = gpt_image(os.path.join(self.dir, "other.img"), IMAGE, seed=1)   # same GPT ...
        with open(other, "r+b") as f:                    # ... different partition contents
            f.seek(2048 * SECTOR)
            f.write(os.urandom(10 << 20))
        shutil.copyfile(other, self.target)
        with open(self.target, "r+b") as f:
            f.truncate(TARGET)
        g = gpt.GPT(file_reader(other), SECTOR)
        with open(self.target, "r+b") as f:
            for off, data in g.relocated(TARGET // SECTOR):
                f.seek(off)
                f.write(data)
        r, s = self.pushed_ok()
        self.assertRegex(r.stdout, r"target does not match the image \(\d+ of \d+ chunks differ\): full write")
        self.assertEqual(s["mode"], "full (target does not match)")
        self.assertGreater(s["queried"], 0)
        self.assertEqual(s["written"], len(present_chunks(self.image)))
        self.assertPresentEqual(self.image, self.target)

    def test_d_verify_failure_falls_back_to_a_full_write(self):
        self.pushed_ok("--full")
        r, s = self.pushed_ok(fault=str(100 * CS + 5))
        self.assertIn("SSDPUSH_TEST_FAULT: flipped the byte", r.stderr)
        self.assertIn(f"VERIFY FAILED: 1 chunks and 0 other ranges differ from the image (first: chunk 100 "
                      f"(offset {100 * CS}))", r.stdout)
        self.assertIn("verify failed after the delta write: full write", r.stdout)
        self.assertEqual(s["mode"], "delta")
        self.assertEqual(s["fallback"], 1)
        self.assertEqual(s["written"], 1 + len(present_chunks(self.image)))
        self.assertIn("all match", r.stdout)
        self.assertPresentEqual(self.image, self.target)

    def test_d_sticky_fault_is_a_hard_failure(self):
        self.pushed_ok("--full")
        r = self.push(fault=f"{100 * CS + 5}:sticky")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(summary(r)["fallback"], 1)
        self.assertEqual(r.stdout.count("VERIFY FAILED"), 1)          # the first, before the fallback
        self.assertIn(f"VERIFY FAILED: 1 chunks and 0 other ranges differ from the image (first: chunk 100 "
                      f"(offset {100 * CS}))", r.stderr)               # the second: the exit message

    def test_d_full_write_verify_failure_is_a_hard_failure(self):
        r = self.push("--full", fault=str(100 * CS + 5))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(summary(r)["fallback"], 0)
        self.assertIn("VERIFY FAILED", r.stderr)


# ---------------------------------------------------------------- (e) --usb guard and write order

USB_DISK = {"DeviceIdentifier": "disk4", "WholeDisk": True, "Internal": False, "VirtualOrPhysical": "Physical",
            "BusProtocol": "USB", "Removable": False, "RemovableMedia": False, "Ejectable": True,
            "MediaName": "JMicron Generic Media", "TotalSize": 250059350016, "DeviceBlockSize": 512}
INTERNAL_DISK = {"DeviceIdentifier": "disk0", "WholeDisk": True, "Internal": True, "VirtualOrPhysical": "Physical",
                 "BusProtocol": "SATA", "Removable": False, "RemovableMedia": False, "Ejectable": False,
                 "MediaName": "Samsung SSD 850 EVO 250GB", "TotalSize": 250059350016, "DeviceBlockSize": 512}
RAM_DISK = {"DeviceIdentifier": "disk1", "WholeDisk": True, "Internal": False, "VirtualOrPhysical": "Virtual",
            "BusProtocol": "Disk Image", "Ejectable": True, "MediaName": "Disk Image", "TotalSize": 4000000000}
IDENT = "media=JMicron Generic Media,size=250059350016,lun=1"
IOREG = """    | |   "Protocol Characteristics" = {"Physical Interconnect"="USB","SCSI Logical Unit Number"=0}
    | |   "BSD Name" = "disk3"
    | |   "Protocol Characteristics" = {"Physical Interconnect"="USB","SCSI Logical Unit Number"=1}
    | |   "BSD Name" = "disk4"
    | |   "BSD Name" = "disk4s1"
"""


class UsbGuard(unittest.TestCase):
    def setUp(self):
        self.t0 = time.time()

    def tearDown(self):
        TIMES[self.id().split(".", 1)[1]] = time.time() - self.t0

    def test_e_identity_parse(self):
        self.assertEqual(push.parse_identity(IDENT),
                         {"media": "JMicron Generic Media", "size": "250059350016", "lun": "1"})
        self.assertEqual(push.parse_identity("lun=-, size=1000 ,media=X")["lun"], "-")
        for bad in ("media=X,size=1", "media=X,size=1,lun=0,lun=1", "media=X,size=1G,lun=0", "media=,size=1,lun=0",
                    "media=X,size=1,lun=a", "vendor=X,size=1,lun=0", "media=X;size=1;lun=0"):
            with self.assertRaises(push.PushError, msg=bad):
                push.parse_identity(bad)

    def test_e_lun_from_ioreg(self):
        self.assertEqual(push.lun_of(IOREG, "disk4"), "1")
        self.assertEqual(push.lun_of(IOREG, "disk3"), "0")
        self.assertEqual(push.lun_of(IOREG, "disk9"), "-")
        self.assertEqual(push.lun_of('"BSD Name" = "disk2"\n', "disk2"), "-")

    def test_e_accepts_exactly_the_named_drive(self):
        self.assertIn("LUN 1", push.usb_guard(USB_DISK, "1", push.parse_identity(IDENT)))
        thunderbolt_fixed = {**USB_DISK, "BusProtocol": "Thunderbolt", "Ejectable": False}
        push.usb_guard(thunderbolt_fixed, "1", push.parse_identity(IDENT))

    def test_e_refuses_everything_else(self):
        ident = push.parse_identity(IDENT)
        cases = {
            "internal": (INTERNAL_DISK, "-", push.parse_identity(
                "media=Samsung SSD 850 EVO 250GB,size=250059350016,lun=-"), "an internal disk"),
            "ram disk": (RAM_DISK, "-", ident, "not a physical disk"),
            "partition": ({**USB_DISK, "WholeDisk": False, "DeviceIdentifier": "disk4s2"}, "1", ident, "partition"),
            "no Internal key": ({k: v for k, v in USB_DISK.items() if k != "Internal"}, "1", ident,
                                "not reported as external"),
            "fixed SATA, not internal": ({**USB_DISK, "BusProtocol": "SATA", "Ejectable": False}, "1", ident,
                                         "not removable"),
            "other LUN (the other bay)": (USB_DISK, "0", ident, "lun '0' (expected '1')"),
            "no LUN": (USB_DISK, "-", ident, "lun '-' (expected '1')"),
            "other size": ({**USB_DISK, "TotalSize": 500107862016}, "1", ident, "size '500107862016'"),
            "other media": ({**USB_DISK, "MediaName": "SanDisk Extreme"}, "1", ident, "media 'SanDisk Extreme'"),
        }
        for name, (info, lun, want, why) in cases.items():
            with self.subTest(name), self.assertRaises(push.PushError) as cm:
                push.usb_guard(info, lun, want, "/dev/" + info["DeviceIdentifier"])
            self.assertIn(why, str(cm.exception), name)

    def test_e_usb_needs_a_rec_target(self):
        with self.assertRaisesRegex(push.PushError, "--usb needs a rec@"):
            push.guard("local", None, "/nonexistent", IDENT)

    def test_e_zero_ranges(self):
        self.assertEqual(push.usb_zero_ranges(TARGET), [(0, 4 << 20), (TARGET - (4 << 20), 4 << 20)])
        self.assertEqual(push.usb_zero_ranges(6 << 20), [(0, 4 << 20), (4 << 20, 2 << 20)])
        self.assertEqual(push.usb_zero_ranges(3 << 20), [(0, 3 << 20)])


class UsbWriteOrder(Base):
    """(e) the USB write order, through the real agent on a file (the --usb guard itself needs a rec target)."""

    def test_e_usb_order_tables_zeroed_first_primary_gpt_last(self):
        repo = make_repo(os.path.join(self.dir, "repo"), seed=3)
        target = blank_target(os.path.join(self.dir, "target.img"), fill=os.urandom)   # stale data everywhere
        man, meta = repo.manifest("HEAD"), repo.meta("HEAD")
        present = set(man) | set(present_chunks(repo.work))
        src = push.RepoSource(repo, man, meta, present)
        old_agent, push.LOCAL_AGENT = push.LOCAL_AGENT, AGENT
        frames, phases = [], [[]]
        try:
            with redirect_stdout(io.StringIO()):
                link = push.Link("local", None, target, src.size, src.cs, verify=False)
            send = link.send

            def record(data):
                kind = data[:1]
                if kind in (b"D", b"Z", b"R"):
                    off, n = struct.unpack("<QI", data[1:13])
                    phases[-1].append((kind, off, n))
                elif kind == b"F":
                    phases.append([])
                send(data)
            link.send = record
            raw = gpt.GPT(src.read, SECTOR).relocated(link.size // SECTOR)
            st = {"mode": "full", "queried": 0, "matched": 0, "written": 0, "bytes": 0, "fallback": 0, "seconds": {}}
            with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()):
                push.write_pass(link, src, sorted(present), raw, st, usb=True)
                push.verify_pass(link, man, present, CS, src.size, raw, overlay=raw, read=src.read)
            link.close()
        finally:
            push.LOCAL_AGENT = old_agent
        head = SECTOR * 34
        zeroing, body, last = phases[0], phases[1], phases[2]
        self.assertEqual([(k, o) for k, o, _n in zeroing], [(b"R", 0), (b"R", TARGET - (4 << 20))])
        self.assertTrue(all(o >= head for _k, o, _n in body), "nothing before the first usable LBA in the body")
        self.assertIn((b"R", TARGET - SECTOR, SECTOR), body, "backup GPT header written with the body")
        self.assertTrue(last and all(o < head for _k, o, _n in last), last)
        self.assertEqual(last[0][:2], (b"D", 0))                     # chunk 0, then MBR and primary GPT pieces
        self.assertEqual({o for k, o, _n in last if k == b"R"}, {0, SECTOR, 2 * SECTOR})
        self.assertIn("all match", out.getvalue())
        with open(target, "rb") as f:
            data = f.read()
        self.assertEqual(data[CS:1 << 20], bytes((1 << 20) - CS), "unallocated space in the zeroed head reads zeros")
        self.assertPresentEqual(repo.work, target)


# ---------------------------------------------------------------- (f) push --image FILE (no repository)

class RawImagePush(Base):
    def push(self, *extra, fault=None):
        return run_ssdimg("push", "--image", self.image, "local:" + self.target, "--yes", "--no-check", *extra,
                          fault=fault)

    def test_f_raw_image_push_delta_and_verify(self):
        self.image = gpt_image(os.path.join(self.dir, "raw.img"), IMAGE, seed=5)
        self.target = blank_target(os.path.join(self.dir, "target.img"))
        n = len(present_chunks(self.image, 256 << 10))
        r = self.push()                                           # empty target: GPT differs, full write
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        s = summary(r)
        self.assertEqual((s["mode"], s["written"]), ("full (target does not match)", n))
        self.assertRegex(r.stdout, r"image: .*raw\.img .* raw, \d+ present chunks of 262.1 KB")
        self.assertPresentEqual(self.image, self.target)
        r = self.push()                                           # holds it: only the partial last chunk
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((summary(r)["mode"], summary(r)["written"]), ("delta", 1))
        with open(self.target, "r+b") as f:                       # one bad chunk in partition 2
            f.seek(9 << 20)
            f.write(os.urandom(4096))
        r = self.push(fault=str((7 << 20) + 3))                   # and a bad byte after the write: fallback
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        s = summary(r)
        self.assertEqual((s["mode"], s["written"], s["fallback"]), ("delta", 2 + n, 1))
        v = run_ssdimg("verify", "--image", self.image, "local:" + self.target)
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        self.assertIn("all match", v.stdout)

    def test_f_raw_image_chunk_size(self):
        self.image = gpt_image(os.path.join(self.dir, "raw.img"), IMAGE, seed=6)
        self.target = blank_target(os.path.join(self.dir, "target.img"))
        r = self.push("--chunk-size", str(CS), "--full")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(summary(r)["written"], len(present_chunks(self.image, CS)))
        self.assertPresentEqual(self.image, self.target)
        bad = self.push("--chunk-size", "1000")
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("multiple of 4096", bad.stderr)
        rev = run_ssdimg("push", "--image", self.image, "local:" + self.target, "--rev", "HEAD", "--yes")
        self.assertIn("--image and --rev exclude each other", rev.stderr)


class DiskToDiskPush(Base):
    """push --from-disk: one "laptop's" disk (a file) to another's through the source agent's --relay."""

    def push(self, *extra, fault=None):
        return run_ssdimg("push", "--from-disk", "local:" + self.source, "local:" + self.target, "--yes", *extra,
                          fault=fault)

    def test_g_disk_to_disk_full_delta_fallback(self):
        import hashlib
        self.source = gpt_image(os.path.join(self.dir, "laptop1.img"), TARGET, seed=7)
        self.target = blank_target(os.path.join(self.dir, "laptop2.img"))
        digest = lambda: hashlib.sha256(Path(self.source).read_bytes()).hexdigest()
        before = digest()
        n = len(present_chunks(self.source, 256 << 10))
        r = self.push()                                           # blank target: full write
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        s = summary(r)
        self.assertEqual((s["mode"], s["written"]), ("full (target does not match)", n))
        self.assertRegex(r.stdout, r"source disk: local:.* present chunks of 262.1 KB \(\d+ not zero\) hashed on the source")
        wire = re.search(r"pushed .* \((\d+) chunks, ([\d.]+) (\w+) on the wire\)", r.stdout)
        self.assertIsNotNone(wire, r.stdout)                      # the host sent 33-byte S frames, not the data
        self.assertLess(float(wire.group(2)) * {"B": 1, "KB": 1e3, "MB": 1e6}.get(wire.group(3), 1e9), 64 * n)
        self.assertRegex(r.stderr, r"ssdpush-agent relay: \d+ S frames")
        self.assertPresentEqual(self.source, self.target)
        r = self.push()                                           # holds it: nothing to write
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((summary(r)["mode"], summary(r)["written"]), ("delta", 0))
        with open(self.target, "r+b") as f:                       # one bad chunk in partition 2
            f.seek(9 << 20)
            f.write(os.urandom(4096))
        r = self.push()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((summary(r)["mode"], summary(r)["written"]), ("delta", 1))
        self.assertPresentEqual(self.source, self.target)
        r = self.push(fault=str((7 << 20) + 3))                   # a bad byte after the write: full write fallback
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        s = summary(r)
        self.assertEqual((s["mode"], s["fallback"], s["written"]), ("delta", 1, n))
        self.assertPresentEqual(self.source, self.target)
        self.assertEqual(digest(), before, "the source was written")

    def test_g_refusals(self):
        self.source = gpt_image(os.path.join(self.dir, "laptop1.img"), TARGET, seed=8)
        self.target = blank_target(os.path.join(self.dir, "laptop2.img"))
        r = run_ssdimg("push", "--from-disk", "local:" + self.source, "local:" + self.source, "--yes")
        self.assertIn("names the target itself", r.stderr)
        r = run_ssdimg("push", "--from-disk", "local:" + self.source, "local:" + self.target, "--image", self.source,
                       "--yes")
        self.assertIn("--from-disk excludes --rev and --image", r.stderr)
        small = blank_target(os.path.join(self.dir, "small.img"), size=TARGET - (1 << 20))
        r = run_ssdimg("push", "--from-disk", "local:" + self.source, "local:" + small, "--yes")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("image needs", r.stdout + r.stderr)

    def test_g_relay_refuses_a_changed_source_chunk(self):
        """The relay checks each chunk against the hash the host was given (the source must not change)."""
        src = gpt_image(os.path.join(self.dir, "laptop1.img"), TARGET, seed=9)
        tgt = blank_target(os.path.join(self.dir, "laptop2.img"))
        with redirect_stdout(io.StringIO()):
            old, push.LOCAL_AGENT = push.LOCAL_AGENT, AGENT
            try:
                link = push.RelayLink("local", None, tgt, None, src, TARGET, CS, verify=False)
                link.send(b"S" + struct.pack("<QI", 2048 * SECTOR, CS) + bytes(20))
                link.send(b"F")
                line = link.line()
                link.abort()
            finally:
                push.LOCAL_AGENT = old
        self.assertIn("changed since it was hashed", line)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------- (h) whole-sector reads only

class SectorAlignedReads(Base):
    """A read of /dev/rdiskN that is not whole sectors fails with EINVAL (`dd bs=1000000` then reads 0 bytes and
    `| sha256` hashes nothing: laptop 1's hand-run, 2026-11-18, a false mismatch). Every ssdimg read unit is whole
    sectors, and the agent refuses an unaligned request outright instead of handing it to the device."""

    def test_h_init_refuses_a_chunk_size_that_is_not_whole_blocks(self):
        for cs in ("1000000", "1000", "512"):
            r = run_ssdimg("init", os.path.join(self.dir, "r" + cs), "--chunk-size", cs)
            self.assertNotEqual(r.returncode, 0, cs)
            self.assertIn("multiple of 4096", r.stderr)
        r = run_ssdimg("init", os.path.join(self.dir, "ok"), "--chunk-size", "1048576")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_h_push_and_verify_refuse_an_old_repo_with_a_ragged_chunk_size(self):
        repo = make_repo(os.path.join(self.dir, "repo"), seed=7)
        m = repo.meta()
        m["chunk_size"] = 1000000                                # as a repository made before init checked it
        repo.save_meta(m)
        repo.git("commit", "-q", "-am", "ragged chunk size")      # push and verify read the committed image.json
        target = blank_target(os.path.join(self.dir, "target.img"))
        for cmd in (("push", "local:" + target, "--yes", "--no-check"), ("verify", "local:" + target)):
            r = run_ssdimg("-C", repo.root, *cmd)
            self.assertNotEqual(r.returncode, 0, cmd)
            self.assertIn("not a whole number of 512-byte sectors", r.stdout + r.stderr, cmd)

    def test_h_agent_refuses_unaligned_reads(self):
        target = blank_target(os.path.join(self.dir, "target.img"), size=4 << 20)
        cases = [(b"P", struct.pack("<QI", 0, 1000000)),                         # length not whole sectors
                 (b"P", struct.pack("<QI", 100, 4096)),                          # offset not whole sectors
                 (b"H", struct.pack("<IQI", 1, 0, 1000)),
                 (b"Q", struct.pack("<IQI", 1, 512, 700) + bytes(20))]
        for op, body in cases:
            p = subprocess.run([AGENT, target, "--read-only"], capture_output=True,
                               input=b"SSDPUSH1" + struct.pack("<QII", 0, 1 << 20, 0) + op + body)
            self.assertNotEqual(p.returncode, 0, op)
            self.assertIn(b"ERR unaligned", p.stdout, (op, p.stdout))           # the agent's errors go to stdout
        ok = subprocess.run([AGENT, target, "--read-only"], capture_output=True,
                            input=b"SSDPUSH1" + struct.pack("<QII", 0, 1 << 20, 0) + b"P" + struct.pack("<QI", 512, 4096)
                            + b"X")
        self.assertIn(b"READY", ok.stdout)
        self.assertNotIn(b"ERR", ok.stdout)
        self.assertEqual(len(ok.stdout.split(b"\n", 1)[1]), 4096, ok.stdout[-200:])

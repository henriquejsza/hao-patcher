# metal-metalold

Our own `MetalOld.dylib`, the legacy Metal (Apple's macOS 13.2.1, 22D68, Metal 306.3.5) that the HD 4000 driver
and the Metal wrapper sit on. It is meant to replace the copy OCLP's PatcherSupportPkg ships.

## How it works

- **Input row `metalold_22d68`:** Apple's x86_64 Metal, cut out of the 13.2.1 IPSW's Rosetta cache by
  `cache-dylib` r5 (a dyld-cache extractor, not yet published), with the install name set to
  `MetalOld.dylib` and no other change. Its `build.json` names the pinned IPSW (URL, size) and the six cache hashes. The extraction gives the same bytes on every run.
- **The one code edit**, declared in [`edits/metalold.json`](edits/metalold.json): in
  `+[MTLLoader sliceIDForDevice:legacyDriverVersion:airntDriverVersion:]`, the `je` after the device-type test
  becomes two NOPs (file offset 0xd94a1), as in OCLP's copy. The file is then signed ad hoc once, keeping its
  identifier.

Compared with OCLP's MetalOld, the instruction stream is identical except for that edit, and the dependencies and
exports are identical. The files are not byte-identical, because the extraction differs: cache addresses are kept
and there are no chained fixups.

It has no hook yet and is in no set. It is installed once a check on the target shows parity with OCLP's copy. The
builder will then fetch the IPSW's x86_64 cache itself (`tools/acquire`, pinned) and run the extraction.

## Verify

```sh
python3.14 -I -B -m unittest discover -s patches/metal-metalold/tests   # METALOLD_22D68=PATH adds the real cut
```

## Validation

NEEDS VALIDATION: not installed on any image yet. Next is an A/B on the target against OCLP's MetalOld (Metal apps,
WindowServer effects, the hello shaders).

## Revisions
- r4 2026-11-17 `requires`: os 26B131, donor 25G342, gpu intel-ivb (the HD 4000), cpu and firmware any; replaces `applies`.
- r3 2026-11-16 Declares its pack (metal-3802-extras): recipe layout format pass; its pack decides the machines (applies.models dropped); nothing it installs changes.
- r2 2026-11-15 edits/metalold.json's evidence line names the comparison instead of a private document; the edit and its bytes are unchanged.
- r1 2026-11-12 Our own MetalOld from Apple's 13.2.1 cut (cache-dylib r5) plus the declared je->nop edit; no hook, in no set.

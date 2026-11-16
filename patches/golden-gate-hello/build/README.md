# libhelloblur generator

Builds `libhelloblur.dylib` (row `libhelloblur`), which [golden-gate-hello](../README.md) installs at
`/usr/lib/libhelloblur.dylib` and OCLP's Metal wrapper loads weakly.

## Usage

```sh
patches/golden-gate-hello/build/make.sh OUTDIR                     # OUTDIR/libhelloblur.dylib, prints its sha256
python3.14 -I patches/golden-gate-hello/build/compare.py ROW_FILE OUTDIR/libhelloblur.dylib
python3.14 -I -B -m unittest discover -s patches/golden-gate-hello/build/tests   # HELLOBLUR_REFERENCE=ROW_FILE adds the comparison
```

## Inputs and outputs

- In: `src/hello_blurcache.m`, Xcode (27.2 for the row's bytes) and its macOS SDK (`HELLOBLUR_SDK` names another).
- Out: an x86_64 `MH_DYLIB`, macOS 13 minimum, manual reference counting (`-fno-objc-arc`), `-O2 -Wall -Werror`,
  install name `/usr/lib/libhelloblur.dylib`, linking only Foundation, libobjc and libSystem (not Metal: the Metal
  wrapper loads it; not AppKit: it is mapped into every Metal process), ad hoc signed with identifier
  `local.libhelloblur`.

## What it does

A constructor returns after one `strcmp` unless the process is Language Chooser or Setup Assistant. There, on the main
queue:

- **Blur cache**: hello's renderer re-runs an identical `MPSImageGaussianBlur` (sigma 8) on the same background into the
  same texture every frame. After two identical repeats of (kernel, sigma, edge mode, source, destination), and only
  for calls from `SetupAssistantSupportUI`, the encode is skipped; it is re-run every 120th repeat. The kernel and
  textures are retained while cached, so a reused address cannot be mistaken for the cached texture.
- **Continue-button warm-up** (Language Chooser): builds the glass Continue button once in a never-shown window and
  asks for its size, so the first real layout does not stall the animation (about 380 ms on first boot).

Kill switches: `HELLO_BLURCACHE=0`, `HELLO_PILLWARM=0`, files `/private/var/db/hello_blurcache.disable` and
`/private/var/db/hello_pillwarm.disable`. Unified log lines start with `hello_blurcache:` and `hello_pillwarm:`.

## Reproduction

The row's file (sha256 `9c273f39...`) is `make.sh` with Xcode 27.2 (27B52: clang-2100.4.1.1, ld 27106.1, SDK 27.2);
the same Xcode gives it byte for byte. Another Xcode writes its own linker and SDK versions into the load commands,
and the `LC_UUID` and signature follow from them: `compare.py` copies the row's UUID and linker version into such a
rebuild, re-signs it ad hoc and says whether anything else differs. The earlier row, `d471519b...` (Command Line
Tools SDK 26.5), has the same code.

## Verify

`tests/test_build.py` builds the dylib and checks its architecture, install name, minimum OS, that it links neither
Metal nor AppKit, and its ad hoc signature; with `HELLOBLUR_REFERENCE` set it runs `compare.py` against the row's
file. Nothing is executed: the dylib is x86_64 and loads only inside the target's Metal processes.

## Provenance

Written for this project; the hello blur cache was proven live in Language Chooser on the MacBookPro9,2 (57.9 to 60
fps). Dependencies: clang, codesign and otool from the Command Line Tools.

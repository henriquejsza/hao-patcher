# opencore-mbp92

The MacBookPro9,2's part of the image's OpenCore configuration (pack `mbp92`): its early Tahoe display and wired-network
kexts. Split out of [hao-opencore](../hao-opencore/README.md) (r67) unchanged; it runs just before that recipe, on the
EFI partition that `pipeline/stages/build-efi.py` made from OCLP's model data.

## How it works

`apply.sh` runs `src/early_kexts.py`, which injects the Tahoe drivers listed in `src/early-kexts.txt` (Capri
framebuffer, HD 4000, BCM5701 Ethernet, the same set as [rec-display-ethernet](../rec-display-ethernet/README.md)) and
their dependencies, in OSBundleLibraries order, into `EFI/OC/Kexts` and `Kernel.Add`, only when neither the Boot nor the
System collection has them. Drivers already in the System collection stay there: injecting a second copy makes the
kernel discard the collection's copy while other drivers still call into it.

On every recorded build all three are in a collection, so it adds nothing and `config.plist` keeps its content
(hao-opencore writes the file last). That is why `patch.json` declares no file.

## Verify

- `python3.14 -I -B -m unittest discover -s patches/opencore-mbp92/tests`.
- The build log prints `Tahoe driver already supplied by collection or EFI:` for each of the three, or
  `Early Tahoe injection:` with the kext's version and sha256.

## Validation

NEEDS VALIDATION: the split itself is not built yet. The same step was in hao-opencore until r66.

## Revisions
- r1 2026-11-16 New: hao-opencore's early Tahoe kext step (src/early_kexts.py, src/early-kexts.txt and its test), unchanged, in pack mbp92.

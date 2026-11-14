# golden-gate-shared-cache

Makes the B image of the shared-cache fold-in (owner, 2026-11-14: "The fold-in is the main effort"). The OS
cryptex's x86_64 shared cache becomes a rebuilt family that holds the libraries the image otherwise has on disk at
cache install paths, and those files leave System. dyld then loads nothing from disk that the cache also has,
`_dyld_shared_cache_some_image_overridden()` is false, and libswiftCore keeps its prespecialized metadata on with no
cache edit. This is the 26B131 port of Tahoe's `shared-cache` recipe (19 providers, installed acceptance on
Tahoe images). Only `pipeline/sets/dev-bs-test-fold.txt` has it. The A image (golden-gate-userspace r75: the switch
reads false, 113 descriptor slots nulled) stays as it is.

## Input

`rebuilt_cache` (`pipeline/inputs/25G342/`): the shared-cache generator's artifact, made from a dev-bs-test image's OS cryptex and System. The recipe reads:
- `dyld_shared_cache_x86_64*`: the family (main, subcaches, `.map`, `.atlas`);
- `retired-roots.txt`: the providers' install paths, one per line;
- `provider-provenance.json`: `path` (under `build.json` `system`) and `sha256` of every provider;
- `build.json` `inputs`: each input cache file (`.../System/Library/dyld/dyld_shared_cache_x86_64*`) and its sha256;
  `revision`, `git_commit` and `git_dirty` go into the record.

## How it works

`src/kc-hook.sh` runs `src/fold.py install` in set order, after every recipe that changes a provider and before
golden-gate-native-identities. `make.sh` stages golden-gate-userspace's `src` as `build/userspace`, so the image
build, seal, 4 KiB re-sign and Swift reference check are that recipe's own code.

1. **Roots.** The artifact's roots must include every `R` line of `src/providers.txt` (the 10 images
   golden-gate-userspace's gate counts as overridden) and may include only its `C` lines (companions the providers
   load). Any other root stops the build until its lane has reviewed it.
2. **Provider bytes.** Each root on this System must have the sha256 the artifact folded in. A provider changed
   since the artifact was made (a new OCLP, a Metal or Wi-Fi recipe revision) stops the build: rebuild the artifact.
3. **Input cache.** The artifact must have been made from this image's cache. Its recorded input files must equal
   the x86_64 files of the OS cryptex golden-gate-userspace just built. They may match as built, or with that
   recipe's prespecialization edits (`src/prespecialization-26B131.json`) taken back out and the file re-signed:
   that is the cache of an image from before r75. Either way the rebuilt family already carries every other
   in-cache repair of golden-gate-userspace (trackpad V3, EndpointSecurity selectors, CoreRoutine, MPSMatrix,
   audiomxd, Swift conformance references, the code identity carrier). The record says which one matched.
4. **Cryptex.** A new raw image gets the current OS cryptex's files with the x86_64 family replaced as a whole
   (Apple's arm64e cache and DriverKit's cache are untouched). Each file takes the old main file's owner, mode and
   flags and is re-signed with 4 KiB pages if it is not already. Every Swift metadata reference is checked, then
   the image is sealed and installed as `os.dmg` and `os.clone.dmg`. Rosetta's cache directory still links to it.
5. **Retirement and gate.** The roots are removed from System. The build stops if any image of the new family is
   still a file on System (`/usr/lib/dyld` aside).

The record is `System/Library/CoreServices/golden-gate-shared-cache.json`.

**Composition with golden-gate-userspace.** On the B image, golden-gate-userspace still builds its cryptex (with the
r75 edits, its gate passes because the providers are still on disk then); this recipe replaces that cryptex's
x86_64 family. What B drops: the r75 prespecialization edits and their gate (B overrides nothing), and every
in-cache edit of `edits/cache-*.json` as applied on the B image (the artifact carries those repairs from the image
it was made from, which step 3 proves current). No input row drops; `codeid_carrier` and the rest still feed the
cryptex build that step 3 compares against. The compat libraries (`io80211_compat`, `wifip2p_compat`,
`corewifi_compat`) are still installed, then folded in and removed from System by this recipe.

## Verify

- `python3.14 -I -B -m unittest discover -s patches/golden-gate-shared-cache/tests`: a stand-in artifact in the
  generator's format (and the Tahoe artifact's `build.json`, when it is in the store).
- `python3.14 -I patches/golden-gate-shared-cache/src/fold.py check SYSTEM ARTIFACT` (read-only): steps 1 and 2 on
  a mounted System.
- Build log: `golden-gate-shared-cache: removed /PATH` per root and one JSON line (input match, files, 4 KiB
  re-signs, Swift references, images, seconds).
- On the image: `shasum -a 256` of `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_x86_64*`
  equals the artifact's files (modulo 4 KiB re-signs listed in the record); no root of `retired-roots.txt` exists;
  with `SWIFT_DEBUG_ENABLE_LIB_PRESPECIALIZED_LOGGING=1` no "Disabling prespecialized metadata" line.

## Validation

NEEDS VALIDATION: not built or booted. Host tests pass with a stand-in artifact; the generator's artifact for
26B131 does not exist yet, so the row `rebuilt_cache` does not either and `status` is `unfinished`. It becomes
`experiment` (r2) in the commit that adds the row.

## Revisions
- r1 2026-11-14 New: the 26B131 B image's OS cryptex gets the rebuilt x86_64 family with the on-disk providers folded in, after checking the reviewed roots, the provider bytes and the input cache; the roots leave System and no cache image may stay on disk.

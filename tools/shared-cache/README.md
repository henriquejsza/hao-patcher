# shared-cache

Rebuilds the x86_64 dyld shared cache of macOS 27 with libraries from the disk folded in as cache images
("providers"), with the ObjC tables, Swift prespecialized metadata, patch table and code signatures regenerated for
the new image set. On a hao image, OCLP and hao replace some of the cache's libraries on disk (Metal, Wi-Fi, video
decode, multitouch, Live Text). dyld then treats those cache images as overridden: it loads the disk copies, turns off
Swift prespecialization for the processes that load them and cannot use conformance caching. Folding the replacements
into the cache removes those overrides.

The tool reads Apple's cache and libraries from the user's own image and writes a new cache family next to it. It
ships as code only: no Apple binary, cache or library is part of this repository, and the family it writes is an
Apple-derived file that stays on the user's Mac.

Native acceptance of a rebuilt family is established only by booting it (a laptop test of the image that installs
it); a passing build and readback do not prove it.

## Requirements

- A Mac with Apple silicon or an Intel Mac. Built and checked on Apple silicon with macOS 27.2 and Xcode 27.2.
- Xcode (the full app: `xcodebuild` builds Apple's cache builder) and its command-line tools.
- Python 3.14 (`python3.14` on the `PATH`).
- Apple's published dyld source, tag `dyld-1378`, from
  [apple-oss-distributions/dyld](https://github.com/apple-oss-distributions/dyld/tree/dyld-1378).
- The macOS 27 26B131 system to rebuild, mounted read-only: the System volume (or its snapshot), the OS and App
  cryptexes and the Data volume. A hao image built with `tools/hao` has all four.
- About 30 GB free: the work folder holds about 21 GB during a build, the family about 7 GB.

## Build

```sh
git clone --depth 1 --branch dyld-1378 https://github.com/apple-oss-distributions/dyld.git DYLD_SOURCE

# Apple's cache builder and the host adapters, from DYLD_SOURCE plus toolchain/source.patch and
# toolchain/added-source; built for this Mac's architecture (--arch arm64|x86_64 to choose).
python3.14 -I tools/shared-cache/toolchain/make DYLD_SOURCE TOOLCHAIN

# The fold-in family: the 26 providers of features/fold-in-26B131.json, Apple's Swift entries kept,
# no prebuilt loader sets (dyld uses its just-in-time loaders).
python3.14 -I -B tools/shared-cache/make \
  --system SYSTEM --os OS_CRYPTEX --app APP_CRYPTEX --data DATA \
  --features fold-in-26B131 --no-swift-catalog --no-prebuilt-loaders \
  --toolchain TOOLCHAIN --work NEW_WORK --output NEW_FAMILY
```

`SYSTEM`, `OS_CRYPTEX`, `APP_CRYPTEX` and `DATA` are the mount points of the image's System, OS cryptex, App
cryptex and Data volume. Instead of the four, `make IMAGE` mounts a disk image (`IMAGE` a `.img`, or a folder with
`target.img`) read-only itself; an image repository (a folder with `image.json`) is exported first with
`tools/bin/ssdimg` (`SSDIMG` names another copy). `NEW_WORK` and `NEW_FAMILY` must not exist.

A provider's bytes come from the System given, at the path its feature names. A feature file may instead name a
file outside the System for a provider (`"sources": {"NAME": {"path": FILE, "sha256": HASH}}`), for example a
library built after the image; the hash is checked before the build.

`--swift-catalog CATALOG` adds Swift prespecialized metadata from a catalog that `make swift-capture` made for the
same Mach-O build (it is captured on the target, a 26B131 x86_64 system); its entries go into libswiftCore's
pointer-keyed table next to Apple's. Without it (`--no-swift-catalog`) Apple's entries are kept as they are.

## Outputs

`NEW_FAMILY` holds:

- `dyld_shared_cache_x86_64` and its subcaches (`.01` ... `.33`), `.atlas` and `.map`: the family, signed.
- `retired-roots.txt`: the providers' install paths. The image that installs the family removes these files from
  the disk (or keeps them; then dyld still loads the disk copies).
- `provider-provenance.json`: each provider's source (system or file), install path and sha256.
- `optimizations.json`: what the readback of the final family found: images, ObjC roots and header-infos, Swift
  keys (retained and added) and relocated pointers.
- `build.json`: the generator's revision (the newest line of Revisions below) and git commit, the date, and the
  path and sha256 of every input. It names the build machine's paths; it stays with the family.

The build refuses, rather than guesses, when an input does not fit: an import no image defines, a provider outside
the given System without a pinned source, an interpose section left in the family, a table that does not read back.
The refusal names the image and symbol.

## How it works

1. **Providers.** Each provider is read from the System (or its pinned source) and laid out like a cache image.
   Every image that depended on the cache image it replaces is bound to the provider's exports; a symbol the
   provider lacks gets dyld's missing-symbol marker (a non-weak import), null (a weak import) or keeps its old
   target (an ObjC class reference whose old class bytes stay in the cache), and anything else stops the build.
2. **Interposers.** dyld ignores `__interpose` in cache images, so each interpose tuple of a provider becomes cache
   patches: every use of the original that the cache's patch table lists is retargeted to the replacement, while the
   interposer's own calls through keep the original. The section is zeroed and renamed `__ipose_applied`.
3. **Cache.** Apple's cache builder (built from dyld-1378 by `toolchain/make`) lays out the new family. The ObjC
   selector, class and protocol tables, header-infos and image indexes are rebuilt for the new image set; Swift's
   prespecialized tables are rebuilt with Apple's entries kept and any catalog entries added.
4. **Readback.** The signed family is read back independently of the writer: image list, loader fields, ObjC roots
   in both dyld's and libobjc's views, every Swift key and every relocated pointer. `optimizations.json` records it.

`tools/live-text/interpose-check FAMILY RUNTIME` checks step 2 on a family through `ipsw`, independently of this
tool.

## Other commands

`make` takes a subcommand instead of an image as its first argument for the Swift metadata work: `swift-capture`
(prepare a capture bundle for the target, or normalize a capture into a catalog), `inventory` and `swift-select`
(list and subset a catalog), `prespecialization-overrides` (edit libswiftCore and dyld so prespecialization stays on
with overridden images, the alternative to folding them in), `fastpaths`, `metadata-expand`, `swift-coverage` and
the probes listed in `make`. Each prints its usage with `--help`.

## Verify

```sh
python3.14 -I -B -m unittest discover -s tools/shared-cache/tests
```

The host suite (about 470 tests, a few seconds) uses synthetic Mach-O and cache fixtures; it needs no Apple data.
Tests that need a real cache, a built toolchain or a target runtime skip unless their variables are set:
`CACHE_TOOLCHAIN` (a `toolchain/make` output), `SHARED_CACHE_STORE` (a store with saved catalogs),
`SWIFT_WITNESS_RUNTIME_TOOLCHAIN`, `SWIFT_WITNESS_CONSUMER_BUNDLE`.

FACT (2026-11-15): from a fresh clone (6abda8e6 and ff6708d2), with a toolchain built from GitHub's `dyld-1378` both
for arm64 and for x86_64 (its adapters run under Rosetta on an Apple silicon host), the fold-in build reproduces the
reference family made by r83 (cache UUID 7c4bc5cb): 39 of its 40 files byte for byte. `build.json` differs only in
date, commit, revision, input paths and the toolchain's compiled objects (they embed their build folder). OPEN: a
build on an Intel Mac itself.

## Validation

NEEDS VALIDATION: no family built by this revision has been booted. The reference family it reproduces (cache UUID
7c4bc5cb, made by r83) is installed by the `dev-bs-test-fold` set; its laptop test is pending.

## Licences

See [NOTICE.md](NOTICE.md): the vendored frida-gum and Swift headers and Apple's open-source headers and the patch
against dyld keep their own licences. The rest is covered by the repository's MIT license.

## Revisions
- r84 2026-11-15 Public, in hao-patcher `tools/shared-cache` (moved from the project's development tools, r83 code): `toolchain/make --arch`
  builds Apple's cache builder for the Mac it runs on (arm64 or x86_64; before, arm64 only) and the host adapters
  link for the toolchain's architecture (`host_tools.toolchain_arch`); no default path outside the repository (store:
  `SHARED_CACHE_STORE`, else the repository's `store/`; image tool: `SSDIMG`, else `tools/bin/ssdimg`); this README
  rewritten for an end user; a `.git` folder in DYLD_SOURCE (a clone) is not copied into the toolchain. The family's
  bytes are unchanged (Validation).
- r83 2026-11-15 A reference from an Apple image to a class of a replaced image that the replacement does not define
  keeps its original pointer (to the old class bytes, which stay in the cache) instead of stopping the ObjC recipe;
  the metadata report lists them (`retained_external_class_references`). FACT: OCLP's Metal wrapper (re-exporting
  MetalOld) lacks Apple 27 Metal's `_MTLTensorAuxiliaryPlane`; with Metal overridden on disk (8fb92d5) Apple's cache
  images hold the same pointers today. OPEN: whether anything messages that class on this system. The patch stage's
  policy for uses of such absent exports (`run_patch.missing_use_policy`): a non-weak GOT gets dyld's missing-export
  marker as before, a weak import null, an ObjC class/metaclass PATCH use keeps its pointer; anything else is still
  refused. FACT (this run): 61 uses of Apple 27 Metal's tensor API absent from the wrapper, 26 marker, 3 weak-null,
  32 retained (isa/superclass fields of the Apple-silicon AGX drivers, not loaded on the MBP9,2).
- r82 2026-11-15 Providers' `__interpose` tuples become cache patches (project decision, 2026-11-14): dyld
  ignores interposing in cache images (dyld-1378 DyldRuntimeState.cpp:1310), and the Live Text interposers
  (libLiveTextPolicy 2 tuples, libhao_input_coherence 19, libLiveTextLibrary 3) would lose their hooks once folded in. Flat-namespace imports
  (ordinal -2) now resolve to the single image that defines the symbol itself (`FinalGraph.resolve_flat`); none is
  weak_null / missing_strong, several a refusal (FACT on 262FA161: every e5rt original is defined only by Espresso).
  For each tuple, every patch-table use of the original (GOT and PATCH, v4 table) is retargeted to the replacement in
  its existing slide-chain member (`run_patch.interpose_edits`), as is any other provider's bind to it. The
  interposer's own binds to its originals keep the original (its calls through) and are not listed in the patch table,
  so every listed use of an interposed original holds the replacement. OPEN: a root of the original's image would
  not reach those call-through slots. The tuples carry no fixups and are zeroed; the section is renamed
  `__ipose_applied` with type S_REGULAR. Gate: the producer refuses a family with an interpose section in any image
  (`cache.interpose_sections`). An original may also be a provider's export: libLiveTextLibrary (3 tuples) hooks
  `MTLCreateSystemDefaultDevice`, `MTLCopyAllDevices`, `MTLCopyAllDevicesWithObserver` of Metal, a provider replacing
  Apple's Metal; Apple's uses of the old Metal migrate to the replacement instead of the new Metal export. On disk
  dyld interposes only in processes that load the interposer; baked into the cache the hook is in every process.
  FACT (8fb92d5 providers): Metal weak-links libhelloblur, which links LiveText.dylib, which links all three
  interposers, so every process that uses Metal, Espresso or their callers has them loaded already. Tests: `tests/test_interpose.py`, `tests/test_imports.py` (flat lookup). OPEN until metal's
  `interpose-check` passes on the full fold-in family.
- r81 2026-11-14 Producer port to macOS 27, layers 1-2 (option B: the images dyld finds overridden on disk are folded in):
  `CacheFamily` takes the subcache and image counts from the header (26B131: 6 and 3,945) instead of 25G241's
  6/3,608, and accepts the image row's last word on 568-byte headers. Writers take the header size from the source
  cache: 568-byte headers carry the source's 16 extra bytes (FACT on 262FA161: `07000001 03000000` and 8 zero bytes
  in all 7 files, read as cputype 0x01000007 / cpusubtype 3), mapping, slide and image tables move by 16 bytes.
  Image rows keep their last word; a new row takes 1 on 27 (FACT: 3,941 of 3,945 rows are 1, four libSystem members
  are 2; mtime and inode are 0 in every row). OPEN: what the word means. The 25G241 relayout fixture keeps its pins.
  Main's TPRO records (header +512; 26B131: main RW2 and .06 RW2, 16 KB each; subcaches list none) are carried
  after the subcache table, and no metadata slot may overlap one. Layer 5: FACT on 262FA161, the descriptor map's
  u16 aux value is the ObjC header-info index (all 365,361 occupied slots; none match the dyld image table), which
  the ObjC table builder's remap already uses; it now accepts prespecialization data 1.5.
  New `make` options for the fold-in's first version: `--no-swift-catalog` (no Swift additions; Apple's
  entries stay) and `--no-prebuilt-loaders` (`tools/finalize-no-loaders.py` replaces the two loader steps: the
  main header's dylibs-set, program-pool and program-trie fields are zeroed and header-info loader fields must be 0;
  dyld then uses JIT loaders, per runtime's reading of 26B131's dyld). OPEN: who reads the header-info loader field
  on 27; no family built yet.
- r80 2026-11-14 `prespecialization-overrides --conformance`: also make libswiftCore's
  conformance call false, after setting to the sentinel every dyld conformance bucket (type, metadata, foreign
  tables) whose key or all of whose conformances lie in an overridden image. It refuses when a conformance declared
  in an ordinary cache image is keyed on an overridden type or protocol: today that image's section is scanned and
  resolves to the disk copy, and with the call false it would be lost. FACT on 262FA161 with the measured override
  list: refused, 5 metadata-table rows (WiFiSettingsKit conformances on CoreWiFi types); 438 + 5 + 4 buckets would
  otherwise go and 5 mixed foreign groups stay (dyld returns only a loaded duplicate).
- r79 2026-11-14 Read macOS 27 (26B131) x86_64 caches, and `prespecialization-overrides` (option A, prespecialization phase 1). Readers: the 568-byte cache header (26: 552), image rows whose last word is
  used on 27 (1, or 2 for four libsystem images), LibPrespecializedData 1.5 (26: 1.4; the metadata map stays at +24,
  now dyld's pointer table slot 1; +48 is a new empty pointer-keyed table), and no default selector base (read from
  the input cache's ObjC header, v2 only; 27's v4 header is refused until checked). `prespecialization-overrides`
  keeps prespecialized metadata on when cache images are overridden on disk (hao images: golden-gate-dyld-internal):
  it finds libswiftCore's two switch-off calls by their bytes, gates on no pointer-keyed entry or catalog key in an
  overridden image, nulls descriptor-map slots whose descriptor is in one, leaves the conformance site alone, and
  writes hao-patcher-shaped edits (or re-signed copies with `--apply`). FACT on cache 262FA161 with the measured override
  list: 2 + 113 edits; 0 of 2,762 Apple entries and 0 of 1,282 catalog keys blocked; installed 8fb92d5 files re-sign
  with no bytes changed outside the edits (evidence kept with the project's research records).
  Running it on a laptop is OPEN.
- r78 2026-11-02 Add `inventory` (one row per catalog entry: kind, owner and referenced images,
  installed state against the cache, introducing catalog/session, requesting processes) and
  `swift-select` (a catalog subset by those columns plus its owned closure), owner 2026-11-02: know
  whether the Swift metadata is current, what it goes to, and build from itemized inputs. Fix
  `build.json` `revision`: a constant in `provenance` stayed at 75 through r76/r77; it is now read from
  this list (this commit).
- r77 2026-11-02 Remove the research tools imported in 1c791cf that no make step, test, README or other
  tool calls (owner: clean the repo of what we won't use; README.md rule 8). src/dyld_rebuild:
  certificate_publication, dev_payload, marker_reachability, rc_inputs, regeneration_workspace,
  release_manifest, run_marker_policy, swift_combined, swift_miss_inventory, swift_request_replay,
  wifiaware_abi; src/wifi_shim/; tools: audit-marker-reachability, audit-wifiaware-abi, emit-provider-objc,
  materialize-cache-family, plan-objc-transfer, prepare-graphics-fold-identities,
  prepare-graphics-method-policy, prepare-objc-inputs, prepare-swift-combined, replay-swift-requests,
  test-wifi-datapath (.py), wifi-shim/, combine-null-subject/, swift-normal-collector/,
  cross-process-cache-probe/, native-cache-probe/, loader-generator/export-reader.cpp. None is a
  provenance or verify step of this README or of the selected rebuilt_cache artifact (this commit)
- r76 2026-11-01 Pair every table call and return when summarizing a lookup. The native r75 trace
  exposed the old one-table assumption after the normalized fallback ran; retain both results and
  reject missing, mismatched or impossible fallback sequences (this commit).
- r75 2026-11-01 Match redirected lookup entry/return probes at the installed wrapper and observe both
  pointer-table calls. Native r74 capture found every lookup incomplete: its original-body return had an
  extra wrapper stack frame. Follow indirect calls through the runtime configuration, retaining original
  table-call sites; the complete wrapper result includes normalized hits (this commit).
- r74 2026-11-01 Profile a redirected metadata lookup with `runtime-probes --runtime-recipe`.
  Validate the installed entry bytes against the producer recipe, then decode the original body without
  modifying the cache. Exact-pointer hit/miss counts remain comparable; final generic return counters
  include secondary lookup adoption. The previous profiler could not follow the out-of-function redirect
  and stopped with no reachable return (this commit).

- r73 2026-11-01 Add a secondary conformance-descriptor metadata map after exact-pointer lookup misses.
  Swift's MetadataCacheKey treats witness tables with the same conformance descriptor as equal; a fresh
  Optional<CGSize> witness previously missed the installed exact key and created a second FamilyCircleUI
  modifier identity. Keep the native policy and exact lookup first, preserve every catalog identity, and
  relocate a sorted descriptor/arity index with the map. Source-built native proof completes all 75,972
  metadata and 17,636 witness records, including associated-type-first checks; installed acceptance OPEN
  (this commit). ABI reference: the pinned Swift toolchain's stdlib/public/runtime/MetadataCache.h,
  areWitnessTablesEqual; extends r52's equivalent-key allocation to runtime lookup.

- r72 2026-11-01 Reconcile saved request outcomes against the corrected catalog without regenerating completed
  batches. Separate canonical aliases and unavailable owners from unsupported types; keep installed misses and
  time attribution unknown until measured (this commit).
- r71 2026-11-01 Audit actual installed associated-witness slots against the
  original image initializers during final cache readback. Add a read-only
  `witness-initializers --installed` audit for existing caches. Count aliases once:
  r14's 28 affected lookups share 24 stale slots in 20 physical tables. This checks
  emitted bytes independently of the catalog that the generator normalized;
  native Photos/editor acceptance remains OPEN (this commit).
- r70 2026-11-01 Restore associated witness initializers in inherited catalogs and
  at cache installation. Photos on r14 reached an Optional through a retained
  witness memo before Swift registered its metadata-state entry. The earlier
  ea01323 capture fix corrected new records but incremental catalogs retained 24
  stale slots in 20 witnesses. Read original pattern/resilient/default typerefs
  from the input images, preserving every metadata and witness identity. Add
  `witness-initializers CACHE CATALOG OUTPUT` to audit/normalize a complete catalog.
  The native verifier exercises associated types before warming all metadata.
  Native Photos launch/editor and installed cold-witness validation remain OPEN;
  do not select a replacement cache on host checks alone (this commit).
- r69 2026-11-01 Require the descriptor image to be loaded before reflected native
  construction. Shared-cache residency alone allowed an iOSSupport SwiftUI descriptor
  to construct an orphan record in the macOS helper despite its owner's failed load;
  the fresh verifier correctly refused that catalog. Preserve the unavailable-image
  outcome before calling the constructor, without weakening verification (this commit).

- r68 2026-11-01 Classify inventory names with upstream type trees before execution.
  Six Jet dependency names contained unbound generic contexts and aborted the native
  runtime with a metadata-pack diagnostic. Keep those requests unresolved. Also
  report an unavailable reference per constructor: a Weather widget leaf belonged
  to iOSSupport WidgetKit, which the macOS collector could not load, and formerly
  terminated the whole batch (this commit).

- r67 2026-10-31 Feed multiple saved inventories and reflection graphs directly into
  metadata-expand's native construction/export/verification workflow. The manual
  inventory bridge omitted the resolver load image and failed in host preparation;
  reuse swift-discover's all-observed resolver semantics and preserve private-context
  blockers. FACT: 412 tests pass (16 optional skips). The r66 Control Center batch
  adds 3,606 metadata and 1,047 witnesses, with zero isolated native verification
  failures; installed adoption remains OPEN (this commit).

- r66 2026-10-31 Preserve image-backed metadata identities from conformance observations
  as portable leaf constructors. Private nongeneric names do not round-trip, but their
  recorded metadata already belongs to an image; use its UUID/section reference and
  the existing dependency initializer. Ambiguous and process-local observations remain
  unresolved. FACT: saved Control Center planning selects 6,429 roots, up from 5,615;
  native static-leaf identity and planner ambiguity regressions pass. OPEN: target
  generation, installed adoption and speedup (this commit).

- r65 2026-10-31 Resolve reflected generic protocol requirements through ordinary Swift
  conformance lookup, then use the existing witness exporter. The reflection planner
  still rejected witness-dependent constructors even though metadata-expand supported
  their payloads. FACT: native Set<Optional<UInt32>> constructor identity agrees with
  name lookup; missing conformances remain failures. The saved Control Center inventory
  selects 5,615 of 20,957 roots, formerly 2,789. OPEN: matching-target generation,
  installed adoption and speedup (this commit).

- r64 2026-10-31 Align collector dependency initialization with the installed verifier: retain
  compiler-canonical specializations and accept foreign-template aliases only when the accessor and
  `swift_checkMetadataState` agree on the complete canonical identity. The collector omitted both
  cases and rejected 486 r12 roots before their own identity check. FACT: saved dependency closures
  classify 163 as static-only, 319 as foreign-only and four as both; native callback fixtures preserve
  disagreement/incomplete-state failures. OPEN: matching-target recollection (this commit).

- r63 2026-10-31 Read the five disk images rejected during shader enumeration: allow final empty
  export-trie edges and bind streams ending at their byte extent; decode both absolute and relative
  64-bit chained pointers and reuse the existing import decoder for signed table addends. The old
  readers accepted only a subset of the formats present in the target. FACT: all five open with zero
  selector-read errors; all 121 libgnsdk_manager exports match Apple dyld_info. These are reader changes;
  generated-cache installation and runtime behavior remain OPEN (this commit).

- r62 2026-10-31 Use shared provenance for runtime and fast-path probe bundles, including their source inputs and target cache UUID. Their local writers still reported r35 after later generator changes; record the completed r61 full-cache readback (this commit).
- r61 2026-10-31 Size Swift table reservations from key/value extents and Apple's maximum writer capacity. The fixed 2 KB per-record estimate made the expanded catalog exceed the runtime entry's jump range despite ample space for its actual tables; retain all records and existing relocation checks (this commit).
- r60 2026-10-31 Correct artifact provenance to the current generator revision; r59 updated the component frontend but left the shared provenance writer reporting r58 (this commit).
- r59 2026-10-31 Reuse unchanged component frontends when expanding an app dependency selection. Analyze changed or additional binaries, preserve constructor dependencies and saved resolution scope, renew analysis when cache binaries change, and recalculate generation outcomes (this commit).
- r58 2026-10-31 Compare retained owned aliases transitively by constructor identity. Matching only immediate installed references still duplicated seven parent records that referenced equivalent retained aliases under different IDs (this commit).
- r57 2026-10-31 Match retained keys after binding image and source-installed owned references. Replaying an expanded baseline changed reference spelling and falsely added 298 aliases without adding any native lookup keys or payload; preserve original records and distinct keys (this commit).
- r56 2026-10-31 Attribute verified expansion results to existing app manifests by exact binary identity, preserving missing analysis and referencing shared discovery edges instead of duplicating them. Correct the older foreign-initialization description to match the target evidence (this commit).
- r55 2026-10-31 Verify ordinary lookup against its native-selected constructor and report uncovered native results separately from catalog adoption. Requiring every direct variant to be selected by ordinary lookup contradicted unmodified runtime behavior. Preserve failure reports and component generation attribution when verification fails (this commit).
- r54 2026-10-31 Follow ordinary conformance selection through the native matching superclass and export its supported dependency closure. Direct witness constructors can differ from ordinary selection even without replacements; preserve both paths and expose unsupported selected dependencies (this commit).
- r53 2026-10-31 Initialize foreign dependencies before exact-key replay, including those without completion functions. Their missing state-cache entries crashed ordinary conformance lookup; native accessor/state agreement proves foreign template aliases without relaxing catalog identity checks (this commit).
- r52 2026-10-31 Share canonical metadata across exact keys whose witness arguments have the same conformance descriptor, preserving every key and catalog record. Separate allocations disagreed with Swift's runtime identity. Allow saved construction evidence with an explicit native verification adapter (this commit).
- r51 2026-10-31 Preserve associated-requirement symbolic initializers when exporting witnesses. Captured completion memos bypassed singleton initialization in a fresh process, causing the expanded catalog's native replay to crash (this commit).

- r50 2026-10-31 Attribute native constructor faults, preserve their evidence and retry with explicit unresolved results in a fresh worker. A target framework's null imported accessor previously terminated the entire recursive expansion (this commit).
- r49 2026-10-31 Exercise cached reflection inventory against a complete target component. The matching Swift reader fix uses remote references for fallback type strings instead of dereferencing target-relative pointers in host buffers (this commit).
- r48 2026-10-31 Read compiler and native JSON Lines by newline, preserving Unicode separators within type expressions. Root cause: the full framework walk reached SwiftUI expressions containing U+0085 and Python splitlines split valid JSON records (this commit).
- r47 2026-10-31 Preserve inherited LC_RPATHs through cache-to-disk dependencies and add explicit target-prefix mappings for cryptex inputs. Root cause: cached images discarded caller paths, and `/` overlays could not resolve Safari's cryptex-prefixed helpers; bundle links could also resolve against the host (this commit).
- r46 2026-10-31 Index runtime connections by client and preserve unconfirmed activation requests as candidates. A client request alone previously marked its service executable as observed (this commit).
- r45 2026-10-31 Follow library, bundle, launchd-service and supplied runtime connections into per-app manifests and the existing metadata generator; Safari main-executable zero requests missed six generated SafariSharedUI records. (this commit).

- r44 2026-10-31 Expose upstream reflection inventory through the existing cache MemoryReader bridge; previously linked framework bytes only resolved references from explicitly scanned binaries. (this commit).

- r43 2026-10-31 Allow empty constructor selections to retain and verify the existing catalog: SystemUIServer and loginwindow have no executable static Swift requests, which the old nonempty-recipe guard incorrectly rejected (this commit).
- r42 2026-10-31 Export ordinary metatype closures through the shared graph, allocate a separate registered map and source-built runtime consumer, and verify native names/value operations; preserve reflected binary identity and keep unsupported ABI families explicit (this commit).
- r41 2026-10-31 Add metadata-expand from target binaries or portable requests through explicit runtime/saved adapters, graph export, allocation and native verification; remove superseded witness generation/merge orchestration and retain prior evidence separately from new results (this commit).

- r40 2026-10-31 Consolidate generic-value and protocol-witness exporters by ABI family and fold runtime outcomes into the portable graph; keep generated, retained, unresolved and compiler-provided facts separate from unmeasured installed/native use (this commit).

- r39 2026-10-31 Introduce the shared portable metadata graph and bind static/reflected constructors through image sections at execution; reject stale cache-bound recipes instead of preparing a bundle against the wrong cache (this commit).

- r38 2026-10-31 Continue generation from complete dependency catalogs, preserving witnesses and resolving installed metadata/witness keys from their separate maps; previously only metadata-only baselines were accepted (this commit).

- r37 2026-10-31 Preserve the actual ABI metadata kind of rejected dependency leaves through root coverage, so the next generation work uses observed dependency families rather than inferred type-name subtrees (this commit).

- r36 2026-10-31 Recognize canonical compiler-specialized metadata through upstream Swift ABI APIs and report existing coverage separately; do not reject its trailing flags or generate duplicate identities (this commit).

- r35 2026-10-31 Normalize typed metadata/witness self-edges as intra-record relocations; associated-conformance slots that refer to their own witness table previously looked like constructor cycles (this commit).

- r34 2026-10-31 Preserve complete dependency catalogs during laptop verification: compare exact installed identities instead of reserializing existing witness-dependent metadata (this commit).

- r33 2026-10-31 Resolve combined catalogs from installed tables and prepare exact-key native verification without replacement records or hooks; preserve metadata tracing for witness-dependent keys (this commit).
- r32 2026-10-31 Integrate metadata/witness catalogs into the producer with separate registered tables, a source-built lookup honoring native policy, and an offline Frida-relocated entry/fallback; keep installed acceptance explicitly unvalidated (this commit).
- r31 2026-10-31 Allocate metadata and witnesses together with separate lookup tables; replay the entire relocated candidate through Swift's metadata lookup and ordinary conformance paths, preserving state registration and ABI-defined lazy/static initialization (this commit).

- r30 2026-10-31 Record actual witness constructor keys during static recipe replay, traverse upstream-described base-protocol dependencies, and serialize complete metadata/witness closures into a distinct dependency catalog pending image integration (this commit).
- r29 2026-10-31 Add a reproducible isolated witness-consumer experiment using upstream Swift schemas and Frida Gum; exercise the internal runtime entry because ordinary conformance lookup bypasses the exported wrapper (this commit).
- r28 2026-10-30 Construct opaque return metadata through the target runtime API from upstream-decoded parent signatures; preserve canonical protocol resolution and existing serialization limits (this commit).
- r27 2026-10-30 Expose target-cache bytes, decoded pointers and linked-image symbols to upstream Swift's reusable semantic resolver; preserve unresolved dependencies without target execution (this commit).

- r26 2026-10-30 preserve reflected generic-constructor planning and canonical runtime generation; classify every selected blocker and add 11 serializable records in the ControlCenter Optional trial. Retain the unvalidated full-key recorder for future work; static binary analysis now defines coverage (this commit).

- r25 2026-10-30 replace handwritten live dependency decoding with Swift Remote Mirror; normalize image-backed contexts, retain variants and unresolved families, and capture conformance observations through upstream APIs. Preserve the existing generator where the upstream builder lacks class/layout support (this commit).

- r24 2026-10-30 capture live dependency graphs read-only and replay their saved pages offline; retain witnesses, tuples, functions and app-owned descriptor evidence. Serialize complete noncopyable values while continuing to reject incomplete witnesses, closing the last of 332 exact-key requests (this commit).

- r23 2026-10-30 initialize lazy value/class dependencies and register installed generic dependencies before exact-key replay; fixes fresh-helper null metadata-state crashes. Carry the full installed dependency closure, retain address-independent new IDs, and add native collector regressions. Native replay adds 331 entries; next-cache adoption remains open (this commit).

- r22 2026-10-30 recover stable exact generic keys from saved runtime misses to bypass anonymous-name lookup; retain process-local/type/witness/class blockers in the report and prepare UUID-bound capture recipes (this commit).

- r21 2026-10-30 Accept four-byte-aligned Swift layout pointers in fresh metadata
  assembly, retaining the one-page extent. The expanded build exposed one packed
  enum pointer rejected by the inherited ObjC-only eight-byte assumption; r19 had
  corrected existing-page edits but missed this separate new-page writer. Add a
  signed assembly and runtime-slide regression (this commit).

- r20 2026-10-30 Port the archived witness-map capability probe with cache-derived
  identities and addresses. Select the debug library inside its own helper, avoiding
  DYLD overrides and tracer environment contamination. Native v1.4/v1.5 controls
  complete cleanly but show no automatic witness-map calls (this commit).

- r19 2026-10-30 Decode nested enum layout programs and capture their typed metadata
  dependencies. Relocate resolved tag functions and packed pointer fields, placing
  allocations so pointers never straddle pages. Native retry adds 208 records;
  copied Combine enum layouts and full-catalog slide encoding pass (this commit).

- r18 2026-10-30 Read metadata layout prefixes only when HasLayoutString is set;
  the unconditional read rejected unrelated preceding words. Native retry adds
  1,486 records. Scope utilization to the traced executable so shared type names
  do not attribute Control Center hits to other processes (this commit).

- r17 2026-10-30 Add reproducible native Swift conformance checks. Bracket the
  cache-derived caller because libdyld's tail-jump has no return probe; join
  descriptor-keyed hits even when the metadata argument is null. Native r9
  normal queries hit with SwiftUI/Metal loaded, without forcing gates (this commit).

- r16 2026-10-30 Capture runtime-generated flat layout strings and relocate their
  typed metadata references. Reject unknown bytecode explicitly instead of
  rejecting every process-local layout. Native capture resolves all five remaining
  r9 variants; exact-key verification adopts all 7,606 installed r9 entries
  (this commit).

- r15 2026-10-30 Retain metadata variants by pointer key instead of dropping
  duplicate type names; preserve semantic module loads when verifying captured
  payloads. Exact-key verification exercises each installed variant, and coverage
  sums variant utilization without inflating the observed type count (this commit).

- r14 2026-10-30 Package the catalog and full verification recipe with the
  coverage report through the generator entry point. One dated artifact now
  supplies the cache build, the type coverage map and the verification bundle
  (this commit).

- r13 2026-10-30 Include payload and witness images in the full-catalog
  verification recipe. Root owners alone loaded only libswiftCore for Optional
  entries and omitted the frameworks needed to resolve their payload types
  (this commit).

- r12 2026-10-30 Normalize explicitly recovered completed prefixes after a native
  resolver abort. Keep the original incomplete trace and failure distinct from
  a complete native capture; never combine addresses from separate processes
  (this commit).

- r11 2026-10-30 Attempt all inventoried roots, including composite and app type
  spellings. Add a per-process coverage report joining generation, installation
  and measured use without treating unresolved ownership as a generator gap
  or an installed entry as a runtime hit (this commit).

- r10 2026-10-30 Stop a parent capture at a rejected dependency and preserve its
  leaf failure in coverage. Swift's name builder crashed on a TeaFoundation
  Optional tuple/function after its dependency had already been rejected. The
  fixed native capture completed all 10,052 Optional roots (this commit).

- r9 2026-10-30 Resolve imported ObjC class owners for Optional capture from the
  supplied cache. The shared __C namespace named 896 images; treating that as one
  Swift module unnecessarily preloaded nearly the whole cache (this commit).
- r8 2026-10-30 Generate an Optional capture recipe from the complete saved type
  inventory, including app-defined, collection, tuple and function wrappers the
  previous display-prefix owner selection omitted. Preserve per-process coverage
  and unresolved owner information for every selected type (this commit).
- r7 2026-10-30 Bind private Swift/ObjC instruction probes by absolute address and
  the target's cache slide: on-device DTrace lacks local symbols and rejects
  export offsets beyond their function extent. Move catalog matching off-device
  to remove catalog-dependent program growth. Validated on the live owner session
  without restarting ControlCenter or rebooting (this commit).
- r6 2026-10-29 Extend Optional-only generation to generic structs/enums and owned
  dependencies; derive module owners from the cache and discover across processes.
  Exclude the runtime's zero-fill pool from reusable image references, preserve
  the base catalog, size variable allocations and count multi-argument table hits
  in plain trace output. Generic capture/registration awaits the shared boot (this commit).
- r5 2026-10-29 Add per-catalog request/result counts and a full-catalog native
  adoption verifier. Follow the public generic metadata trampoline to its real
  return, because the broad pid return probe included unrelated functions.
  Reuse lookup frame slots; report orphaned rows as trace loss (this commit).
- r4 2026-10-29 Trace pointer-table calls at cache-derived Swift call/resume sites.
  The aux-kc laptop run failed compilation because DTrace could not resolve the private
  dyld implementation symbol used by r1-r3. Resolve direct calls or cache stubs
  offline and observe ABI registers around the call; no private dyld pid probe is
  required. Native validation is OPEN for the next shared boot (821829d).
- r3 2026-10-29 Report the actual Optional layout on capture failure: the original
  message hid which check rejected entry 226. Two subsequent native captures
  completed all 412 records with identical catalogs; the intermittent rejection
  remains unexplained (9307fa9).
- r2 2026-10-29 Generate Swift layouts from semantic names on the matching runtime,
  relocate and register merged metadata in the cache build, and read back Swift
  and ObjC registration from the signed family. The archived expansion had no
  production registration path and its addresses/layouts belonged to 25G241 (ef5f5f1).
- r1 2026-10-29 Derive Swift/ObjC runtime probes from the selected cache: archived
  lookup traces were bound to 25G241 and did not establish 25G332 behavior (261b41b).

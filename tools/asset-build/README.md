# asset-build

Builds a release asset of hao-patcher from this checkout with Xcode and compares it with its input row, so a user
can make every "ours" asset from the tagged source instead of downloading it.

```sh
python3.14 -I tools/asset-build/asset-build list
python3.14 -I tools/asset-build/asset-build ROW OUT [--hao-runtime CHECKOUT]
```

`OUT` is a new folder (a file asset is written as `OUT/NAME`). The command prints `SHA256 ROW`, the sha256 as the
row defines it (`pipeline/lock.py`, so a `# hash:` line applies), and exits 1 when that is not the row's.
`codeid_carrier` also needs a clean hao-runtime checkout at the commit `asset-build` names.

| Row | Producer | Compared |
|---|---|---|
| display_state_shim | tools/display-state-shim | the dylib |
| io80211_compat, wifip2p_compat, corewifi_compat | patches/golden-gate-userspace/src/{io80211,wifip2p,corewifi}/make `build()` | the dylib |
| windowserver_filter_shim | patches/golden-gate-windowserver-filter/make | the dylib |
| corespotlight_compat_shim | patches/golden-gate-corespotlight-compat/make | the dylib |
| codeid_carrier | patches/golden-gate-userspace/src/codeid/make | carrier.o, libhao_codeid.a (row: `# hash: without build.json`) |
| appstore_slice_guard | patches/golden-gate-appstore-slices/build/make | hao-slice-guard (row: `# hash: release-files`) |

The Wi-Fi libraries' coverage checks need the build's Apple files and are a maintainer gate, not part of the asset.
The kernel repairs (`kernel_repair_efi`, `kernel_repair_binding`, `intel_commpage_abi`) are not here yet: they
rebuild identically from tools/kernel-foundation and tools/kernel-fixes given their recorded inputs, some of which
are not yet rows a user's Mac can make.

Tests: `python3.14 -I -B -m unittest discover -s tools/asset-build/tests`. test_from_archive.py builds from `git archive HEAD`
(a folder with no .git) and checks the rows and build records there; its docstring names the env vars it needs.

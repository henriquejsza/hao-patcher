# golden-gate-mobile-assets

A new Mac's first login doesn't download Apple's MobileAssets: the image already has them. On 26B131 that first login
fetched about 0.9 GB (Siri voices 551 MB, accessibility voices 100 MB, search understanding 92 MB, speech
recognition 40 MB, and catalogs) between 2 and 10 minutes after Setup, inside the login window.

## What it installs (Data volume)

| Path | Content | From |
|---|---|---|
| `System/Library/AssetsV2/` | 25 asset types and mobileassetd's `persisted/` and `locks/` state, with their owners, modes and xattrs; then `chflags -R restricted`, as on a stock Mac | row `mobile_assets`, cut by [cache/mobile-assets](../../cache/mobile-assets/README.md) |

`apply.sh` checks the pack's `SHA256SUMS` and that its `INFO` build is the System's, then extracts it.

## Why (S18)

- **Measured:** a test Mac's 26B131 first login (2026-11-18): Setup Assistant finished at 17:19, and mobileassetd
  wrote these asset folders at 17:27-17:29, while the login was still settling.
- **What the pack leaves out:** what the OS install lays down itself (`PreinstalledAssetsV2`), mobileassetd's session
  state, and asset types for disabled services (`cache/mobile-assets/exclude.txt`).
- **Privacy:** the shipped state holds asset versions, Apple's catalog IDs and URLs, and mobileassetd's own random
  UUIDs, but no account or device data (checked on this pack).
- **Precedent:** this is the Tahoe images' mobile-assets recipe, ported.

## Verify

- `python3.14 -I -B -m unittest discover -s patches/golden-gate-mobile-assets/tests`
- On the Mac after the first login: `log show --predicate 'process == "mobileassetd"'` shows no download of the
  shipped types, and `find /System/Library/AssetsV2 ! -flags -restricted` lists nothing.

## Validation

NEEDS VALIDATION: host-tested only; not yet in a built image.

## Revisions
- r1 2026-11-18 New: the 26B131 MobileAssets pack (752 MB, harvested after a first login; Tahoe recipe ported).

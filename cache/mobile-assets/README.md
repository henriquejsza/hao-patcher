# cache/mobile-assets

Helps image builders ship Apple's MobileAssets (dictionaries, voices, linguistic data, Spotlight resources), so a
new Mac's first login doesn't download them (about 0.9 GB on 26B131, inside the login window).

| Step | Command | Result |
|---|---|---|
| 1. Harvest | `./harvest.sh "ssh root@HOST" store/artifacts/mobile-assets-BUILD-raw-DATE` after an online first login has settled | the test Mac's `System/Library/AssetsV2` as a tar, with `INFO` |
| 2. Cut | `./make store/artifacts/mobile-assets-BUILD-raw-DATE` | `store/artifacts/mobile-assets-BUILD-SHA12/` and the row line to paste |

`make` keeps every asset type folder and mobileassetd's `persisted/` and `locks/`, which record what is installed.
They hold asset versions, Apple's catalog IDs and URLs, and mobileassetd's own random UUIDs; no account or device data.
It drops:
- `._*` AppleDouble members;
- `*.xml.purged` catalogs;
- `persisted/HealthReport/` (the harvest Mac's first-run date);
- `persisted/AutoStagerTargetLookupResults/` (that session's update lookup);
- the `com.apple.provenance` xattr;
- asset types listed in `exclude.txt`, each with its reason.

Ported from the Tahoe images' `cache/mobile-assets` (the same drop rules, measured on 25G332).

## Verify
`python3.14 -I -B -m unittest discover -s cache/mobile-assets/tests`

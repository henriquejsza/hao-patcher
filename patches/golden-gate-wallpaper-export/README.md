# golden-gate-wallpaper-export

Gives each new account the export of the default wallpaper that WallpaperAgent would otherwise make at its first login.
One input, `wallpaper_export_golden_gate`: WallpaperAgent's own `Wallpaper.png` and `Metadata.plist` for this build's
default wallpaper, copied byte for byte from an account of the same build.

| From the artifact | Installed at (Data, root:wheel 644) | Used by |
|---|---|---|
| `wallpaper/Metadata.plist` | `Library/Application Support/PerUserSeed/wallpaper/Metadata.plist` | golden-gate-user-seed's seed.zsh (`place_wp`) |
| `wallpaper/Wallpaper.png` | `Library/Application Support/PerUserSeed/wallpaper/Wallpaper.png` | the same |

Post patch; list it after golden-gate-user-seed (apply.sh refuses otherwise). apply.sh refuses an export whose
`BuildVersion` is not the System's.

## Why
- 26B131 first login, MacBookPro9,2 (2026-11-18): WallpaperAgent logs "No existing exported wallpaper exists -
  exporting default wallpaper" and exports for 64 s (11:24:50 to 11:25:54), during the account's first login.
- The export is the same for every Mac on this build. The PNG is 3840x2160, not the screen's 1280x800, and
  `Metadata.plist` holds only `BuildVersion` 26B131, `IsSystemDefault` true and the aerials provider with its asset id.
  It holds no account, device or session data.
- seed.zsh already has the step (`place_wp`, from the earlier Tahoe image project's seed v6/v7). For each new account it
  writes the metadata first, then the picture, into root's `/private/var/db/Wallpapers/<GeneratedUID>/`. It never
  writes over a folder WallpaperAgent made first. Until now it had no payload ("no wallpaper in the payload").

## Declared files
`patch.json` `files` lists the two files apply.sh installs. Both are whole files from the row. Not declared: the
per-account copy seed.zsh makes at run time (its path holds the account's GeneratedUID).

## Verify
Host: `python3.14 -I -B -m unittest discover -s patches/golden-gate-wallpaper-export/tests` (apply.sh on a fixture,
the build check). On a laptop after a new account's first login:
- `/private/var/log/peruser-seed.log` says "wallpaper export metadata placed" and "wallpaper cache placed".
- WallpaperAgent does not log "exporting default wallpaper".

## Validation
NEEDS VALIDATION (r1): a first login on an image with r1 shows both log lines above, and the desktop shows the
default wallpaper.

## Revisions
- r1 2026-11-18 New: the default wallpaper's export for 26B131, so each new account skips WallpaperAgent's 64 s export at first login.

# golden-gate-wallpaper-export: WallpaperAgent's export of this build's default wallpaper (input
# wallpaper_export_golden_gate: Wallpaper.png and its Metadata.plist) into PerUserSeed/wallpaper/. golden-gate-user-seed's
# seed.zsh copies them (as root, into root's /private/var/db/Wallpapers/<GeneratedUID>/, metadata first) for each new
# account before its WallpaperAgent starts, so the first login does not export the default wallpaper again (list this
# after golden-gate-user-seed).
A="$P/inputs/wallpaper_export_golden_gate"
B=$(/usr/libexec/PlistBuddy -c 'Print :ProductBuildVersion' "$SYS/System/Library/CoreServices/SystemVersion.plist")
W=$(/usr/libexec/PlistBuddy -c 'Print :BuildVersion' "$A/wallpaper/Metadata.plist")
[ "$W" = "$B" ] || { echo "golden-gate-wallpaper-export: the export is from $W, System is $B" >&2; exit 1; }
SEED="$DATA/Library/Application Support/PerUserSeed"
[ -d "$SEED" ] || { echo "golden-gate-wallpaper-export: list it after golden-gate-user-seed" >&2; exit 1; }
install -d -o root -g wheel -m 755 "$SEED/wallpaper"
install -o root -g wheel -m 644 "$A/wallpaper/Metadata.plist" "$SEED/wallpaper/Metadata.plist"
install -o root -g wheel -m 644 "$A/wallpaper/Wallpaper.png" "$SEED/wallpaper/Wallpaper.png"
echo "golden-gate-wallpaper-export: default wallpaper export for $B"

# golden-gate-mobile-assets: Apple's MobileAssets (System/Library/AssetsV2 on the Data volume: dictionaries, voices,
# linguistic data, Spotlight resources), cut by cache/mobile-assets/make from a harvest after an online first login of
# this build. Extracted with their owners, modes and xattrs, so the first login does not download them.
A="$P/inputs/mobile_assets"
(cd "$A" && shasum -a 256 -c SHA256SUMS) || { echo "golden-gate-mobile-assets: the pack does not match its SHA256SUMS" >&2; exit 1; }
B=$(/usr/libexec/PlistBuddy -c 'Print :ProductBuildVersion' "$SYS/System/Library/CoreServices/SystemVersion.plist")
H=$(sed -n 's/^build //p' "$A/INFO")
[ "$H" = "$B" ] || { echo "golden-gate-mobile-assets: the pack is from $H, System is $B" >&2; exit 1; }
tar -xpf "$A/mobile-assets.tar" --numeric-owner -C "$DATA"
# A stock Mac has the restricted flag on every AssetsV2 entry. tar does not carry it, and mobileassetd repairs each
# entry without it at its first start (measured on the Tahoe images: 7,650 entries).
V="$DATA/System/Library/AssetsV2"
chflags -R restricted "$V"
echo "golden-gate-mobile-assets: $(find "$V" ! -flags -restricted | wc -l | tr -d ' ') entries without the restricted flag, $(find "$V" | wc -l | tr -d ' ') entries for $B"

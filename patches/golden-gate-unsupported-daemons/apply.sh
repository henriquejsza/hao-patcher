# golden-gate-unsupported-daemons: system LaunchDaemons that cannot work on an Intel Mac are disabled through launchd's
# own override file (what `launchctl disable system/LABEL` writes), on the Data volume. The labels and each one's
# reason are in src/disabled-daemons.txt. Other entries in the file (Apple's own, or a user's) are kept.
D="$DATA/private/var/db/com.apple.xpc.launchd"
F="$D/disabled.plist"
[ -d "$D" ] || { mkdir -p "$D"; chown root:wheel "$D"; chmod 755 "$D"; }
[ -f "$F" ] || plutil -create xml1 "$F"
grep -v '^#' "$P/src/disabled-daemons.txt" | awk 'NF {print $1}' | while read -r label; do
    # plutil reads "." in a key as a path separator: escape it so the label stays one top-level key
    plutil -replace "$(printf %s "$label" | sed 's/\./\\./g')" -bool YES "$F"
done
chown root:wheel "$F"
chmod 644 "$F"
plutil -lint "$F"
plutil -p "$F"

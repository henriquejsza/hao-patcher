# golden-gate-update-policy: Background Security Improvements (Rapid Security Responses, "splats") and macOS
# updates never download or install on their own. A splat replaces the OS/App cryptex this image modifies (README).
# softwareupdated (OSUpdate.framework, 26B131) gates a splat's background download and Install Tonight on
# SplatEnabled alone, read from /Library/Preferences/com.apple.SoftwareUpdate.plist; AutomaticDownload and the
# critical-update keys do not apply to splats. A missing SplatEnabled means on. A product key already queued
# (AutoInstallProductKeys) bypasses SplatEnabled, so the queue is cleared too. Other keys are kept.
F="$DATA/Library/Preferences/com.apple.SoftwareUpdate.plist"
[ -d "$DATA/Library/Preferences" ] || { mkdir -p "$DATA/Library/Preferences"; chown root:wheel "$DATA/Library/Preferences"; chmod 755 "$DATA/Library/Preferences"; }
[ -f "$F" ] || plutil -create xml1 "$F"
plutil -replace SplatEnabled -bool NO "$F"
# macOS updates: SUOSUAutoUpdatePolicy gates them on doesMacOSAutoUpdate, the AutomaticallyInstallMacOSUpdates key (owner 2026-11-18)
plutil -replace AutomaticallyInstallMacOSUpdates -bool NO "$F"
for k in AutoInstallProductKeys FirstInstallTonightDateDictionary; do
    if plutil -extract "$k" xml1 -o /dev/null "$F" 2>/dev/null; then plutil -remove "$k" "$F"; fi
done
chown root:wheel "$F"
chmod 644 "$F"
plutil -lint "$F"
plutil -p "$F"

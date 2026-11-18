# dev-capture: what every dev run collects (owner 2026-11-18, "Always capture"). com.hao's log messages keep their
# private data and their info lines persist, so a refusal or crash reason reads in full from any boot's log. The folder
# /private/var/db/hao-capture is where the metadata recorder writes. Dev sets only.
install -d -o root -g wheel -m 755 "$DATA/Library/Preferences/Logging/Subsystems"
install -o root -g wheel -m 644 "$P/src/com.hao.plist" "$DATA/Library/Preferences/Logging/Subsystems/com.hao.plist"
plutil -lint "$DATA/Library/Preferences/Logging/Subsystems/com.hao.plist"
install -d -o root -g wheel -m 755 "$DATA/private/var/db/hao-capture"

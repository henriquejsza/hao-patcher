# dev-access: root SSH on the test laptop for test runs, and Screen Sharing for the listed accounts (dev set only). launchd starts sshd per connection on port 22
# with its own config: root by the one public key in inputs, no passwords. Apple's Remote Login setting is untouched.
T=$DATA/private/var/root/.testssh
install -d -o root -g wheel -m 700 $T
install -o root -g wheel -m 600 $P/inputs/test_host_key $T/ssh_host_ed25519_key
install -o root -g wheel -m 600 $P/inputs/test_authorized_key $T/authorized_keys
install -o root -g wheel -m 644 $P/src/sshd_config $T/sshd_config
install -d -o root -g wheel -m 755 $DATA/Library/LaunchDaemons
install -o root -g wheel -m 644 $P/src/local.testssh.plist $DATA/Library/LaunchDaemons/local.testssh.plist
# Screen Sharing (owner, 2026-11-14), from the first boot: at every boot dev.hao.screensharing adds the accounts named in
# screensharing-users to com.apple.access_screensharing (by name, so before they exist) and enables and loads Apple's service.
install -o root -g wheel -m 600 $P/inputs/screensharing_users $T/screensharing-users
install -o root -g wheel -m 644 $P/src/dev.hao.screensharing.plist $DATA/Library/LaunchDaemons/dev.hao.screensharing.plist
ls -la $T $DATA/Library/LaunchDaemons/local.testssh.plist $DATA/Library/LaunchDaemons/dev.hao.screensharing.plist

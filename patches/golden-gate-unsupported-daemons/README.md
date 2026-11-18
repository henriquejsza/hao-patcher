# golden-gate-unsupported-daemons

Apple services that cannot work on an Intel Mac do not start. Each is disabled with launchd's own override (what
`launchctl disable system/LABEL` writes), so `launchctl enable` turns it back on.

## What it changes (Data volume)

- `private/var/db/com.apple.xpc.launchd/disabled.plist`: each label in `src/disabled-daemons.txt` is set to true.
  Apple's own entries and any others are kept.

## Why (S18)

Each label's reason is in `src/disabled-daemons.txt`. The first two are the Apple Intelligence daemons, which need
Apple silicon:
- `com.apple.modelmanagerd` respawns every 1-3 s on an Intel image (diag#19). Each instance exits after a
  memory-limit warning, and the next call from RunningBoard or gamepolicyd starts it again. In the first-login tail
  that was 26 instances in 44 s and 62% of the CPU (measured 2026-11-18).
- `com.apple.modelcatalogd` downloads assets for it.

A label is added here only with evidence that the service is inert or failing on this hardware.

## Verify

- `python3.14 -I -B -m unittest discover -s patches/golden-gate-unsupported-daemons/tests`: the plist gets every
  label, keeps other entries, and is root 644.
- On the Mac: `launchctl print-disabled system` lists the labels as disabled; no modelmanagerd runs after login; its
  callers (runningboardd, gamepolicyd) log no retry loop; first login settles sooner.

## Validation

NEEDS VALIDATION: host tests only.

## Revisions
- r1 2026-11-18 New: modelmanagerd and modelcatalogd disabled (diag#19; owner: disable what this hardware cannot run).

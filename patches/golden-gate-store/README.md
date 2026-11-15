# golden-gate-store

App Store: Apple-silicon-only apps can be downloaded and updated on macOS 27.2.1 (26B131), MacBookPro9,2.

Changes: adds `usr/lib/hao/libhao-appstore-policy.dylib` and `usr/lib/hao/libhao-ios-coordinator-test.dylib` (which
needs golden-gate-ids' library, so golden-gate-ids comes first); replaces `appstoreagent` and `appstored`
(`System/Library/PrivateFrameworks/AppStoreDaemon.framework/Support/`) and `App Store.app/Contents/MacOS/App Store`
(row `store_service`); keeps the image's two daemons as `usr/lib/hao/store-policy-original-*`; updates
`usr/lib/hao/stub-identities` for the replaced programs. Stops unless the three files are the ones the image had. Runs
before golden-gate-native-identities, which lists the replaced daemon.

Proof: these bytes on a test machine, owner 2026-11-15: "These are proven live fixes". Open: diag#0051 (a password
prompt on every download).

## Verify

`patches.py check`; after a build, the four files have the row's sha256.

## Validation

NEEDS VALIDATION on an image built with this recipe.

## Revisions
- r2 2026-11-15 Adds libhao-ios-coordinator-test.dylib, which the replaced appstoreagent loads.
- r1 2026-11-15 New.

# Verify a release

For checking a signed hao builder kit before making an installer.

The release's `hao` bootstrap carries the owner's SSH public key, fingerprint
`SHA256:HPvLz28RozOa/bJ+7bJ0ha4s27LBEjQ/B3TxSqQCdek`. Verify that fingerprint
through a trusted copy of this project before trusting a newly downloaded bootstrap.

## What a release holds

The hao-assets release page lists six files:

| File | What it is |
|---|---|
| `hao` | The command you run: a short shell script you can read |
| `release.json` | Every file the installer uses, each with its origin, size and SHA256 |
| `SHA256SUMS` | Checksums of `hao`, `release.json` and the archive |
| `release.json.sig`, `SHA256SUMS.sig` | SSH signatures of those two files |
| `hao-<RELEASE>.tar` | Everything of ours in one archive: the builder kit, hao-runtime, the compatibility fixes, the cache builder and the pinned build tools |

`release.json` lists each file inside the archive under `assets`, with its own size, SHA256 and the commit that
built it. Apple's files and third-party tools (Python, the Kernel Debug Kit, OpenCore) are not on the page: hao
downloads them from their publishers, pinned by SHA256 in `release.json`.

## Automatic checks

`sh hao` verifies the SSH signatures on `release.json` and `SHA256SUMS` with
namespace `hao-release`. It then checks the release manifest's checksum, the archive's
SHA256, and the SHA256 of each file it takes from the archive or downloads, before
extracting or executing it. A failed signature,
hash, download or architecture check stops with exit status 4. Finished, verified
downloads are kept for the next run.

The manifest pins the code snapshot, Python for each architecture, LLVM tools,
our binaries, and Apple's inputs. A final cut names one clean tagged commit.
Development after that cut cannot change the pinned files. A shipped release's
fixes are cut from its release branch as a new release.

## Check by hand

Download the six files of one release. Save the trusted public key as `owner.pub`, then run:

```sh
ssh-keygen -lf owner.pub
{ printf 'hao-release '; cat owner.pub; } > allowed-signers
ssh-keygen -Y verify -f allowed-signers -I hao-release -n hao-release -s release.json.sig < release.json
ssh-keygen -Y verify -f allowed-signers -I hao-release -n hao-release -s SHA256SUMS.sig < SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Both signature checks must succeed and every downloaded file must say `OK`.
Files you have not downloaded are skipped. Check the bootstrap itself against the
signed checksum list before running it when verifying manually.

To check one file inside the archive against `release.json`, for example the builder kit:

```sh
tar -xOf hao-<RELEASE>.tar hao-kit-<RELEASE>.tar.gz | shasum -a 256
plutil -extract assets json -o - release.json | grep -B4 -A4 hao-kit
```

v0.0.1-beta.1, the first preview, is not signed: its page has no `.sig` files, `hao` says so when it
runs, and the checksums are the only check (skip the two `ssh-keygen -Y verify` lines). Later releases are signed. Four
harvested caches remain covered by the existing [reproduction exception](reproduce.md#what-must-match).

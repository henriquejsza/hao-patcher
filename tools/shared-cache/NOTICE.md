# Notices

The code in this folder is covered by the repository's [MIT license](../../LICENSE), except the third-party source
listed here, which keeps its own license. It contains no Apple binaries; the dyld cache and libraries it reads and the
family it writes are the user's own files and keep Apple's terms.

- `vendor/frida-gum/gumx86relocator.h`: [frida-gum](https://github.com/frida/frida-gum) 17.25.0, wxWindows Library
  Licence 3.1 (`vendor/frida-gum/COPYING`; provenance in `source.json`).
- `vendor/swift-remote-mirror/`: headers from [Swift](https://github.com/swiftlang/swift) at caab90f, Apache License
  2.0 with Runtime Library Exception (`vendor/swift-remote-mirror/LICENSE.txt`; provenance in `source.json`).
- `toolchain/added-source/` and `toolchain/source.patch`: headers from Apple's open-source
  releases (libc, xnu, libpthread, CommonCrypto and others) and a patch against Apple's published dyld source
  ([dyld-1378](https://github.com/apple-oss-distributions/dyld/tree/dyld-1378)), under the Apple Public Source
  License 2.0 or the Apache License 2.0 as stated in each file. The dyld source itself is downloaded by the user and
  is not stored here.
- `toolchain/availability/availability` and `availability.dsl`: from Apple's open-source
  [AvailabilityVersions](https://github.com/apple-oss-distributions/AvailabilityVersions) (the script as in tag
  AvailabilityVersions-157.2; the data file as in its current main). That repository and these files state no
  license; they are published by Apple with its other open-source releases. `VersionMap.h` is generated from them.

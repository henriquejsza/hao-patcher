# Install

> [!WARNING]
> Pre-alpha, and this path is still being validated. Installing erases the MacBook Pro's internal disk.

Making the USB installer yourself is in progress: parts made on another macOS version may differ in signature; the
graphics parts need Xcode's Metal toolchain.

hao installs macOS 27 on an Intel Mac. You make a USB installer on any Mac, then install from it on the
MacBook Pro.

## Requirements

| Part | Requirement |
|---|---|
| Target | MacBook Pro (13-inch, Mid 2012), the first supported model. Its internal disk is erased. |
| Build Mac | Any Mac, Intel or Apple silicon, on its normal macOS, with no SIP or AMFI changes. It needs the Command Line Tools (`xcode-select --install`) and Python 3.14 (python.org's build: run its Install Certificates once). |
| USB drive | 64 GB or larger. It is erased. |
| Free disk | About 190 GB on the build Mac; the downloads are about 48 GB. |
| Time | On the build Mac about 7 minutes of downloads and 15 of making; the install about 1-2 hours, most of it one quiet step. |
| Network | Internet on the build Mac (the downloads come from Apple and this project's releases). |

## Install

1. Get hao at the release tag:

   ```sh
   git clone --branch v0.0.1 https://github.com/lythka/hao-patcher && cd hao-patcher/tools/hao
   ```

2. Plug in the USB drive and run:

   ```sh
   ./hao create-installer
   ```

   Choose the USB drive and confirm. This erases the drive; you may be asked for your password.
   Today this step is still four commands (fetch, place, make-on-Mac, create-installer); [the developer
   guide](building.md) lists them until `create-installer` does all four.
3. On the MacBook Pro, hold Option at startup and choose **EFI Boot**. Expect a silent pause of several minutes
   before the Apple logo. In the Recovery, open Utilities > Terminal and run `/Volumes/HAO/install`.
4. After the first start-up, run once:

   ```sh
   sudo /usr/libexec/hao --aot
   ```

   Until then, apps take longer to open the first time.

## Logs

If something doesn't work, save a report and attach it to a
[GitHub issue](https://github.com/lythka/hao-patcher/issues/new/choose):

```sh
./hao report --output report.txt
```

The report leaves out the serial number, user names and Wi-Fi names.

## Build from source

To build hao and its kit yourself, follow [the developer guide](building.md):

```sh
git clone https://github.com/lythka/hao-patcher && cd hao-patcher
tools/hao/hao create-installer
```

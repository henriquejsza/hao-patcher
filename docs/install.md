# Install

> [!WARNING]
> Pre-alpha, and this path is still being validated. Installing erases the MacBook Pro's internal disk.

hao installs macOS 27 on an Intel Mac. You make a USB stick on any Mac, then install from the stick on the
MacBook Pro.

## Requirements

| Part | Requirement |
|---|---|
| Target | MacBook Pro (13-inch, Mid 2012), the first supported model. Its internal disk is erased. |
| Build Mac | Any Mac, Intel or Apple silicon, on its normal macOS, with no SIP or AMFI changes. |
| USB stick | Size measured soon. The stick is erased. |
| Free disk | On the build Mac: measured soon. |
| Time | Measured soon. |
| Network | Internet on the build Mac (the downloads come from Apple and this project's releases). |

## Install

1. Download `hao` from the [releases page](https://github.com/lythka/hao-patcher/releases).
2. Plug in the USB stick and run:

   ```sh
   ./hao create-installer
   ```

   Choose the USB stick and confirm. This erases the USB stick; you may be asked for your password.
   Today this step is still four commands (fetch, place, make-on-Mac, create-installer); [the developer
   guide](building.md) lists them until `create-installer` does all four.
3. On the MacBook Pro, hold Option at startup and choose **HAOBOOT**. In the Recovery, open Utilities > Terminal and
   run `/Volumes/HAO/install`.
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

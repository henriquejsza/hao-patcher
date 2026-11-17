#!/bin/sh
# golden-gate-wifi-compat (kc-hook, right after golden-gate-userspace): the IO80211 and WiFiPeerToPeer compat
# libraries in front of OCLP's Modern Wireless wrappers, which OCLP's hardware overlay installed.
#   kc-hook.sh SYSTEM_MOUNT     env OCLP_PYTHON
set -eu
S=${1:?System mount}; H=$(cd "$(dirname "$0")" && pwd)
"${OCLP_PYTHON:?}" -I "$H/install.py" "$S" "$H/inputs/io80211_compat" "$H/inputs/wifip2p_compat"

# pipeline/vm

The builder VM on the host side. The VM itself is [`tools/ssdvm`](../../tools/ssdvm/README.md).

- `clones.py`: APFS clones of a base VM (`clone`, `list`, `remove-clone`) and their start (`start VM SHARE`), which
  puts the root agent into a new clone from its recoveryOS on the first start.
- `vmctl`: the VM's screen (VNC) and its command agent (`exec`, `serve`). In full macOS the agent mounts the share
  at `/private/var/ssdshare`.
- `start.sh VM SHARE`, `stop.sh VM`: boot a clone with its share and wait for the agent; shut it down cleanly.
- `clean-vm`: a fresh VM with known tools, for reproducing a release build.

## clean-vm

```sh
pipeline/vm/clean-vm make-base KIND IPSW --xcode XIP --python PKG [--disk-gb N]
pipeline/vm/clean-vm up KIND NAME
pipeline/vm/clean-vm down NAME
```

`KIND` is `tahoe` or `golden`; its base is `store/vm/base-KIND`.

- `make-base` runs once per base. It installs macOS from `IPSW` (`ssdvm install`), gives the base an agent
  configuration (`vmctl init-agent`), and from recoveryOS installs the agent, turns SIP off and sets
  `amfi_get_out_of_my_way=1` (`clones.py` provisioning). It then boots the base with a setup share
  (`store/vm/base-KIND.share`, removed afterwards) and, as root in the guest, expands `XIP` into
  `/Applications/Xcode.app`, accepts the license, runs `xcodebuild -runFirstLaunch` and installs the python.org
  `PKG`. It writes `base.json`: the output of `sw_vers`, `xcodebuild -version`, `xcrun clang --version`,
  `python3.14 --version`, `git --version`, `csrutil status`, `nvram boot-args`, and the sha256 of IPSW, XIP and
  PKG. It refuses if the base folder exists; to make a base again, remove it first.
- `up` clones the base (`clones.py clone`), starts the clone with its share (`clones.py start`), and checks that the
  guest's tool output equals `base.json` and that the share is mounted. Otherwise it stops the clone and refuses.
  It prints `VMDIR` and `SHARE`.
- `down` stops the clone (`stop.sh`) and removes it (`clones.py remove-clone`).

Needs `store/vm/bin/ssdvm` (`tools/ssdvm/build.sh store/vm/bin`) and the vmctl Python with Pillow and cryptography
(`store/cache/vmctl-venv`, or `VMCTL_PYTHON`); see `docs/building.md`. The Xcode setup waits up to 4 hours.

## Verify

```sh
python3.14 -I -B -m unittest discover -s pipeline/tests -k clean_vm -k vm_clones
```

The tests use a fake host: they make and start no VM.

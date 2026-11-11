# Radio: firmware and driver

PiCast talks to Apple devices over **AWDL**, Apple's own peer-to-peer Wi-Fi. The
Raspberry Pi Zero 2 W's radio (Broadcom/Cypress BCM43436, also reported as
BCM43430 revision 2) cannot do that with its stock firmware: PiCast needs to
receive and send raw 802.11 frames on a fixed channel at exactly the right
moments. This folder holds the changes that make that possible. Everything else
(AWDL timing, IPv6, AirPlay) is PiCast's own code in `src/`.

## Where it comes from

Base: [seemoo-lab/nexmon](https://github.com/seemoo-lab/nexmon), pinned to commit
[`68720406`](https://github.com/seemoo-lab/nexmon/tree/68720406f54ff16cad28fd3c51f2392aefad9fb7),
which patches the BCM43436b0 firmware **9.88.4.65** and ships a matching
`brcmfmac` driver. [`tools/build_radio.sh`](../tools/build_radio.sh) builds both
from that tree, in CI on every release:

| File | What it changes |
| --- | --- |
| [`nexmon-6.18.patch`](nexmon-6.18.patch) | Ports Nexmon's `brcmfmac` driver to Linux 6.18 (current Raspberry Pi OS). Adds the module option `picast_monitor=1`, which enables monitor mode with frame injection on this chip only; off by default. Removes Nexmon's private netlink ioctl channel (PiCast uses standard nl80211 vendor commands). |
| [`picast_null_sample_guard.c`](picast_null_sample_guard.c) | A firmware fix: one firmware function crashed the radio when called with a NULL pointer during long monitor sessions. The guard returns early for that input and runs the original instructions otherwise. [`check_guard_input.py`](check_guard_input.py) refuses to build it unless the firmware file and the patched instructions are exactly the expected ones. |
| [`picast_monitor_profile.h`](picast_monitor_profile.h), [`nexmon-monitor-profile.patch`](nexmon-monitor-profile.patch), [`apply_monitor_profile.py`](apply_monitor_profile.py) | Lets only AWDL frames reach the host in monitor mode, and drops an optional monitor copy instead of borrowing from the radio's shared receive pool when memory is short. This keeps the radio's receive path healthy under the load of a mirroring session. |

The driver is compiled on the Pi itself (or in the image build) for the exact
kernel it runs on; see the kernel rule in [`tools/picast-setup.sh`](../tools/picast-setup.sh).
The release workflow checks that the driver built in CI is identical
(`srcversion`) to the one tested on hardware.

## Checks without hardware

- [`test_monitor_profile.py`](test_monitor_profile.py) compiles the original and the
  patched monitor function with [`monitor_profile_harness.c`](monitor_profile_harness.c)
  and runs both against synthetic frames.
- [`test_guard_emulated.py`](test_guard_emulated.py) executes the original and the
  guarded firmware code in an ARM Thumb emulator ([Unicorn](https://www.unicorn-engine.org/),
  development only).

## Licenses

- Nexmon's firmware patching framework and the patches here that build on it:
  GPL-3.0-or-later.
- The `brcmfmac` driver: Dual BSD/GPL, with its original copyright notices.
- The base firmware is Broadcom/Cypress's, redistributed in patched form as
  Nexmon does. Calibration and regulatory files stay those of the installed system.

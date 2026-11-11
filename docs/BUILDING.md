# Building and developing PiCast

## Build and test

PiCast is C11 plus a small Python runner. It builds on Raspberry Pi OS and on
any recent Debian or Ubuntu (arm64 or x86-64):

```bash
sudo apt install build-essential pkg-config libssl-dev libplist-dev libcairo2-dev libdrm-dev \
  libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev python3-cryptography
make            # build/picast and build/picast-power
make test       # unit tests; no radio, display or network needed
make sanitize   # the same with AddressSanitizer and UBSan
sudo make namespace-test   # the private network namespace (needs root, changes nothing on the host)
```

The radio firmware is not built by `make`: it needs the pinned Nexmon tree and a
32-bit x86 toolchain. `tools/build_radio.sh WORK OUT` does it (x86-64 Linux, see
the `radio` job in `.github/workflows/release.yml`).

## Layout

| Path | What |
| --- | --- |
| `src/`, `include/` | The receiver: radio, AWDL, AirPlay, media, screens. [How it works](HOW_IT_WORKS.md) |
| `tools/picast_product.py` | The device runner (`picast.service`) |
| `tools/picast-setup.sh` | Installer, updates, driver builds; becomes `picast-install.sh` |
| `tools/make_installer.sh` | Packs `picast-install.sh` (setup script + source + radio parts) |
| `tools/build_image.sh` | Builds the SD card image from Raspberry Pi OS Lite and `picast-install.sh` |
| `tools/build_radio.sh` | Builds the patched radio firmware and driver source |
| `system/` | systemd units, udev rule, the default `picast.txt` |
| `radio/` | Firmware and driver patches. [Details](../radio/README.md) |
| `tests/` | Unit tests (C drivers, Python checks) |
| `third_party/playfair/` | PlayFair, unmodified. [Notes](../third_party/README.md) |

## The `picast` program

The service uses these commands; they are handy when developing on a Pi in
maintenance mode:

```text
picast version
picast config [show | maintenance]       settings from /boot/firmware/picast.txt as JSON
picast ui SCREEN [TEXT] | off | battery  draw a screen (starting, ready, pin, connecting, recovering, blank)
picast ui-png SCREEN TEXT OUT.png [WxH]  the same screen as a picture
picast capture MONITOR SECONDS OUT.pcap  record what the radio hears
picast analyze CAPTURE.pcap              senders in a recording, as JSON lines
picast serve MONITOR PEER_MAC TOKEN_HEX  one mirroring session
picast radio-wake|radio-check|radio-counters INTERFACE
```

Environment variables for experiments: `PICAST_LANGUAGE` (`en`/`de`) and
`PICAST_NAME` override `picast.txt`; `PICAST_NO_CROP` turns off black-bar
removal; `PICAST_MAX_FPS=30` caps the frame rate.

A bounded test run that gives the normal Wi-Fi back afterwards:

```bash
sudo systemctl stop picast
sudo python3 /opt/picast/lib/picast_product.py run --for 600
```

## Releases

Pushing a tag `v*` runs `.github/workflows/release.yml`:

1. **radio**: Nexmon firmware and driver source (x86-64).
2. **installer**: packs `picast-install.sh` and test-builds everything on
   Raspberry Pi OS packages (arm64 under QEMU). It warns if the driver differs
   from the hardware-tested build.
3. **image**: downloads the newest Raspberry Pi OS Lite (64-bit), checks its
   SHA-256, runs `picast-install.sh --image` inside it and compresses the result.
4. **release**: publishes `picast-install.sh`, `picast-VERSION.img.xz` and its checksum.

To build an image yourself on an arm64 or x86-64 Linux machine (with
`qemu-user-static` on x86-64):

```bash
sudo apt install parted zerofree xz-utils e2fsprogs
sudo tools/build_image.sh 2026-10-06-raspios-trixie-arm64-lite.img.xz picast-install.sh picast.img.xz
```

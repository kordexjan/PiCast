# Third-party components

PiCast is licensed under the [GNU General Public License v3.0](../LICENSE). It
includes or builds on the following components.

## PlayFair (in this repository)

`third_party/playfair/`, unmodified from [FDH2/UxPlay](https://github.com/FDH2/UxPlay)
(`lib/playfair`). The exact revision and a SHA-256 hash of every file are in
[`playfair/PROVENANCE.json`](playfair/PROVENANCE.json). License: GPL-3.0, see
[`playfair/LICENSE.md`](playfair/LICENSE.md).

PiCast uses it for one step only: unwrapping the media key that the sender
sends during FairPlay setup. [`src/fp_key.c`](../src/fp_key.c) checks every length
and mode before calling it and wipes the copies afterwards. Pairing, encryption,
the radio link, AirPlay control and video/audio output are PiCast's own code.

## Nexmon and the brcmfmac driver (built by the release workflow)

The radio firmware and driver are built from
[seemoo-lab/nexmon](https://github.com/seemoo-lab/nexmon) at a pinned commit,
with the changes in [`radio/`](../radio/README.md):

- Nexmon's firmware patching framework: GPL-3.0-or-later.
- The `brcmfmac` Linux driver: Dual BSD/GPL.
- The Broadcom/Cypress BCM43436b0 base firmware 9.88.4.65, redistributed in
  patched form as Nexmon does. Its calibration and regulatory files are not
  replaced: PiCast uses those of the installed system.

`picast-install.sh` and the SD card image contain the license texts in
`radio/licenses` and `/opt/picast/src`.

## The SD card image

The image is the official Raspberry Pi OS Lite (64-bit) with PiCast installed
by `picast-install.sh`. Raspberry Pi OS and its packages keep their own
licenses; see `/usr/share/doc/*/copyright` on the card. PiCast's complete source
for the version in the image is in `/opt/picast/src` and in the GitHub release.

## Protocol references

PiCast's code was written for this project. These public works describe the
protocols and were used as references, not copied:

- Milan Stute, David Kreitschmann, Matthias Hollick: *One Billion Apples' Secret
  Sauce: Recipe for the Apple Wireless Direct Link Ad hoc Protocol*, MobiCom 2018
  ([arXiv](https://arxiv.org/abs/1808.03156)), and their
  [Open Wireless Link](https://github.com/seemoo-lab/owl) implementation.
- The [Wireshark AWDL dissector](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-awdl.c).
- [UxPlay](https://github.com/FDH2/UxPlay) and its
  [protocol notes](https://github.com/FDH2/UxPlay/wiki) for AirPlay mirroring.

## Trademarks

AirPlay, Apple, iPhone, iPad and Mac are trademarks of Apple Inc. Raspberry Pi
is a trademark of Raspberry Pi Ltd. PiCast is an independent project and is not
affiliated with, endorsed by or sponsored by Apple or Raspberry Pi.

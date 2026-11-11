# How PiCast works

An iPhone mirrors its screen to an Apple TV without any Wi-Fi network in common:
the two talk directly over **AWDL** (Apple Wireless Direct Link), Apple's
peer-to-peer Wi-Fi. PiCast does the same on a Raspberry Pi Zero 2 W. Everything
from the radio frames up to the picture on HDMI is in this repository.

```text
 iPhone / iPad / Mac
        │  AWDL action frames and data frames, Wi-Fi channel 6
        ▼
 BCM43436 radio ── patched firmware + driver (radio/), monitor mode with injection
        │  raw 802.11 frames (AF_PACKET)
        ▼
 AWDL         src/protocol.c  src/follow.c  src/schedule.c  src/data.c
   find senders, follow their timing, send our own announcements,
   carry IPv6 in AWDL data frames
        │  IPv6 packets
        ▼
 TUN device in a private network namespace   src/netns.c  src/tcp_diag.c  src/probe.c
   the Linux kernel's own TCP/UDP; the host's networking is never touched
        │
        ▼
 AirPlay      src/info.c  src/rtsp.c  src/control.c
   DNS-SD announcement on the link, /info, RTSP control
   PIN pairing (SRP, src/pin.c src/srp.c), pair-verify (src/pair.c)
   FairPlay setup (src/fairplay.c, PlayFair for the key: src/fp_key.c)
        │  encrypted H.264 and AAC-ELD
        ▼
 Media        src/mirror.c  src/mirror_crypto.c  src/media.c  src/audio.c
   decrypt, shared clock with the sender (src/clock.c), playout delay (src/playout.c)
        │
        ▼
 Output       src/video_output.c  src/crop.c  src/ui.c  src/overlay.c
   GStreamer: hardware H.264 decoder → kmssink on HDMI; audio → ALSA HDMI
   black-bar removal, receiver screens, battery corner above the video
```

## The pieces

**Radio.** The stock firmware cannot inject frames or receive another device's
AWDL traffic. Nexmon's patched firmware and driver can; PiCast adds a crash fix
and a filter so that only AWDL frames reach Linux. See [radio/](../radio/README.md).

**AWDL.** AWDL devices agree on a shared schedule of short *availability
windows* on a few channels. PiCast does not run its own schedule: it listens for
a sender, takes over its timing, announces itself in that sender's windows on
channel 6 and sends its data frames there. While the sender still uses its home
Wi-Fi on 2.4 GHz, PiCast leaves it free slots (the radio profile chosen by
`tools/picast_product.py`), so the iPhone keeps its internet connection.

**IPv6 without touching the network.** AWDL carries ordinary IPv6. PiCast hands
those packets to a TUN device inside a fresh network namespace, so the kernel's
TCP and UDP do the transport work, and nothing outside that namespace (routes,
Wi-Fi settings) changes.

**AirPlay.** The receiver announces itself with DNS-SD directly on the AWDL
link, answers `/info` with what it can show (the display's shape, from
`PICAST_SCREEN`), and runs the RTSP control session: PIN pairing on first
contact, pair-verify, FairPlay setup, then `SETUP` for the video and audio
streams.

**Media.** Video arrives as encrypted H.264 over TCP, audio as encrypted
AAC-ELD over UDP. Both are decrypted and timed against the sender's clock, then
played out after a fixed delay (`delay` in `picast.txt`, 270 ms by default),
which keeps picture and sound in step and evens out radio gaps.

**Output.** The Pi's hardware decoder feeds `kmssink` on HDMI. When an app shows
a video with black bars inside the mirrored screen, `src/crop.c` finds the
picture and zooms to it. The screens (starting, ready, PIN, …) are drawn with
Cairo straight into the framebuffer.

## The device

`picast.service` runs [`tools/picast_product.py`](../tools/picast_product.py),
which loops:

1. Turn the radio on (patched driver, monitor interface `picastmon`, channel 6).
2. Listen for a few seconds; parse who is there (`picast capture`, `picast analyze`).
3. When an iPhone, iPad or Mac opens Screen Mirroring, run one session with it
   (`picast serve`) until it disconnects.
4. Watch the radio; restart it if it hangs, and the whole Pi if that fails three times.

Pairing keys live in memory only (`/run/picast`), so after each power-on every
device enters the PIN once again. Nothing about the senders is stored except a
short, size-limited session log in `/var/lib/picast`.

The optional battery board (Waveshare UPS HAT (C)) is read by `picast-power`,
which shows the charge in the corner and shuts the Pi down cleanly before the
battery runs empty.

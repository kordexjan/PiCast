#!/usr/bin/env python3
"""PiCast as a device: from power-on a receiver in the AirPlay menu, no network needed.

Runs as picast.service. Settings come from picast.txt on the SD card's boot
partition (see `picast config`); with maintenance = on, systemd skips this service
and the Pi stays a normal Raspberry Pi with WLAN and SSH.

    picast_product.py run                 the device (systemd)
    picast_product.py run --for 900       a bounded test: afterwards the stock
                                          WLAN driver and NetworkManager return
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time

PRODUCT = Path("/opt/picast")              # installed by picast-setup
PICAST = PRODUCT / "bin/picast"
SETUP = PRODUCT / "bin/picast-setup"
STATE = Path("/var/lib/picast")
SESSIONS_LOG = STATE / "sessions.log"       # one short line per connection
SESSIONS_LOG_LIMIT = 256 * 1024
RUN = Path("/run/picast")
# Pairing key and paired devices live in memory only: after every start of the
# Pi the receiver is new to every device, so each one needs the PIN again.
# A restart of the service alone keeps them.
IDENTITY = RUN / "identity"
OLD_IDENTITY = STATE / "identity"
# What the display offers, readable from any computer: the SD card's boot partition.
DISPLAY_REPORT = Path("/boot/firmware/picast-display.txt")
FRAMEBUFFER_SIZE = Path("/sys/class/graphics/fb0/virtual_size")
FW_PATH = Path("/sys/module/firmware_class/parameters/path")
SRCVERSION = Path("/sys/module/brcmfmac/srcversion")
RFKILL = Path("/sys/class/rfkill")

SESSION_SECONDS = 43200        # one connection may last 12 h
LISTEN_SECONDS = 3
MIN_FRAMES = 3
CLASS_IOS, CLASS_MAC = 2, 1    # AWDL device classes: iPhone/iPad, Mac
PEER_UNCLAIMED, PEER_SWITCH = 3, 4
CHECK_SECONDS = 5
STUCK_MIN_FAILURES = 15
RADIO_FAILURES_BEFORE_REBOOT = 3
SILENCE = ["gst-launch-1.0", "-q", "audiotestsrc", "wave=silence", "num-buffers=60", "!",
           "audioconvert", "!", "alsasink", "device=plughw:0,0"]
# Lines worth keeping from a session; everything else (per-packet notes) is dropped.
KEPT_EVENTS = {"native_media_summary", "native_video_output_summary", "native_clock_summary",
               "native_audio_clock_summary", "ip_probe_summary", "probe_runtime_summary",
               "peer_switch_request", "receiver_hangup", "awdl_profile"}

stopping = threading.Event()


def log(event, **fields):
    print(json.dumps({"event": event, **fields}), flush=True)


def sh(*argv, check=True, timeout=25):
    result = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{Path(str(argv[0])).name} {argv[1] if len(argv) > 1 else ''} failed: {result.stderr.strip()[:200]}")
    return result


def picast(*args, **kw):
    return sh(PICAST, *args, **kw)


def screen(name, text=None):
    """A receiver screen; for "starting", text is a step: radio or driver."""
    picast("ui", name, *([text] if text else []), check=False, timeout=5)


def settings():
    """picast.txt as the receiver reads it (name, language, delay_ms, maintenance)."""
    defaults = {"name": "PiCast", "language": "en", "delay_ms": 270, "country": "DE", "maintenance": False, "warnings": []}
    try:
        values = json.loads(picast("config", check=False, timeout=5).stdout)
    except (ValueError, RuntimeError, OSError, subprocess.TimeoutExpired):
        return defaults
    return {**defaults, **values} if isinstance(values, dict) else defaults


# --- display -----------------------------------------------------------------

def display_size():
    """The mode the display came up in, as WIDTHxHEIGHT, or None without one."""
    try:
        width, height = (int(v) for v in FRAMEBUFFER_SIZE.read_text().split(","))
    except (OSError, ValueError):
        return None
    return f"{width}x{height}" if width > 0 and height > 0 else None


def edid_native(edid):
    """The monitor's own resolution and pixel clock from its first detailed timing."""
    if len(edid) < 72 or edid[:8] != bytes.fromhex("00ffffffffffff00"):
        return None
    d = edid[54:72]
    clock = int.from_bytes(d[0:2], "little") * 10   # kHz
    if not clock:
        return None
    width, height = d[2] | (d[4] >> 4) << 8, d[5] | (d[7] >> 4) << 8
    return {"width": width, "height": height, "pixel_clock_mhz": clock / 1000}


def display_report():
    """Records on the boot partition what each HDMI port reports, so a display that
    PiCast does not use well can be looked at from any computer. Written only when
    something changed."""
    lines = [f"PiCast: display at start ({display_size() or 'no picture'})", ""]
    for port in sorted(Path("/sys/class/drm").glob("card*-HDMI-A-*")):
        try:
            status = (port / "status").read_text().strip()
            modes = (port / "modes").read_text().split()
            edid = (port / "edid").read_bytes()
        except OSError:
            continue
        lines.append(f"{port.name}: {status}")
        if status != "connected":
            continue
        lines.append(f"  native: {edid_native(edid)}")
        lines.append(f"  modes: {' '.join(dict.fromkeys(modes))}")
        lines.append(f"  edid: {edid.hex()}")
    text = "\n".join(lines) + "\n"
    try:
        if not DISPLAY_REPORT.exists() or DISPLAY_REPORT.read_text() != text:
            DISPLAY_REPORT.write_text(text)
    except OSError:
        pass


# --- radio -------------------------------------------------------------------

def unload_driver():
    names = [line.split()[0] for line in Path("/proc/modules").read_text().splitlines()]
    for name in sorted(n for n in names if n.startswith("brcmfmac_")):
        sh("rmmod", name, check=False)
    if "brcmfmac" in names:
        sh("rmmod", "brcmfmac")


def stable_address(original):
    """A locally administered address derived from the chip's own, the same on
    every boot, so devices find the same receiver again (they still need the
    PIN after a restart, because the pairing key is new)."""
    mac = bytearray.fromhex(original.replace(":", ""))
    mac[0] |= 2
    mac[5] ^= 0x80
    return mac.hex(":")


def radio_driver():
    """The PiCast radio driver for the running kernel; built now if missing
    (for example after a kernel update made outside picast-setup)."""
    kernel = os.uname().release
    driver = PRODUCT / "driver" / kernel / "brcmfmac.ko"
    if not driver.exists():
        screen("starting", "driver")
        log("radio_driver_build", kernel=kernel)
        sh(SETUP, "--build-driver", kernel, check=False, timeout=3600)
        if not driver.exists():
            raise RuntimeError(f"no radio driver for kernel {kernel}")
    return driver


def unblock_radio(rfkill=RFKILL):
    """Raspberry Pi OS keeps the WLAN switched off (RF-kill) until a WLAN country
    is set, which the SD card image leaves out: PiCast needs no network. Lifts
    that software block for the WLAN radio; it is not a regulatory setting."""
    for switch in sorted(rfkill.glob("rfkill*")):
        try:
            if (switch / "type").read_text().strip() == "wlan" and (switch / "soft").read_text().strip() != "0":
                (switch / "soft").write_text("0")
                log("radio_unblocked", switch=switch.name)
        except OSError as error:
            raise RuntimeError(f"radio is switched off (rfkill) and cannot be switched on: {error}") from error


def set_country(country):
    """The WLAN country, before the radio driver loads, as Raspberry Pi OS does
    with cfg80211.ieee80211_regdom: the driver passes it on to the radio. Without
    it the radio stays in its restricted worldwide mode, in which Apple devices
    do not find PiCast."""
    if not (isinstance(country, str) and len(country) == 2 and country.isascii() and country.isalpha()):
        country = "DE"
    sh("iw", "reg", "set", country.upper(), check=False, timeout=5)
    log("radio_country", country=country.upper())


def start_radio(country):
    driver = radio_driver()
    expected = sh("modinfo", "-F", "srcversion", driver).stdout.strip()
    FW_PATH.write_text(str(PRODUCT / "firmware") + "\n")
    unload_driver()
    set_country(country)
    sh("insmod", driver, "picast_monitor=1")
    deadline = time.monotonic() + 20
    while not Path("/sys/class/net/wlan0").exists():
        if time.monotonic() > deadline:
            raise RuntimeError("radio driver did not come up")
        time.sleep(0.25)
    if SRCVERSION.read_text().strip() != expected:
        raise RuntimeError("unexpected radio driver")
    unblock_radio()
    sh("iw", "dev", "wlan0", "interface", "add", "picastmon", "type", "monitor")
    address = stable_address(Path("/sys/class/net/picastmon/address").read_text().strip())
    sh("ip", "link", "set", "picastmon", "address", address)
    sh("ip", "link", "set", "picastmon", "up")
    picast("radio-wake", "picastmon")
    sh("iw", "dev", "picastmon", "set", "channel", "6", "HT20")
    return address


def stop_radio():
    sh("iw", "dev", "picastmon", "del", check=False, timeout=5)


def restore_stock_wlan():
    """For bounded tests and maintenance: the normal WLAN as after boot."""
    try:
        stop_radio()
        FW_PATH.write_text("\n")
        unload_driver()
        sh("modprobe", "brcmfmac")
    finally:
        sh("systemctl", "--no-block", "start", "NetworkManager", check=False, timeout=10)


def radio_alive():
    return picast("radio-check", "picastmon", check=False, timeout=3).returncode == 0


def tx_counters():
    out = picast("radio-counters", "wlan0", check=False, timeout=3).stdout
    for line in out.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and "tx_bad" in record:
            return record["tx_good"], record["tx_bad"]
    return None


# --- senders -----------------------------------------------------------------

def listen():
    """What the radio hears for a few seconds, as analyzer lines."""
    path = RUN / "listen.pcap"
    picast("capture", "picastmon", LISTEN_SECONDS, path, check=False, timeout=LISTEN_SECONDS + 7)
    try:
        return picast("analyze", path, check=False, timeout=10).stdout
    finally:
        path.unlink(missing_ok=True)


def heard_senders(analyzer_output, own):
    """{address: (device class, frames heard, channels announced)}."""
    senders, source = {}, None
    for line in analyzer_output.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        if record.get("event") == "awdl_action":
            source = (record.get("source") or "").lower()
            continue
        if not source or source == own:
            continue
        entry = senders.setdefault(source, [None, 0, set()])
        if record.get("type") == 21:
            raw = record.get("hex", "")
            entry[0] = record.get("version_tag", {}).get("device_class", int(raw[2:4], 16) if len(raw) == 4 else None)
            entry[1] += 1
        if "channel_sequence" in record:
            entry[2] |= {c.get("number", 0) for c in record["channel_sequence"].get("channels", [])}
    return senders


def choose_sender(senders, avoid):
    """An iPhone or iPad before a Mac: an idle Mac nearby announces itself too."""
    best = None
    for address, (kind, frames, _) in senders.items():
        if kind not in (CLASS_IOS, CLASS_MAC) or frames < MIN_FRAMES or address == avoid:
            continue
        rank = (kind == CLASS_IOS, frames)
        if not best or rank > best[0]:
            best = (rank, address)
    return best[1] if best else None


def radio_profile(channels, previous):
    """Whether the sender needs free slots for its own WLAN on 2.4 GHz.

    Another 2.4 GHz channel: yes. Only 5 GHz besides ours: no. Only channel 6
    (a sender busy with us says nothing else): what we knew, else yes, since a
    sender without internet is worse than a slightly less smooth picture.
    """
    others = set(channels) - {0, 6}
    if any(c <= 13 for c in others):
        return True
    if others:
        return False
    return previous if previous is not None else True


# --- sessions ----------------------------------------------------------------

def append_session_log(entry):
    try:
        if SESSIONS_LOG.exists() and SESSIONS_LOG.stat().st_size > SESSIONS_LOG_LIMIT:
            SESSIONS_LOG.replace(SESSIONS_LOG.with_suffix(".log.1"))
        with SESSIONS_LOG.open("a") as f:
            f.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except OSError:
        pass


def session_environment(config, shares_band, size):
    """What one session needs to know: name, delay, radio profile, display shape."""
    env = dict(os.environ, PICAST_NAME=config["name"], PICAST_PLAYOUT_DELAY_MS=str(config["delay_ms"]),
               PICAST_STATE_DIR=str(IDENTITY), PICAST_AWDL_PROFILE="gaps1" if shares_band else "full")
    if size:
        env["PICAST_SCREEN"] = size      # a Mac then sends a picture of the display's shape
    return env


def serve(config, peer, shares_band, token):
    """One connection, until the sender leaves. Returns (exit code, summaries, radio stuck)."""
    env = session_environment(config, shares_band, display_size())
    command = [PICAST, "serve", "picastmon", peer, token]
    process = subprocess.Popen([str(c) for c in command], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=env)
    kept, errors = [], []

    def read():
        for line in process.stdout:
            if '"event":"' in line and any(f'"event":"{e}"' in line for e in KEPT_EVENTS):
                try:
                    kept.append(json.loads(line))
                except ValueError:
                    pass

    def read_errors():
        for line in process.stderr:
            errors.append(line.strip()[:200])
            del errors[:-3]          # the last few lines say why a session ended
    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    threading.Thread(target=read_errors, daemon=True).start()
    last, stuck = tx_counters(), False
    while process.poll() is None:
        if stopping.wait(CHECK_SECONDS):
            process.terminate()
            break
        now = tx_counters()
        if last and now:
            good, bad = now[0] - last[0], now[1] - last[1]
            if bad >= STUCK_MIN_FAILURES and good * 4 <= bad:
                stuck = True     # the transmitter hangs; only a new firmware helps
                process.terminate()
                break
        last = now or last
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    reader.join(timeout=5)
    if process.returncode not in (0, None) and errors:
        kept.append({"event": "session_error", "lines": list(errors)})
    return process.returncode, kept, stuck


def summarize(peer, profile, code, kept, started):
    entry = {"t": int(time.time()), "peer": peer[-5:], "profile": profile, "code": code,
             "seconds": round(time.monotonic() - started)}
    for record in kept:
        e = record.get("event")
        if e == "native_media_summary":
            entry.update(frames=record.get("decoded_frames"), size=f'{record.get("width")}x{record.get("height")}')
        elif e == "native_video_output_summary":
            entry.update(uneven=record.get("uneven_frames"), stalls=record.get("stalled_frames"))
        elif e == "ip_probe_summary":
            entry.update(resyncs=record.get("clock_resyncs"))
        elif e == "session_error":
            entry["error"] = record["lines"]
        elif e == "peer_switch_request":
            entry["next"] = (record.get("peer") or "").lower()
    return entry


def run(seconds):
    config = settings()
    if config["maintenance"]:
        log("maintenance_mode")      # systemd normally does not start us at all
        return
    for warning in config["warnings"]:
        log("settings_warning", line=warning)
    RUN.mkdir(exist_ok=True)
    shutil.rmtree(OLD_IDENTITY, ignore_errors=True)   # from builds that kept pairings
    IDENTITY.mkdir(parents=True, exist_ok=True)
    os.chmod(IDENTITY, 0o700)
    deadline = time.monotonic() + seconds if seconds else None
    # "Ready" only once the radio listens: from then on PiCast answers a device
    # that opens screen mirroring, and appears in its menu.
    screen("starting")
    display_report()
    sh("systemctl", "stop", "NetworkManager", "wpa_supplicant", check=False, timeout=20)
    screen("starting", "radio")
    own = start_radio(config["country"])
    log("receiver_ready", name=config["name"], language=config["language"], delay_ms=config["delay_ms"])
    token = secrets.token_hex(16)
    band, avoid, knocked, radio_failures, listening = {}, None, None, 0, False
    while not stopping.is_set() and (deadline is None or time.monotonic() < deadline):
        if not radio_alive():
            radio_failures += 1
            log("radio_restart", failures=radio_failures)
            if radio_failures >= RADIO_FAILURES_BEFORE_REBOOT:
                raise RuntimeError("radio keeps failing")
            screen("recovering")
            stop_radio()
            own = start_radio(config["country"])
            listening = False
            continue
        if knocked:
            peer, channels, knocked = knocked, [], None
        else:
            heard = listen()
            # A capture the analyzer could read ends with its summary line.
            if not listening and '"event":"summary"' in heard:
                screen("ready")
                listening = True
            senders = heard_senders(heard, own)
            peer = choose_sender(senders, avoid)
            if not peer:
                avoid = None
                continue
            channels = senders[peer][2]
        shares = radio_profile(channels, band.get(peer))
        band[peer] = shares
        started = time.monotonic()
        code, kept, stuck = serve(config, peer, shares, token)
        entry = summarize(peer, "gaps1" if shares else "full", code, kept, started)
        append_session_log(entry)
        log("session", **entry)
        sh(*SILENCE, check=False, timeout=5)   # the TV repeats the last sound otherwise
        if stuck:
            screen("recovering")
            stop_radio()
            own = start_radio(config["country"])
            listening = False
        else:
            radio_failures = 0
        avoid = peer if code == PEER_UNCLAIMED else None
        if code == PEER_SWITCH and entry.get("next") and entry["next"] != own:
            knocked = entry["next"]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    go = sub.add_parser("run")
    go.add_argument("--for", dest="seconds", type=int, default=0,
                    help="bounded test: stop after this many seconds and bring the normal WLAN back")
    args = parser.parse_args()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopping.set())
    if args.seconds and not 60 <= args.seconds <= 3600:
        parser.error("--for takes 60..3600 seconds")
    try:
        run(args.seconds)
        code = 0
    except Exception as error:
        log("receiver_error", error=str(error))
        code = 1
    finally:
        if args.seconds:
            restore_stock_wlan()
            screen("off")
    if code and not args.seconds and not stopping.is_set():
        # A radio that does not come back needs a fresh chip: restart the device.
        screen("recovering")
        os.sync()
        sh("systemctl", "--no-block", "reboot", check=False)
    return code


if __name__ == "__main__":
    sys.exit(main())

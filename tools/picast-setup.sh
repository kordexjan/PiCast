#!/bin/bash
# PiCast setup: turns Raspberry Pi OS Lite (64-bit) on a Raspberry Pi Zero 2 W
# into a PiCast receiver. The release file picast-install.sh is this script with
# everything it needs appended (source, radio firmware, driver source), so it
# works without access to GitHub.
#
#   sudo bash picast-install.sh            install or update on the Pi, then reboot
#   picast-install.sh --image              the same inside a Raspberry Pi OS image
#                                          (chroot; used to build the SD card image)
#   picast-setup --update                  maintenance mode: system updates (timer)
#   picast-setup --build-driver VERSION    driver for one kernel (also at boot)
#   picast-setup --build-only DIR          CI: build everything from DIR, change nothing
#
# Kernel rule: the radio driver is built for one exact kernel. The kernel is
# therefore held and only moves on once the driver has been built for the new
# one; until then the Pi keeps the kernel it has.
set -euo pipefail

ROOT=/opt/picast
BOOT=/boot/firmware
CONFIG=$BOOT/picast.txt
KERNEL_META=linux-image-rpi-v8
LOG=/var/log/picast-setup.log
LOCK=/run/picast-setup.lock
export DEBIAN_FRONTEND=noninteractive
# Waits for another package manager (the daily update in maintenance mode) instead of failing.
APT=(apt-get -y -q -o DPkg::Lock::Timeout=900 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)

BUILD_PACKAGES=(build-essential pkg-config bc libssl-dev libplist-dev libcairo2-dev libdrm-dev
                libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev kmod)
RUN_PACKAGES=(python3 iw gstreamer1.0-tools gstreamer1.0-plugins-base gstreamer1.0-plugins-good
              gstreamer1.0-plugins-bad gstreamer1.0-alsa fonts-inter i2c-tools)

say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf '\033[1;31mError: %s\033[0m\n' "$*" >&2; exit 1; }

# One setup at a time, whatever started it.
exclusive() {
    exec 9>"$LOCK"
    flock -w 1800 9 || die "Another PiCast setup is still running"
}

# --- kernels -----------------------------------------------------------------

# Newest installed Raspberry Pi 64-bit kernel, e.g. 6.18.50+rpt-rpi-v8.
installed_kernel() {
    dpkg-query -W -f='${Package} ${db:Status-Status}\n' 'linux-image-*-rpi-v8' 2>/dev/null |
        awk '$2=="installed"{sub("^linux-image-","",$1); print $1}' | sort -V | tail -n1
}

# The kernel the archive offers right now.
candidate_kernel() {
    apt-cache depends "$KERNEL_META" 2>/dev/null |
        awk '/Depends: linux-image-.*-rpi-v8$/{sub(".*linux-image-",""); print; exit}'
}

kernel_build_dir() {
    if [ -d "/lib/modules/$1/build" ]; then echo "/lib/modules/$1/build"
    elif [ -d "/usr/src/linux-headers-$1" ]; then echo "/usr/src/linux-headers-$1"
    else return 1; fi
}

# Build the PiCast radio driver for kernel $1 into $ROOT/driver/$1.
# $2: driver source (default: installed copy).
build_driver() {
    local version=$1 source=${2:-$ROOT/driver/src} kdir work
    kdir=$(kernel_build_dir "$version") || { "${APT[@]}" install "linux-headers-$version" >/dev/null && kdir=$(kernel_build_dir "$version"); } ||
        { note "No kernel headers for $version"; return 1; }
    work=$(mktemp -d)
    cp -a "$source/." "$work/"
    if ! make -C "$kdir" M="$work" -j2 modules >"$work/build.log" 2>&1; then
        tail -n 20 "$work/build.log" >&2
        rm -rf "$work"
        return 1
    fi
    if ! modinfo -F vermagic "$work/brcmfmac.ko" | grep -q "^$version "; then
        rm -rf "$work"; note "Driver does not match $version"; return 1
    fi
    mkdir -p "$ROOT/driver/$version"
    install -m 0644 "$work/brcmfmac.ko" "$ROOT/driver/$version/brcmfmac.ko"
    rm -rf "$work"
    note "Radio driver built for $version ($(modinfo -F srcversion "$ROOT/driver/$version/brcmfmac.ko"))"
}

# Keep the held kernel, move to a newer one only with a driver for it.
update_kernel() {
    local current candidate
    current=$(installed_kernel)
    [ -n "$current" ] || die "No Raspberry Pi kernel (rpi-v8) installed"
    apt-mark hold "$KERNEL_META" >/dev/null
    if [ ! -f "$ROOT/driver/$current/brcmfmac.ko" ]; then
        build_driver "$current" || note "The driver for the installed kernel $current did not build"
    fi
    candidate=$(candidate_kernel)
    if [ -n "$candidate" ] && [ "$candidate" != "$current" ] && \
       [ "$(printf '%s\n%s\n' "$current" "$candidate" | sort -V | tail -n1)" = "$candidate" ]; then
        say "New kernel $candidate available, building the radio driver for it first"
        if build_driver "$candidate"; then
            apt-mark unhold "$KERNEL_META" >/dev/null
            "${APT[@]}" install "$KERNEL_META" "linux-image-$candidate" "linux-headers-$candidate"
            apt-mark hold "$KERNEL_META" >/dev/null
            current=$candidate
        else
            note "The driver does not build for $candidate. The Pi stays on kernel $current."
        fi
    fi
    [ -f "$ROOT/driver/$current/brcmfmac.ko" ] ||
        die "There is no radio driver for kernel $current. Please report this on GitHub."
    # Drivers for kernels that are gone.
    for dir in "$ROOT"/driver/*-rpi-v8; do
        [ -d "$dir" ] || continue
        dpkg-query -W -f='${db:Status-Status}' "linux-image-$(basename "$dir")" 2>/dev/null | grep -q installed || rm -rf "$dir"
    done
}

# --- building ----------------------------------------------------------------

build_programs() {
    local src=$1 version=$2
    say "Building PiCast (takes a few minutes on the Zero 2 W)"
    make -C "$src" -j2 VERSION="$version" build/picast build/picast-power >"$src/build.log" 2>&1 ||
        { tail -n 30 "$src/build.log" >&2; die "PiCast did not build (log: $src/build.log)"; }
}

install_firmware() {
    local radio=$1 stem board prefix suffix stock
    rm -rf "$ROOT/firmware.new"
    mkdir -p "$ROOT/firmware.new/brcm"
    for stem in brcmfmac43430b0-sdio brcmfmac43436-sdio; do
        for board in "" ".raspberrypi,model-zero-2-w"; do
            prefix=$ROOT/firmware.new/brcm/$stem$board
            install -m 0644 "$radio/firmware/brcmfmac43436-sdio.bin" "$prefix.bin"
            # Calibration and regulatory data stay the system's own.
            for suffix in .txt .clm_blob; do
                stock=/lib/firmware/brcm/brcmfmac43436-sdio$suffix
                if [ -e "$stock" ]; then cp -L "$stock" "$prefix$suffix"
                elif [ -e "$stock.zst" ]; then zstd -qdc "$stock.zst" >"$prefix$suffix"
                elif [ -e "$stock.xz" ]; then xz -dc "$stock.xz" >"$prefix$suffix"
                else die "System file $stock is missing (package firmware-brcm80211)"; fi
            done
        done
    done
    rm -rf "$ROOT/firmware"
    mv "$ROOT/firmware.new" "$ROOT/firmware"
}

# --- system ------------------------------------------------------------------

drop_in() {   # unit, file name, content
    mkdir -p "/etc/systemd/system/$1.d"
    printf '%s\n' "$3" >"/etc/systemd/system/$1.d/$2"
}

configure_system() {
    local src=$1 image=$2 line word unit
    say "Setting the system up as a receiver"
    # The user's settings, kept on updates.
    [ -e "$CONFIG" ] || install -m 0644 "$src/system/picast.txt" "$CONFIG"
    # The normal WLAN and the login prompt only in maintenance mode (picast.txt).
    for unit in NetworkManager.service wpa_supplicant.service NetworkManager-wait-online.service getty@tty1.service; do
        drop_in "$unit" picast.conf "$(printf '[Unit]\nRequiresMountsFor=%s\n\n[Service]\nExecCondition=%s/bin/picast config maintenance' "$BOOT" "$ROOT")"
    done
    # A hung system restarts by itself; logs only in memory.
    mkdir -p /etc/systemd/system.conf.d /etc/systemd/journald.conf.d
    printf '[Manager]\nRuntimeWatchdogSec=15s\nRebootWatchdogSec=2min\n' >/etc/systemd/system.conf.d/picast.conf
    printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=16M\n' >/etc/systemd/journald.conf.d/picast.conf
    # Less to start and less to power.
    for unit in bluetooth.service hciuart.service udisks2.service apt-daily.timer apt-daily-upgrade.timer \
                man-db.timer dpkg-db-backup.timer rpi-eeprom-update.service ModemManager.service \
                avahi-daemon.service avahi-daemon.socket triggerhappy.service triggerhappy.socket; do
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    if [ "$image" = 1 ]; then
        # A fresh image still applies the Imager's settings (user, WLAN, SSH) on its
        # first start; picast-first-boot then switches cloud-init off. Without
        # settings there is no user to create: the receiver needs none.
        systemctl disable userconfig.service >/dev/null 2>&1 || true
        # The image carries no SSH host keys; each card makes its own.
        drop_in ssh.service picast-keys.conf "$(printf '[Service]\nExecStartPre=-/usr/bin/ssh-keygen -A')"
        install -m 0644 "$src/system/picast-first-boot.service" /etc/systemd/system/
        systemctl enable picast-first-boot.service >/dev/null 2>&1
    else
        for unit in cloud-init-local.service cloud-init-main.service cloud-init-network.service \
                    cloud-init.service cloud-config.service cloud-final.service; do
            systemctl disable --now "$unit" >/dev/null 2>&1 || true
        done
    fi
    # Battery HAT on I2C; a quiet start without rainbow, text or cursor.
    [ -e "$BOOT/config.txt.before-picast" ] || cp -a "$BOOT/config.txt" "$BOOT/config.txt.before-picast"
    grep -q '^# PiCast' "$BOOT/config.txt" ||
        printf '\n# PiCast\n[all]\ndtparam=i2c_arm=on\ndisable_splash=1\ndtoverlay=disable-bt\n' >>"$BOOT/config.txt"
    echo i2c-dev >/etc/modules-load.d/picast-i2c.conf
    [ -e "$BOOT/cmdline.txt.before-picast" ] || cp -a "$BOOT/cmdline.txt" "$BOOT/cmdline.txt.before-picast"
    line=$(tr -d '\n' <"$BOOT/cmdline.txt" | sed 's/ console=tty1//')
    for word in quiet loglevel=3 logo.nologo vt.global_cursor_default=0 consoleblank=0; do
        case " $line " in *" $word "*) ;; *) line="$line $word" ;; esac
    done
    printf '%s\n' "$line" >"$BOOT/cmdline.txt"
    # Services.
    install -m 0644 "$src"/system/picast.service "$src"/system/picast-power.service \
        "$src"/system/picast-update.service "$src"/system/picast-update.timer \
        "$src"/system/picast-boot-screen.service /etc/systemd/system/
    # The start screen as soon as the display exists (no [Install]: udev starts it).
    install -m 0644 "$src"/system/90-picast-boot-screen.rules /etc/udev/rules.d/
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable picast.service picast-power.service picast-update.timer >/dev/null 2>&1
}

# Development installs from before the first release kept a bundle in /opt/picast.
migrate() {
    if [ -f "$ROOT/manifest.json" ] && [ ! -d "$ROOT/bin" ]; then
        rm -rf /opt/picast.lab
        mv "$ROOT" /opt/picast.lab
        note "Moved an old development install to /opt/picast.lab"
    fi
    rm -rf /usr/local/lib/picast /opt/picast.old
    rm -f /usr/local/bin/picast-power
}

# --- modes -------------------------------------------------------------------

check_device() {
    [ "$(id -u)" = 0 ] || die "Please run with sudo: sudo bash $0"
    [ "$(uname -m)" = aarch64 ] || die "PiCast needs the 64-bit Raspberry Pi OS Lite"
    [ -d "$BOOT" ] && [ -f "$BOOT/config.txt" ] || die "$BOOT is missing; is this Raspberry Pi OS?"
    [ "$1" = 1 ] && return 0   # an image: no board to look at
    local model
    model=$(tr -d '\0' </proc/device-tree/model 2>/dev/null || true)
    case "$model" in
        *"Zero 2 W"*) ;;
        *) [ "${PICAST_ANY_PI:-}" = 1 ] || die "PiCast runs on the Raspberry Pi Zero 2 W only (found: ${model:-unknown})" ;;
    esac
}

payload_line() { awk '/^__PICAST_PAYLOAD__$/{print NR + 1; exit}' "$1"; }

do_install() {
    local image=$1 self tmp start version
    self=$(readlink -f "$0")
    start=$(payload_line "$self")
    [ -n "$start" ] || die "This file holds no PiCast package; please use picast-install.sh from the GitHub release"
    check_device "$image"
    exclusive
    exec > >(tee -a "$LOG") 2>&1
    # Not while the daily update of maintenance mode runs.
    [ "$image" = 1 ] || systemctl stop picast-update.timer picast-update.service >/dev/null 2>&1 || true
    tmp=$(mktemp -d)
    # shellcheck disable=SC2064  # expand now: $tmp is local
    trap "rm -rf '$tmp'" EXIT
    tail -n +"$start" "$self" | tar -xz -C "$tmp"
    version=$(cat "$tmp/VERSION")
    say "Installing PiCast $version"
    getent hosts deb.debian.org >/dev/null 2>&1 || getent hosts archive.raspberrypi.com >/dev/null 2>&1 ||
        die "No internet connection. The Pi needs WLAN with internet once, for the installation."

    say "Updating and installing system packages"
    apt-mark hold "$KERNEL_META" >/dev/null 2>&1 || true
    "${APT[@]}" update
    "${APT[@]}" full-upgrade
    "${APT[@]}" install --no-install-recommends "${BUILD_PACKAGES[@]}" "${RUN_PACKAGES[@]}" zstd xz-utils

    migrate
    mkdir -p "$ROOT/bin" "$ROOT/lib" "$ROOT/driver" /var/lib/picast
    rm -rf "$ROOT/src.new"
    mv "$tmp/src" "$ROOT/src.new"
    build_programs "$ROOT/src.new" "$version"

    say "Radio driver and radio firmware"
    rm -rf "$ROOT/driver/src"
    cp -a "$tmp/radio/driver" "$ROOT/driver/src"
    install_firmware "$tmp/radio"
    update_kernel

    # Everything built: switch over.
    install -m 0755 "$ROOT/src.new/build/picast" "$ROOT/bin/picast"
    install -m 0755 "$ROOT/src.new/build/picast-power" "$ROOT/bin/picast-power"
    install -m 0755 "$ROOT/src.new/tools/picast_product.py" "$ROOT/lib/picast_product.py"
    install -m 0755 "$ROOT/src.new/tools/picast-setup.sh" "$ROOT/bin/picast-setup"
    ln -sf "$ROOT/bin/picast-setup" /usr/local/sbin/picast-setup
    ln -sf "$ROOT/bin/picast" /usr/local/bin/picast
    rm -rf "$ROOT/src"
    mv "$ROOT/src.new" "$ROOT/src"
    rm -rf "$ROOT/src/build"   # the source stays (GPL); the build output is installed
    cp "$tmp/radio/BUILD.json" "$ROOT/radio.json"
    echo "$version" >"$ROOT/VERSION"
    configure_system "$ROOT/src" "$image"

    if [ "$image" = 1 ]; then
        "${APT[@]}" autoremove --purge
        "${APT[@]}" clean
        rm -f /var/lib/apt/lists/*_Packages /var/lib/apt/lists/*_Sources 2>/dev/null || true
        say "Done: PiCast $version is in the image"
        return
    fi
    say "Done: PiCast $version is installed"
    if "$ROOT/bin/picast" config maintenance; then
        note "Maintenance mode is on (picast.txt on the SD card)."
        note "To make the Pi a receiver, set maintenance = off in $CONFIG, then: sudo reboot"
    else
        note "After the next restart the Pi is a PiCast receiver:  sudo reboot"
        note "WLAN and SSH are then off. For maintenance, set maintenance = on in picast.txt"
        note "on the SD card's bootfs drive."
    fi
}

do_update() {
    [ "$(id -u)" = 0 ] || die "Please run with sudo"
    "$ROOT/bin/picast" config maintenance || { note "Not in maintenance mode: no updates"; exit 0; }
    exclusive
    exec >>"$LOG" 2>&1
    say "Updates $(date -Is)"
    apt-mark hold "$KERNEL_META" >/dev/null
    "${APT[@]}" update
    "${APT[@]}" upgrade
    update_kernel
    "${APT[@]}" autoremove --purge
    "${APT[@]}" clean
}

# CI: everything that is built, against the newest kernel headers; no system changes.
do_build_only() {
    local payload=$1 kernel
    "${APT[@]}" update
    "${APT[@]}" install --no-install-recommends "${BUILD_PACKAGES[@]}" "${RUN_PACKAGES[@]}" zstd xz-utils
    kernel=$(candidate_kernel)
    [ -n "$kernel" ] || die "No kernel found in the package archive"
    "${APT[@]}" install --no-install-recommends "linux-headers-$kernel"
    build_programs "$payload/src" "$(cat "$payload/VERSION")"
    ROOT=$(mktemp -d)
    build_driver "$kernel" "$payload/radio/driver" || die "The radio driver does not build for $kernel"
    printf '{"kernel":"%s","srcversion":"%s","version":"%s"}\n' "$kernel" \
        "$(modinfo -F srcversion "$ROOT/driver/$kernel/brcmfmac.ko")" \
        "$(modinfo -F version "$ROOT/driver/$kernel/brcmfmac.ko")"
}

case "${1:-}" in
    --update) do_update ;;
    --build-driver) [ "$(id -u)" = 0 ] || die "Please run with sudo"; build_driver "${2:?kernel version}" ;;
    --build-only) do_build_only "${2:?payload directory}" ;;
    --image) do_install 1 ;;
    ""|--install) do_install 0 ;;
    *) die "Unknown option: $1" ;;
esac
exit 0

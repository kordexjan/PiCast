#!/bin/bash
# Builds the ready-to-flash PiCast SD card image: the official Raspberry Pi OS
# Lite (64-bit) with picast-install.sh already run inside it (an arm64 chroot,
# through qemu-user on other machines). Needs root, losetup, parted, e2fsck,
# resize2fs, zerofree and xz; arm64 binaries must run (binfmt with qemu-aarch64).
#
#   sudo tools/build_image.sh BASE_IMAGE.img.xz picast-install.sh OUT.img.xz
#
# The result boots straight into PiCast. Settings from the Raspberry Pi Imager
# (user, WLAN, SSH) still apply on the first start, for maintenance mode.
set -euo pipefail
BASE=$(readlink -f "$1")
INSTALLER=$(readlink -f "$2")
OUT=$3
GROW_MB=1536          # room for the build tools and PiCast; the card's rest comes at first boot

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
WORK=$(mktemp -d)
IMAGE=$WORK/picast.img
MNT=$WORK/root
ROOTDEV='' BOOTDEV=''
cleanup() {
    set +e
    for m in "$MNT/boot/firmware" "$MNT/dev/pts" "$MNT/dev" "$MNT/proc" "$MNT/sys" "$MNT/run" "$MNT"; do
        mountpoint -q "$m" && umount -l "$m"
    done
    [ -n "$BOOTDEV" ] && losetup -d "$BOOTDEV"
    [ -n "$ROOTDEV" ] && losetup -d "$ROOTDEV"
    rm -rf "$WORK"
}
# A loop device for partition $1 (by offset: works without udev, also in containers).
partition() {
    local start size
    read -r start size < <(parted -ms "$IMAGE" unit B print | awk -F: -v n="$1" '$1==n{sub("B","",$2); sub("B","",$4); print $2, $4}')
    losetup -f --show -o "$start" --sizelimit "$size" "$IMAGE"
}
trap cleanup EXIT

echo "==> Unpacking $(basename "$BASE")"
xz -dc "$BASE" >"$IMAGE"
truncate -s "+${GROW_MB}M" "$IMAGE"
parted -s "$IMAGE" resizepart 2 100%
ROOTDEV=$(partition 2)
BOOTDEV=$(partition 1)
e2fsck -fy "$ROOTDEV" >/dev/null || [ $? -le 1 ]
resize2fs "$ROOTDEV" >/dev/null

mkdir -p "$MNT"
mount "$ROOTDEV" "$MNT"
mount "$BOOTDEV" "$MNT/boot/firmware"
mount --bind /dev "$MNT/dev"
mount --bind /dev/pts "$MNT/dev/pts"
mount -t proc proc "$MNT/proc"
mount -t sysfs sys "$MNT/sys"
mount -t tmpfs tmpfs "$MNT/run"
# Network for apt inside the chroot; the image's own file comes back afterwards.
cp -a "$MNT/etc/resolv.conf" "$WORK/resolv.conf" 2>/dev/null || true
rm -f "$MNT/etc/resolv.conf"
cp /etc/resolv.conf "$MNT/etc/resolv.conf"
# No services start inside the chroot while packages install.
printf '#!/bin/sh\nexit 101\n' >"$MNT/usr/sbin/policy-rc.d"
chmod 0755 "$MNT/usr/sbin/policy-rc.d"

echo "==> Running the PiCast installer inside the image"
install -m 0755 "$INSTALLER" "$MNT/tmp/picast-install.sh"
chroot "$MNT" /bin/bash /tmp/picast-install.sh --image
chroot "$MNT" /opt/picast/bin/picast version

rm -f "$MNT/tmp/picast-install.sh" "$MNT/usr/sbin/policy-rc.d" "$MNT/etc/resolv.conf"
if [ -e "$WORK/resolv.conf" ] || [ -L "$WORK/resolv.conf" ]; then cp -a "$WORK/resolv.conf" "$MNT/etc/resolv.conf"; fi
rm -rf "$MNT/var/cache/apt/archives/"*.deb "$MNT/root/.cache"
# A fresh SSH host key per card: Raspberry Pi OS makes it on first boot when none exists.
rm -f "$MNT"/etc/ssh/ssh_host_*

for m in "$MNT/boot/firmware" "$MNT/dev/pts" "$MNT/dev" "$MNT/proc" "$MNT/sys" "$MNT/run" "$MNT"; do umount "$m"; done
# Unused blocks as zeros compress to nothing.
e2fsck -fy "$ROOTDEV" >/dev/null || [ $? -le 1 ]
zerofree "$ROOTDEV"
losetup -d "$BOOTDEV"; BOOTDEV=
losetup -d "$ROOTDEV"; ROOTDEV=

echo "==> Compressing"
xz -T0 -6 -c "$IMAGE" >"$OUT"
sha256sum "$OUT" | sed 's|  .*/|  |' >"$OUT.sha256"
echo "$OUT: $(du -h "$OUT" | cut -f1)"

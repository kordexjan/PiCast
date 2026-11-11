#!/bin/bash
# Builds PiCast's radio parts from the pinned Nexmon source on an x86-64 Linux
# machine (GitHub Actions; needs gawk, qpdf, xxd and libc6:i386): the patched BCM43436 firmware and the patched
# brcmfmac driver source, which picast-setup compiles on the Pi for its kernel.
#
#   tools/build_radio.sh WORK_DIR OUT_DIR
#
# OUT_DIR/firmware/brcmfmac43436-sdio.bin, OUT_DIR/driver/, OUT_DIR/BUILD.json
# Details and history: radio/README.md
set -euo pipefail
PROJECT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mkdir -p "$1" && cd "$1" && pwd)
OUT=$(mkdir -p "$2" && cd "$2" && pwd)
COMMIT=68720406f54ff16cad28fd3c51f2392aefad9fb7
NEXMON=$WORK/nexmon
FW_DIR=firmwares/bcm43436b0/9_88_4_65
PATCH_DIR=patches/bcm43436b0/9_88_4_65/nexmon
DRIVER_DIR=patches/driver/brcmfmac_6.6.y-nexmon
ORIGINAL_SHA=6dc7b3b53a1b69637a9e10e675e73ef56ca689d5bd279b78bd2f2719970cb80b

if [ ! -d "$NEXMON/.git" ]; then
    git init -q "$NEXMON"
    git -C "$NEXMON" remote add origin https://github.com/seemoo-lab/nexmon.git
    git -C "$NEXMON" fetch -q --depth 1 origin "$COMMIT"
    git -C "$NEXMON" checkout -q FETCH_HEAD
fi
cd "$NEXMON"
git reset -q --hard "$COMMIT"
git clean -qfdx
# Upstream would otherwise report build statistics.
touch DISABLE_STATISTICS

# Inputs: driver port to Linux 6.18, firmware NULL guard, monitor-copy profile.
git apply "$PROJECT/radio/nexmon-6.18.patch"
echo "$ORIGINAL_SHA  $FW_DIR/brcmfmac43436-sdio.bin" | sha256sum -c --quiet
python3 "$PROJECT/radio/check_guard_input.py" "$FW_DIR/brcmfmac43436-sdio.bin" >/dev/null
cp "$PROJECT/radio/picast_null_sample_guard.c" "$PATCH_DIR/src/"
python3 "$PROJECT/radio/apply_monitor_profile.py" . >/dev/null

# The 2016 toolchain is 32-bit x86 and needs only the i386 C library
# (dpkg --add-architecture i386; apt-get install libc6:i386).
[ -e /lib/ld-linux.so.2 ] || { echo "i386 C library missing (libc6:i386)" >&2; exit 1; }

set +u
# shellcheck disable=SC1091
source setup_env.sh
set -u
make -s -C buildtools/ucode_extractor
make -s -C buildtools/flash_patch_extractor
make -s -C "$FW_DIR"
make -C "$PATCH_DIR" GIT_VERSION=68720406-picast brcmfmac43436-sdio.bin

# Checks that the result is the intended kind of firmware.
python3 - "$FW_DIR/brcmfmac43436-sdio.bin" "$PATCH_DIR/brcmfmac43436-sdio.bin" "$PATCH_DIR/src/monitormode.c" <<'EOF'
import hashlib, json, sys
original, patched, monitor = (open(p, "rb").read() for p in sys.argv[1:])
assert len(original) <= len(patched) <= 0x650F0 + 0xC00, "unexpected firmware size"
assert patched != original, "firmware unchanged"
assert b"9.88.4.65 (nexmon.org: 68720406-picast-" in patched, "version marker missing"
assert original[0x204c4:0x204c8] != patched[0x204c4:0x204c8], "NULL guard entry not patched"
assert b"picast_monitor_profile.h" in monitor, "monitor profile not applied"
print(json.dumps({"size": len(patched), "sha256": hashlib.sha256(patched).hexdigest()}))
EOF

rm -rf "$OUT/firmware" "$OUT/driver"
mkdir -p "$OUT/firmware"
cp "$PATCH_DIR/brcmfmac43436-sdio.bin" "$OUT/firmware/"
cp -a "$DRIVER_DIR" "$OUT/driver"
(cd "$OUT/driver" && rm -f ./*.o ./*.ko ./*.mod* ./.*.cmd Module.symvers modules.order)
# Built on the Pi without the Nexmon tree: include paths relative to the driver itself.
sed -i 's|\$(NEXMON_ROOT)/patches/driver/brcmfmac_6.6.y-nexmon|$(src)|g' "$OUT/driver/Makefile"
grep -q 'NEXMON_ROOT' "$OUT/driver/Makefile" && { echo "driver Makefile still needs NEXMON_ROOT" >&2; exit 1; }
mkdir -p "$OUT/licenses"
cp LICENSE.txt "$OUT/licenses/Nexmon-GPL-3.0.txt"
python3 - "$OUT" "$COMMIT" <<'EOF'
import hashlib, json, pathlib, sys
out, commit = pathlib.Path(sys.argv[1]), sys.argv[2]
fw = out / "firmware/brcmfmac43436-sdio.bin"
json.dump({"nexmon_commit": commit,
           "firmware_sha256": hashlib.sha256(fw.read_bytes()).hexdigest(),
           "firmware_size": fw.stat().st_size,
           "driver_files": sorted(p.name for p in (out / "driver").iterdir() if p.is_file())},
          open(out / "BUILD.json", "w"), indent=1)
EOF
echo "radio parts in $OUT"

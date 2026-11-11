#!/bin/bash
# Packs the single-file installer: tools/picast-setup.sh followed by a tar.gz
# with the PiCast source (tracked files of this checkout), the radio parts from
# tools/build_radio.sh and the version.
#
#   tools/make_installer.sh RADIO_DIR VERSION OUT_FILE
set -euo pipefail
PROJECT=$(cd "$(dirname "$0")/.." && pwd)
RADIO=$(cd "$1" && pwd)
VERSION=$2
OUT=$3
for f in firmware/brcmfmac43436-sdio.bin driver/Makefile BUILD.json; do
    [ -e "$RADIO/$f" ] || { echo "missing $RADIO/$f" >&2; exit 1; }
done
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/src"
# Only what the device builds and runs, with the licenses.
(cd "$PROJECT" && git ls-files -z -- Makefile LICENSE README.md include src third_party system \
    tools/picast_product.py tools/picast-setup.sh |
    while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done |
    tar -c --null -T - -f -) | tar -x -C "$STAGE/src"
mkdir -p "$STAGE/radio"
cp -a "$RADIO/firmware" "$RADIO/driver" "$RADIO/BUILD.json" "$STAGE/radio/"
[ -d "$RADIO/licenses" ] && cp -a "$RADIO/licenses" "$STAGE/radio/"
echo "$VERSION" >"$STAGE/VERSION"
{
    cat "$PROJECT/tools/picast-setup.sh"
    echo "__PICAST_PAYLOAD__"
    tar -C "$STAGE" -cz --owner=0 --group=0 VERSION src radio
} >"$OUT"
chmod 0755 "$OUT"
echo "$OUT: $(wc -c <"$OUT") bytes, PiCast $VERSION"

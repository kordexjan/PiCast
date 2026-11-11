#!/bin/bash
# Inside a debian:trixie arm64 container: adds the Raspberry Pi OS package
# archive and runs the installer's build stage (all packages, PiCast, radio
# driver for the newest Raspberry Pi kernel). Used by CI and for local tests.
#
#   tools/ci_build_check.sh PAYLOAD_DIR
set -euo pipefail
PROJECT=$(cd "$(dirname "$0")/.." && pwd)
KEYRING=raspberrypi-archive-keyring_2025.1+rpt1_all.deb
KEYRING_SHA=2e727149d7acb8cc7f604e66d0049161039c8aa1eaf1175e54f9e69d963d60e4
export DEBIAN_FRONTEND=noninteractive
apt-get update -q >/dev/null
apt-get install -y -q curl ca-certificates >/dev/null
curl -fsSLo "/tmp/$KEYRING" "http://archive.raspberrypi.com/debian/pool/main/r/raspberrypi-archive-keyring/$KEYRING"
echo "$KEYRING_SHA  /tmp/$KEYRING" | sha256sum -c --quiet
dpkg -i "/tmp/$KEYRING" >/dev/null
cat >/etc/apt/sources.list.d/raspi.sources <<'EOF'
Types: deb
URIs: http://archive.raspberrypi.com/debian
Suites: trixie
Components: main
Signed-By: /usr/share/keyrings/raspberrypi-archive-keyring.pgp
EOF
bash "$PROJECT/tools/picast-setup.sh" --build-only "$1"

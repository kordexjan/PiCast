#!/usr/bin/env python3
"""Check the exact supported firmware bytes before building the NULL guard."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("firmware", type=Path)
args = parser.parse_args()
data = args.firmware.read_bytes()
if hashlib.sha256(data).hexdigest() != "6dc7b3b53a1b69637a9e10e675e73ef56ca689d5bd279b78bd2f2719970cb80b":
    raise SystemExit("Unsupported firmware SHA256; refusing guard")
if data[0x204c4:0x204cc] != bytes.fromhex("002381681a46c818"):
    raise SystemExit("Unsupported instruction signature; refusing guard")
if data[8:12] != bytes.fromhex("11200000") or b"9.88.4.65" not in data:
    raise SystemExit("Unsupported firmware identity; refusing guard")
print(json.dumps(dict(input_sha256=hashlib.sha256(data).hexdigest(),
                      entry="0x204c4", continuation="0x204c8", signature_verified=True,
                      hardware_changed=False)))

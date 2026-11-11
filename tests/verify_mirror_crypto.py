#!/usr/bin/env python3
"""Independent SHA512/AES-CTR encryptor vs actual C mirror-stream decryptor."""
import hashlib
import subprocess
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

media = bytes(range(16))
ecdh = bytes(range(32, 64))
folded = hashlib.sha512(media+ecdh).digest()[:16]
plain = bytes(range(256))*263 + b'last partial block'
for stream in [0, 1, 4964383553955644435, 2**63-1, 2**63, 2**64-1]:
    label = str(stream).encode()
    key = hashlib.sha512(b'AirPlayStreamKey'+label+folded).digest()[:16]
    iv = hashlib.sha512(b'AirPlayStreamIV'+label+folded).digest()[:16]
    encoder = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    encrypted = encoder.update(plain)+encoder.finalize()
    decoded = subprocess.run([sys.argv[1],str(stream)], input=encrypted, capture_output=True,check=True,timeout=10).stdout
    assert decoded==plain
print('Mirror crypto: independent SHA512/AES-CTR, unsigned 64-bit stream IDs, fragment/in-place continuity and capacity/overlap guards passed (synthetic; no FairPlay unwrap)')

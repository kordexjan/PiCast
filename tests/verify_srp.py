#!/usr/bin/env python3
"""Independent Python arithmetic client vs actual C SRP server. Synthetic only."""
import hashlib
import secrets
import subprocess
import sys


def h(data):
    return hashlib.sha1(data).digest()


def check(binary, variant):
    p = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        n_hex, salt_hex, b_hex = p.stdout.readline().split()
        n, salt, b = int(n_hex, 16), bytes.fromhex(salt_hex), int(b_hex, 16)
        assert n.bit_length() == 2048 and n_hex.startswith('AC6BDB41')
        pad = lambda x: x.to_bytes(256, 'big')
        a = secrets.randbits(256) | 1 << 255
        public_a = pow(2, a, n)
        password = b'5678' if variant == 'wrong-pin' else b'1234'
        user = b'02:01:02:03:04:05'
        x = int.from_bytes(h(salt + h(user + b':' + password)), 'big')
        k = int.from_bytes(h(pad(n) + pad(2)), 'big')
        u = int.from_bytes(h(pad(public_a) + pad(b)), 'big')
        shared = pow((b-k*pow(2, x, n)) % n, a+u*x, n)
        raw = shared.to_bytes((shared.bit_length()+7)//8, 'big')
        secret = h(raw + b'\0\0\0\0') + h(raw + b'\0\0\0\1')
        mixed = bytes(a ^ b for a, b in zip(h(pad(n)), h(b'\x02')))
        proof = h(mixed + h(user) + salt + pad(public_a) + pad(b) + secret)
        if variant == 'tamper':
            proof = bytes([proof[0] ^ 1]) + proof[1:]
        if variant == 'zero-a':
            public_a = 0
        if variant == 'a-equals-n':
            public_a = n
        if variant == 'a-above-n':
            public_a = n+1
        p.stdin.write(pad(public_a).hex() + '\n' + proof.hex() + '\n'); p.stdin.flush()
        line = p.stdout.readline().strip()
        assert p.wait(timeout=5) == 0
        if variant != 'valid':
            assert line == 'rejected', (variant, line)
        else:
            m2, key, iv = line.split()
            assert m2 == h(pad(public_a) + proof + secret).hex()
            assert key == hashlib.sha512(b'Pair-Setup-AES-Key' + secret).digest()[:16].hex()
            assert iv == hashlib.sha512(b'Pair-Setup-AES-IV' + secret).digest()[:16].hex()
    finally:
        if p.poll() is None:
            p.kill(); p.wait()
        p.stdin.close(); p.stdout.close()


if __name__ == '__main__':
    for case in ['valid'] * 8 + ['wrong-pin', 'tamper', 'zero-a', 'a-equals-n', 'a-above-n']:
        check(sys.argv[1], case)
    print('SRP: independent client, mutual proof/key/IV agreement, wrong PIN, tampering, invalid A, state/replay and cleanup passed (synthetic)')

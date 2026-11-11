#!/usr/bin/env python3
"""Independent binary-plist/SRP/AES-GCM client; synthetic test keys only."""
import hashlib
import plistlib
import secrets
import subprocess
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def h(x):
    return hashlib.sha1(x).digest()


def check(binary, variant):
    p = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        line = p.stdout.readline()
        while line.startswith('{'):      # the receiver's own event lines
            line = p.stdout.readline()
        header = line.split()
        n_hex, pin = header[:2]
        server_key = bytes.fromhex(header[2]) if len(header)==3 else bytes(32)
        n = int(n_hex, 16)
        assert len(pin) == 4 and pin.isdigit() and n.bit_length() == 2048
        def send(obj):
            p.stdin.write(plistlib.dumps(obj, fmt=plistlib.FMT_BINARY).hex()+'\n'); p.stdin.flush()
            line = p.stdout.readline().strip()
            while line.startswith('{'):
                line = p.stdout.readline().strip()
            return None if line == 'rejected' else plistlib.loads(bytes.fromhex(line))
        initial = {'method': 'pin', 'user': '02:01:02:03:04:05'}
        if variant == 'bad-user':
            initial['user'] = 'not a MAC'
        if variant == 'extra-field':
            initial['extra'] = b'bad'
        if variant in ('bad-user', 'extra-field'):
            assert send(initial) is None
            return
        user = initial['user'].encode()
        pad = lambda x: x.to_bytes(256, 'big')
        def attempt(code):
            reply = send(initial)
            assert set(reply) == {'pk', 'salt'} and len(reply['pk']) == 256 and len(reply['salt']) == 16
            b, salt = int.from_bytes(reply['pk'], 'big'), reply['salt']
            a = secrets.randbits(256) | 1 << 255
            public_a = pow(2, a, n)
            x = int.from_bytes(h(salt+h(user+b':'+code.encode())), 'big')
            k = int.from_bytes(h(pad(n)+pad(2)), 'big')
            u = int.from_bytes(h(pad(public_a)+pad(b)), 'big')
            shared = pow((b-k*pow(2,x,n))%n,a+u*x,n)
            raw = shared.to_bytes((shared.bit_length()+7)//8,'big')
            secret = h(raw+b'\0\0\0\0')+h(raw+b'\0\0\0\1')
            mixed = bytes(x^y for x,y in zip(h(pad(n)),h(b'\x02')))
            proof = h(mixed+h(user)+salt+pad(public_a)+pad(b)+secret)
            return send({'pk': pad(public_a), 'proof': proof}), public_a, proof, secret
        wrong = f'{(int(pin)+1)%10000:04d}'
        if variant == 'wrong-pin':
            assert attempt(wrong)[0] is None
            return
        if variant == 'wrong-limit':
            # The last allowed mistype retires the code, and the screen shows a new one:
            # the old one fails then (equal by chance once in 10000 runs).
            for _ in range(5):
                assert attempt(wrong)[0] is None
            if send(initial) is None:
                return  # The bare PIN object has no display to show a new code on.
            assert attempt(pin)[0] is None
            return
        if variant == 'restart':
            assert send(initial) is not None  # Reply lost: the sender starts over.
        if variant == 'wrong-then-right':
            for _ in range(4):
                assert attempt(wrong)[0] is None
        reply, public_a, proof, secret = attempt(pin)
        assert reply == {'proof': h(pad(public_a)+proof+secret)}
        key = hashlib.sha512(b'Pair-Setup-AES-Key'+secret).digest()[:16]
        iv = bytearray(hashlib.sha512(b'Pair-Setup-AES-IV'+secret).digest()[:16])
        iv[15] = (iv[15]+1)&255
        encrypted = AESGCM(key).encrypt(bytes(iv),b'\x42'*32,None)
        tag = encrypted[32:]
        if variant == 'bad-tag':
            tag = bytes([tag[0]^1])+tag[1:]
        reply = send({'epk': encrypted[:32], 'authTag': tag})
        if variant == 'bad-tag':
            assert reply is None
            return
        assert set(reply) == {'epk','authTag'}
        iv[15] = (iv[15]+1)&255
        assert AESGCM(key).decrypt(bytes(iv),reply['epk']+reply['authTag'],None) == server_key
        assert send(initial) is None  # no replay after authenticated completion
    finally:
        p.stdin.close()
        assert p.wait(timeout=5) == 0
        p.stdout.close()


if __name__ == '__main__':
    for case in ['valid']*5+['bad-user','extra-field','wrong-pin','wrong-then-right','wrong-limit','restart','bad-tag']:
        check(sys.argv[1],case)
    print('PIN: independent binary-plist/SRP/mutual AES-GCM exchange, random PIN, wrong PIN with retry and limit, bad tag, malformed identity/fields and replay checks passed (synthetic)')

#!/usr/bin/env python3
"""Independently decode actual C /info output with Python's standard plistlib."""
import plistlib
import subprocess
import sys
import uuid

raw = subprocess.run([sys.argv[1], '--info-vector'], check=True, capture_output=True, timeout=5).stdout
assert raw.startswith(b'bplist00')
info = plistlib.loads(raw)
assert isinstance(info, dict) and info['name'] == 'PiCast'
assert info['deviceID'] == '02:01:02:03:04:05'
assert isinstance(info['pk'], bytes) and len(info['pk']) == 32
pairing = uuid.UUID(info['pi'])
expected = bytearray(info['pk'][:16])
expected[6] = expected[6] & 15 | 64
expected[8] = expected[8] & 63 | 128
assert pairing.bytes == bytes(expected) and pairing.version == 4
system = bytearray(info['pk'][16:])
system[6] = system[6] & 15 | 64
system[8] = system[8] & 63 | 128
assert info['psi'] == str(uuid.UUID(bytes=bytes(system)))
assert info['model'] == 'AppleTV3,2' and info['sourceVersion'] == '220.68'
assert info['protocolVersion'] == '1.0' and 'srcvers' not in info
assert type(info['features']) is int and info['features'] == 0x48184280
assert info['statusFlags'] == 0
# The display PiCast offers: 1920x1080 unless the runner names another shape.
display = info['displays'][0]
assert display['widthPixels'] == 1920 and display['heightPixels'] == 1080
print('/info: actual binary plist independently parsed; identity, keys and capabilities valid')

raw_txt=info['txtAirPlay']; assert isinstance(raw_txt,bytes)
fields={}; offset=0
while offset<len(raw_txt):
    length=raw_txt[offset]; offset+=1
    entry=raw_txt[offset:offset+length]; assert len(entry)==length
    offset+=length; key,value=entry.decode('ascii').split('=',1)
    assert key not in fields; fields[key]=value
assert fields['pw']=='false' and fields['flags']=='0x0'
assert fields['deviceid']==info['deviceID'] and fields['pk']==info['pk'].hex()
assert fields['model']==info['model'] and fields['srcvers']==info['sourceVersion']
assert fields['pi']==info['pi'] and fields['psi']==info['psi']
assert int(fields['features'],16)==info['features'] and fields['vv']=='2'
print('/info: raw txtAirPlay decoded independently, public identity/settings consistent')

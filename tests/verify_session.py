#!/usr/bin/env python3
"""Independent plist encoder vs typed C SETUP parser; encrypted data synthetic."""
import json
import plistlib
import subprocess
import sys
base = {'et':32,'ekey':b'FPLY'+bytes(68),'eiv':bytes(16),'timingProtocol':'NTP',
        'timingPort':51907,'isScreenMirroringSession':True,'combinedGetInfoWithControlSetup':True}

def run(obj, valid):
    raw = plistlib.dumps(obj,fmt=plistlib.FMT_BINARY)
    r = subprocess.run([sys.argv[1]],input=raw,capture_output=True,timeout=5)
    assert r.returncode==(0 if valid else 3), (r.returncode,r.stderr)
    if valid:
        d=json.loads(r.stdout)
        assert d=={'sender_timing_port':obj['timingPort'],'combined_info':int(obj.get('combinedGetInfoWithControlSetup',False)),
                   'wrapped_key_bytes':72,'iv_bytes':16,'media_key_decoded':False}
    else:
        assert not r.stdout

run(base,True)
for key, values in {'et':[0,True,32.0,'32'], 'ekey':[bytes(72),b'FPLY'+bytes(67)],
                    'eiv':[bytes(15),'x'*16], 'timingPort':[0,-1,65536,True,1.0],
                    'timingProtocol':['PTP',b'NTP'],'isScreenMirroringSession':[False,1],
                    'combinedGetInfoWithControlSetup':['yes',1]}.items():
    for value in values:
        d=dict(base);d[key]=value;run(d,False)
for key in base:
    d=dict(base);del d[key];run(d,key=='combinedGetInfoWithControlSetup')
for port in [1,65535]:
    d=dict(base);d['timingPort']=port;run(d,True)
run([],False)
print('SETUP: independent binary plists, typed fields, encrypted-key/IV lengths, NTP/ports and atomic failure passed; no media-ready claim')

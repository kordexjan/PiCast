#!/usr/bin/env python3
"""Modify only the pinned private Nexmon source checkout; never install firmware."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('lab',type=Path)
    a=p.parse_args()
    root=Path(__file__).resolve().parent
    spec=json.loads((root/'monitor-profile-source.json').read_text())
    target=a.lab/'patches/bcm43436b0/9_88_4_65/nexmon/src/monitormode.c'
    original=a.lab/'firmwares/bcm43436b0/9_88_4_65/brcmfmac43436-sdio.bin'
    assert sha(original)=='6dc7b3b53a1b69637a9e10e675e73ef56ca689d5bd279b78bd2f2719970cb80b','Unsupported firmware'
    assert (a.lab/'DISABLE_STATISTICS').exists(),'Build statistics must remain disabled'
    if sha(target) in spec.get('superseded_patch_sha256',[]):
        backup=target.with_suffix('.c.picast-original')
        assert sha(backup)==spec['original_sha256'],'Missing verified source backup'
        shutil.copyfile(backup,target)
    if sha(target)==spec['original_sha256']:
        backup=target.with_suffix('.c.picast-original')
        if backup.exists():assert sha(backup)==spec['original_sha256']
        else:shutil.copyfile(target,backup)
        patch=root/'nexmon-monitor-profile.patch'
        if shutil.which('git'):
            subprocess.run(['git','apply','--check',str(patch)],cwd=a.lab,check=True)
            subprocess.run(['git','apply',str(patch)],cwd=a.lab,check=True)
        else:
            subprocess.run(['patch','--batch','--fuzz=0','--dry-run','-p1','-i',str(patch)],cwd=a.lab,check=True)
            subprocess.run(['patch','--batch','--fuzz=0','-p1','-i',str(patch)],cwd=a.lab,check=True)
    assert sha(target)==spec['patched_sha256'],'Unexpected existing monitor changes; not overwritten'
    shutil.copyfile(root/'picast_monitor_profile.h',target.with_name('picast_monitor_profile.h'))
    print(json.dumps({'source_profile_applied':True,'source_sha256':sha(target),'hardware_changed':False}))


if __name__=='__main__':
    main()

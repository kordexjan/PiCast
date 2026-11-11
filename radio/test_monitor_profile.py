#!/usr/bin/env python3
"""Compile and execute the actual original/patched monitor function offline.
No firmware RAM, network, radio, private keys, or Unicorn on the Mac.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(path):
    source=path.read_text()
    begin=source.index('void\nwl_monitor_radiotap(')
    end=source.index('\nvoid\nwl_monitor_hook(',begin)
    return source[begin:end]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('original',type=Path)
    p.add_argument('patched',type=Path)
    p.add_argument('--firmware',type=Path)
    p.add_argument('--elf',type=Path)
    p.add_argument('--rom-report',type=Path)
    p.add_argument('--sanitizers',choices=('address,undefined','undefined'),default='address,undefined')
    a=p.parse_args()
    root=Path(__file__).resolve().parent
    harness=root/'monitor_profile_harness.c'
    with tempfile.TemporaryDirectory(prefix='picast-monitor-test-') as tmp:
        directory=Path(tmp)
        for name,source in [('original',a.original),('patched',a.patched)]:
            target=directory/(name+'.c');binary=directory/name
            target.write_text(harness.read_text().replace('/* ACTUAL_MONITOR_FUNCTION */',function(source)))
            subprocess.run(['cc','-std=c11','-g','-O1','-Wall','-Wextra','-Werror','-fsanitize='+a.sanitizers,'-fno-sanitize-recover=all','-fno-omit-frame-pointer','-I',str(root),str(target),'-o',str(binary)],check=True,capture_output=True,text=True)
        baseline=subprocess.run([str(directory/'original'),'allocation-failure'],capture_output=True,text=True,timeout=10)
        assert baseline.returncode!=0 and 'null pointer' in baseline.stderr.lower(),'Baseline did not demonstrate the actual NULL-allocation failure'
        subprocess.run([str(directory/'patched'),'allocation-failure'],check=True,capture_output=True,text=True,timeout=10)
        subprocess.run([str(directory/'patched')],check=True,capture_output=True,text=True,timeout=20)
    assembly_verified=False
    if a.elf:
        result=subprocess.run(['arm-linux-gnueabihf-objdump','-d','--disassemble=wl_monitor_radiotap',str(a.elf)],capture_output=True,text=True,check=True)
        assert '807b91' in result.stdout.lower() or '807b90' in result.stdout.lower(),'Actual ARM function is not using the measured primary allocation entry'
        assert '807c48' not in result.stdout.lower(),'Shared-pool fallback still referenced'
        assembly_verified=True
    rom_sha=None
    if a.rom_report:
        report=json.loads(a.rom_report.read_text())
        assert report.get('trial_completed') and report.get('restored') and not report.get('firmware_dumps')
        for command in report['trial_commands']:
            for line in command.get('stdout','').splitlines():
                try:item=json.loads(line)
                except ValueError:continue
                if item.get('query')=='rom_allocator_code':
                    code=bytes.fromhex(item['data_hex'])
                    assert item.get('rom_start')=='0x807c00' and len(code)==1024
                    rom_sha=hashlib.sha256(code).hexdigest()
        expected=json.loads((root/'monitor-profile-source.json').read_text())['rom_allocator_page_sha256']
        assert rom_sha==expected,'Measured ROM ABI not confirmed'
    print(json.dumps({'passed':True,'original_allocation_failure_confirmed':True,'patched_allocation_failure_safe':True,
                      'ownership_and_bounds_cases_passed':True,'arm_primary_allocator_call_verified':assembly_verified,
                      'rom_allocator_page_sha256':rom_sha,
                      'patched_firmware_sha256':sha(a.firmware) if a.firmware else None,'original_source_sha256':sha(a.original),
                      'patched_source_sha256':sha(a.patched),'profile_header_sha256':sha(root/'picast_monitor_profile.h'),
                      'harness_sha256':sha(harness),'test_script_sha256':sha(Path(__file__)),'sanitizers':a.sanitizers,'hardware_tested':False},indent=2))


if __name__=='__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr[-2000:],file=sys.stderr)
        raise

#!/usr/bin/env python3
"""Execute actual original/patched Thumb code offline before any radio test.

Development-only dependency: unicorn==2.1.4 in an isolated temporary venv.
No hardware access and no firmware RAM dump required.
"""
import argparse
import hashlib
import json
from pathlib import Path
import random
import struct

from unicorn import Uc, UcError, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_MCLASS, UC_ERR_READ_UNMAPPED
from unicorn import arm_const as reg

ENTRY, CONTINUE, RETURN = 0x204c4, 0x204c8, 0x7e000
OBJECT, SAMPLES = 0x71000, 0x73000
REGISTERS = [getattr(reg, "UC_ARM_REG_R" + str(i)) for i in range(13)] + [reg.UC_ARM_REG_SP, reg.UC_ARM_REG_LR, reg.UC_ARM_REG_XPSR]


def run(image, pointer, samples):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    # The Zero 2 W cannot reserve the default large translation buffer.
    # This routine has fewer than 200 executed instructions per invocation.
    cpu.ctl_set_tcg_buffer_size(1024 * 1024)
    # The NULL page is deliberately unmapped: a NULL access faults in this
    # isolated emulator, without inducing a physical firmware/kernel crash.
    cpu.mem_map(0x1000, 0x7f000)
    cpu.mem_write(0x1000, image[0x1000:])
    cpu.mem_write(OBJECT + 8, struct.pack("<I", SAMPLES))
    cpu.mem_write(SAMPLES + 0x72, bytes(value & 255 for value in samples))
    for index, register in enumerate(REGISTERS[:13]):
        cpu.reg_write(register, 0x11220000 + index)
    cpu.reg_write(reg.UC_ARM_REG_SP, 0x78000)
    cpu.reg_write(reg.UC_ARM_REG_LR, RETURN | 1)
    cpu.reg_write(reg.UC_ARM_REG_XPSR, 0x61000000)
    cpu.reg_write(reg.UC_ARM_REG_R0, pointer)
    cpu.emu_start(ENTRY | 1, RETURN, timeout=100000, count=200)
    if cpu.reg_read(reg.UC_ARM_REG_PC) != RETURN:
        raise AssertionError("Function failed to return within instruction bound")
    return [cpu.reg_read(register) for register in REGISTERS]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("patched", type=Path)
    args = parser.parse_args()
    original, patched = args.original.read_bytes(), args.patched.read_bytes()
    assert hashlib.sha256(original).hexdigest() == "6dc7b3b53a1b69637a9e10e675e73ef56ca689d5bd279b78bd2f2719970cb80b"
    assert len(original) <= len(patched) <= 0x65cf0
    assert original[ENTRY:CONTINUE] != patched[ENTRY:CONTINUE]
    assert original[CONTINUE:0x204e4] == patched[CONTINUE:0x204e4]
    # Verify actual failure before checking the fix; do not silently accept a
    # test setup where address0 happens to be valid.
    try:
        run(original, 0, [0] * 8)
        raise AssertionError("Original NULL input unexpectedly succeeded")
    except UcError as error:
        assert error.errno == UC_ERR_READ_UNMAPPED
    null_result = run(patched, 0, [0] * 8)
    assert null_result[0] == 0
    generator = random.Random(0x504943415354)
    cases = [[0] * 8, [-128] * 8, [127] * 8, [-90, -70, -45, -42, -30, -15, -2, 0]]
    cases += [[generator.randrange(-128, 128) for _ in range(8)] for _ in range(256)]
    for samples in cases:
        before, after = run(original, OBJECT, samples), run(patched, OBJECT, samples)
        assert before == after, "Valid input changed registers or flags"
        value = after[0] if after[0] < 0x80000000 else after[0] - 0x100000000
        total = sum(samples)
        expected = (abs(total) // 8) * (-1 if total < 0 else 1)
        assert value == expected
    # A different invalid non-NULL pointer must still fault: this is not a
    # blanket memory-protection bypass.
    for image in (original, patched):
        try:
            run(image, 0x90000000, [0] * 8)
            raise AssertionError("Invalid non-NULL pointer unexpectedly succeeded")
        except UcError as error:
            assert error.errno == UC_ERR_READ_UNMAPPED
    print(json.dumps(dict(original_sha256=hashlib.sha256(original).hexdigest(),
                          patched_sha256=hashlib.sha256(patched).hexdigest(),
                          original_null_fault_confirmed=True, patched_null_returns_zero=True,
                          valid_cases_unchanged=len(cases), invalid_non_null_still_faults=True,
                          guard_source_sha256=hashlib.sha256(Path(__file__).with_name("picast_null_sample_guard.c").read_bytes()).hexdigest(),
                          test_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                          hardware_tested=False), indent=2))


if __name__ == "__main__":
    main()

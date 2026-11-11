/* SPDX-License-Identifier: GPL-3.0-or-later
 * PiCast, BCM43436b0 firmware 9.88.4.65.
 *
 * A crash report of the radio showed R0=0 at 0x204ca, after the function at
 * 0x204c4 loaded [R0+8] (R1=0x2011, exactly the image's word at address8).
 * The function averages eight signed samples. Its symbolic name is unknown.
 * Return the unavailable-value0 for this observed NULL input; preserve the
 * original instructions and continuation for every non-NULL input. Do not
 * disable the firmware's debug monitor or memory protection.
 *
 * The input instruction signature must be checked before building/applying.
 */
#pragma NEXMON targetregion "patch"
#include <firmware_version.h>
#include <patcher.h>

__attribute__((naked)) void picast_null_sample_guard(void)
{
    asm volatile (
        "cmp r0, #0\n"
        "bne 1f\n"
        "bx lr\n"              /* R0 is already zero. */
        "1:\n"
        "movs r3, #0\n"        /* Exact displaced original instructions. */
        "ldr r1, [r0, #8]\n"
        "b.w 0x204c8\n"       /* Original continuation; LR untouched. */
    );
}

__attribute__((at(0x204c4, "", CHIP_VER_BCM43436b0, FW_VER_9_88_4_65)))
BPatch(picast_null_sample_entry, picast_null_sample_guard);

/* SPDX-License-Identifier: MIT */
ENTRY(orbit_connect)
SECTIONS {
    . = 0;
    .text : { *(.hook_entry) *(.text .text.*) *(.rodata .rodata.*) }
    ASSERT(orbit_connect == 0, "Orbit connect entry offset changed")
    ASSERT(SIZEOF(.text) <= 0x2000, "Orbit connect code overlaps the boot entry")
    . = 0x2000;
    .hook_boot : { *(.hook_boot) }
    ASSERT(orbit_boot_entry == 0x2000, "Orbit boot entry offset changed")
    ASSERT(. <= 0x4000, "Orbit code exceeds one PS5 page")
    . = 0x4000;
    .hook_data : { *(.hook_data) }
    ASSERT(orbit_config == 0x4000, "Orbit connect config offset changed")
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}

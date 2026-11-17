/* SPDX-License-Identifier: MIT */
ENTRY(orbit_connect)
SECTIONS {
    . = 0;
    .text : { *(.hook_entry) *(.text .text.*) *(.rodata .rodata.*) }
    ASSERT(orbit_connect == 0, "WebView connect entry offset changed")
    ASSERT(SIZEOF(.text) <= 0x4000, "WebView code exceeds one PS5 page")
    . = 0x4000;
    .hook_data : { *(.hook_data) }
    ASSERT(webview_config == 0x4000, "WebView connect config offset changed")
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}

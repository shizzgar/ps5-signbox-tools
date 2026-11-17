/* SPDX-License-Identifier: MIT */
#ifndef PS5_ORBIT_WIRE_H
#define PS5_ORBIT_WIRE_H

#include <netinet/in.h>
#include <stdint.h>

enum {
    ORBIT_HOOK_PAGE = 0x4000,
    ORBIT_BOOT_ENTRY = 0x2000,
    ORBIT_BOOT_WAIT_MS = 30000,
    ORBIT_TOKEN_SIZE = 16,
    ORBIT_PROBE_PORT = 57311,
};

#define ORBIT_BOOT_POINTER_OFFSET 32

struct orbit_config {
    uint64_t connect_function;
    uint16_t port;
    uint16_t probe_port;
    unsigned char token[ORBIT_TOKEN_SIZE];
    uint64_t boot_entry;
};

struct orbit_request {
    unsigned char token[ORBIT_TOKEN_SIZE];
    struct sockaddr_in target;
};

struct orbit_boot {
    unsigned char token[ORBIT_TOKEN_SIZE];
    int32_t pid;
};

static inline int
public_ipv4(struct in_addr address) {
    uint32_t ip = __builtin_bswap32(address.s_addr);
    return ip >> 24 != 0 && ip >> 24 != 10 && ip >> 24 != 127 && ip >> 24 < 224 &&
           ip >> 22 != (UINT32_C(0x64400000) >> 22) && ip >> 16 != 0xa9fe &&
           ip >> 20 != 0xac1 && ip >> 16 != 0xc0a8 &&
           ip >> 8 != 0xc00000 && ip >> 8 != 0xc00002 && ip >> 8 != 0xc05863 &&
           ip >> 17 != (UINT32_C(0xc6120000) >> 17) && ip >> 8 != 0xc63364 && ip >> 8 != 0xcb0071;
}

#endif

/* SPDX-License-Identifier: MIT */
#ifndef PS5_ORBIT_RELAY_H
#define PS5_ORBIT_RELAY_H

#include <stdatomic.h>
#include "orbit-wire.h"

struct orbit_relay {
    int socket;
    unsigned char token[ORBIT_TOKEN_SIZE];
    unsigned char webview_token[ORBIT_TOKEN_SIZE];
    int allow_webview;
    const struct sockaddr_in *probe_target;
    const atomic_bool *stop;
    atomic_bool shutdown;
    unsigned bridged;
};

int orbit_open_control(struct orbit_config *config);
int orbit_reserve_relay(const struct orbit_config *config, const struct sockaddr_in *target,
                        struct sockaddr_in *local);
void *orbit_relay_run(void *argument);

#endif

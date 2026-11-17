/* SPDX-License-Identifier: MIT */
#ifndef PS5_NETWORK_WEBVIEW_H
#define PS5_NETWORK_WEBVIEW_H

#include <stdatomic.h>

#include "orbit-wire.h"

struct webview_route {
    const atomic_bool *stop;
    struct orbit_config config;
    atomic_int armed;
    atomic_int failures;
};

int webview_open_check(void);
void *webview_route_run(void *argument);

#endif

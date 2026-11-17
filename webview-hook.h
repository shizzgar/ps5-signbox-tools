/* SPDX-License-Identifier: MIT */
#ifndef PS5_WEBVIEW_HOOK_H
#define PS5_WEBVIEW_HOOK_H

#include <poll.h>
#include <stddef.h>
#include <sys/socket.h>

#include "orbit-wire.h"

struct webview_socket_api {
    int (*socket)(int, int, int);
    int (*connect)(int, const struct sockaddr *, socklen_t);
    int (*getsockopt)(int, int, int, void *, socklen_t *);
    ssize_t (*sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
    ssize_t (*recvfrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
    int (*poll)(struct pollfd *, nfds_t, int);
    int (*close)(int);
    int *(*error_location)(void);
};

struct webview_hook_config {
    struct orbit_config route;
    struct webview_socket_api api;
};

_Static_assert(offsetof(struct webview_hook_config, route) == 0, "WebView route config offset changed");

#endif

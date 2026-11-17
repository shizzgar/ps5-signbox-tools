/* SPDX-License-Identifier: MIT */
#ifndef PS5_TUNNEL_SERVICE_H
#define PS5_TUNNEL_SERVICE_H

#include <stdatomic.h>
#include <stddef.h>
#include <sys/types.h>

#include "report.h"

enum service_state { SERVICE_OFF, SERVICE_STARTING, SERVICE_READY, SERVICE_ERROR };
enum network_check { CHECK_HTTPS, CHECK_DOWNLOAD };
enum proxy_check_result { PROXY_CHECK_PASSED = 0, PROXY_CHECK_FAILED = -1, PROXY_CHECK_DISCONNECTED = -2 };

struct managed_proxy {
    pid_t pid;
    int control;
    long long deadline;
    enum service_state state;
};

int proxy_start(struct managed_proxy *proxy);
void proxy_poll(struct managed_proxy *proxy);
void proxy_stop(struct managed_proxy *proxy);
int loader_upload_output(const void *image, size_t size);
int proxy_check(int control, enum network_check check, const atomic_bool *stop);

#endif

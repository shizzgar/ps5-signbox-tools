/* SPDX-License-Identifier: MIT */
#ifndef TCP_RELAY_H
#define TCP_RELAY_H

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>

struct relay_counts {
    uint64_t sent;
    uint64_t received;
    int64_t first_rx_ms;
    int64_t rx_span_ms;
    int64_t app_wait_ms;
};

int relay_open(const struct sockaddr_in *target, int *socks_reply);
int relay_connect_duplicate(int fd, const struct sockaddr_in *local);
int relay_ready(void);
enum { ORBIT_PORT = 34177 };
int orbit_service_ready(int timeout_ms);
int relay_copy(int client, int upstream, struct relay_counts *counts);
int relay_listen(struct sockaddr_in *local);
int relay_accept(int listener);
int relay_accept_until(int listener, int64_t deadline);
int connect_local(int fd, in_port_t port, int64_t deadline);
int connect_control(int fd, in_port_t port, int64_t deadline);
int socket_send_all(int fd, const void *data, size_t size, int64_t deadline);
int socket_send_control(int fd, const void *data, size_t size, int64_t deadline);
int socket_read_all(int fd, void *data, size_t size, int64_t deadline);
void relay_stop(void);
void relay_reset(void);
int64_t monotonic_ms(void);

#endif

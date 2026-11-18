/* SPDX-License-Identifier: MIT */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "panel-access.h"

int
panel_request_is_trusted(int socket, const char *host, const char *origin) {
    struct sockaddr_in local;
    socklen_t length = sizeof(local);
    if (!host || getsockname(socket, (struct sockaddr *)&local, &length) != 0 ||
        length != sizeof(local) || local.sin_family != AF_INET)
        return 0;
    char address[INET_ADDRSTRLEN], authority[INET_ADDRSTRLEN + 7];
    if (!inet_ntop(AF_INET, &local.sin_addr, address, sizeof(address)))
        return 0;
    snprintf(authority, sizeof(authority), "%s:%u", address, (unsigned)ntohs(local.sin_port));
    return !strcmp(host, authority) &&
        (!origin || (!strncmp(origin, "http://", 7) && !strcmp(origin + 7, authority)));
}

int
panel_client_is_local(int socket) {
    struct sockaddr_in peer;
    socklen_t length = sizeof(peer);
    return getpeername(socket, (struct sockaddr *)&peer, &length) == 0 &&
        length == sizeof(peer) && peer.sin_family == AF_INET &&
        (ntohl(peer.sin_addr.s_addr) >> 24) == 127;
}

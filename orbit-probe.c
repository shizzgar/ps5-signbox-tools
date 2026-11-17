/* SPDX-License-Identifier: MIT */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "orbit-wire.h"

static void
probe_notice(char stage, int value) {
    char line[64];
    int size = snprintf(line, sizeof(line), "PS5NET probe %c %d\n", stage, value);
    if (size > 0 && (size_t)size < sizeof(line))
        (void)send(STDERR_FILENO, line, (size_t)size, MSG_NOSIGNAL | MSG_DONTWAIT);
}

int
main(void) {
    probe_notice('M', (int)getpid());
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        probe_notice('S', errno);
        return 1;
    }
    const struct timeval timeout = {.tv_sec = 2};
    struct sockaddr_in target = {
        .sin_len = sizeof(target),
        .sin_family = AF_INET,
        .sin_port = htons(ORBIT_PROBE_PORT),
        .sin_addr.s_addr = htonl(UINT32_C(0x7f000002)),
    };
    // Imported connect verifies the same relocation and shim used for Orbit.
    int error = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
        error = errno;
    else if (connect(fd, (const struct sockaddr *)&target, sizeof(target)) != 0)
        error = errno;
    probe_notice('C', error);
    if (!error && send(fd, "O", 1, MSG_NOSIGNAL) != 1)
        error = errno;
    close(fd);
    return error ? 1 : 0;
}

/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "relay.h"
#include "service.h"
#include "worker.h"

#ifndef ELFLDR_PORT
#define ELFLDR_PORT 9021
#endif

enum {
    LOADER_CONNECT_MS = 3000,
    LOADER_SEND_MS = 20000,
    WORKER_CONNECT_MS = 12000,
    PROXY_START_MS = 20000,
    TEST_MAX_MS = 30000,
    STOP_GRACE_MS = 2000,
};

extern const unsigned char worker_image[], worker_image_end[];
__asm__(".section .rodata\n"
        ".balign 0x4000\n"
        ".global worker_image\n"
        "worker_image:\n"
        ".incbin \"proxy-worker.elf\"\n"
        ".global worker_image_end\n"
        "worker_image_end:\n"
        ".text\n");

static int
upload_segments(const struct iovec *segments, size_t count) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;

    int64_t deadline = monotonic_ms() + LOADER_CONNECT_MS;
    int result = connect_local(fd, ELFLDR_PORT, deadline);
    int error = errno;
    if (result != 0) {
        report_log("Local ELF loader at 127.0.0.1:%d: %s", ELFLDR_PORT, strerror(error));
    } else {
        deadline = monotonic_ms() + LOADER_SEND_MS;
        for (size_t i = 0; i < count && result == 0; i++)
            result = socket_send_all(fd, segments[i].iov_base, segments[i].iov_len, deadline);
        error = errno;
        if (result != 0)
            report_log("Sending built-in ELF to local loader: %s", strerror(error));
        else
            (void)shutdown(fd, SHUT_WR);
    }
    if (result == 0)
        return fd;
    close(fd);
    errno = error;
    return -1;
}

int
loader_upload_output(const void *image, size_t size) {
    const struct iovec segment = {.iov_base = (void *)image, .iov_len = size};
    return upload_segments(&segment, 1);
}

static int
close_upload(int fd) {
    if (fd < 0)
        return -1;
    close(fd);
    return 0;
}

static int
send_worker(const struct worker_ticket *ticket) {
    size_t length = (size_t)(worker_image_end - worker_image);
    size_t offset = 0;
    while (offset + sizeof(*ticket) <= length) {
        if (worker_image[offset] == WORKER_MARKER[0] &&
            memcmp(worker_image + offset, WORKER_MARKER, WORKER_MARKER_SIZE) == 0)
            break;
        offset++;
    }
    if (offset + sizeof(*ticket) > length) {
        report_log("Invalid launch record in embedded sing-box ELF");
        errno = ENOEXEC;
        return -1;
    }
    size_t suffix = offset + sizeof(*ticket);
    const struct iovec segments[] = {
        {.iov_base = (void *)worker_image, .iov_len = offset},
        {.iov_base = (void *)ticket, .iov_len = sizeof(*ticket)},
        {.iov_base = (void *)(worker_image + suffix), .iov_len = length - suffix},
    };
    return close_upload(upload_segments(segments, sizeof(segments) / sizeof(segments[0])));
}

int
proxy_start(struct managed_proxy *proxy) {
    struct sockaddr_in local;
    int listener = relay_listen(&local);
    if (listener < 0)
        return -1;
    struct worker_ticket ticket = {.marker = WORKER_MARKER};
    memcpy(ticket.port, &local.sin_port, sizeof(ticket.port));
    if (random_bytes(ticket.token, sizeof(ticket.token)) != 0 || send_worker(&ticket) != 0)
        goto failed;

    const int64_t deadline = monotonic_ms() + WORKER_CONNECT_MS;
    for (;;) {
        int control = relay_accept_until(listener, deadline);
        if (control < 0)
            break;
        struct worker_hello hello;
        uint32_t pid_network;
        int64_t hello_deadline = monotonic_ms() + 500;
        if (hello_deadline > deadline)
            hello_deadline = deadline;
        if (socket_read_all(control, &hello, sizeof(hello), hello_deadline) == 0 &&
            memcmp(hello.token, ticket.token, sizeof(ticket.token)) == 0) {
            memcpy(&pid_network, hello.pid, sizeof(pid_network));
            uint32_t pid = ntohl(pid_network);
            if (pid > 1 && pid <= INT_MAX && pid != (uint32_t)getpid() &&
                socket_send_all(control, "G", 1, hello_deadline) == 0) {
                close(listener);
                *proxy = (struct managed_proxy){
                    .pid = (pid_t)pid, .control = control, .state = SERVICE_STARTING,
                    .deadline = monotonic_ms() + PROXY_START_MS,
                };
                report_log("Integrated sing-box ELF started, PID %d", (int)proxy->pid);
                return 0;
            }
        }
        close(control);
    }
    int error = errno;
    report_log("Embedded sing-box did not connect back: %s", strerror(error));
    errno = error;

failed:;
    error = errno;
    close(listener);
    errno = error;
    return -1;
}

void
proxy_stop(struct managed_proxy *proxy) {
    int fd = proxy->control;
    *proxy = (struct managed_proxy){.control = -1};
    if (fd < 0)
        return;
    if (shutdown(fd, SHUT_WR) == 0) {
        int64_t deadline = monotonic_ms() + STOP_GRACE_MS;
        for (;;) {
            int64_t now = monotonic_ms();
            if (now < 0 || now >= deadline)
                break;
            struct pollfd ready = {.fd = fd, .events = POLLIN};
            int result = poll(&ready, 1, (int)(deadline - now));
            if (result < 0 && errno == EINTR)
                continue;
            if (result <= 0)
                break;
            char bytes[16];
            if (recv(fd, bytes, sizeof(bytes), MSG_DONTWAIT) <= 0)
                break;
        }
    }
    close(fd);
}

void
proxy_poll(struct managed_proxy *proxy) {
    if (proxy->control < 0)
        return;

    // The panel gives a test exclusive use of the control stream until its reply.
    char ready;
    ssize_t size = recv(proxy->control, &ready, 1, MSG_DONTWAIT);
    if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
        if (proxy->state == SERVICE_READY || monotonic_ms() < proxy->deadline)
            return;
        report_log("Integrated sing-box timed out before starting");
    } else if (size == 1 && proxy->state == SERVICE_STARTING) {
        if (ready == 'L') {
            report_log("sing-box launcher entered the Go runtime");
            return;
        }
        if (ready == 'R') {
            proxy->state = SERVICE_READY;
            return;
        }
    } else {
        report_log("Integrated sing-box control disconnected. See the earlier log lines.");
    }

    proxy_stop(proxy);
    proxy->state = SERVICE_ERROR;
}

int
proxy_check(int control, enum network_check check, const atomic_bool *stop) {
    if (atomic_load(stop))
        return PROXY_CHECK_FAILED;
    const char command = check == CHECK_DOWNLOAD ? 'D' : 'H';
    if (send(control, &command, 1, MSG_DONTWAIT) != 1)
        return PROXY_CHECK_DISCONNECTED;

    int64_t deadline = monotonic_ms() + TEST_MAX_MS;
    int cancelling = 0;
    for (;;) {
        int64_t now = monotonic_ms();
        if (now < 0 || (cancelling && now >= deadline))
            return PROXY_CHECK_DISCONNECTED;
        if (!cancelling && (atomic_load(stop) || now >= deadline)) {
            if (send(control, "C", 1, MSG_DONTWAIT) != 1)
                return PROXY_CHECK_DISCONNECTED;
            cancelling = 1;
            deadline = now + STOP_GRACE_MS;
        }

        struct pollfd ready = {.fd = control, .events = POLLIN};
        int count = poll(&ready, 1, 100);
        if (count == 0 || (count < 0 && errno == EINTR))
            continue;
        char reply;
        if (count < 0 || recv(control, &reply, 1, MSG_DONTWAIT) != 1 || (reply != 'P' && reply != 'F'))
            return PROXY_CHECK_DISCONNECTED;
        if (cancelling)
            report_log("Network check stopped");
        return !cancelling && reply == 'P' ? PROXY_CHECK_PASSED : PROXY_CHECK_FAILED;
    }
}

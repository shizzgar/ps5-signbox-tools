/* SPDX-License-Identifier: MIT */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "relay.h"

enum {
    PROXY_PORT = 17890,
    SOCKS_TIMEOUT_MS = 15000,
    LISTENER_TIMEOUT_MS = 6000,
    CANCEL_POLL_MS = 250,
    BUFFER_SIZE = 64 * 1024,
};

static atomic_bool relay_stopping;

void
relay_stop(void) {
    atomic_store(&relay_stopping, 1);
}

void
relay_reset(void) {
    atomic_store(&relay_stopping, 0);
}

int64_t
monotonic_ms(void) {
    struct timespec clock;
    if (clock_gettime(CLOCK_MONOTONIC, &clock) != 0)
        return -1;
    return (int64_t)clock.tv_sec * 1000 + clock.tv_nsec / 1000000;
}

static int
cancelled(void) {
    if (!atomic_load(&relay_stopping))
        return 0;
    errno = ECANCELED;
    return 1;
}

static int
wait_socket(int fd, short events, int64_t deadline, int cancellable) {
    struct pollfd event = {.fd = fd, .events = events};
    while (!cancellable || !cancelled()) {
        int64_t now = monotonic_ms();
        if (now < 0)
            return -1;
        if (now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        int delay = deadline - now > CANCEL_POLL_MS ? CANCEL_POLL_MS : (int)(deadline - now);
        int ready = poll(&event, 1, delay);
        if (ready > 0) {
            if ((event.revents & POLLNVAL) == 0)
                return 0;
            errno = EBADF;
            return -1;
        }
        if (ready < 0 && errno != EINTR)
            return -1;
    }
    return -1;
}

static int
wait_io(int fd, short events, int64_t deadline) {
    return wait_socket(fd, events, deadline, 1);
}

static int
nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 ? -1 : fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void
enable_nodelay(int fd) {
    const int enabled = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled));
}

static struct sockaddr_in
loopback(in_port_t port) {
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
#if defined(__FreeBSD__)
    address.sin_len = sizeof(address);
#endif
    return address;
}

int
relay_listen(struct sockaddr_in *local) {
    *local = loopback(0);
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    socklen_t length = sizeof(*local);
    if (nonblocking(fd) != 0 || bind(fd, (struct sockaddr *)local, length) != 0 ||
        getsockname(fd, (struct sockaddr *)local, &length) != 0 || listen(fd, 1) != 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

int
relay_connect_duplicate(int fd, const struct sockaddr_in *local) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return errno;
    int blocking = !(flags & O_NONBLOCK);
    if (blocking && fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
        return errno;
    int error = connect(fd, (const struct sockaddr *)local, sizeof(*local)) == 0 ? 0 : errno;
    if (error == EINPROGRESS) {
        struct pollfd pending = {.fd = fd, .events = POLLOUT};
        int ready = poll(&pending, 1, 100);
        socklen_t size = sizeof(error);
        if (ready == 0)
            error = ETIMEDOUT;
        else if (ready < 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) != 0)
            error = errno;
    }
    if (blocking && fcntl(fd, F_SETFL, flags) != 0)
        error = errno;
    return error;
}

int
relay_accept(int listener) {
    int64_t start = monotonic_ms();
    if (start < 0)
        return -1;
    return relay_accept_until(listener, start + LISTENER_TIMEOUT_MS);
}

int
relay_accept_until(int listener, int64_t deadline) {
    while (wait_io(listener, POLLIN, deadline) == 0) {
        int fd = accept(listener, NULL, NULL);
        if (fd >= 0)
            return fd;
        if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK && errno != ECONNABORTED)
            return -1;
    }
    return -1;
}

static int
exchange(int fd, void *receive, const void *transmit, size_t size, int64_t deadline, int cancellable) {
    unsigned char *input = receive;
    const unsigned char *output = transmit;
    while (size > 0) {
        if (wait_socket(fd, output ? POLLOUT : POLLIN, deadline, cancellable) != 0)
            return -1;
        ssize_t count = output ? send(fd, output, size, MSG_DONTWAIT) :
                                 recv(fd, input, size, MSG_DONTWAIT);
        if (count > 0) {
            if (output)
                output += count;
            else
                input += count;
            size -= (size_t)count;
        } else if (count == 0) {
            errno = ECONNRESET;
            return -1;
        } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
            return -1;
        }
    }
    return 0;
}

int
socket_send_all(int fd, const void *data, size_t size, int64_t deadline) {
    return exchange(fd, NULL, data, size, deadline, 1);
}

int
socket_send_control(int fd, const void *data, size_t size, int64_t deadline) {
    return exchange(fd, NULL, data, size, deadline, 0);
}

int
socket_read_all(int fd, void *data, size_t size, int64_t deadline) {
    return exchange(fd, data, NULL, size, deadline, 1);
}

static int
socks5_hello(int fd, int64_t deadline) {
    unsigned char greeting[] = {5, 1, 0};
    unsigned char reply[2];
    if (socket_send_all(fd, greeting, sizeof(greeting), deadline) != 0 ||
        socket_read_all(fd, reply, sizeof(reply), deadline) != 0)
        return -1;
    if (reply[0] != 5 || reply[1] != 0) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int
connect_port(int fd, in_port_t port, int64_t deadline, int cancellable) {
    struct sockaddr_in target = loopback(port);
    if (nonblocking(fd) != 0)
        return -1;
    if (connect(fd, (struct sockaddr *)&target, sizeof(target)) == 0)
        return 0;
    if ((errno != EINPROGRESS && errno != EINTR) || wait_socket(fd, POLLOUT, deadline, cancellable) != 0)
        return -1;
    int error = 0;
    socklen_t length = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0)
        return -1;
    if (error != 0) {
        errno = error;
        return -1;
    }
    return 0;
}

int
connect_local(int fd, in_port_t port, int64_t deadline) {
    return connect_port(fd, port, deadline, 1);
}

int
connect_control(int fd, in_port_t port, int64_t deadline) {
    return connect_port(fd, port, deadline, 0);
}

int
orbit_service_ready(int timeout_ms) {
    static const char request[] = "GET /api/v1/system HTTP/1.0\r\n"
                                  "Host: 127.0.0.1:34177\r\nConnection: close\r\n\r\n";
    int64_t now = monotonic_ms();
    if (now < 0)
        return 0;
    const int64_t deadline = now + timeout_ms;
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return 0;
    char response[4096];
    size_t used = 0;
    int found = 0;
    if (connect_control(fd, ORBIT_PORT, deadline) != 0 ||
        socket_send_control(fd, request, sizeof(request) - 1, deadline) != 0)
        goto done;
    while (used < sizeof(response) - 1 && wait_socket(fd, POLLIN, deadline, 0) == 0) {
        ssize_t size = recv(fd, response + used, sizeof(response) - used - 1, 0);
        if (size == 0)
            break;
        if (size < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            break;
        }
        used += (size_t)size;
        response[used] = '\0';
        char *body = strstr(response, "\r\n\r\n");
        if (body && (!strncmp(response, "HTTP/1.0 200 ", 13) || !strncmp(response, "HTTP/1.1 200 ", 13)) &&
            strstr(body + 4, "\"name\":\"Orbit Store\"")) {
            found = 1;
            break;
        }
    }
done:
    close(fd);
    return found;
}

static int
socks5_connect(int fd, const struct sockaddr_in *target, int *socks_reply, int64_t deadline) {
    unsigned char request[10] = {5, 1, 0, 1};
    unsigned char reply[4];
    memcpy(request + 4, &target->sin_addr, sizeof(target->sin_addr));
    memcpy(request + 8, &target->sin_port, sizeof(target->sin_port));
    if (socket_send_all(fd, request, sizeof(request), deadline) != 0 ||
        socket_read_all(fd, reply, sizeof(reply), deadline) != 0)
        return -1;
    *socks_reply = reply[1];
    if (reply[0] != 5 || reply[2] != 0) {
        errno = EPROTO;
        return -1;
    }
    if (*socks_reply != 0) {
        errno = ECONNREFUSED;
        return -1;
    }

    unsigned char bound[255 + 2];
    size_t tail;
    switch (reply[3]) {
    case 1:
        tail = 4 + 2;
        break;
    case 4:
        tail = 16 + 2;
        break;
    case 3:
        if (socket_read_all(fd, bound, 1, deadline) != 0)
            return -1;
        tail = (size_t)bound[0] + 2;
        break;
    default:
        errno = EPROTO;
        return -1;
    }
    return socket_read_all(fd, bound, tail, deadline);
}

int
relay_open(const struct sockaddr_in *target, int *socks_reply) {
    *socks_reply = -1;
    int64_t start = monotonic_ms();
    if (start < 0)
        return -1;
    const int64_t deadline = start + SOCKS_TIMEOUT_MS;
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;

    enable_nodelay(fd);
    if (connect_local(fd, PROXY_PORT, deadline) != 0 || socks5_hello(fd, deadline) != 0 ||
        (target && socks5_connect(fd, target, socks_reply, deadline) != 0))
        goto failed;
    return fd;

failed:;
    int error = errno;
    close(fd);
    errno = error;
    return -1;
}

int
relay_ready(void) {
    int reply;
    int fd = relay_open(NULL, &reply);
    if (fd < 0)
        return -1;
    close(fd);
    return 0;
}

struct flow {
    unsigned char data[BUFFER_SIZE];
    size_t next;
    size_t used;
    int eof;
};

static int
read_flow(int fd, struct flow *flow, short events, int peer) {
    if (flow->eof || flow->used != flow->next || !(events & (POLLIN | POLLHUP | POLLERR)))
        return 0;
    ssize_t count = recv(fd, flow->data, sizeof(flow->data), MSG_DONTWAIT);
    if (count > 0) {
        flow->next = 0;
        flow->used = (size_t)count;
        return 1;
    } else if (count == 0) {
        flow->eof = 1;
        shutdown(peer, SHUT_WR);
    } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
        return -1;
    }
    return 0;
}

static int
write_flow(int fd, struct flow *flow, uint64_t *total) {
    if (flow->used == flow->next)
        return 0;
    ssize_t count = send(fd, flow->data + flow->next, flow->used - flow->next, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (count > 0) {
        flow->next += (size_t)count;
        *total += (uint64_t)count;
    } else if (count == 0) {
        errno = EPIPE;
        return -1;
    } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
        return -1;
    }
    return 0;
}

static int
pump_flow(int source, short source_events, int destination, short destination_events,
          struct flow *flow, uint64_t *total) {
    if ((destination_events & (POLLOUT | POLLHUP | POLLERR)) &&
        write_flow(destination, flow, total) != 0)
        return -1;
    int read = read_flow(source, flow, source_events, destination);
    if (read <= 0)
        return read;
    return write_flow(destination, flow, total) == 0 ? 1 : -1;
}

int
relay_copy(int client, int upstream, struct relay_counts *counts) {
    counts->first_rx_ms = -1;
    counts->rx_span_ms = -1;
    counts->app_wait_ms = 0;
    enable_nodelay(client);
    struct flow *flows = calloc(2, sizeof(*flows));
    if (!flows)
        return -1;
    struct flow *out = &flows[0], *in = &flows[1];
    int result = -1;
    const int64_t started = monotonic_ms();
    int64_t first_rx = -1, app_wait = 0;
    while (!cancelled()) {
        if (out->eof && in->eof) {
            result = 0;
            break;
        }
        struct pollfd events[] = {
            {.fd = client, .events = ((!out->eof && out->used == out->next) ? POLLIN : 0)
                                  | (in->used != in->next ? POLLOUT : 0)},
            {.fd = upstream, .events = ((!in->eof && in->used == in->next) ? POLLIN : 0)
                                    | (out->used != out->next ? POLLOUT : 0)},
        };
        if (events[0].events == 0)
            events[0].fd = -1;
        if (events[1].events == 0)
            events[1].fd = -1;
        int64_t wait_started = in->used != in->next ? monotonic_ms() : -1;
        int ready = poll(events, 2, CANCEL_POLL_MS);
        if (ready < 0 && errno != EINTR)
            break;
        if (wait_started >= 0) {
            int64_t now = monotonic_ms();
            if (now >= wait_started)
                app_wait += now - wait_started;
        }
        if (ready <= 0)
            continue;
        if ((events[0].revents | events[1].revents) & POLLNVAL) {
            errno = EBADF;
            break;
        }
        if (pump_flow(client, events[0].revents, upstream, events[1].revents, out, &counts->sent) < 0)
            break;
        uint64_t before = counts->received;
        int incoming = pump_flow(upstream, events[1].revents, client, events[0].revents, in, &counts->received);
        if (incoming < 0)
            break;
        if ((incoming > 0 && first_rx < 0) || before != counts->received) {
            int64_t now = monotonic_ms();
            if (incoming > 0 && first_rx < 0 && now >= 0) {
                first_rx = now;
                if (started >= 0)
                    counts->first_rx_ms = now - started;
            }
            if (before != counts->received && first_rx >= 0 && now >= first_rx)
                counts->rx_span_ms = now - first_rx;
        }
    }
    int error = errno;
    counts->app_wait_ms = app_wait;
    free(flows);
    errno = error;
    return result;
}

/* SPDX-License-Identifier: MIT */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "relay.h"
#include "report.h"
#include "trace.h"

struct echo {
    int listener;
    int ok;
};

connect_function volatile webview_probe_connect = connect;

static int
short_io(int fd) {
    const struct timeval timeout = {.tv_sec = 5};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0)
        return -1;
    return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static int
echo_exchange(int fd) {
    // BSD accept() can inherit O_NONBLOCK from relay_listen().
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) != 0 || short_io(fd) != 0) {
        int error = errno;
        report_log("Echo socket setup failed: %s (errno=%d)", strerror(error), error);
        return -1;
    }
    char byte = 0;
    ssize_t count = recv(fd, &byte, 1, 0);
    if (count != 1) {
        int error = errno;
        if (count == 0)
            report_log("Echo did not receive a request (EOF)");
        else
            report_log("Echo receive failed: %s (errno=%d)", strerror(error), error);
        return -1;
    }
    if (byte != 'T') {
        report_log("Echo received an unexpected request byte");
        return -1;
    }
    if (send(fd, "P", 1, 0) != 1) {
        int error = errno;
        report_log("Echo send failed: %s (errno=%d)", strerror(error), error);
        return -1;
    }
    report_log("Echo received 1 byte and sent 1 byte");
    return 0;
}

static void *
echo_server(void *arg) {
    struct echo *echo = arg;
    for (int index = 0; index < RELAY_CHECK_CONNECTIONS; index++) {
        int fd = relay_accept(echo->listener);
        if (fd < 0) {
            int error = errno;
            report_log("Echo accept failed: %s (errno=%d)", strerror(error), error);
            break;
        }
        int exchanged = echo_exchange(fd);
        close(fd);
        if (exchanged != 0)
            break;
        echo->ok++;
    }
    close(echo->listener);
    return NULL;
}

static int
check_connection(struct sockaddr_in *target, const struct timeval *timeout,
                 connect_function entry, int nonblocking) {
    long fd = ps5_syscall(SYS_socket, AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
    if (fd < 0)
        return 2;
    // Reuse the same sockaddr and exercise curl's nonblocking connect pattern.
    if (ps5_syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_RCVTIMEO, (long)timeout, sizeof(*timeout), 0) != 0 ||
        ps5_syscall(SYS_setsockopt, fd, SOL_SOCKET, SO_SNDTIMEO, (long)timeout, sizeof(*timeout), 0) != 0 ||
        (nonblocking && ps5_syscall(SYS_fcntl, fd, F_SETFL, O_NONBLOCK, 0, 0, 0) != 0))
        return 2;
    connect_function volatile native_connect = entry;
    int connected = native_connect ? native_connect((int)fd, (const struct sockaddr *)target, sizeof(*target))
        : (int)ps5_syscall(SYS_connect, fd, (long)target, sizeof(*target), 0, 0, 0);
    if (connected != 0) {
        if (errno != EINPROGRESS)
            return 2;
        struct pollfd ready = {.fd = (int)fd, .events = POLLOUT};
        int error = 0;
        socklen_t length = sizeof(error);
        if (ps5_syscall(SYS_poll, (long)&ready, 1, 5000, 0, 0, 0) != 1 ||
            ps5_syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR, (long)&error, (long)&length, 0) != 0 ||
            error != 0)
            return 2;
    }
    if (ps5_syscall(SYS_fcntl, fd, F_SETFL, 0, 0, 0, 0) != 0)
        return 2;
    char result = 0;
    if (ps5_syscall(SYS_write, fd, (long)"T", 1, 0, 0, 0) != 1 ||
        ps5_syscall(SYS_read, fd, (long)&result, 1, 0, 0, 0) != 1 || result != 'P')
        return 3;
    ps5_syscall(SYS_close, fd, 0, 0, 0, 0, 0);
    return 0;
}

static _Noreturn void
check_client(struct sockaddr_in target, int control, int other, int listener, int webview) {
    const struct timeval timeout = {.tv_sec = 5};
    ps5_syscall(SYS_close, other, 0, 0, 0, 0, 0);
    ps5_syscall(SYS_close, listener, 0, 0, 0, 0, 0);
    char start = 0;
    if (ps5_syscall(SYS_read, control, (long)&start, 1, 0, 0, 0) != 1 || start != 'S')
        _exit(1);
    ps5_syscall(SYS_close, control, 0, 0, 0, 0, 0);
    if (webview)
        target.sin_addr.s_addr = htonl(UINT32_C(0x7f000002));
    connect_function native_connect = webview ? webview_probe_connect : NULL;
    if (webview && (native_connect(-1, (const struct sockaddr *)&target, sizeof(target)) != -1 || errno != EBADF))
        _exit(4);
    for (int index = 0; index < RELAY_CHECK_CONNECTIONS; index++) {
        int result = check_connection(&target, &timeout, native_connect, !webview || index != 0);
        if (result != 0)
            _exit(result);
    }
    _exit(0);
}

static int
run_relay_check(const atomic_bool *stop, int proxy_control, int webview) {
    struct sockaddr_in local;
    struct echo echo = {.listener = relay_listen(&local)};
    if (echo.listener < 0)
        return -1;
    int control[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, control) != 0) {
        close(echo.listener);
        return -1;
    }
    pid_t child = (pid_t)ps5_syscall(SYS_fork, 0, 0, 0, 0, 0, 0);
    if (child == 0) {
        if (proxy_control >= 0)
            ps5_syscall(SYS_close, proxy_control, 0, 0, 0, 0, 0);
        check_client(local, control[1], control[0], echo.listener, webview);
    }
    close(control[1]);
    if (child < 0) {
        close(control[0]);
        close(echo.listener);
        return -1;
    }
    pthread_t thread;
    const int started = pthread_create(&thread, NULL, echo_server, &echo);
    int result = -1;
    if (started == 0) {
        report_log("Local relay check target 127.0.0.1:%u (%d TCP connections)",
                   ntohs(local.sin_port), RELAY_CHECK_CONNECTIONS);
        result = webview ? trace_webview(child, NULL, &local, control[0], stop, NULL, NULL)
            : trace_process(child, NULL, &local, control[0], stop, NULL);
    } else {
        close(echo.listener);
        report_log("Could not start local echo thread (errno=%d)", started);
    }
    close(control[0]);
    relay_stop();
    if (started == 0)
        pthread_join(thread, NULL);
    // If the debugger already consumed exit status, this returns ECHILD.
    if (waitpid(child, NULL, WNOHANG) == 0) {
        kill(child, SIGKILL);
        for (int attempt = 0; attempt < 100 && waitpid(child, NULL, WNOHANG) == 0; attempt++) {
            const struct timespec delay = {.tv_nsec = 10 * 1000 * 1000};
            nanosleep(&delay, NULL);
        }
    }
    if (result != 0)
        report_log("The local relay check did not complete through sing-box");
    return result == 0 && echo.ok == RELAY_CHECK_CONNECTIONS ? 0 : -1;
}

int
relay_check(const atomic_bool *stop, int proxy_control) {
    return run_relay_check(stop, proxy_control, 0);
}

int
relay_webview_check(const atomic_bool *stop, int proxy_control) {
    return run_relay_check(stop, proxy_control, 1);
}

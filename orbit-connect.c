/* SPDX-License-Identifier: MIT */
/* Freestanding PIC for Orbit and the WebView process. */
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>

#include "orbit-wire.h"
#ifdef PS5_WEBVIEW_SHIM
#include "webview-hook.h"
#endif

typedef int (*connect_function)(int, const struct sockaddr *, socklen_t);

#ifdef PS5_WEBVIEW_SHIM
__attribute__((section(".hook_data"), visibility("hidden"), used))
volatile struct webview_hook_config webview_config;
#define hook_route webview_config.route
#else
__attribute__((section(".hook_data"), visibility("hidden"), used))
volatile struct orbit_config orbit_config;
#define hook_route orbit_config

_Static_assert(offsetof(struct orbit_config, boot_entry) == ORBIT_BOOT_POINTER_OFFSET,
               "Orbit boot entry pointer offset changed");
#endif

static inline long
raw(long number, long a, long b, long c, long d, long e, long f) {
#ifdef PS5_WEBVIEW_SHIM
    // Use the browser's own libc ABI and TLS errno from libkernel_web.
    const volatile struct webview_socket_api *api = &webview_config.api;
    long result;
    switch (number) {
    case SYS_socket:
        result = api->socket((int)a, (int)b, (int)c);
        break;
    case SYS_connect:
        result = api->connect((int)a, (const struct sockaddr *)b, (socklen_t)c);
        break;
    case SYS_close:
        result = api->close((int)a);
        break;
    case SYS_getsockopt:
        result = api->getsockopt((int)a, (int)b, (int)c, (void *)d, (socklen_t *)e);
        break;
    case SYS_sendto:
        result = api->sendto((int)a, (const void *)b, (size_t)c, (int)d, (const struct sockaddr *)e, (socklen_t)f);
        break;
    case SYS_recvfrom:
        result = api->recvfrom((int)a, (void *)b, (size_t)c, (int)d, (struct sockaddr *)e, (socklen_t *)f);
        break;
    case SYS_poll:
        result = api->poll((struct pollfd *)a, (nfds_t)b, (int)c);
        break;
    default:
        return -ENOSYS;
    }
    if (result < 0) {
        int error = *api->error_location();
        return error > 0 ? -error : -EIO;
    }
    return result;
#else
    register long arg4 __asm__("r10") = d;
    register long arg5 __asm__("r8") = e;
    register long arg6 __asm__("r9") = f;
    unsigned char carry;
    __asm__ volatile("syscall; setc %1"
                     : "+a"(number), "=qm"(carry), "+d"(c)
                     : "D"(a), "S"(b), "r"(arg4), "r"(arg5), "r"(arg6)
                     : "rcx", "r11", "memory", "cc");
#ifdef __linux__
    return number;
#else
    return carry && number > 0 ? -number : number;
#endif
#endif
}

static long
controller_socket(void) {
    long control = raw(SYS_socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, 0);
    if (control < 0)
        return control;

    struct sockaddr_in address = {
#ifdef __FreeBSD__
        .sin_len = sizeof(address),
#endif
        .sin_family = AF_INET,
        .sin_port = hook_route.port,
        .sin_addr.s_addr = __builtin_bswap32(INADDR_LOOPBACK),
    };
    long result = raw(SYS_connect, control, (long)&address, sizeof(address), 0, 0, 0);
    if (result < 0) {
        raw(SYS_close, control, 0, 0, 0, 0, 0);
        return result;
    }
    return control;
}

static uint16_t
ask_controller(const struct sockaddr_in *target, int *disabled) {
    long control = controller_socket();
    if (control < 0) {
        *disabled = control == -ECONNREFUSED;
        return 0;
    }

    uint16_t port = 0;
    struct orbit_request request;
    for (unsigned i = 0; i < sizeof(request.token); i++)
        request.token[i] = hook_route.token[i];
    request.target = *target;
    long result = raw(SYS_sendto, control, (long)&request, sizeof(request), MSG_DONTWAIT, 0, 0);
    if (result == (long)sizeof(request)) {
        struct pollfd ready = {.fd = (int)control, .events = POLLIN};
        result = raw(SYS_poll, (long)&ready, 1, 550, 0, 0, 0);
        if (result > 0)
            result = raw(SYS_recvfrom, control, (long)&port, sizeof(port), MSG_DONTWAIT, 0, 0);
        if (result != (long)sizeof(port))
            port = 0;
    }
    if (result == -ECONNREFUSED)
        *disabled = 1;
    raw(SYS_close, control, 0, 0, 0, 0, 0);
    return port;
}

#ifndef PS5_WEBVIEW_SHIM
static void
boot_notice(char stage, long value) {
    static const char hex[] = "0123456789abcdef";
    char line[] = "PS5NET boot ? 0x00000000\n";
    line[sizeof("PS5NET boot ") - 1] = stage;
    uint32_t code = (uint32_t)value;
    for (unsigned i = 0; i < 8; i++) {
        line[sizeof(line) - 3 - i] = hex[code & 15];
        code >>= 4;
    }
    (void)raw(SYS_sendto, 2, (long)line, sizeof(line) - 1, MSG_NOSIGNAL | MSG_DONTWAIT, 0, 0);
}

__attribute__((used, noinline)) static void
orbit_wait_for_start(void) {
    boot_notice('E', 0);
    long control = controller_socket();
    boot_notice('S', control);
    if (control >= 0) {
        struct orbit_boot boot = {.pid = (int32_t)raw(SYS_getpid, 0, 0, 0, 0, 0, 0)};
        for (unsigned i = 0; i < sizeof(boot.token); i++)
            boot.token[i] = orbit_config.token[i];
        struct pollfd ready = {.fd = (int)control, .events = POLLIN};
        char reply = 0;
        boot_notice('P', boot.pid);
        if (boot.pid > 1) {
            long sent = raw(SYS_sendto, control, (long)&boot, sizeof(boot), MSG_DONTWAIT, 0, 0);
            boot_notice('T', sent);
            if (sent == sizeof(boot)) {
                long result = raw(SYS_poll, (long)&ready, 1, ORBIT_BOOT_WAIT_MS, 0, 0, 0);
                boot_notice('W', result);
                if (result > 0) {
                    long received = raw(SYS_recvfrom, control, (long)&reply, sizeof(reply), MSG_DONTWAIT, 0, 0);
                    boot_notice('R', received == sizeof(reply) ? (unsigned char)reply : received);
                }
            }
        }
        raw(SYS_close, control, 0, 0, 0, 0, 0);
        if (reply == 'G')
            return;
    }
    raw(SYS_exit, 1, 0, 0, 0, 0, 0);
    __builtin_trap();
}

#define ORBIT_STRING_INNER(value) #value
#define ORBIT_STRING(value) ORBIT_STRING_INNER(value)

// Preserve the loader's entry registers and stack before entering the saved ELF.
__asm__(".pushsection .hook_boot,\"ax\",@progbits\n"
        ".global orbit_boot_entry\n"
        "orbit_boot_entry:\n"
        "push %rax; push %rdi; push %rsi; push %rdx; push %rcx\n"
        "push %r8; push %r9; push %r10; push %r11\n"
        "call orbit_wait_for_start\n"
        "pop %r11; pop %r10; pop %r9; pop %r8\n"
        "pop %rcx; pop %rdx; pop %rsi; pop %rdi; pop %rax\n"
        "jmp *orbit_config+" ORBIT_STRING(ORBIT_BOOT_POINTER_OFFSET) "(%rip)\n"
        ".popsection\n");
#endif

__attribute__((section(".hook_entry"), visibility("hidden"), used))
int
orbit_connect(int fd, const struct sockaddr *address, socklen_t length) {
    connect_function native = (connect_function)(uintptr_t)hook_route.connect_function;
    if (!hook_route.port || !address || length != sizeof(struct sockaddr_in) || address->sa_family != AF_INET)
        return native(fd, address, length);

    const struct sockaddr_in *destination = (const struct sockaddr_in *)address;
    int probe = destination->sin_addr.s_addr == __builtin_bswap32(UINT32_C(0x7f000002)) &&
                destination->sin_port == hook_route.probe_port;
    if (!destination->sin_port || (!probe && !public_ipv4(destination->sin_addr)))
        return native(fd, address, length);

    int type = 0;
    socklen_t size = sizeof(type);
    if (raw(SYS_getsockopt, fd, SOL_SOCKET, SO_TYPE, (long)&type, (long)&size, 0) != 0 ||
        type != SOCK_STREAM)
        return native(fd, address, length);

    int disabled = 0;
    uint16_t port = ask_controller(destination, &disabled);
    if (disabled)
        return native(fd, address, length);
    if (!port)
        return native(fd, address, 0); /* Failed broker request. Retain native errno handling. */
    struct sockaddr_in redirected = *destination;
    redirected.sin_addr.s_addr = __builtin_bswap32(INADDR_LOOPBACK);
    redirected.sin_port = port;
    return native(fd, (const struct sockaddr *)&redirected, sizeof(redirected));
}

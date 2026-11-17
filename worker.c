/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "goload.h"
#include "panel.h"
#include "relay.h"
#include "worker.h"

static volatile struct worker_ticket start_ticket = {.marker = WORKER_MARKER};

extern const uint8_t core_image[], core_image_end[];
__asm__(".section .rodata\n"
        ".balign 0x4000\n"
        ".global core_image\n"
        "core_image:\n"
        ".incbin \"proxy-go.bin\"\n"
        ".global core_image_end\n"
        "core_image_end:\n"
        ".text\n");

static long
rtprio_thread(long operation, void *value) {
    long number = 466;
    unsigned char failed;
    __asm__ volatile("syscall; setc %1"
                     : "+a"(number), "=q"(failed)
                     : "D"(operation), "S"(0L), "d"(value)
                     : "rcx", "r11", "memory");
    return failed ? -number : number;
}

static int
set_background_priority(void) {
    struct rtprio { unsigned short type, priority; };
    struct rtprio choices[] = {{3, 767}, {2, 767}};
    for (size_t index = 0; index < sizeof(choices) / sizeof(choices[0]); index++) {
        struct rtprio current = {0};
        if (rtprio_thread(1, &choices[index]) == 0 &&
            rtprio_thread(0, &current) == 0 &&
            current.type == choices[index].type && current.priority == choices[index].priority) {
            report_log("Scheduling class %u, priority %u", current.type, current.priority);
            return 0;
        }
    }
    report_log("Cannot verify background scheduling for integrated sing-box");
    return -1;
}

static int
connect_panel(uint16_t port, const struct worker_hello *hello) {
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;
    int64_t deadline = monotonic_ms() + 3000;
    char permit;
    if (connect_local(fd, port, deadline) == 0 &&
        socket_send_all(fd, hello, sizeof(*hello), deadline) == 0 &&
        socket_read_all(fd, &permit, 1, deadline) == 0 && permit == 'G')
        return fd;
    int error = errno;
    close(fd);
    errno = error ? error : EPROTO;
    return -1;
}

int
main(void) {
    uint16_t port = (uint16_t)(start_ticket.port[0] << 8 | start_ticket.port[1]);
    if (!port)
        return 1;
    if ((kernel_get_fw_version() >> 16) != 0x1220 || prepare_data_dir() != 0 ||
        report_begin(RELAY_LOG, 0) != 0)
        return 1;
    name_payload(PROXY_PROCESS_NAME);

    struct worker_hello hello;
    for (size_t i = 0; i < sizeof(hello.token); i++)
        hello.token[i] = start_ticket.token[i];
    uint32_t pid = htonl((uint32_t)getpid());
    memcpy(hello.pid, &pid, sizeof(pid));

    int control = connect_panel(port, &hello);
    if (control < 0) {
        report_log("Integrated sing-box could not reach its panel: %s", strerror(errno));
        return 1;
    }

    if (set_background_priority() == 0) {
        static char *args[] = {"ps5-tunnel-proxy", "managed", NULL};
        static char *environment[] = {
            "HOME=" DATA_DIR, "TMPDIR=" DATA_DIR, "GOMAXPROCS=2", "GODEBUG=multipathtcp=0", NULL,
        };
        goload_run_managed(core_image, (size_t)(core_image_end - core_image), args, environment, control, 3);
    }
    close(control);
    return 1;
}

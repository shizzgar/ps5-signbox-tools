/* SPDX-License-Identifier: MIT */
#include <arpa/inet.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "diagnostics.h"
#include "orbit-image.h"
#include "orbit-relay.h"
#include "orbit-run.h"
#include "relay.h"
#include "report.h"
#include "service.h"

#ifndef ORBIT_RUNTIME
#define ORBIT_RUNTIME "/data/orbit-store/orbit_store.elf"
#endif

enum { ORBIT_BOOT_REPORT_MS = 15000 };

struct orbit_gate {
    pid_t pid;
    struct sockaddr_in peer;
};

struct loader_output {
    int fd;
    const char *label;
    char line[160];
    size_t used;
    unsigned bytes, omitted;
    int overlong;
    int probe_main;
    int loader_error;
};

extern const unsigned char orbit_probe_image[], orbit_probe_image_end[];
__asm__(".section .rodata\n"
        ".balign 16\n"
        ".global orbit_probe_image\n"
        "orbit_probe_image:\n"
        ".incbin \"orbit-probe.elf\"\n"
        ".global orbit_probe_image_end\n"
        "orbit_probe_image_end:\n"
        ".text\n");

int
orbit_open_control(struct orbit_config *config) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return -1;
    struct sockaddr_in local = {
#ifdef __FreeBSD__
        .sin_len = sizeof(local),
#endif
        .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    socklen_t size = sizeof(local);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0 ||
        getsockname(fd, (struct sockaddr *)&local, &size) != 0 ||
        random_bytes(config->token, sizeof(config->token)) != 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    config->port = local.sin_port;
    return fd;
}

int
orbit_reserve_relay(const struct orbit_config *config, const struct sockaddr_in *target,
                    struct sockaddr_in *local) {
    int64_t now = monotonic_ms();
    if (now < 0)
        return -1;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        return -1;
    struct sockaddr_in controller = {
#ifdef __FreeBSD__
        .sin_len = sizeof(controller),
#endif
        .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK), .sin_port = config->port,
    };
    struct orbit_request request = {.target = *target};
    memcpy(request.token, config->token, sizeof(request.token));
    uint16_t port = 0;
    int result = connect(fd, (const struct sockaddr *)&controller, sizeof(controller));
    if (result == 0) {
        ssize_t sent = send(fd, &request, sizeof(request), MSG_DONTWAIT | MSG_NOSIGNAL);
        if (sent == sizeof(request)) {
            result = socket_read_all(fd, &port, sizeof(port), now + 500);
        } else {
            if (sent >= 0)
                errno = EIO;
            result = -1;
        }
    }
    int detail = errno;
    close(fd);
    if (result != 0 || !port) {
        errno = result != 0 ? detail : EAGAIN;
        return -1;
    }
    *local = controller;
    local->sin_port = port;
    return 0;
}

static void
loader_line(struct loader_output *output) {
    output->line[output->used] = '\0';
    const char *line = output->line;
    char stage = 0;
    unsigned value = 0;
    int number = 0, end = 0;
    if (output->overlong) {
        output->omitted++;
    } else if (sscanf(line, "PS5NET boot %c 0x%8x%n", &stage, &value, &end) == 2 &&
               line[end] == '\0' && strchr("ESPTWR", stage)) {
        report_diag("ELF loader %s boot stage=%c value=%#x (%d)", output->label, stage, value, (int32_t)value);
    } else if (sscanf(line, "PS5NET probe %c %6d%n", &stage, &number, &end) == 2 &&
               line[end] == '\0' && strchr("MSC", stage)) {
        report_diag("ELF loader %s probe stage=%c value=%d", output->label, stage, number);
        if (stage == 'M')
            output->probe_main = 1;
    } else if (!strcmp(line, "[elfldr.elf] Error reading ELF payload") ||
               !strcmp(line, "[elfldr.elf] Error spawning payload") ||
               !strcmp(line, "[elfldr.elf] Unknown payload format")) {
        report_diag("ELF loader %s %s", output->label, line);
        output->loader_error = 1;
    } else {
        unsigned major = 0, minor = 0;
        if (sscanf(line, "Starting on firmware %2x.%2x, PID %6d%n", &major, &minor, &number, &end) == 3 &&
            line[end] == '\0')
            report_diag("ELF loader %s payload firmware=%x.%02x PID=%d", output->label, major, minor, number);
        else if (output->used)
            output->omitted++;
    }
    output->used = 0;
    output->overlong = 0;
}

static void
drain_loader(struct loader_output *output) {
    if (output->fd < 0)
        return;
    for (int read_no = 0; read_no < 8; read_no++) {
        char bytes[512];
        ssize_t count = recv(output->fd, bytes, sizeof(bytes), MSG_DONTWAIT);
        if (count <= 0) {
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))
                return;
            report_diag("ELF loader %s output %s errno=%d", output->label, count == 0 ? "EOF" : "read failed",
                        count == 0 ? 0 : errno);
            close(output->fd);
            output->fd = -1;
            return;
        }
        output->bytes += (unsigned)count;
        for (ssize_t i = 0; i < count; i++) {
            if (bytes[i] == '\0' || bytes[i] == '\n') {
                loader_line(output);
            } else if (bytes[i] != '\r') {
                if (output->used < sizeof(output->line) - 1)
                    output->line[output->used++] = bytes[i];
                else
                    output->overlong = 1;
            }
        }
    }
}

static void
close_loader_output(struct loader_output *output) {
    int detail = errno;
    drain_loader(output);
    if (output->used)
        loader_line(output);
    if (output->fd >= 0)
        close(output->fd);
    report_diag("ELF loader %s output_bytes=%u other_lines=%u", output->label, output->bytes, output->omitted);
    output->fd = -1;
    errno = detail;
}

static int
open_loader_output(struct loader_output *output, const unsigned char *image, size_t size) {
    Elf64_Ehdr header;
    memcpy(&header, image, sizeof(header));
    int64_t start = monotonic_ms();
    output->fd = loader_upload_output(image, size);
    int detail = errno;
    report_diag("ELF loader %s upload bytes=%zu ELF_entry=%#lx phnum=%u shnum=%u result=%s errno=%d elapsed_ms=%lld",
                output->label, size, (unsigned long)header.e_entry, (unsigned)header.e_phnum, (unsigned)header.e_shnum,
                output->fd < 0 ? "failed" : "sent", output->fd < 0 ? detail : 0,
                (long long)(monotonic_ms() - start));
    errno = detail;
    return output->fd < 0 ? -1 : 0;
}

static void
probe_standard_loader(const atomic_bool *stop) {
    struct loader_output output = {.fd = -1, .label = "plain-probe"};
    if (open_loader_output(&output, orbit_probe_image, (size_t)(orbit_probe_image_end - orbit_probe_image)) == 0) {
        const int64_t deadline = monotonic_ms() + 5000;
        while (output.fd >= 0 && !atomic_load(stop) && monotonic_ms() < deadline) {
            struct pollfd ready = {.fd = output.fd, .events = POLLIN};
            (void)poll(&ready, 1, 100);
            drain_loader(&output);
            if (output.probe_main)
                break;
        }
    }
    close_loader_output(&output);
    report_diag("ELF loader plain-probe reached_main=%d", output.probe_main);
}

static int
receive_orbit_gate(int control, const struct orbit_config *config, struct orbit_gate *gate,
                   struct loader_output *output, const atomic_bool *stop) {
    int64_t start = monotonic_ms();
    if (start < 0)
        return -1;
    unsigned rejected = 0;
    while (!atomic_load(stop)) {
        int64_t now = monotonic_ms();
        if (now < 0 || now - start >= ORBIT_BOOT_REPORT_MS)
            break;
        struct pollfd ready[] = {{.fd = control, .events = POLLIN}, {.fd = output->fd, .events = POLLIN}};
        int result = poll(ready, 2, 100);
        int poll_error = errno;
        drain_loader(output);
        if (output->loader_error) {
            errno = EPROTO;
            return -1;
        }
        if (result < 0 && poll_error != EINTR) {
            errno = poll_error;
            return -1;
        }
        if (result <= 0 || !(ready[0].revents & POLLIN))
            continue;
        unsigned char packet[sizeof(struct orbit_boot) + 1];
        socklen_t length = sizeof(gate->peer);
        ssize_t size = recvfrom(control, packet, sizeof(packet), MSG_DONTWAIT,
                                (struct sockaddr *)&gate->peer, &length);
        if (size != sizeof(struct orbit_boot) || length != sizeof(gate->peer) ||
            gate->peer.sin_family != AF_INET || gate->peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
            rejected++;
            continue;
        }
        struct orbit_boot boot;
        memcpy(&boot, packet, sizeof(boot));
        if (boot.pid > 1 && memcmp(boot.token, config->token, sizeof(boot.token)) == 0) {
            gate->pid = (pid_t)boot.pid;
            report_diag("ELF loader %s gate hello PID=%d after %lldms rejected=%u", output->label, (int)gate->pid,
                        (long long)(monotonic_ms() - start), rejected);
            return 0;
        }
        rejected++;
    }
    errno = atomic_load(stop) ? ECANCELED : ETIMEDOUT;
    report_diag("ELF loader %s waiting for gate hello errno=%d rejected=%u", output->label, errno, rejected);
    return -1;
}

static int
reply_orbit_gate(int control, const struct orbit_gate *gate, char reply) {
    return sendto(control, &reply, sizeof(reply), MSG_DONTWAIT,
                  (const struct sockaddr *)&gate->peer, sizeof(gate->peer)) == sizeof(reply) ? 0 : -1;
}

static int
check_connect_shim(const atomic_bool *stop, int gated) {
    struct orbit_config config = {.probe_port = htons(ORBIT_PROBE_PORT)};
    struct sockaddr_in echo_address;
    struct loader_output output = {.fd = -1, .label = gated ? "gated-probe" : "original-entry-probe"};
    const char *stage = "build probe image";
    unsigned char *image = NULL;
    size_t image_size = 0;
    int control = orbit_open_control(&config);
    if (control < 0)
        return -1;
    int echo = relay_listen(&echo_address);
    int result = -1;
    struct orbit_gate gate = {0};
    if (echo < 0 || orbit_image(orbit_probe_image, (size_t)(orbit_probe_image_end - orbit_probe_image),
                                &config, gated, &image, &image_size) != 0)
        goto done;
    stage = "upload probe";
    if (open_loader_output(&output, image, image_size) != 0)
        goto done;
    if (gated) {
        stage = "wait for boot report";
        if (receive_orbit_gate(control, &config, &gate, &output, stop) != 0)
            goto done;
        stage = "reply to boot report";
        int stopped = atomic_load(stop);
        if (reply_orbit_gate(control, &gate, stopped ? 'X' : 'G') != 0)
            goto done;
        if (stopped) {
            errno = ECANCELED;
            goto done;
        }
    }

    stage = "wait for connect shim request";
    int64_t deadline = monotonic_ms() + 6500;
    struct orbit_request request;
    struct sockaddr_in peer;
    for (;;) {
        int64_t now = monotonic_ms();
        if (atomic_load(stop) || now < 0 || now >= deadline) {
            errno = atomic_load(stop) ? ECANCELED : ETIMEDOUT;
            goto done;
        }
        struct pollfd readiness[] = {{.fd = control, .events = POLLIN}, {.fd = output.fd, .events = POLLIN}};
        int ready = poll(readiness, 2, 100);
        drain_loader(&output);
        if (output.loader_error) {
            errno = EPROTO;
            goto done;
        }
        if (ready <= 0 || !(readiness[0].revents & POLLIN))
            continue;
        socklen_t length = sizeof(peer);
        ssize_t got = recvfrom(control, &request, sizeof(request), MSG_DONTWAIT,
                               (struct sockaddr *)&peer, &length);
        if (got == sizeof(request) && length == sizeof(peer) &&
            peer.sin_family == AF_INET && peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
            memcmp(request.token, config.token, sizeof(config.token)) == 0 &&
            request.target.sin_addr.s_addr == htonl(UINT32_C(0x7f000002)) &&
            request.target.sin_port == config.probe_port)
            break;
    }
    stage = "connect shim loopback exchange";
    if (sendto(control, &echo_address.sin_port, sizeof(echo_address.sin_port), MSG_DONTWAIT,
               (const struct sockaddr *)&peer, sizeof(peer)) != sizeof(echo_address.sin_port))
        goto done;
    int incoming = relay_accept_until(echo, monotonic_ms() + 1000);
    if (incoming >= 0) {
        char byte;
        if (socket_read_all(incoming, &byte, 1, monotonic_ms() + 500) == 0) {
            if (byte == 'O')
                result = 0;
            else
                errno = EPROTO;
        }
        close(incoming);
    }
done:
    close_loader_output(&output);
    report_diag("ELF loader %s result=%s last_step=%s errno=%d reached_main=%d",
                output.label, result == 0 ? "pass" : "fail", stage, result == 0 ? 0 : errno, output.probe_main);
    free(image);
    if (echo >= 0)
        close(echo);
    close(control);
    return result;
}

void
orbit_probe_diagnostics(const atomic_bool *stop) {
    int fd = open(ORBIT_RUNTIME, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) {
        struct stat info;
        Elf64_Ehdr header;
        if (fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && read(fd, &header, sizeof(header)) == sizeof(header) &&
            memcmp(header.e_ident, ELFMAG, SELFMAG) == 0) {
            report_diag("Orbit saved ELF size=%lld class=%u machine=%u type=%u entry=%#lx phnum=%u shnum=%u",
                        (long long)info.st_size, header.e_ident[EI_CLASS], header.e_machine, header.e_type,
                        (unsigned long)header.e_entry, header.e_phnum, header.e_shnum);
        } else {
            report_diag("Orbit saved ELF header check failed errno=%d", errno);
        }
        close(fd);
    } else {
        report_diag("Orbit saved ELF open failed errno=%d", errno);
    }
    if (!atomic_load(stop))
        probe_standard_loader(stop);
    if (!atomic_load(stop))
        (void)check_connect_shim(stop, 0);
    if (!atomic_load(stop))
        (void)check_connect_shim(stop, 1);
}

int
orbit_read_saved(unsigned char **source, size_t *size) {
    int file = open(ORBIT_RUNTIME, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (file < 0) {
        int detail = errno;
        report_log("Open saved Orbit ELF at %s: %s", ORBIT_RUNTIME, strerror(detail));
        errno = detail;
        return -1;
    }
    struct stat info;
    if (fstat(file, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size <= 0 || info.st_size > 64 * 1024 * 1024) {
        report_log("Orbit runtime is not a supported ELF file");
        close(file);
        errno = ENOEXEC;
        return -1;
    }
    size_t source_size = (size_t)info.st_size;
    unsigned char *buffer = malloc(source_size);
    if (!buffer) {
        close(file);
        return -1;
    }
    size_t used = 0;
    while (used < source_size) {
        ssize_t count = read(file, buffer + used, source_size - used);
        if (count <= 0) {
            if (count < 0 && errno == EINTR)
                continue;
            break;
        }
        used += (size_t)count;
    }
    close(file);
    if (used != source_size) {
        free(buffer);
        errno = EIO;
        return -1;
    }

    *source = buffer;
    *size = source_size;
    return 0;
}

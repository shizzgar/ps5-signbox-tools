/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "report.h"

int sceKernelSendNotificationRequest(int, void *, size_t, int);

void
notify(const char *message) {
    char request[0xc30] = {0};
    snprintf(request + 0x2d, sizeof(request) - 0x2d, "%s", message);
    sceKernelSendNotificationRequest(0, request, sizeof(request), 0);
}

int
prepare_data_dir(void) {
    struct stat status;
    pid_t pid = getpid();
    intptr_t root = kernel_get_root_vnode();

    signal(SIGPIPE, SIG_IGN);
    if (!root ||
        kernel_set_proc_rootdir(pid, root) ||
        kernel_set_proc_jaildir(pid, 0) ||
        kernel_set_ucred_uid(pid, 0) ||
        kernel_set_ucred_ruid(pid, 0) ||
        kernel_set_ucred_svuid(pid, 0) ||
        kernel_set_ucred_rgid(pid, 0) ||
        kernel_set_ucred_svgid(pid, 0)) {
        report_fail("Cannot prepare the payload process");
        return -1;
    }

    if (mkdir(DATA_DIR, 0700) && errno != EEXIST) {
        report_fail("mkdir %s: %s", DATA_DIR, strerror(errno));
        return -1;
    }
    if (lstat(DATA_DIR, &status) || !S_ISDIR(status.st_mode)) {
        report_fail("Cannot use %s as the data directory", DATA_DIR);
        return -1;
    }
    return 0;
}

int
random_bytes(unsigned char *data, size_t size) {
    const int mib[] = {CTL_KERN, KERN_ARND};
    size_t length = size;
    if (sysctl(mib, 2, data, &length, NULL, 0) == 0 && length == size)
        return 0;

    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    size_t used = 0;
    while (used < size) {
        ssize_t count = read(fd, data + used, size - used);
        if (count > 0) {
            used += (size_t)count;
        } else if (count == 0 || errno != EINTR) {
            break;
        }
    }
    int error = errno;
    close(fd);
    if (used == size)
        return 0;
    errno = error ? error : EIO;
    return -1;
}

int
report_begin(const char *path, int rotate) {
    struct stat status;
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) {
        report_fail("Cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &status) || !S_ISREG(status.st_mode) ||
        (rotate && status.st_size > 1024 * 1024 && ftruncate(fd, 0))) {
        close(fd);
        report_fail("Cannot prepare log %s", path);
        return -1;
    }

    fflush(stdout);
    fflush(stderr);
    int result = dup2(fd, STDOUT_FILENO);
    if (result >= 0)
        result = dup2(fd, STDERR_FILENO);
    if (fd > STDERR_FILENO)
        close(fd);
    if (result < 0) {
        report_fail("Cannot redirect output to %s: %s", path, strerror(errno));
        return -1;
    }
    unsigned firmware = kernel_get_fw_version();
    report_log("Starting on firmware %x.%02x, PID %d", firmware >> 24,
               (firmware >> 16) & 0xff, (int)getpid());
    return 0;
}

static int
payload_comm(char name[20]) {
    const int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    unsigned char record[4096];
    size_t size = sizeof(record);
    const size_t offset = offsetof(struct kinfo_proc, ki_comm);
    _Static_assert(sizeof(((struct kinfo_proc *)0)->ki_comm) == 20, "check process name ABI");
    if (sysctl(mib, 4, record, &size, NULL, 0) != 0 || size < offset + 20)
        return -1;
    memcpy(name, record + offset, 20);
    name[19] = '\0';
    return 0;
}

void
name_payload(const char *name) {
    // Match elfldr's naming syscall, and leave a shared host's name alone.
    if (kernel_dynlib_dlsym(-1, 0x2001, "sceKernelDlsym")) {
        report_log("Requested process label %s, PID %d belongs to a shared host", name, (int)getpid());
        return;
    }
    int result = (int)syscall(SYS_thr_set_name, -1L, name);
    char current[20] = "";
    if (payload_comm(current) == 0 && strcmp(current, name) == 0) {
        report_log("Process name: %s, PID %d", current, (int)getpid());
        return;
    }
    typedef int (*set_process_name)(const char *);
    set_process_name setter = (set_process_name)kernel_dynlib_dlsym(-1, 0x1, "sceKernelSetProcessName");
    if (setter)
        result = setter(name);
    if (payload_comm(current) == 0 && strcmp(current, name) == 0) {
        report_log("Process name: %s, PID %d", current, (int)getpid());
        return;
    }
    report_log("Process label %s, PID %d (kernel name %s, rename result %d)",
               name, (int)getpid(), current[0] ? current : "unavailable", result);
}

void
report_log(const char *format, ...) {
    va_list args;
    flockfile(stderr);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputc('\n', stderr);
    fflush(stderr);
    funlockfile(stderr);
}

void
report_fail(const char *format, ...) {
    char message[384];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    report_log("%s", message);
    notify(message);
}


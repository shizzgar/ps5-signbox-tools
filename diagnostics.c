/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "diagnostics.h"
#include "relay.h"

static pthread_mutex_t report_mutex = PTHREAD_MUTEX_INITIALIZER;
static int report_fd = -1;
static size_t report_size;
static int64_t report_start;

int
diagnostics_open(void) {
    int fd = open(DIAGNOSTICS_PATH, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    struct stat status;
    if (fstat(fd, &status) != 0 || !S_ISREG(status.st_mode) || fchmod(fd, 0600) != 0 || ftruncate(fd, 0) != 0) {
        int detail = errno;
        close(fd);
        errno = detail;
        return -1;
    }
    report_start = monotonic_ms();
    report_fd = fd;
    return 0;
}

void
report_diag(const char *format, ...) {
    if (report_fd < 0)
        return;
    int detail = errno;
    char message[768];
    int prefix = snprintf(message, sizeof(message), "+%lldms ", (long long)(monotonic_ms() - report_start));
    if (prefix < 0 || (size_t)prefix >= sizeof(message) - 2) {
        errno = detail;
        return;
    }
    va_list args;
    va_start(args, format);
    int formatted = vsnprintf(message + prefix, sizeof(message) - (size_t)prefix - 1, format, args);
    va_end(args);
    if (formatted >= 0) {
        size_t length = (size_t)prefix + (size_t)formatted;
        if (length >= sizeof(message) - 1)
            length = sizeof(message) - 2;
        for (size_t i = (size_t)prefix; i < length; i++) {
            unsigned char byte = (unsigned char)message[i];
            if (byte < 32 || byte > 126)
                message[i] = '?';
        }
        message[length++] = '\n';
        pthread_mutex_lock(&report_mutex);
        if (report_size + length <= DIAGNOSTICS_LIMIT || ftruncate(report_fd, 0) == 0) {
            if (report_size + length > DIAGNOSTICS_LIMIT)
                report_size = 0;
            size_t written = 0;
            while (written < length) {
                ssize_t count = write(report_fd, message + written, length - written);
                if (count < 0 && errno == EINTR)
                    continue;
                if (count <= 0)
                    break;
                written += (size_t)count;
            }
            report_size += written;
        }
        pthread_mutex_unlock(&report_mutex);
    }
    errno = detail;
}

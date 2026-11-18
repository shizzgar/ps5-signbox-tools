/* SPDX-License-Identifier: MIT */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "diagnostics.h"
#include "orbit-source.h"
#include "report.h"

static int
read_source(const char *path, unsigned char **source, size_t *size) {
    int file = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (file < 0)
        return -1;
    struct stat info;
    if (fstat(file, &info) != 0 || !S_ISREG(info.st_mode) ||
        info.st_size <= 0 || info.st_size > 64 * 1024 * 1024) {
        close(file);
        errno = ENOEXEC;
        return -1;
    }
    size_t length = (size_t)info.st_size;
    unsigned char *buffer = malloc(length);
    if (!buffer) {
        close(file);
        return -1;
    }
    size_t used = 0;
    while (used < length) {
        ssize_t bytes = read(file, buffer + used, length - used);
        if (bytes < 0 && errno == EINTR)
            continue;
        if (bytes <= 0)
            break;
        used += (size_t)bytes;
    }
    close(file);
    if (used != length) {
        free(buffer);
        errno = EIO;
        return -1;
    }
    *source = buffer;
    *size = length;
    return 0;
}

static int
match_source(const char *path, const struct orbit_region *regions, size_t count,
             int (*read_memory)(void *, uintptr_t, void *, size_t), void *context,
             uintptr_t *base, uintptr_t *slot) {
    unsigned char *source = NULL;
    size_t size = 0;
    int result = read_source(path, &source, &size);
    if (result == 0)
        result = orbit_find_live_import(source, size, regions, count, read_memory, context, base, slot);
    int detail = result == 0 ? 0 : errno;
    free(source);
    report_diag("Orbit reference path=%s bytes=%zu result=%d errno=%d", path, size, result, detail);
    if (result == 0)
        report_log("Orbit live image matched %s (%zu bytes)", path, size);
    errno = detail;
    return result;
}

int
orbit_find_runtime_import(const struct orbit_region *regions, size_t count,
                          int (*read_memory)(void *, uintptr_t, void *, size_t), void *context,
                          uintptr_t *base, uintptr_t *slot) {
    if (match_source(ORBIT_RUNTIME, regions, count, read_memory, context, base, slot) == 0)
        return 0;
    int detail = errno;
    if (detail == EEXIST || detail == ENOMEM)
        return -1;

    // A TV-app update may start its bundled service while the downloaded cache
    // still contains another build with the same version number. Verify code
    // samples and the connect slot in memory for each candidate, never versions.
    DIR *directory = opendir(ORBIT_SANDBOX);
    if (!directory)
        goto unmatched;
    struct dirent *entry;
    unsigned attempts = 0;
    while ((entry = readdir(directory)) && attempts < 8) {
        const char prefix[] = "PPSA99177_";
        if (strncmp(entry->d_name, prefix, sizeof(prefix) - 1))
            continue;
        const char *suffix = entry->d_name + sizeof(prefix) - 1;
        size_t digits = strspn(suffix, "0123456789");
        if (!digits || digits > 10 || suffix[digits])
            continue;
        char path[512];
        int length = snprintf(path, sizeof(path), "%s/%s/app0/orbit/orbit_store.elf",
                              ORBIT_SANDBOX, entry->d_name);
        if (length < 0 || (size_t)length >= sizeof(path))
            continue;
        attempts++;
        if (match_source(path, regions, count, read_memory, context, base, slot) == 0) {
            closedir(directory);
            return 0;
        }
        detail = errno;
        if (detail == EEXIST || detail == ENOMEM)
            break;
    }
    closedir(directory);
unmatched:
    report_log("No Orbit reference matched the running service (errno=%d). See diagnostics.", detail);
    errno = detail;
    return -1;
}

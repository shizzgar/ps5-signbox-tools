/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <unistd.h>

#include "process.h"
#include "relay.h"
#include "trace.h"

_Static_assert(offsetof(struct kinfo_proc, ki_pid) == 72, "check PS5 process PID ABI");
_Static_assert(offsetof(struct kinfo_proc, ki_comm) == 447, "check PS5 process name ABI");
_Static_assert(sizeof(((struct kinfo_proc *)0)->ki_comm) == PROCESS_NAME_SIZE,
               "check PS5 process name ABI");

static int
snapshot(const int mib[4], unsigned char **out, size_t *length) {
    for (int attempt = 0; attempt < 3; attempt++) {
        size_t capacity = 0;
        if (sysctl(mib, 4, NULL, &capacity, NULL, 0) != 0)
            return -1;
        if (capacity == 0 || capacity > 16 * 1024 * 1024) {
            errno = capacity == 0 ? ESRCH : EOVERFLOW;
            return -1;
        }
        unsigned char *buffer = malloc(capacity);
        if (!buffer)
            return -1;
        size_t used = capacity;
        int result = sysctl(mib, 4, buffer, &used, NULL, 0);
        if (result == 0 && used <= capacity) {
            *out = buffer;
            *length = used;
            return 0;
        }
        int error = result == 0 ? EOVERFLOW : errno;
        free(buffer);
        if (error != ENOMEM) {
            errno = error;
            return -1;
        }
    }
    errno = ENOMEM;
    return -1;
}

static int
record_size(const unsigned char *buffer, size_t remaining, size_t minimum) {
    int size;
    if (remaining >= sizeof(size)) {
        memcpy(&size, buffer, sizeof(size));
        if (size > 0 && (size_t)size >= minimum && (size_t)size <= remaining)
            return size;
    }
    errno = EPROTO;
    return -1;
}

static int
collect_processes(pid_t pid, int include_traced, struct process **list, size_t *count) {
    const int mib[4] = {CTL_KERN, KERN_PROC, pid ? KERN_PROC_PID : KERN_PROC_PROC, pid};
    unsigned char *buffer;
    size_t length;
    if (snapshot(mib, &buffer, &length) != 0)
        return -1;

    pid_t self = getpid(), parent = getppid();
    const size_t prefix = offsetof(struct kinfo_proc, ki_comm) + PROCESS_NAME_SIZE;
    struct process *entries = calloc(length / prefix + 1, sizeof(*entries));
    if (!entries) {
        free(buffer);
        return -1;
    }
    size_t used = 0;
    for (size_t offset = 0; offset < length;) {
        int size = record_size(buffer + offset, length - offset, prefix);
        if (size < 0) {
            free(entries);
            free(buffer);
            errno = EPROTO;
            return -1;
        }
        struct kinfo_proc info;
        memcpy(&info, buffer + offset, prefix);
        offset += (size_t)size;
        if (info.ki_pid <= 1 || info.ki_pid == self || info.ki_pid == parent ||
            (info.ki_flag & P_SYSTEM) != 0 || (!include_traced && (info.ki_flag & P_TRACED)) ||
            info.ki_stat == SZOMB ||
            info.ki_comm[0] == '\0' || !memchr(info.ki_comm, '\0', sizeof(info.ki_comm)))
            continue;
        if (pid != 0 && pid != info.ki_pid)
            continue;
        entries[used] = (struct process){.pid = info.ki_pid, .start = info.ki_start};
        memcpy(entries[used].name, info.ki_comm, sizeof(entries[used].name));
        used++;
    }
    free(buffer);
    *list = entries;
    *count = used;
    return 0;
}

int
process_list(struct process **list, size_t *count) {
    return collect_processes(0, 0, list, count);
}

static int
find_process(pid_t pid, int include_traced, struct process *target) {
    struct process *list;
    size_t count;
    if (pid <= 1 || collect_processes(pid, include_traced, &list, &count) != 0) {
        if (pid <= 1)
            errno = ESRCH;
        return -1;
    }
    if (count == 1)
        *target = list[0];
    free(list);
    if (count == 1)
        return 0;
    errno = ESRCH;
    return -1;
}

int
process_select(pid_t pid, struct process *target) {
    return find_process(pid, 0, target);
}

int
process_matches(const struct process *target) {
    struct process current;
    if (find_process(target->pid, 1, &current) != 0)
        return 0;
    return current.start.tv_sec == target->start.tv_sec && current.start.tv_usec == target->start.tv_usec &&
           strcmp(current.name, target->name) == 0;
}

static int
listens_on_orbit_port(pid_t pid) {
    const int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_FILEDESC, pid};
    unsigned char *buffer;
    size_t length;
    if (snapshot(mib, &buffer, &length) != 0)
        return 0;

    int found = 0;
    const size_t prefix = offsetof(struct kinfo_file, kf_sa_peer) + sizeof(struct sockaddr_in);
    for (size_t offset = 0; offset < length;) {
        int size = record_size(buffer + offset, length - offset, sizeof(int));
        if (size < 0)
            break;
        const unsigned char *record = buffer + offset;
        offset += (size_t)size;
        if ((size_t)size < prefix)
            continue;
        struct kinfo_file info;
        memcpy(&info, record, prefix);
        if (info.kf_fd < 0 || info.kf_type != KF_TYPE_SOCKET || info.kf_sock_domain != AF_INET ||
            info.kf_sock_type != SOCK_STREAM || info.kf_sock_protocol != IPPROTO_TCP)
            continue;
        struct sockaddr_in local, peer;
        memcpy(&local, &info.kf_sa_local, sizeof(local));
        memcpy(&peer, &info.kf_sa_peer, sizeof(peer));
        if (local.sin_family == AF_INET && local.sin_port == htons(ORBIT_PORT) &&
            (peer.sin_family == AF_UNSPEC || (peer.sin_family == AF_INET && peer.sin_port == 0))) {
            found = 1;
            break;
        }
    }
    free(buffer);
    return found;
}

static int
could_be_orbit(const char *name) {
    return !strcasecmp(name, "orbit_store.elf") || !strcasecmp(name, "orbit_runtime.elf") ||
           !strcasecmp(name, "payload.elf");
}

int
process_owns_orbit(const struct process *target, const atomic_bool *stop) {
    if (listens_on_orbit_port(target->pid))
        return 1;
    return could_be_orbit(target->name) &&
           trace_find_listener(target->pid, ORBIT_PORT, monotonic_ms() + 600, stop);
}

int
process_orbit(struct process *target, pid_t proxy_pid, const atomic_bool *stop) {
    if (!orbit_service_ready(1500)) {
        errno = ENETUNREACH;
        return -1;
    }
    struct process *list;
    size_t count;
    if (process_list(&list, &count) != 0)
        return -1;

    size_t listeners = 0;
    for (size_t index = 0; index < count; index++) {
        const struct process *entry = &list[index];
        if (entry->pid != proxy_pid && listens_on_orbit_port(entry->pid)) {
            *target = *entry;
            listeners++;
        }
    }
    if (listeners == 0) {
        const int64_t deadline = monotonic_ms() + 1800;
        for (size_t index = 0; index < count && !atomic_load(stop); index++) {
            const struct process *entry = &list[index];
            if (entry->pid != proxy_pid && could_be_orbit(entry->name) &&
                trace_find_listener(entry->pid, ORBIT_PORT, deadline, stop)) {
                *target = *entry;
                listeners++;
            }
        }
    }
    free(list);
    if (listeners != 1) {
        errno = listeners > 1 ? EEXIST : ENXIO;
        return -1;
    }
    if (!process_matches(target)) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}

int
process_tcp_socket(pid_t pid, int fd) {
    const int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_FILEDESC, pid};
    unsigned char *buffer;
    size_t length;
    if (snapshot(mib, &buffer, &length) != 0)
        return -1;

    int result = -1, error = EBADF;
    const size_t prefix = offsetof(struct kinfo_file, kf_sock_protocol) + sizeof(int);
    for (size_t offset = 0; offset < length;) {
        int size = record_size(buffer + offset, length - offset, prefix);
        if (size < 0) {
            error = errno;
            break;
        }
        struct kinfo_file info;
        memcpy(&info, buffer + offset, prefix);
        offset += (size_t)size;
        if (info.kf_fd != fd)
            continue;
        result = info.kf_type == KF_TYPE_SOCKET && info.kf_sock_domain == AF_INET &&
                 info.kf_sock_type == SOCK_STREAM && info.kf_sock_protocol == IPPROTO_TCP;
        break;
    }
    free(buffer);
    errno = error;
    return result;
}

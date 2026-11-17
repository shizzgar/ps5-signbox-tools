/* SPDX-License-Identifier: MIT */
#ifndef RELAY_PROCESS_H
#define RELAY_PROCESS_H

#include <stddef.h>
#include <stdatomic.h>
#include <sys/types.h>
#include <sys/time.h>

enum { PROCESS_NAME_SIZE = 20 };

struct process {
    pid_t pid;
    struct timeval start;
    char name[PROCESS_NAME_SIZE];
};

int process_select(pid_t pid, struct process *target);
int process_matches(const struct process *target);
int process_list(struct process **list, size_t *count);
int process_orbit(struct process *target, pid_t proxy_pid, const atomic_bool *stop);
int process_owns_orbit(const struct process *target, const atomic_bool *stop);
int process_tcp_socket(pid_t pid, int fd);

#endif

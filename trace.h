/* SPDX-License-Identifier: MIT */
#ifndef RELAY_TRACE_H
#define RELAY_TRACE_H

#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

struct orbit_config;
struct process;

// The SDK's kernel read/write pipe and temporary tracer credentials are process-wide.
extern pthread_mutex_t trace_kernel_access;

enum { RELAY_CHECK_CONNECTIONS = 3 };
enum { TRACE_WEBVIEW_RETRY = 2 };
#define TRACE_WAKE_SIGNAL SIGUSR1

typedef int (*connect_function)(int, const struct sockaddr *, socklen_t);
extern connect_function volatile webview_probe_connect;

int prepare_tracing(void);
int trace_process(pid_t pid, const struct process *target,
                  const struct sockaddr_in *check, int start_fd,
                  const atomic_bool *stop, atomic_bool *attached);
int trace_webview(pid_t pid, const struct process *target,
                  const struct sockaddr_in *check, int start_fd,
                  const atomic_bool *stop, atomic_int *armed, const struct orbit_config *config);
int trace_orbit(const struct process *target, const atomic_bool *stop, atomic_bool *attached,
                const struct orbit_config *config);
int trace_find_listener(pid_t pid, uint16_t port, int64_t deadline, const atomic_bool *stop);
long ps5_syscall(long number, long a, long b, long c, long d, long e, long f);
int relay_check(const atomic_bool *stop, int proxy_control);
int relay_webview_check(const atomic_bool *stop, int proxy_control);

#endif

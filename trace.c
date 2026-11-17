/* SPDX-License-Identifier: MIT */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <machine/psl.h>
#include <pthread.h>
#include <poll.h>
#include <ps5/kernel.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "diagnostics.h"
#include "orbit-image.h"
#include "orbit-relay.h"
#include "orbit-run.h"
#include "process.h"
#include "relay.h"
#include "report.h"
#include "trace.h"
#include "webview-imports.h"

enum { MAX_CONNECTIONS = 32, STOP_TIMEOUT_MS = 3500, SYS_RDUP = 0x25b };
static const uint64_t debugger_authid = UINT64_C(0x4800000000010003);
static sigset_t child_events;
pthread_mutex_t trace_kernel_access = PTHREAD_MUTEX_INITIALIZER;

struct job {
    pthread_t thread;
    int active;
    atomic_bool finished;
    unsigned id;
    int listener;
    struct sockaddr_in target;
    struct relay_counts counts;
    char label[32];
};

struct patch {
    lwpid_t thread;
    uintptr_t address;
    size_t size;
    struct sockaddr_in original;
    struct sockaddr_in rewritten;
};

struct debug_access {
    uintptr_t address;
    uint64_t authid;
    int error;
};

struct session {
    pid_t pid;
    const char *route_name;
    struct debug_access debug;
    int attached;
    int stopped;
    int resume_on_detach;
    int signal;
    const struct sockaddr_in *check;
    const atomic_bool *stop;
    const struct orbit_config *broker_config;
    unsigned sequence;
    unsigned bypass;
    unsigned bridged;
    unsigned restored_at_entry;
    unsigned connect_calls;
    unsigned redirected;
    unsigned broker_failures;
    uint64_t entry_stops;
    struct job jobs[MAX_CONNECTIONS];
    struct patch patches[MAX_CONNECTIONS];
};

static void
trace_error(const char *operation) {
    int error = errno;
    report_log("%s: %s (errno=%d)", operation, strerror(error), error);
    report_diag("trace %s errno=%d", operation, error);
    errno = error;
}

long
ps5_syscall(long number, long a, long b, long c, long d, long e, long f) {
    register long fourth __asm__("r10") = d;
    register long fifth __asm__("r8") = e;
    register long sixth __asm__("r9") = f;
    unsigned char carry;
    // Unlike the SDK syscall symbol, account for FreeBSD's carry flag.
    __asm__ volatile("syscall; setc %1"
                     : "+a"(number), "=qm"(carry), "+d"(c)
                     : "D"(a), "S"(b), "r"(fourth), "r"(fifth), "r"(sixth)
                     : "rcx", "r11", "cc", "memory");
    if (carry || (number < 0 && number >= -4095)) {
        errno = (int)(number < 0 ? -number : number);
        return -1;
    }
    return number;
}

static int
debug_init(struct debug_access *access) {
    pthread_mutex_lock(&trace_kernel_access);
    intptr_t credential = kernel_get_proc_ucred(getpid());
    int result = -1;
    if (credential != 0) {
        access->address = (uintptr_t)(credential + KERNEL_OFFSET_UCRED_CR_SCEAUTHID);
        if (kernel_copyout(access->address, &access->authid, sizeof(access->authid)) == 0 && access->authid)
            result = 0;
    }
    pthread_mutex_unlock(&trace_kernel_access);
    return result;
}

static int
debug_enter(struct debug_access *access) {
    pthread_mutex_lock(&trace_kernel_access);
    if (kernel_copyin(&debugger_authid, access->address, sizeof(debugger_authid)) != 0) {
        pthread_mutex_unlock(&trace_kernel_access);
        errno = EACCES;
        return -1;
    }
    return 0;
}

static void
debug_leave(struct debug_access *access) {
    int error = errno;
    if (kernel_copyin(&access->authid, access->address, sizeof(access->authid)) != 0) {
        access->error = 1;
        report_log("Could not restore tracer authid");
    }
    pthread_mutex_unlock(&trace_kernel_access);
    errno = error;
}

static long
debug_call(struct debug_access *access, long number, long a, long b, long c, long d) {
    if (debug_enter(access) != 0)
        return -1;
    long result = ps5_syscall(number, a, b, c, d, 0, 0);
    debug_leave(access);
    return result;
}

static int
trace(struct session *session, int request, pid_t pid, void *addr, int data) {
    return (int)debug_call(&session->debug, SYS_ptrace, request, pid, (long)addr, data);
}

static void
wake_wait(int signum) {
    (void)signum;
}

int
prepare_tracing(void) {
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR)
        return -1;
    struct sigaction wake = {.sa_handler = wake_wait};
    sigemptyset(&wake.sa_mask);
    if (sigaction(TRACE_WAKE_SIGNAL, &wake, NULL) != 0)
        return -1;
    sigset_t wake_signal;
    sigemptyset(&wake_signal);
    sigaddset(&wake_signal, TRACE_WAKE_SIGNAL);
    if (sigprocmask(SIG_UNBLOCK, &wake_signal, NULL) != 0)
        return -1;
    sigemptyset(&child_events);
    sigaddset(&child_events, SIGCHLD);
    return sigprocmask(SIG_BLOCK, &child_events, NULL);
}

static int
wait_event(struct session *session, int controlled, int64_t deadline) {
    const int blocking = controlled && deadline < 0;
    for (;;) {
        if (controlled && atomic_load(session->stop))
            return 0;
        int status;
        pid_t ready = waitpid(session->pid, &status, blocking ? 0 : WNOHANG);
        if (ready == session->pid) {
            if (WIFSTOPPED(status)) {
                session->stopped = 1;
                session->signal = WSTOPSIG(status);
                return 1;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                session->attached = 0;
                session->stopped = 0;
                report_log("Process %d exited (status=%#x)", (int)session->pid, (unsigned)status);
                return session->check && (!WIFEXITED(status) || WEXITSTATUS(status) != 0) ? -1 : 0;
            }
        } else if (ready < 0 && errno != EINTR) {
            if (errno == ECHILD || errno == ESRCH)
                session->attached = 0;
            trace_error("waitpid");
            return -1;
        }
        if (blocking)
            continue;
        if (deadline >= 0) {
            int64_t now = monotonic_ms();
            if (now < 0 || now >= deadline) {
                if (now >= 0)
                    errno = ETIMEDOUT;
                return -1;
            }
        }
        const struct timespec delay = {.tv_nsec = 5 * 1000 * 1000};
        if (sigtimedwait(&child_events, NULL, &delay) < 0 && errno != EAGAIN && errno != EINTR)
            nanosleep(&delay, NULL);
    }
}

static void *
forward_job(void *argument) {
    struct job *job = argument;
    int client = relay_accept(job->listener);
    int error = errno;
    close(job->listener);
    if (client < 0) {
        if (error != ECANCELED)
            report_log("Relay #%u: local connect failed (%s)", job->id, strerror(error));
    } else {
        int reply;
        int64_t dial_start = monotonic_ms();
        int upstream = relay_open(&job->target, &reply);
        error = errno;
        int64_t dial_end = monotonic_ms();
        int64_t socks_ms = dial_start >= 0 && dial_end >= dial_start ? dial_end - dial_start : -1;
        if (upstream < 0) {
            report_log("SOCKS5 FAIL #%u %s (reply=%d, %s)", job->id, job->label, reply, strerror(error));
            report_diag("SOCKS5 relay=%u reply=%d errno=%d socks_ms=%lld",
                        job->id, reply, error, (long long)socks_ms);
        } else {
            report_log("SOCKS5 OK #%u %s", job->id, job->label);
            int result = relay_copy(client, upstream, &job->counts);
            error = errno;
            report_log("Relay #%u %s sent=%llu received=%llu (%s)", job->id, job->label,
                       (unsigned long long)job->counts.sent, (unsigned long long)job->counts.received,
                       result == 0 ? "EOF" : strerror(error));
            report_diag("TCP relay=%u sent=%llu received=%llu errno=%d "
                        "socks_ms=%lld first_rx_ms=%lld rx_span_ms=%lld app_wait_ms=%lld",
                        job->id, (unsigned long long)job->counts.sent,
                        (unsigned long long)job->counts.received, result == 0 ? 0 : error,
                        (long long)socks_ms, (long long)job->counts.first_rx_ms,
                        (long long)job->counts.rx_span_ms, (long long)job->counts.app_wait_ms);
            close(upstream);
        }
        close(client);
    }
    atomic_store(&job->finished, 1);
    return NULL;
}

static void
join_jobs(struct session *session, int all) {
    for (size_t index = 0; index < MAX_CONNECTIONS; index++) {
        struct job *job = &session->jobs[index];
        if (job->active && (all || atomic_load(&job->finished))) {
            pthread_join(job->thread, NULL);
            if (job->counts.sent && job->counts.received)
                session->bridged++;
            job->active = 0;
        }
    }
}

static struct job *
job_slot(struct session *session) {
    join_jobs(session, 0);
    for (size_t index = 0; index < MAX_CONNECTIONS; index++) {
        if (!session->jobs[index].active)
            return &session->jobs[index];
    }
    errno = EMFILE;
    return NULL;
}

static struct job *
start_forward(struct session *session, const struct sockaddr_in *destination, struct sockaddr_in *local) {
    struct job *job = job_slot(session);
    if (!job)
        return NULL;
    int listener = relay_listen(local);
    if (listener < 0)
        return NULL;
    job->listener = listener;
    job->target = *destination;
    job->counts = (struct relay_counts){0};
    job->id = ++session->sequence;
    atomic_store(&job->finished, 0);
    char ip[INET_ADDRSTRLEN];
    const char *formatted = inet_ntop(AF_INET, &destination->sin_addr, ip, sizeof(ip));
    snprintf(job->label, sizeof(job->label), "%s:%u", formatted ? formatted : "?", ntohs(destination->sin_port));
    int error = pthread_create(&job->thread, NULL, forward_job, job);
    if (error != 0) {
        close(listener);
        report_log("Start relay: %s (errno=%d)", strerror(error), error);
        errno = error;
        return NULL;
    }
    job->active = 1;
    return job;
}

void *
orbit_relay_run(void *argument) {
    struct orbit_relay *relay = argument;
    struct session session = {0};
    while (!atomic_load(relay->stop) && !atomic_load(&relay->shutdown)) {
        struct pollfd ready = {.fd = relay->socket, .events = POLLIN};
        int available = poll(&ready, 1, 100);
        if (available <= 0) {
            if (available < 0 && errno != EINTR)
                break;
            continue;
        }
        if (!(ready.revents & POLLIN))
            break;
        struct sockaddr_in peer = {0};
        socklen_t length = sizeof(peer);
        struct orbit_request request;
        ssize_t bytes = recvfrom(relay->socket, &request, sizeof(request), MSG_DONTWAIT,
                                 (struct sockaddr *)&peer, &length);
        if (bytes != sizeof(request) || length != sizeof(peer) ||
            peer.sin_family != AF_INET || peer.sin_addr.s_addr != htonl(INADDR_LOOPBACK))
            continue;
        int webview = relay->allow_webview &&
                      !memcmp(request.token, relay->webview_token, sizeof(request.token));
        if (!webview && memcmp(request.token, relay->token, sizeof(request.token)))
            continue;
        uint16_t port = 0;
        if (request.target.sin_family == AF_INET && request.target.sin_port) {
            int allowed = public_ipv4(request.target.sin_addr);
            if (relay->probe_target) {
                allowed = request.target.sin_addr.s_addr == htonl(UINT32_C(0x7f000002)) &&
                          request.target.sin_port == relay->probe_target->sin_port;
                if (allowed)
                    request.target = *relay->probe_target;
            }
            if (allowed) {
                struct sockaddr_in local;
                struct job *job = start_forward(&session, &request.target, &local);
                const char *label = relay->probe_target ? "WebView check" : webview ? "WebView TCP" : "Orbit relay";
                if (job) {
                    port = local.sin_port;
                    report_log("%s #%u %s", label, job->id, job->label);
                    report_diag("%s relay=%u destination_port=%u", label, job->id, (unsigned)ntohs(request.target.sin_port));
                } else {
                    report_diag("%s relay reservation failed errno=%d jobs_limit=%d", label, errno, MAX_CONNECTIONS);
                }
            }
        }
        (void)sendto(relay->socket, &port, sizeof(port), MSG_DONTWAIT,
                     (struct sockaddr *)&peer, length);
    }
    relay_stop();
    join_jobs(&session, 1);
    relay->bridged = session.bridged;
    const char *label = relay->probe_target ? "WebView check" : relay->allow_webview ? "Orbit and WebView" : "Orbit TCP";
    report_log("%s connections: %u, relays with bytes both ways: %u", label, session.sequence, session.bridged);
    report_diag("%s connections=%u bidirectional=%u", label, session.sequence, session.bridged);
    return NULL;
}

static int
memory_transfer(struct session *session, lwpid_t thread, int operation, uintptr_t address,
                void *data, size_t length, size_t *transferred) {
    struct ptrace_io_desc io = {
        .piod_op = operation,
        .piod_offs = (void *)address,
        .piod_addr = data,
        .piod_len = length,
    };
    if (transferred)
        *transferred = 0;
    if (trace(session, PT_IO, thread, &io, 0) != 0)
        return -1;
    if (transferred)
        *transferred = io.piod_len;
    if (io.piod_len != length) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int
restore_patch(struct session *session, struct patch *patch) {
    if (!patch->address)
        return 0;
    if (patch->size != 0) {
        unsigned char current[sizeof(struct sockaddr_in)];
        if (memory_transfer(session, session->pid, PIOD_READ_D, patch->address, current,
                            patch->size, NULL) != 0)
            return -1;
        // Leave values written by the app after connect started in place.
        if (memcmp(current, &patch->rewritten, patch->size) == 0 &&
            memory_transfer(session, session->pid, PIOD_WRITE_D, patch->address,
                            &patch->original, patch->size, NULL) != 0)
            return -1;
    }
    patch->address = 0;
    return 0;
}

static int
socket_is_tcp(struct session *session, int fd) {
    int result = process_tcp_socket(session->pid, fd);
    if (result >= 0)
        return result;
    int original_error = errno;
    int copy = (int)debug_call(&session->debug, SYS_RDUP, session->pid, fd, 0, 0);
    if (copy < 0) {
        int error = errno;
        report_log("Cannot classify fd %d: filedesc errno=%d, rdup errno=%d", fd, original_error, error);
        return -1;
    }
    int type = 0;
    socklen_t length = sizeof(type);
    result = getsockopt(copy, SOL_SOCKET, SO_TYPE, &type, &length);
    int error = errno;
    close(copy);
    errno = error;
    return result == 0 ? type == SOCK_STREAM : -1;
}

int
trace_find_listener(pid_t pid, uint16_t port, int64_t deadline, const atomic_bool *stop) {
    struct debug_access access = {0};
    if (debug_init(&access) != 0)
        return 0;
    // The loader opens the HTTP listener near startup. Probe the first descriptors
    // only when Sony's descriptor snapshot does not identify that listener.
    for (int remote = 0; remote < 96 && !atomic_load(stop) && !access.error; remote++) {
        int64_t now = monotonic_ms();
        if (now < 0 || now >= deadline)
            break;
        int fd = (int)debug_call(&access, SYS_RDUP, pid, remote, 0, 0);
        if (fd < 0) {
            if (errno == EBADF || errno == EINVAL)
                continue;
            break;
        }
        struct sockaddr_in address;
        socklen_t size = sizeof(address);
        int listening = 0;
        socklen_t listening_size = sizeof(listening);
        int matches = getsockname(fd, (struct sockaddr *)&address, &size) == 0 &&
                      size == sizeof(address) && address.sin_family == AF_INET &&
                      address.sin_port == htons(port) &&
                      getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &listening, &listening_size) == 0 &&
                      listening;
        close(fd);
        if (matches && !access.error)
            return 1;
    }
    return 0;
}

static int
rewrite_connect(struct session *session, lwpid_t thread, const struct reg *regs) {
    int64_t code = regs->r_rax, fd = regs->r_rdi;
    uintptr_t addr = (uintptr_t)regs->r_rsi;
    uint64_t length = (uint64_t)regs->r_rdx;
    if (code == SYS_syscall || code == SYS___syscall) {
        code = regs->r_rdi;
        fd = regs->r_rsi;
        addr = (uintptr_t)regs->r_rdx;
        length = (uint64_t)regs->r_r10;
    }
    if (code != SYS_connect || fd < 0 || fd > INT_MAX || !addr)
        return 0;
    session->connect_calls++;
    if (length != sizeof(struct sockaddr_in)) {
        if (length == sizeof(struct sockaddr_in6) && session->bypass++ == 0)
            report_log("Observed an IPv6 connect; this session intercepts IPv4 TCP");
        return 0;
    }
    struct patch *patch = NULL;
    for (size_t index = 0; index < MAX_CONNECTIONS; index++) {
        struct patch *entry = &session->patches[index];
        if (entry->address &&
            (entry->thread == thread || (addr >= entry->address ? addr - entry->address
                                                              : entry->address - addr) < length)) {
            report_log("Connect sockaddr overlap: pid=%d tid=%d fd=%d owner_tid=%d. Detaching.",
                       (int)session->pid, (int)thread, (int)fd, (int)entry->thread);
            return -1;
        }
        if (!entry->address && !patch)
            patch = entry;
    }

    struct sockaddr_in original;
    if (memory_transfer(session, thread, PIOD_READ_D, addr, &original, sizeof(original), NULL) != 0) {
        trace_error("Read connect sockaddr");
        return 0;
    }
    if (original.sin_family != AF_INET ||
        (original.sin_len != 0 && original.sin_len != sizeof(original)) || !original.sin_port)
        return 0;
    if (session->check) {
        if (original.sin_addr.s_addr != session->check->sin_addr.s_addr ||
            original.sin_port != session->check->sin_port)
            return 0;
    } else if (!public_ipv4(original.sin_addr)) {
        return 0;
    }
    int tcp = socket_is_tcp(session, (int)fd);
    if (tcp < 0)
        report_log("Skipped unclassified IPv4 socket fd=%d", (int)fd);
    if (tcp <= 0)
        return 0;

    if (!patch) {
        report_log("Cannot reserve TCP relay for fd=%d", (int)fd);
        return 0;
    }
    struct sockaddr_in local = {0};
    struct job *job = NULL;
    int reserved = 1;
    if (session->broker_config) {
        if (orbit_reserve_relay(session->broker_config, &original, &local) != 0) {
            if (atomic_load(session->stop))
                return 0;
            trace_error("Reserve WebView TCP relay");
            // Fail this connect locally if no relay is available for a selected destination.
            local.sin_family = AF_INET;
            local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            local.sin_port = 0;
            session->broker_failures++;
            reserved = 0;
        }
    } else {
        job = start_forward(session, &original, &local);
        if (!job) {
            report_log("Cannot reserve TCP relay for fd=%d", (int)fd);
            return 0;
        }
    }

    local.sin_len = original.sin_len;
    memcpy(local.sin_zero, original.sin_zero, sizeof(local.sin_zero));
    *patch = (struct patch){.thread = thread, .address = addr, .original = original, .rewritten = local};
    if (memory_transfer(session, thread, PIOD_WRITE_D, addr, &local, sizeof(local), &patch->size) != 0) {
        trace_error("Rewrite connect sockaddr");
        return -1;
    }
    session->redirected += reserved;
    if (job) {
        report_log("Redirect #%u pid=%d tid=%d fd=%d %s", job->id, (int)session->pid,
                   (int)thread, (int)fd, job->label);
    } else if (reserved) {
        report_diag("WebView syscall redirect PID=%d TID=%d fd=%d port=%u", (int)session->pid,
                    (int)thread, (int)fd, (unsigned)ntohs(original.sin_port));
    }
    return 0;
}

static int
handle_trap(struct session *session) {
    struct ptrace_lwpinfo info = {0};
    struct reg regs = {0};
    const char *request = "PT_LWPINFO";
    if (debug_enter(&session->debug) != 0)
        return -1;
    int result = (int)ps5_syscall(SYS_ptrace, PT_LWPINFO, session->pid, (long)&info,
                                 offsetof(struct ptrace_lwpinfo, pl_sigmask), 0, 0);
    if (result == 0 && info.pl_lwpid > 0 && (info.pl_flags & PL_FLAG_SCE) &&
        !(info.pl_flags & PL_FLAG_EXEC)) {
        request = "PT_GETREGS";
        result = (int)ps5_syscall(SYS_ptrace, PT_GETREGS, info.pl_lwpid, (long)&regs, 0, 0, 0);
    }
    debug_leave(&session->debug);
    if (result != 0) {
        trace_error(request);
        return -1;
    }
    if (!(info.pl_flags & (PL_FLAG_SCE | PL_FLAG_SCX | PL_FLAG_EXEC)))
        return 0;
    session->signal = 0;
    if (info.pl_flags & PL_FLAG_EXEC) {
        report_log("Traced process changed its executable");
        memset(session->patches, 0, sizeof(session->patches));
        return -1;
    }
    if (info.pl_lwpid <= 0) {
        errno = EPROTO;
        trace_error("PT_LWPINFO thread ID");
        return -1;
    }
    // A new syscall entry in this thread also puts the previous connect behind us.
    for (size_t index = 0; index < MAX_CONNECTIONS; index++) {
        struct patch *patch = &session->patches[index];
        if (!patch->address || patch->thread != info.pl_lwpid)
            continue;
        if (restore_patch(session, patch) != 0) {
            trace_error("Restore connect sockaddr");
            return -1;
        }
        if (!(info.pl_flags & PL_FLAG_SCX)) {
            if (session->restored_at_entry++ == 0)
                report_log("Restored connect sockaddr at next syscall entry (tid=%d)",
                           (int)info.pl_lwpid);
        }
    }
    if (!(info.pl_flags & PL_FLAG_SCE))
        return 0;
    session->entry_stops++;
    return rewrite_connect(session, info.pl_lwpid, &regs);
}

static int
trace_connect_calls(struct session *session, int64_t deadline) {
    while (!session->debug.error) {
        if (atomic_load(session->stop))
            return session->check ? -1 : 0;
        if (session->check && monotonic_ms() >= deadline) {
            report_log("Local relay check timed out");
            return -1;
        }
        if (trace(session, PT_TO_SCE, session->pid, (void *)1, session->signal) != 0) {
            trace_error("PT_TO_SCE");
            return -1;
        }
        session->stopped = 0;
        int event = wait_event(session, 1, deadline);
        if (event <= 0) {
            if (event < 0 && session->attached)
                trace_error("Wait for syscall stop");
            return event;
        }
        if (session->signal == SIGTRAP && handle_trap(session) != 0)
            return -1;
    }
    return -1;
}

static int
stop_for_detach(struct session *session) {
    if (!session->attached || session->stopped)
        return 0;
    int64_t now = monotonic_ms();
    int sent_stop = kill(session->pid, SIGSTOP) == 0;
    if (sent_stop)
        session->resume_on_detach = 1;
    if (wait_event(session, 0, now < 0 ? -1 : now + STOP_TIMEOUT_MS) <= 0 && session->attached) {
        trace_error("Wait for detach stop");
        report_log("Waiting for PID %d to reach a safe stop", (int)session->pid);
        while (wait_event(session, 0, -1) < 0 && session->attached) {
            const struct timespec delay = {.tv_nsec = 50 * 1000 * 1000};
            nanosleep(&delay, NULL);
        }
    }
    return sent_stop;
}

static int
end_trace(struct session *session) {
    int sent_stop = stop_for_detach(session);
    if (!session->attached)
        return 0;
    int result = 0;
    for (size_t index = 0; index < MAX_CONNECTIONS; index++) {
        if (restore_patch(session, &session->patches[index]) != 0) {
            trace_error("Restore connect sockaddr before detach");
            result = -1;
        }
    }
    int deliver = sent_stop && session->signal == SIGSTOP ? 0 : session->signal;
    if (deliver == SIGTRAP) {
        struct ptrace_lwpinfo info = {0};
        if (trace(session, PT_LWPINFO, session->pid, &info, offsetof(struct ptrace_lwpinfo, pl_sigmask)) != 0 ||
            (info.pl_flags & (PL_FLAG_SCE | PL_FLAG_SCX | PL_FLAG_EXEC)))
            deliver = 0;

    }
    while (trace(session, PT_DETACH, session->pid, (void *)1, deliver) != 0) {
        int error = errno;
        trace_error("PT_DETACH");
        if (error == ESRCH || error == ECHILD) {
            session->attached = 0;
            return 0;
        }
        deliver = 0;
        const struct timespec delay = {.tv_sec = 1};
        nanosleep(&delay, NULL);
    }
    session->attached = 0;
    if (session->resume_on_detach)
        kill(session->pid, SIGCONT);
    session->resume_on_detach = 0;
    report_log("Detached from PID %d", (int)session->pid);
    return result;
}

enum { WEBVIEW_THREADS = 128, WEBVIEW_MAP_SIZE = ORBIT_HOOK_PAGE * 2,
       WEBVIEW_RESERVE_SIZE = WEBVIEW_MAP_SIZE + ORBIT_HOOK_PAGE };
extern const unsigned char orbit_connect_image[], orbit_connect_image_end[];
extern const unsigned char webview_connect_image[], webview_connect_image_end[];
__asm__(".section .rodata\n"
        ".balign 16\n"
        ".global webview_connect_image\n"
        "webview_connect_image:\n"
        ".incbin \"webview-connect.bin\"\n"
        ".global webview_connect_image_end\n"
        "webview_connect_image_end:\n"
        ".text\n");

struct webview_mapping {
    uintptr_t allocation;
    uintptr_t code;
};

struct webview_remote {
    lwpid_t thread;
    uintptr_t instruction;
    unsigned char after_syscall[6];
    int first_call;
    lwpid_t suspended[WEBVIEW_THREADS];
    size_t suspended_count;
    int restore_failed;
};

static int
user_range(uintptr_t address, size_t size) {
    const uintptr_t end = UINT64_C(0x0000800000000000);
    // The PS5 can place an anonymous allocation on the first nonzero 16 KiB page.
    return address >= ORBIT_HOOK_PAGE && address < end && size <= end - address;
}

enum { PROCESS_VM_LIMIT = 2048 };

// These offsets match the VM tree traversal in ps5-payload-sdk v0.45.
extern unsigned long KERNEL_OFFSET_VMSPACE_P_ROOT;
struct kernel_vm_entry {
    uint64_t previous, next, left, right, start, end;
    unsigned char reserved[0x34];
    unsigned char protection;
};
_Static_assert(offsetof(struct kernel_vm_entry, protection) == 0x64, "unexpected PS5 vm_map_entry layout");

static int
ptrace_regions(struct session *session, struct orbit_region *regions) {
    struct ptrace_vm_entry entry = {0};
    int count = 0, timestamp = 0;
    for (unsigned i = 0; i < PROCESS_VM_LIMIT; i++) {
        int previous = entry.pve_entry;
        if (trace(session, PT_VM_ENTRY, session->pid, &entry, 0) != 0)
            return errno == ENOENT && i ? count : -1;
        if (entry.pve_entry <= previous || (i && timestamp != entry.pve_timestamp)) {
            errno = EAGAIN;
            return -1;
        }
        timestamp = entry.pve_timestamp;
        if (entry.pve_start <= entry.pve_end && entry.pve_end < UINTPTR_MAX &&
            user_range(entry.pve_start, entry.pve_end - entry.pve_start + 1)) {
            regions[count++] = (struct orbit_region){entry.pve_start, entry.pve_end + 1, entry.pve_prot};
        }
    }
    errno = EOVERFLOW;
    return -1;
}

static int
kernel_regions(pid_t pid, struct orbit_region *regions) {
    const uint64_t kernel_start = UINT64_C(0xffff800000000000);
    uint64_t pending[PROCESS_VM_LIMIT];
    uint64_t vmspace = 0;
    int count = -1;
    pthread_mutex_lock(&trace_kernel_access);
    intptr_t process = kernel_get_proc(pid);
    if (!process || !KERNEL_OFFSET_VMSPACE_P_ROOT ||
        kernel_copyout(process + KERNEL_OFFSET_PROC_P_VMSPACE, &vmspace, sizeof(vmspace)) != 0 ||
        vmspace < kernel_start ||
        kernel_copyout((intptr_t)(vmspace + KERNEL_OFFSET_VMSPACE_P_ROOT), pending, sizeof(*pending)) != 0 ||
        !pending[0]) {
        errno = EIO;
        goto done;
    }
    size_t queued = 1;
    int used = 0;
    for (unsigned i = 0; queued && i < PROCESS_VM_LIMIT; i++) {
        uint64_t address = pending[--queued];
        struct kernel_vm_entry entry;
        if (address < kernel_start || kernel_copyout((intptr_t)address, &entry, sizeof(entry)) != 0 ||
            entry.start >= entry.end || entry.left == address || entry.right == address) {
            errno = EPROTO;
            goto done;
        }
        if (user_range(entry.start, entry.end - entry.start))
            regions[used++] = (struct orbit_region){entry.start, entry.end, entry.protection};
        if (queued + (entry.left != 0) + (entry.right != 0) > PROCESS_VM_LIMIT) {
            errno = EOVERFLOW;
            goto done;
        }
        if (entry.left)
            pending[queued++] = entry.left;
        if (entry.right)
            pending[queued++] = entry.right;
    }
    if (queued) {
        errno = EOVERFLOW;
        goto done;
    }
    count = used;
done:
    pthread_mutex_unlock(&trace_kernel_access);
    return count;
}

static int
snapshot_regions(struct session *session, struct orbit_region *regions, const char **provider) {
    *provider = "ptrace";
    int count = ptrace_regions(session, regions);
    if (count <= 0) {
        report_diag("%s PID=%d PT_VM_ENTRY failed result=%d errno=%d",
                    session->route_name, (int)session->pid, count, errno);
        *provider = "SDK VM tree";
        count = kernel_regions(session->pid, regions);
    }
    if (count == 0)
        errno = ENOENT;
    return count;
}

static int
read_orbit_memory(void *argument, uintptr_t address, void *buffer, size_t size) {
    struct session *session = argument;
    return memory_transfer(session, session->pid, PIOD_READ_I, address, buffer, size, NULL);
}

static int
find_orbit_import(struct session *session, const unsigned char *source, size_t source_size,
                  struct webview_imports *imports) {
    if (webview_find_exports(session->pid, imports) != 0)
        return -1;
    struct orbit_region *regions = calloc(PROCESS_VM_LIMIT, sizeof(*regions));
    if (!regions)
        return -1;
    const char *provider;
    int count = snapshot_regions(session, regions, &provider);
    uintptr_t base = 0, slot = 0;
    int result = count > 0 ? orbit_find_live_import(source, source_size, regions, (size_t)count,
                                                    read_orbit_memory, session, &base, &slot) : -1;
    int detail = errno;
    free(regions);
    report_diag("Orbit PID=%d live image maps=%d source=%s base=%#lx connect_slot=%#lx result=%d errno=%d",
                (int)session->pid, count, provider, (unsigned long)base, (unsigned long)slot, result,
                result == 0 ? 0 : detail);
    if (result == 0) {
        imports->slots[0].address = slot;
        imports->count = 1;
    }
    errno = detail;
    return result;
}

static int
find_webview_imports(struct session *session, struct webview_imports *imports) {
    if (webview_find_imports(session->pid, imports) != 0)
        return -1;
    struct orbit_region *regions = calloc(PROCESS_VM_LIMIT, sizeof(*regions));
    if (!regions)
        return -1;
    const char *provider;
    int count = snapshot_regions(session, regions, &provider);
    int detail = errno;
    size_t readable = 0, usable = 0;
    unsigned modules = 0;
    for (size_t i = 0; i < imports->count && count > 0; i++) {
        struct webview_import slot = imports->slots[i];
        for (int j = 0; j < count; j++) {
            const struct orbit_region *region = &regions[j];
            if ((region->protection & (PROT_READ | PROT_EXEC)) != PROT_READ ||
                slot.address < region->start || slot.address >= region->end ||
                sizeof(uintptr_t) > region->end - slot.address) {
                continue;
            }
            readable++;
            if (memory_transfer(session, session->pid, PIOD_READ_D, slot.address,
                                &slot.original, sizeof(slot.original), NULL) == 0 &&
                slot.original &&
                (slot.original == imports->exports[0] ||
                 (imports->export_count > 1 && slot.original == imports->exports[1]))) {
                imports->slots[usable++] = slot;
                modules |= slot.module;
            }
            break;
        }
    }
    free(regions);
    report_diag("WebView PID=%d import candidates=%zu readable_data=%zu bound=%zu module_mask=%#x maps=%d source=%s",
                (int)session->pid, imports->count, readable, usable, modules, count, provider);
    imports->count = usable;
    if (count <= 0 || modules != WEBVIEW_IMPORT_REQUIRED) {
        errno = count <= 0 ? detail : EAGAIN;
        return -1;
    }
    return 0;
}

static int
webview_lwp(struct session *session, struct ptrace_lwpinfo *info) {
    return trace(session, PT_LWPINFO, session->pid, info, offsetof(struct ptrace_lwpinfo, pl_sigmask));
}

static int
read_webview_stub(struct session *session, uintptr_t address, unsigned char *bytes, size_t size) {
    if (memory_transfer(session, session->pid, PIOD_READ_I, address, bytes, size, NULL) == 0)
        return 0;
    int ptrace_error = errno;
    if (session->debug.error || !session->attached || !session->stopped ||
        (ptrace_error != EFAULT && ptrace_error != EACCES && ptrace_error != EIO))
        return -1;

    // A Sony system module's executable pages may be unreadable through PT_IO.
    // Split the SDK reads at hardware page boundaries for its page-table fallback.
    enum { HARDWARE_PAGE_SIZE = 4096 };
    memset(bytes, 0, size);
    size_t copied = 0;
    pthread_mutex_lock(&trace_kernel_access);
    while (copied < size) {
        uintptr_t cursor = address + copied;
        size_t amount = HARDWARE_PAGE_SIZE - cursor % HARDWARE_PAGE_SIZE;
        if (amount > size - copied)
            amount = size - copied;
        if (kernel_proc_copyout(session->pid, (intptr_t)cursor, bytes + copied, amount) != 0)
            break;
        copied += amount;
    }
    pthread_mutex_unlock(&trace_kernel_access);
    report_diag("%s PID=%d getpid text source=SDK address=%#lx bytes=%zu/%zu ptrace_errno=%d",
                session->route_name, (int)session->pid, (unsigned long)address, copied, size, ptrace_error);
    errno = ptrace_error;
    return copied == size ? 0 : -1;
}

static int
webview_remote_init(struct session *session, struct webview_remote *remote, uintptr_t getpid_entry) {
    struct ptrace_lwpinfo info = {0};
    unsigned char instructions[24];
    if (!user_range(getpid_entry, sizeof(instructions))) {
        errno = ENOEXEC;
        return -1;
    }
    if (read_webview_stub(session, getpid_entry, instructions, sizeof(instructions)) != 0) {
        trace_error("Read WebView getpid instructions");
        return -1;
    }
    if (webview_lwp(session, &info) != 0) {
        trace_error("Read WebView attach stop");
        return -1;
    }
    // The libkernel getpid stub used by elfldr has its syscall at +0xa.
    size_t offset = 0xa;
    if (instructions[offset] != 0x0f || instructions[offset + 1] != 0x05) {
        for (offset = 0; offset + 2 + sizeof(remote->after_syscall) <= sizeof(instructions); offset++) {
            if (instructions[offset] == 0x0f && instructions[offset + 1] == 0x05)
                break;
        }
    }
    if (offset + 2 + sizeof(remote->after_syscall) > sizeof(instructions) || info.pl_lwpid <= 0) {
        errno = ENOEXEC;
        trace_error("Find WebView syscall instruction and stopped thread");
        return -1;
    }
    remote->instruction = getpid_entry + offset;
    memcpy(remote->after_syscall, instructions + offset + 2, sizeof(remote->after_syscall));
    remote->first_call = 1;

    remote->thread = info.pl_lwpid;
    int count = trace(session, PT_GETNUMLWPS, session->pid, NULL, 0);
    report_diag("WebView PID=%d thread=%d threads=%d getpid=%#lx syscall_offset=%zu next=%02x%02x",
                (int)session->pid, (int)remote->thread, count, (unsigned long)getpid_entry, offset,
                (unsigned)remote->after_syscall[0], (unsigned)remote->after_syscall[1]);
    if (count < 0)
        return -1;
    if (count == 1)
        return 0;
    if (count < 1 || count > WEBVIEW_THREADS) {
        errno = E2BIG;
        return -1;
    }
    lwpid_t threads[WEBVIEW_THREADS] = {0};
    int listed = trace(session, PT_GETLWPLIST, session->pid, threads, count);
    if (listed < 0)
        return -1;
    if (listed != 0 && listed != count) {
        errno = EAGAIN;
        return -1;
    }
    int have_runner = 0;
    for (int i = 0; i < count; i++) {
        if (threads[i] <= 0) {
            errno = EPROTO;
            return -1;
        }
        if (threads[i] == remote->thread) {
            have_runner = 1;
            continue;
        }
        if (trace(session, PT_SUSPEND, threads[i], NULL, 0) != 0)
            return -1;
        remote->suspended[remote->suspended_count++] = threads[i];
    }
    if (!have_runner) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}

static void
webview_remote_done(struct session *session, struct webview_remote *remote) {
    if (session->attached && session->stopped) {
        for (size_t i = 0; i < remote->suspended_count; i++) {
            if (trace(session, PT_RESUME, remote->suspended[i], NULL, 0) != 0 && errno != ESRCH) {
                trace_error("Resume WebView thread");
                remote->restore_failed = 1;
            }
        }
    }
}

static int
webview_step_completed(struct session *session, const struct webview_remote *remote,
                       const struct reg *saved, const struct reg *after) {
    uintptr_t syscall_end = remote->instruction + 2, ip = (uintptr_t)after->r_rip;
    const unsigned char *next = remote->after_syscall;
    if (next[0] == 0xc3 && (uintptr_t)after->r_rsp == (uintptr_t)saved->r_rsp + sizeof(uintptr_t)) {
        uintptr_t target = 0;
        return memory_transfer(session, remote->thread, PIOD_READ_D, (uintptr_t)saved->r_rsp,
                               &target, sizeof(target), NULL) == 0 && ip == target && user_range(ip, 1);
    }
    if (after->r_rsp != saved->r_rsp)
        return 0;
    if (ip == syscall_end)
        return 1;
    // A single step can also complete the stub's carry branch immediately after syscall.
    if (next[0] == 0x72)
        return ip == syscall_end + 2 + ((after->r_rflags & PSL_C) ? (int8_t)next[1] : 0);
    if (next[0] == 0x0f && next[1] == 0x82) {
        int32_t displacement;
        memcpy(&displacement, next + 2, sizeof(displacement));
        return ip == syscall_end + 6 + ((after->r_rflags & PSL_C) ? displacement : 0);
    }
    return 0;
}

static long
webview_syscall(struct session *session, struct webview_remote *remote, long number,
                long a, long b, long c, long d, long e, long f) {
    struct reg saved = {0};
    if (trace(session, PT_GETREGS, remote->thread, &saved, 0) != 0)
        return -1;
    struct reg call = saved;
    call.r_rip = remote->instruction;
    call.r_rax = number;
    call.r_rdi = a;
    call.r_rsi = b;
    call.r_rdx = c;
    call.r_r10 = d;
    call.r_r8 = e;
    call.r_r9 = f;
    call.r_rflags &= ~(PSL_T | PSL_RF);
    long result = -1;
    int64_t now = monotonic_ms();
    if (now < 0)
        return -1;
    int attach_stop = remote->first_call;
    remote->first_call = 0;
    int stepped = 0, request = PT_STEP;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (trace(session, PT_SETREGS, remote->thread, &call, 0) != 0)
            break;
        if (trace(session, request, remote->thread, (void *)1, 0) != 0) {
            if (request == PT_STEP && (errno == EINVAL || errno == EOPNOTSUPP || errno == ENOSYS)) {
                report_log("WebView syscall %ld: PT_STEP errno=%d, trying syscall-exit tracing", number, errno);
                request = PT_TO_SCX;
                continue;
            }
            trace_error("Resume WebView syscall thread");
            break;
        }
        stepped |= request == PT_STEP;
        session->stopped = 0;
        if (wait_event(session, 0, now + 2000) != 1) {
            if (!session->attached)
                errno = ESRCH;
            break;
        }
        struct ptrace_lwpinfo info = {0};
        struct reg after = {0};
        if (webview_lwp(session, &info) != 0 ||
            trace(session, PT_GETREGS, remote->thread, &after, 0) != 0)
            break;
        uintptr_t ip = (uintptr_t)after.r_rip;
        report_diag("WebView PID=%d syscall=%ld arg0=%#lx arg1=%#lx req=%d signal=%d tid=%d flags=%#x rip=%#lx rax=%#lx rflags=%#lx",
                    (int)session->pid, number, (unsigned long)a, (unsigned long)b, request, session->signal,
                    (int)info.pl_lwpid, info.pl_flags, (unsigned long)ip, (unsigned long)after.r_rax,
                    (unsigned long)after.r_rflags);
        if (info.pl_lwpid != remote->thread || (info.pl_flags & PL_FLAG_EXEC)) {
            report_log("WebView syscall %ld: unexpected LWP %d (expected %d), flags=%#x, signal=%d",
                       number, (int)info.pl_lwpid, (int)remote->thread, info.pl_flags, session->signal);
            errno = EPROTO;
            break;
        }
        if (session->signal == SIGSTOP && attach_stop && ip == remote->instruction) {
            report_log("WebView syscall %ld: resuming the attach stop before executing syscall", number);
            attach_stop = 0;
            session->signal = 0;
            session->resume_on_detach = 1;
            continue;
        }
        if (session->signal != SIGTRAP || (request == PT_TO_SCX && !(info.pl_flags & PL_FLAG_SCX))) {
            report_log("WebView syscall %ld: stopped with signal=%d at %#lx (syscall %#lx), flags=%#x",
                       number, session->signal, (unsigned long)ip, (unsigned long)remote->instruction, info.pl_flags);
            // A synchronous fault at the injected instruction belongs to this operation.
            if ((ip == remote->instruction || ip == remote->instruction + 2) &&
                (session->signal == SIGSYS || session->signal == SIGILL || session->signal == SIGSEGV ||
                 session->signal == SIGBUS))
                session->signal = 0;
            errno = EINTR;
            break;
        }
        session->signal = 0;
        if (ip == remote->instruction) {
            errno = EAGAIN;
            continue;
        }
        if (!webview_step_completed(session, remote, &saved, &after)) {
            report_log("WebView syscall %ld: unexpected instruction pointer %#lx (syscall %#lx), flags=%#x",
                       number, (unsigned long)ip, (unsigned long)remote->instruction, info.pl_flags);
            errno = EPROTO;
            break;
        }
        if (after.r_rflags & PSL_C)
            errno = after.r_rax > 0 && after.r_rax <= 4095 ? (int)after.r_rax : EIO;
        else
            result = after.r_rax;
        break;
    }
    int detail = errno;
    int sent_stop = session->stopped ? 0 : stop_for_detach(session);
    if (session->attached && session->stopped) {
        if (sent_stop && session->signal == SIGSTOP)
            session->signal = 0;
        if (stepped && trace(session, PT_CLEARSTEP, remote->thread, NULL, 0) != 0 && errno != ESRCH)
            trace_error("Clear WebView single step");
        if (trace(session, PT_SETREGS, remote->thread, &saved, 0) != 0 &&
            trace(session, PT_SETREGS, remote->thread, &saved, 0) != 0) {
            trace_error("Restore WebView registers");
            remote->restore_failed = 1;
            return -1;
        }
    }
    errno = detail ? detail : EIO;
    return result;
}

static uintptr_t
webview_map_shim(struct session *session, struct webview_remote *remote,
                 const struct orbit_config *config, const struct webview_socket_api *socket_api,
                 uintptr_t original, struct webview_mapping *mapping) {
    const unsigned char *image = socket_api ? webview_connect_image : orbit_connect_image;
    const unsigned char *image_end = socket_api ? webview_connect_image_end : orbit_connect_image_end;
    struct webview_hook_config active = {.route = *config}, readback = {0};
    size_t config_size = socket_api ? sizeof(active) : sizeof(active.route);
    size_t image_size = (size_t)(image_end - image);
    if (image_size != ORBIT_HOOK_PAGE + config_size) {
        report_diag("WebView image_size=%zu expected=%zu", image_size, ORBIT_HOOK_PAGE + config_size);
        errno = ENOEXEC;
        return 0;
    }
    // An mmap base may have a smaller alignment than the shim's code/data boundary.
    long mapped = webview_syscall(session, remote, SYS_mmap, 0, WEBVIEW_RESERVE_SIZE,
                                 PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    report_diag("%s PID=%d mmap result=%#lx bytes=%d errno=%d", session->route_name, (int)session->pid,
                (unsigned long)mapped, WEBVIEW_RESERVE_SIZE, mapped == -1 ? errno : 0);
    if (mapped == -1)
        return 0;
    uintptr_t allocation = (uintptr_t)mapped;
    if (!user_range(allocation, WEBVIEW_RESERVE_SIZE) || allocation % 0x1000) {
        report_diag("%s PID=%d mmap returned an invalid user address", session->route_name, (int)session->pid);
        errno = EPROTO;
        return 0;
    }
    uintptr_t address = (allocation + ORBIT_HOOK_PAGE - 1) & ~(uintptr_t)(ORBIT_HOOK_PAGE - 1);
    *mapping = (struct webview_mapping){.allocation = allocation, .code = address};
    report_diag("%s PID=%d mapping base=%#lx code=%#lx offset=%lu data=%#lx image_bytes=%zu",
                session->route_name, (int)session->pid, (unsigned long)allocation, (unsigned long)address,
                (unsigned long)(address - allocation), (unsigned long)(address + ORBIT_HOOK_PAGE), image_size);
    active.route.connect_function = original;
    if (socket_api)
        active.api = *socket_api;
    uintptr_t data = address + ORBIT_HOOK_PAGE;
    unsigned char verified[ORBIT_HOOK_PAGE];
    if (memory_transfer(session, session->pid, PIOD_WRITE_D, address,
                        (void *)image, ORBIT_HOOK_PAGE, NULL) != 0 ||
        memory_transfer(session, session->pid, PIOD_WRITE_D, data, &active, config_size, NULL) != 0) {
        trace_error("Write WebView shim code and data");
        return 0;
    }
    if (memory_transfer(session, session->pid, PIOD_READ_D, address,
                        verified, sizeof(verified), NULL) != 0 ||
        memory_transfer(session, session->pid, PIOD_READ_D, data, &readback, config_size, NULL) != 0) {
        trace_error("Read back WebView shim code and data");
        return 0;
    }
    if (memcmp(verified, image, sizeof(verified)) || memcmp(&active, &readback, config_size)) {
        report_diag("WebView PID=%d shim readback did not match", (int)session->pid);
        errno = EIO;
        return 0;
    }
    if (webview_syscall(session, remote, SYS_mprotect, (long)address, ORBIT_HOOK_PAGE,
                        PROT_READ | PROT_EXEC, 0, 0, 0) == 0)
        return address;
    report_diag("WebView PID=%d mprotect RX failed errno=%d", (int)session->pid, errno);
    if (errno != EACCES && errno != EPERM)
        return 0;
    // Split the shared mapping before the SDK changes the whole code entry.
    if (webview_syscall(session, remote, SYS_mprotect, (long)address, ORBIT_HOOK_PAGE,
                        PROT_READ, 0, 0, 0) != 0)
        return 0;
    pthread_mutex_lock(&trace_kernel_access);
    int result = kernel_mprotect(session->pid, (intptr_t)address, ORBIT_HOOK_PAGE, PROT_READ | PROT_EXEC);
    pthread_mutex_unlock(&trace_kernel_access);
    report_diag("WebView PID=%d kernel_mprotect RX result=%d", (int)session->pid, result);
    if (result != 0) {
        errno = EACCES;
        return 0;
    }
    return address;
}

static int
webview_restore(struct session *session, const struct webview_imports *imports,
                const struct webview_mapping *mappings, int installing) {
    int result = 0;
    for (size_t i = 0; i < imports->export_count; i++) {
        if (!mappings[i].code)
            continue;
        uintptr_t port = mappings[i].code + ORBIT_HOOK_PAGE + offsetof(struct orbit_config, port);
        uint16_t disabled = 0;
        if (memory_transfer(session, session->pid, PIOD_WRITE_D, port, &disabled, sizeof(disabled), NULL) != 0) {
            trace_error("Disable WebView connect shim");
            result = -1;
        }
    }
    for (size_t i = 0; i < imports->count; i++) {
        const struct webview_import *slot = &imports->slots[i];
        if (!slot->hook)
            continue;
        uintptr_t present = 0;
        uintptr_t original = slot->original;
        if (memory_transfer(session, session->pid, PIOD_READ_D, slot->address,
                            &present, sizeof(present), NULL) != 0) {
            trace_error("Read WebView connect import during cleanup");
            result = -1;
            continue;
        }
        if (present == original || (!installing && present != slot->hook))
            continue;
        if (memory_transfer(session, session->pid, PIOD_WRITE_D, slot->address,
                            &original, sizeof(original), NULL) != 0 ||
            memory_transfer(session, session->pid, PIOD_READ_D, slot->address,
                            &present, sizeof(present), NULL) != 0) {
            trace_error("Restore WebView connect import");
            result = -1;
        } else if (present != original) {
            errno = EIO;
            trace_error("Verify restored WebView connect import");
            result = -1;
        }
    }
    return result;
}

enum { CONNECT_IMPORT_UNAVAILABLE = 1 };

static int
webview_install(struct session *session, struct webview_imports *imports,
                const struct orbit_config *config, struct webview_mapping *mappings) {
    struct webview_remote remote = {0};
    const struct webview_socket_api *socket_api = imports->socket_api.socket ? &imports->socket_api : NULL;
    int result = -1;
    unsigned patched = 0, modules = 0;
    if (webview_remote_init(session, &remote, imports->getpid_entry) != 0) {
        trace_error("Prepare a WebView thread for the mapping syscall");
        goto done;
    }
    long pid = webview_syscall(session, &remote, SYS_getpid, 0, 0, 0, 0, 0, 0);
    if (pid != session->pid) {
        if (pid >= 0)
            errno = EPROTO;
        trace_error("Verify WebView mapping syscall with getpid");
        goto done;
    }
    report_log("%s mapping syscall verified with getpid: PID %d", session->route_name, (int)pid);
    for (size_t i = 0; i < imports->count; i++) {
        if (atomic_load(session->stop))
            goto done;
        struct webview_import *slot = &imports->slots[i];
        uintptr_t original = 0;
        if (memory_transfer(session, session->pid, PIOD_READ_D, slot->address,
                            &original, sizeof(original), NULL) != 0) {
            trace_error("Read WebView connect import");
            goto done;
        }
        size_t index = 0;
        while (index < imports->export_count && imports->exports[index] != original)
            index++;
        if (index == imports->export_count) {
            report_diag("WebView PID=%d import slot=%#lx unresolved or unexpected target=%#lx",
                        (int)session->pid, (unsigned long)slot->address, (unsigned long)original);
            continue;
        }
        if (!mappings[index].code &&
            !webview_map_shim(session, &remote, config, socket_api, original, &mappings[index])) {
            trace_error("Map WebView connect shim");
            goto done;
        }
        // Record ownership before the write, so a failed readback also rolls back.
        uintptr_t hook = mappings[index].code, readback = 0;
        slot->original = original;
        slot->hook = hook;
        if (memory_transfer(session, session->pid, PIOD_WRITE_D, slot->address, &hook, sizeof(hook), NULL) != 0 ||
            memory_transfer(session, session->pid, PIOD_READ_D, slot->address, &readback, sizeof(readback), NULL) != 0) {
            trace_error("Patch WebView connect import");
            goto done;
        }
        if (readback != hook) {
            report_log("WebView connect import did not retain the new address");
            report_diag("WebView PID=%d import readback slot=%#lx expected=%#lx got=%#lx",
                        (int)session->pid, (unsigned long)slot->address, (unsigned long)hook, (unsigned long)readback);
            goto done;
        }
        report_diag("WebView PID=%d import slot=%#lx original=%#lx installed=%#lx", (int)session->pid,
                    (unsigned long)slot->address, (unsigned long)original, (unsigned long)hook);
        patched++;
        modules |= slot->module;
    }
    if (socket_api && !session->check && modules != WEBVIEW_IMPORT_REQUIRED) {
        errno = EAGAIN;
        goto done;
    }
    if (patched) {
        report_log("%s connect route installed: PID %d, %u import slots", session->route_name, (int)session->pid, patched);
        result = 0;
    } else {
        report_log("%s PID %d: %zu candidate imports, none bound to a supported connect export",
                   session->route_name, (int)session->pid, imports->count);
        errno = ENOEXEC;
    }
done:;
    int detail = errno;
    if (result != 0 && session->attached && session->stopped) {
        if (webview_restore(session, imports, mappings, 1) == 0) {
            for (size_t i = 0; i < imports->export_count && !remote.restore_failed; i++) {
                if (mappings[i].allocation && webview_syscall(session, &remote, SYS_munmap,
                        (long)mappings[i].allocation, WEBVIEW_RESERVE_SIZE, 0, 0, 0, 0) != 0)
                    trace_error("Release unused WebView shim mapping");
            }
            result = CONNECT_IMPORT_UNAVAILABLE;
        }
    }
    webview_remote_done(session, &remote);
    if (result == CONNECT_IMPORT_UNAVAILABLE &&
        (remote.restore_failed || session->debug.error || !session->attached || !session->stopped))
        result = -1;
    errno = detail;
    return result;
}

static int
webview_attach(struct session *session, const struct process *target) {
    if (target && !process_matches(target)) {
        errno = ESRCH;
        return -1;
    }
    int64_t now = monotonic_ms();
    if (now < 0 || trace(session, PT_ATTACH, session->pid, NULL, 0) != 0)
        return -1;
    session->attached = 1;
    if (wait_event(session, 0, now + STOP_TIMEOUT_MS) != 1)
        return -1;
    session->signal = 0;
    if (target && !process_matches(target)) {
        errno = ESRCH;
        return -1;
    }
    return 0;
}

static int
trace_webview_calls(struct session *session, atomic_int *armed, const struct orbit_config *config) {
    if (atomic_load(session->stop))
        return 0;
    session->broker_config = config;
    report_log("WebView syscall capture active: PID %d", (int)session->pid);
    report_diag("WebView syscall capture begin PID=%d", (int)session->pid);
    atomic_fetch_add(armed, 1);
    int result = trace_connect_calls(session, -1);
    atomic_fetch_sub(armed, 1);
    return result;
}

static int
trace_connect_imports(pid_t pid, const struct process *target, const struct sockaddr_in *check, int start_fd,
                      const atomic_bool *stop, atomic_int *webview_armed, atomic_bool *orbit_attached,
                      const struct orbit_config *config) {
    const char *label = orbit_attached ? "Orbit" : "WebView";
    struct session session = {.pid = pid, .route_name = label, .check = check, .stop = stop};
    struct webview_imports imports = {0};
    struct webview_mapping mappings[WEBVIEW_EXPORT_LIMIT] = {0};
    struct orbit_config probe = {0};
    struct orbit_relay broker = {.socket = -1, .stop = stop, .probe_target = check};
    pthread_t thread;
    int installed = 0, broker_running = 0, result = -1;
    unsigned char *source = NULL;
    size_t source_size = 0;
    report_diag("%s begin PID=%d role=%s", label, (int)pid, check ? "preflight" : "native");
    if (debug_init(&session.debug) != 0) {
        report_log("Cannot read %s tracer authid", label);
        errno = EACCES;
        return -1;
    }
    if (orbit_attached && orbit_read_saved(&source, &source_size) != 0)
        return -1;
    if (check) {
        probe.probe_port = check->sin_port;
        broker.socket = orbit_open_control(&probe);
        if (broker.socket < 0)
            goto done;
        memcpy(broker.token, probe.token, sizeof(broker.token));
        int error = pthread_create(&thread, NULL, orbit_relay_run, &broker);
        if (error) {
            errno = error;
            trace_error("Start WebView check controller");
            goto done;
        }
        broker_running = 1;
        config = &probe;
    }
    if (!config || !config->port || atomic_load(stop))
        goto done;
    if (webview_attach(&session, target) != 0) {
        trace_error("Stop WebView for connect setup");
        goto done;
    }
    if (check) {
        imports.socket_api = (struct webview_socket_api){
            .socket = socket, .connect = connect, .getsockopt = getsockopt, .sendto = sendto,
            .recvfrom = recvfrom, .poll = poll, .close = close, .error_location = __error,
        };
        imports.getpid_entry = (uintptr_t)getpid;
        imports.slots[0].address = (uintptr_t)&webview_probe_connect;
        imports.exports[0] = (uintptr_t)webview_probe_connect;
        imports.count = imports.export_count = 1;
    } else if (orbit_attached) {
        int found = find_orbit_import(&session, source, source_size, &imports);
        int detail = errno;
        free(source);
        source = NULL;
        errno = detail;
        if (found != 0) {
            trace_error("Match saved Orbit ELF and find live connect import");
            goto done;
        }
    } else if (find_webview_imports(&session, &imports) != 0) {
        if (errno == EAGAIN || errno == ENOENT) {
            report_diag("WebView PID=%d waiting for bound WebKit and curl imports", (int)pid);
            result = TRACE_WEBVIEW_RETRY;
        } else {
            trace_error("Find WebView connect imports");
        }
        goto done;
    }
    int install_status = webview_install(&session, &imports, config, mappings);
    if (install_status == CONNECT_IMPORT_UNAVAILABLE && target && !orbit_attached && !session.debug.error) {
        report_diag("WebView PID=%d import setup rolled back errno=%d", (int)pid, errno);
        result = errno == EAGAIN ? TRACE_WEBVIEW_RETRY : trace_webview_calls(&session, webview_armed, config);
        goto done;
    }
    installed = install_status == 0;
    int install_error = errno;
    int detach_result = end_trace(&session);
    if (!installed)
        errno = install_error;
    if (detach_result != 0 || !installed || session.debug.error)
        goto done;

    if (check) {
        int64_t now = monotonic_ms();
        if (now >= 0 && send(start_fd, "S", 1, MSG_NOSIGNAL) == 1)
            result = wait_event(&session, 1, now + 15000);
        if (result != 0 && errno == ETIMEDOUT)
            report_log("WebView connect check timed out");
    } else {
        const struct timespec delay = {.tv_nsec = 100 * 1000 * 1000};
        if (orbit_attached) {
            report_log("Orbit VPN active: %s, PID %d, local API port %d", target->name, (int)pid, ORBIT_PORT);
            atomic_store(orbit_attached, 1);
        } else {
            atomic_fetch_add(webview_armed, 1);
        }
        while (!atomic_load(stop) && process_matches(target))
            nanosleep(&delay, NULL);
        if (orbit_attached)
            atomic_store(orbit_attached, 0);
        else
            atomic_fetch_sub(webview_armed, 1);
        result = 0;
        if (orbit_attached && !atomic_load(stop)) {
            errno = ESRCH;
            result = -1;
        }
    }
done:;
    int detail = errno;
    free(source);
    if (installed && target && process_matches(target)) {
        if (!session.attached && webview_attach(&session, target) != 0) {
            trace_error("Stop WebView for connect cleanup");
            detail = errno;
            result = -1;
        } else if (webview_restore(&session, &imports, mappings, 0) != 0) {
            detail = errno;
            result = -1;
        } else {
            // An in-flight call may still hold a shim pointer. The VM reclaims it on exit.
            report_log("%s connect route restored: PID %d", label, (int)pid);
        }
    }
    if (end_trace(&session) != 0) {
        detail = errno;
        result = -1;
    }
    if (session.broker_config) {
        report_log("WebView syscall capture ended: PID %d, connect calls %u, redirected %u",
                   (int)pid, session.connect_calls, session.redirected);
        report_diag("WebView syscall capture end PID=%d entries=%llu connects=%u redirected=%u "
                    "ipv6=%u broker_failures=%u result=%d",
                    (int)pid, (unsigned long long)session.entry_stops, session.connect_calls, session.redirected,
                    session.bypass, session.broker_failures, result);
    }
    if (broker_running) {
        atomic_store(&broker.shutdown, 1);
        pthread_join(thread, NULL);
        if (broker.bridged != RELAY_CHECK_CONNECTIONS)
            result = -1;
    }
    if (broker.socket >= 0)
        close(broker.socket);
    report_diag("%s end PID=%d role=%s installed=%d result=%d relays_with_bytes=%u debugger_error=%d",
                label, (int)pid, check ? "preflight" : "native", installed, result, broker.bridged, session.debug.error);
    errno = detail;
    if (!session.debug.error && (result == 0 || result == TRACE_WEBVIEW_RETRY))
        return result;
    return -1;
}

int
trace_webview(pid_t pid, const struct process *target, const struct sockaddr_in *check, int start_fd,
              const atomic_bool *stop, atomic_int *armed, const struct orbit_config *config) {
    return trace_connect_imports(pid, target, check, start_fd, stop, armed, NULL, config);
}

int
trace_orbit(const struct process *target, const atomic_bool *stop, atomic_bool *attached,
            const struct orbit_config *config) {
    return trace_connect_imports(target->pid, target, NULL, -1, stop, NULL, attached, config);
}

int
trace_process(pid_t pid, const struct process *target, const struct sockaddr_in *check,
              int start_fd, const atomic_bool *stop, atomic_bool *attached) {
    struct session session = {
        .pid = pid, .check = check, .stop = stop,
    };
    if (debug_init(&session.debug) != 0) {
        report_log("Cannot read payload authid");
        return -1;
    }
    int64_t now = monotonic_ms();
    if (now < 0)
        return -1;
    if (trace(&session, PT_ATTACH, pid, NULL, 0) != 0) {
        trace_error("PT_ATTACH");
        return -1;
    }
    session.attached = 1;

    int result = -1;
    if (wait_event(&session, 0, now + STOP_TIMEOUT_MS) != 1)
        goto done;
    session.signal = 0;
    if (atomic_load(stop)) {
        result = check ? -1 : 0;
        goto done;
    }
    if (target && !process_matches(target)) {
        report_log("PID %d changed before attach", (int)pid);
        goto done;
    }
    report_log("Attached PID %d (%s)", (int)pid, target ? target->name : "relay check");
    if (attached)
        atomic_store(attached, 1);
    if (start_fd >= 0 && send(start_fd, "S", 1, 0) != 1) {
        trace_error("Start relay check client");
        goto done;
    }
    result = trace_connect_calls(&session, check ? now + 25000 : -1);

done:
    if (end_trace(&session) != 0)
        result = -1;
    if (attached)
        atomic_store(attached, 0);
    relay_stop();
    join_jobs(&session, 1);
    report_log("Redirect attempts: %u, relays with bytes both ways: %u", session.sequence, session.bridged);
    report_log("TCP tracer observed %llu syscall entries", (unsigned long long)session.entry_stops);
    if (session.restored_at_entry)
        report_log("Restored connect sockaddr at syscall entry: %u", session.restored_at_entry);
    if (check && session.bridged != RELAY_CHECK_CONNECTIONS)
        result = -1;
    return result == 0 && !session.debug.error ? 0 : -1;
}


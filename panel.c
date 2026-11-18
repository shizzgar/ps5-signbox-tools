/* SPDX-License-Identifier: MIT */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <microhttpd.h>

#include "assets.h"
#include "diagnostics.h"
#include "orbit-relay.h"
#include "orbit-run.h"
#include "panel.h"
#include "panel-access.h"
#include "process.h"
#include "relay.h"
#include "report.h"
#include "service.h"
#include "trace.h"
#include "webview.h"

enum { LOG_LIMIT = 32 * 1024, REQUEST_LIMIT = 96, PIN_LENGTH = 8, TOKEN_LENGTH = 32 };
enum action { IDLE, SELF_TEST, HTTPS_TEST, DOWNLOAD_TEST, START, ORBIT, DIAGNOSTICS, RESTART };
enum webview_state { WEBVIEW_IDLE, WEBVIEW_QUEUED, WEBVIEW_OPENING, WEBVIEW_LAUNCHED, WEBVIEW_FAILED };
enum webview_route_state { ROUTE_OFF, ROUTE_CHECKING, ROUTE_WATCHING, ROUTE_UNAVAILABLE };

struct panel {
    pthread_mutex_t mutex;
    pthread_cond_t wake;
    struct process target;
    struct managed_proxy proxy;
    enum action action;
    const char *error;
    int check_result;
    int egress_result;
    int download_result;
    enum webview_state webview;
    struct webview_route webview_route;
    atomic_int webview_route_state;
    int closing;
    int watch_orbit;
    int orbit_stalled;
    unsigned capture_attempt;
    atomic_bool stop;
    atomic_bool attached;
    char pin[PIN_LENGTH + 1];
    char token[TOKEN_LENGTH + 1];
    int64_t login_after;
    int64_t notify_after;
};

struct orbit_watch {
    unsigned capture_attempt;
    int64_t next_probe;
    int failed_probes;
};

struct request {
    size_t length;
    int too_long;
    char body[REQUEST_LIMIT + 1];
};

static void show_address(const struct panel *panel);

static volatile sig_atomic_t terminate_requested;

static void
terminate_panel(int signal_number) {
    (void)signal_number;
    terminate_requested = 1;
}

static void
request_stop(struct panel *panel) {
    atomic_store(&panel->stop, 1);
    relay_stop();
}

static int
start_webview_watcher(struct panel *panel, pthread_t *worker, const struct orbit_config *config) {
    panel->webview_route.config = *config;
    int error = pthread_create(worker, NULL, webview_route_run, &panel->webview_route);
    if (error != 0) {
        report_log("Cannot start WebView watcher (errno=%d)", error);
        report_diag("WebView watcher creation failed errno=%d", error);
    }
    atomic_store(&panel->webview_route_state, error ? ROUTE_UNAVAILABLE : ROUTE_WATCHING);
    return error == 0;
}

static int
run_orbit_routes(struct panel *panel, const struct process *target, int proxy_control, const char **error) {
    atomic_store(&panel->webview_route_state, ROUTE_CHECKING);
    report_log("WebView preflight: test an in-memory connect redirect on a child process");
    int webview_ready = relay_webview_check(&panel->stop, proxy_control) == 0;
    if (atomic_load(&panel->stop)) {
        atomic_store(&panel->webview_route_state, ROUTE_OFF);
        return 0;
    }
    report_log(webview_ready ? "PASS: WebView preflight exchanged TCP through sing-box"
                             : "FAIL: WebView preflight. Trying the live Orbit import.");
    relay_reset();

    struct orbit_config config = {0}, webview = {0};
    int control = orbit_open_control(&config);
    if (control < 0) {
        report_diag("Orbit controller open failed errno=%d", errno);
        atomic_store(&panel->webview_route_state, ROUTE_OFF);
        *error = "orbit_live";
        return -1;
    }
    struct orbit_relay relay = {.socket = control, .stop = &panel->stop};
    memcpy(relay.token, config.token, sizeof(config.token));
    if (webview_ready && random_bytes(webview.token, sizeof(webview.token)) == 0) {
        webview.port = config.port;
        memcpy(relay.webview_token, webview.token, sizeof(webview.token));
        relay.allow_webview = 1;
    }
    pthread_t broker, watcher;
    int spawn = pthread_create(&broker, NULL, orbit_relay_run, &relay);
    if (spawn != 0) {
        report_diag("Orbit broker creation failed errno=%d", spawn);
        atomic_store(&panel->webview_route_state, ROUTE_OFF);
        close(control);
        *error = "orbit_live";
        return -1;
    }
    int watching = relay.allow_webview && start_webview_watcher(panel, &watcher, &webview);
    if (!watching)
        atomic_store(&panel->webview_route_state, ROUTE_UNAVAILABLE);

    pthread_mutex_lock(&panel->mutex);
    panel->watch_orbit = 1;
    pthread_mutex_unlock(&panel->mutex);
    int result = trace_orbit(target, &panel->stop, &panel->attached, &config);
    int detail = errno;
    int webview_only = watching && result != 0 && !atomic_load(&panel->stop);
    pthread_mutex_lock(&panel->mutex);
    panel->watch_orbit = 0;
    if (result != 0)
        *error = detail == ENOENT || detail == ENOEXEC || detail == EEXIST ? "orbit_image" : "orbit_live";
    if (webview_only) {
        panel->error = *error;
        panel->target = (struct process){0};
        atomic_store(&panel->attached, 1);
    }
    pthread_mutex_unlock(&panel->mutex);
    if (webview_only)
        report_log("WebView watcher active. Live Orbit import was not installed (errno=%d).", detail);
    else
        atomic_store(&relay.shutdown, 1);
    pthread_join(broker, NULL);
    if (watching) {
        atomic_store(&panel->stop, 1);
        pthread_join(watcher, NULL);
    }
    close(control);
    atomic_store(&panel->webview_route_state, ROUTE_OFF);
    return result;
}

static int
run_diagnostics(struct panel *panel, int proxy_control, pid_t proxy_pid) {
    report_log("Diagnostics: checking WebView and the ELF loader");
    report_diag("Diagnostics begin sing-box_PID=%d SOCKS5=ready Orbit_API=%d", (int)proxy_pid,
                orbit_service_ready(1500));
    atomic_store(&panel->webview_route_state, ROUTE_CHECKING);
    unsigned passed = 0;
    for (unsigned attempt = 1; attempt <= 3 && !atomic_load(&panel->stop); attempt++) {
        int result = relay_webview_check(&panel->stop, proxy_control);
        passed += result == 0;
        report_diag("WebView preflight run %u of 3 result=%s stop=%d", attempt,
                    result == 0 ? "pass" : "fail", atomic_load(&panel->stop));
        if (!atomic_load(&panel->stop))
            relay_reset();
    }
    report_log("Diagnostics: %u of 3 WebView preflights passed. Checking ELF loader variants.", passed);
    if (!atomic_load(&panel->stop))
        orbit_probe_diagnostics(&panel->stop);
    report_diag("Diagnostics probes complete WebView_passed=%u stop=%d", passed, atomic_load(&panel->stop));
    if (atomic_load(&panel->stop)) {
        atomic_store(&panel->webview_route_state, ROUTE_OFF);
        return 0;
    }
    if (!passed) {
        atomic_store(&panel->webview_route_state, ROUTE_UNAVAILABLE);
        return -1;
    }

    struct orbit_config config = {0};
    int control = orbit_open_control(&config);
    if (control < 0) {
        report_diag("Diagnostics WebView controller open failed errno=%d", errno);
        atomic_store(&panel->webview_route_state, ROUTE_UNAVAILABLE);
        return -1;
    }
    struct orbit_relay relay = {.socket = control, .stop = &panel->stop, .allow_webview = 1};
    memcpy(relay.token, config.token, sizeof(config.token));
    memcpy(relay.webview_token, config.token, sizeof(config.token));
    pthread_t broker, watcher;
    int error = pthread_create(&broker, NULL, orbit_relay_run, &relay);
    if (error != 0) {
        report_diag("Diagnostics WebView broker creation failed errno=%d", error);
        atomic_store(&panel->webview_route_state, ROUTE_UNAVAILABLE);
        close(control);
        return -1;
    }
    int watching = start_webview_watcher(panel, &watcher, &config);
    if (watching) {
        atomic_store(&panel->attached, 1);
        report_log("Diagnostics: WebView watcher active. Open the provider page or run the WebView check on PS5.");
    } else {
        atomic_store(&relay.shutdown, 1);
    }
    pthread_join(broker, NULL);
    if (watching) {
        atomic_store(&panel->stop, 1);
        pthread_join(watcher, NULL);
    }
    close(control);
    atomic_store(&panel->webview_route_state, ROUTE_OFF);
    report_diag("Diagnostics end relay_result=%d bidirectional=%u", watching, relay.bridged);
    return watching ? 0 : -1;
}

static void *
relay_worker(void *arg) {
    struct panel *panel = arg;
    for (;;) {
        pthread_mutex_lock(&panel->mutex);
        while (panel->action == IDLE && !panel->closing)
            pthread_cond_wait(&panel->wake, &panel->mutex);
        if (panel->closing) {
            panel->action = IDLE;
            pthread_mutex_unlock(&panel->mutex);
            return NULL;
        }
        enum action action = panel->action;
        struct process target = panel->target;
        int proxy_control = panel->proxy.control;
        pid_t proxy_pid = panel->proxy.pid;
        struct managed_proxy next_proxy = {.control = -1};
        if (action == RESTART) {
            next_proxy = panel->proxy;
            panel->proxy = (struct managed_proxy){.control = -1, .state = SERVICE_STARTING};
        }
        pthread_mutex_unlock(&panel->mutex);

        const char *error = NULL;
        int result = -1;
        int worker_lost = 0;
        if (action == RESTART) {
            proxy_stop(&next_proxy);
            if (!atomic_load(&panel->stop) && proxy_start(&next_proxy) != 0) {
                int detail = errno;
                report_log("Could not start integrated sing-box: %s", strerror(detail));
                error = detail == ECONNREFUSED ? "loader" : "proxy";
                next_proxy.state = SERVICE_ERROR;
            }
        } else if (!atomic_load(&panel->stop)) {
            if (relay_ready() != 0) {
                int e = errno;
                report_log("SOCKS5 127.0.0.1:17890 unavailable: %s (errno=%d)", strerror(e), e);
                error = "proxy";
            } else if (action == SELF_TEST) {
                result = relay_check(&panel->stop, proxy_control);
                if (result != 0) {
                    report_log("FAIL: local relay check did not complete through sing-box");
                    error = "check";
                } else {
                    report_log("PASS: intercepted TCP exchanged bytes through sing-box");
                }
            } else if (action == DIAGNOSTICS) {
                result = run_diagnostics(panel, proxy_control, proxy_pid);
                if (result != 0)
                    error = "diagnostics";
            } else if (action == HTTPS_TEST || action == DOWNLOAD_TEST) {
                result = proxy_check(proxy_control, action == HTTPS_TEST ? CHECK_HTTPS : CHECK_DOWNLOAD,
                                     &panel->stop);
                if (result == PROXY_CHECK_DISCONNECTED) {
                    report_log("Connection to integrated sing-box lost during test");
                    worker_lost = 1;
                    error = "proxy";
                } else if (result != PROXY_CHECK_PASSED) {
                    error = action == HTTPS_TEST ? "egress" : "download";
                }
            } else {
                if (action == ORBIT) {
                    if (process_orbit(&target, proxy_pid, &panel->stop) != 0) {
                        int detail = errno;
                        if (detail == ENETUNREACH)
                            error = "orbit_unreachable";
                        else if (detail == EEXIST)
                            error = "orbit_ambiguous";
                        else
                            error = detail == ENXIO || detail == ESRCH ? "orbit_unidentified" : "processes";
                        report_log("Orbit selection failed: %s", error);
                    } else {
                        pthread_mutex_lock(&panel->mutex);
                        panel->target = target;
                        pthread_mutex_unlock(&panel->mutex);
                    }
                }
                if (!error && (target.pid == proxy_pid || !process_matches(&target))) {
                    report_log("PID %d is unavailable for capture", (int)target.pid);
                    error = "target";
                }
                if (!error && !atomic_load(&panel->stop)) {
                    if (action == ORBIT) {
                        result = run_orbit_routes(panel, &target, proxy_control, &error);
                    } else if (process_owns_orbit(&target, &panel->stop)) {
                        error = "orbit_use_button";
                    } else {
                        result = trace_process(target.pid, &target, NULL, -1, &panel->stop, &panel->attached);
                        if (result != 0)
                            error = "trace";
                    }
                }
            }
        }

        if (action == ORBIT)
            report_diag("Combined Orbit/WebView operation result=%d stop=%d error=%s", result,
                        atomic_load(&panel->stop), error ? error : "none");
        pthread_mutex_lock(&panel->mutex);
        int stopped = atomic_load(&panel->stop);
        if (worker_lost) {
            close(panel->proxy.control);
            panel->proxy = (struct managed_proxy){.control = -1, .state = SERVICE_ERROR};
        }
        panel->error = panel->orbit_stalled ? "orbit_stalled" : (stopped ? NULL : error);
        panel->watch_orbit = 0;
        if (action == SELF_TEST)
            panel->check_result = stopped ? 0 : (result == 0 ? 1 : -1);
        else if (action == HTTPS_TEST)
            panel->egress_result = stopped ? 0 : (result == 0 ? 1 : -1);
        else if (action == DOWNLOAD_TEST)
            panel->download_result = stopped ? 0 : (result == 0 ? 1 : -1);
        else if (action == RESTART)
            panel->proxy = next_proxy;
        panel->action = IDLE;
        atomic_store(&panel->attached, 0);
        pthread_mutex_unlock(&panel->mutex);
    }
}

static void
open_webview_if_queued(struct panel *panel) {
    pthread_mutex_lock(&panel->mutex);
    if (panel->closing || panel->webview != WEBVIEW_QUEUED) {
        pthread_mutex_unlock(&panel->mutex);
        return;
    }
    if (panel->proxy.state != SERVICE_READY) {
        panel->webview = WEBVIEW_FAILED;
        pthread_mutex_unlock(&panel->mutex);
        return;
    }
    panel->webview = WEBVIEW_OPENING;
    pthread_mutex_unlock(&panel->mutex);

    int result = webview_open_check();
    pthread_mutex_lock(&panel->mutex);
    panel->webview = result == 0 ? WEBVIEW_LAUNCHED : WEBVIEW_FAILED;
    pthread_mutex_unlock(&panel->mutex);
}

static void
monitor_orbit(struct panel *panel, struct orbit_watch *watch) {
    pthread_mutex_lock(&panel->mutex);
    unsigned capture_attempt = panel->capture_attempt;
    struct process target = panel->target;
    int monitoring = panel->watch_orbit && atomic_load(&panel->attached) &&
                     !atomic_load(&panel->stop) && !panel->closing;
    pthread_mutex_unlock(&panel->mutex);
    if (!monitoring)
        return;

    int64_t now = monotonic_ms();
    if (now < 0)
        return;
    if (watch->capture_attempt != capture_attempt) {
        *watch = (struct orbit_watch){.capture_attempt = capture_attempt, .next_probe = now + 500};
        return;
    }
    if (now < watch->next_probe)
        return;

    if (process_matches(&target) && orbit_service_ready(1500)) {
        watch->failed_probes = 0;
        watch->next_probe = monotonic_ms() + 2500;
        return;
    }
    if (++watch->failed_probes < 2) {
        watch->next_probe = monotonic_ms() + 300;
        return;
    }

    pthread_mutex_lock(&panel->mutex);
    if (panel->capture_attempt == capture_attempt && panel->watch_orbit &&
        atomic_load(&panel->attached) && !atomic_load(&panel->stop)) {
        report_log("Orbit local API failed twice for PID %d; stopping relay",
                   (int)panel->target.pid);
        panel->orbit_stalled = 1;
        atomic_store(&panel->stop, 1);
        relay_stop();
    }
    pthread_mutex_unlock(&panel->mutex);
}

static int
init_credentials(struct panel *panel) {
    uint32_t number;
    unsigned char token[TOKEN_LENGTH / 2];
    do {
        if (random_bytes((unsigned char *)&number, sizeof(number)) != 0)
            return -1;
    } while (number >= UINT32_C(4200000000));
    if (random_bytes(token, sizeof(token)) != 0)
        return -1;
    snprintf(panel->pin, sizeof(panel->pin), "%08" PRIu32, number % UINT32_C(100000000));
    for (size_t i = 0; i < sizeof(token); i++)
        snprintf(panel->token + i * 2, 3, "%02x", (unsigned int)token[i]);
    return 0;
}

static enum MHD_Result
respond(struct MHD_Connection *connection, unsigned status, const char *type,
        const void *data, size_t length, enum MHD_ResponseMemoryMode memory) {
    struct MHD_Response *response = MHD_create_response_from_buffer(length, (void *)data, memory);
    if (!response) {
        if (memory == MHD_RESPMEM_MUST_FREE)
            free((void *)data);
        return MHD_NO;
    }
    enum MHD_Result result = MHD_NO;
    if (MHD_add_response_header(response, "Content-Type", type) == MHD_YES &&
        MHD_add_response_header(response, "Cache-Control", "no-store") == MHD_YES &&
        MHD_add_response_header(response, "X-Content-Type-Options", "nosniff") == MHD_YES &&
        MHD_add_response_header(response, "X-Frame-Options", "DENY") == MHD_YES &&
        MHD_add_response_header(response, "Referrer-Policy", "no-referrer") == MHD_YES &&
        MHD_add_response_header(response, "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'") == MHD_YES)
        result = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return result;
}

static enum MHD_Result
json(struct MHD_Connection *connection, unsigned status, const char *value) {
    return respond(connection, status, "application/json; charset=utf-8", value,
                   strlen(value), MHD_RESPMEM_MUST_COPY);
}

static int
trusted_request(struct MHD_Connection *connection) {
    const union MHD_ConnectionInfo *info =
        MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CONNECTION_FD);
    const char *host = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Host");
    const char *origin = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Origin");
    return info && panel_request_is_trusted(info->connect_fd, host, origin);
}

static int
secret_matches(const char *given, const char *expected, size_t length) {
    if (!given || strlen(given) != length)
        return 0;
    unsigned difference = 0;
    for (size_t index = 0; index < length; index++)
        difference |= (unsigned char)given[index] ^ (unsigned char)expected[index];
    return difference == 0;
}

static enum MHD_Result
sign_in(struct panel *panel, struct MHD_Connection *connection, const char *pin) {
    int64_t now = monotonic_ms();
    if (now < 0)
        return json(connection, MHD_HTTP_SERVICE_UNAVAILABLE, "{\"error\":\"unavailable\"}");
    if (now < panel->login_after)
        return json(connection, MHD_HTTP_TOO_MANY_REQUESTS, "{\"error\":\"wait\"}");
    if (!secret_matches(pin, panel->pin, PIN_LENGTH)) {
        panel->login_after = now + 2000;
        return json(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"pin\"}");
    }
    char response[64];
    snprintf(response, sizeof(response), "{\"token\":\"%s\"}", panel->token);
    return json(connection, MHD_HTTP_OK, response);
}

static void
process_identity(const struct process *process, char *value, size_t size) {
    snprintf(value, size, "%d:%jd:%jd", (int)process->pid,
             (intmax_t)process->start.tv_sec, (intmax_t)process->start.tv_usec);
}

static void
json_name(const char *name, char *escaped) {
    size_t index = 0;
    for (const unsigned char *byte = (const unsigned char *)name; *byte; byte++) {
        if (*byte == '"' || *byte == '\\')
            escaped[index++] = '\\';
        escaped[index++] = *byte >= 32 && *byte < 127 ? (char)*byte : '?';
    }
    escaped[index] = '\0';
}

static enum MHD_Result
get_status(struct panel *panel, struct MHD_Connection *connection) {
    char response[480], name[2 * PROCESS_NAME_SIZE + 1];
    pthread_mutex_lock(&panel->mutex);
    const char *state = "idle";
    const int diagnosing = panel->action == DIAGNOSTICS;
    const int tracing = panel->action == START || panel->action == ORBIT || diagnosing;
    if (panel->action != IDLE) {
        if (atomic_load(&panel->stop))
            state = "stopping";
        else if (tracing)
            state = atomic_load(&panel->attached) ? "active" : "starting";
        else
            state = panel->action == RESTART ? "restarting" : "checking";
    }
    const char *results[] = {"fail", "ready", "pass"};
    const char *proxy_states[] = {"off", "starting", "ready", "error"};
    const char *webview_states[] = {"idle", "opening", "opening", "launched", "error"};
    const char *route_states[] = {"off", "checking", "waiting", "unavailable"};
    int route_state = atomic_load(&panel->webview_route_state);
    const char *webview_route = route_states[route_state];
    if (route_state == ROUTE_WATCHING) {
        if (atomic_load(&panel->webview_route.armed) > 0)
            webview_route = "armed";
        else if (atomic_load(&panel->webview_route.failures) > 0)
            webview_route = "error";
    }
    const char *check = panel->action == SELF_TEST ? "running" : results[panel->check_result + 1];
    const char *egress = panel->action == HTTPS_TEST ? "running" : results[panel->egress_result + 1];
    const char *download = panel->action == DOWNLOAD_TEST ? "running" : results[panel->download_result + 1];
    const char *orbit_route = panel->action != ORBIT ? "off" :
        panel->error ? "unavailable" : atomic_load(&panel->attached) && panel->target.pid ? "armed" : "checking";
    json_name(tracing ? panel->target.name : "", name);
    snprintf(response, sizeof(response),
             "{\"state\":\"%s\",\"proxy\":\"%s\",\"check\":\"%s\",\"egress\":\"%s\","
             "\"download\":\"%s\",\"webview\":\"%s\",\"webview_route\":\"%s\",\"orbit_route\":\"%s\",\"diagnosing\":%s,\"pid\":%d,\"name\":\"%s\",\"error\":\"%s\"}",
             state, proxy_states[panel->proxy.state], check, egress, download, webview_states[panel->webview],
             webview_route, orbit_route, diagnosing ? "true" : "false", tracing ? (int)panel->target.pid : 0, name,
             panel->error ? panel->error : "");
    pthread_mutex_unlock(&panel->mutex);
    return json(connection, MHD_HTTP_OK, response);
}

static int
process_order(const void *a, const void *b) {
    const struct process *first = a, *second = b;
    int first_core = strncmp(first->name, "Sce", 3) == 0 || strncmp(first->name, "sce", 3) == 0;
    int second_core = strncmp(second->name, "Sce", 3) == 0 || strncmp(second->name, "sce", 3) == 0;
    if (first_core != second_core)
        return first_core - second_core;
    int order = strcasecmp(first->name, second->name);
    return order != 0 ? order : (first->pid > second->pid) - (first->pid < second->pid);
}

static enum MHD_Result
get_processes(struct panel *panel, struct MHD_Connection *connection) {
    struct process *processes;
    size_t count;
    if (process_list(&processes, &count) != 0)
        return json(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"processes\"}");
    pthread_mutex_lock(&panel->mutex);
    pid_t proxy_pid = panel->proxy.pid;
    pthread_mutex_unlock(&panel->mutex);
    qsort(processes, count, sizeof(*processes), process_order);
    size_t capacity = count * 160 + 4;
    char *response = malloc(capacity);
    if (!response) {
        free(processes);
        return MHD_NO;
    }
    size_t used = 1;
    response[0] = '[';
    for (size_t index = 0; index < count; index++) {
        if (processes[index].pid == proxy_pid)
            continue;
        char id[72], name[2 * PROCESS_NAME_SIZE + 1];
        process_identity(&processes[index], id, sizeof(id));
        json_name(processes[index].name, name);
        int size = snprintf(response + used, capacity - used,
            "%s{\"id\":\"%s\",\"pid\":%d,\"name\":\"%s\"}", used > 1 ? "," : "", id,
            (int)processes[index].pid, name);
        if (size < 0 || (size_t)size >= capacity - used - 1) {
            free(processes);
            free(response);
            return MHD_NO;
        }
        used += (size_t)size;
    }
    free(processes);
    response[used++] = ']';
    return respond(connection, MHD_HTTP_OK, "application/json; charset=utf-8",
                   response, used, MHD_RESPMEM_MUST_FREE);
}

static enum MHD_Result
get_log(struct MHD_Connection *connection, const char *path, size_t limit) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)) {
        if (fd >= 0)
            close(fd);
        return json(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"log\"}");
    }
    char *buffer = malloc(limit);
    if (!buffer) {
        close(fd);
        return MHD_NO;
    }
    off_t start = info.st_size > (off_t)limit ? info.st_size - (off_t)limit : 0;
    ssize_t count = pread(fd, buffer, limit, start);
    close(fd);
    if (count < 0) {
        free(buffer);
        return json(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"log\"}");
    }
    char *newline = start && count ? memchr(buffer, '\n', (size_t)count) : NULL;
    if (newline) {
        size_t skip = (size_t)(newline + 1 - buffer);
        count -= (ssize_t)skip;
        memmove(buffer, newline + 1, (size_t)count);
    }
    return respond(connection, MHD_HTTP_OK, "text/plain; charset=utf-8",
                   buffer, (size_t)count, MHD_RESPMEM_MUST_FREE);
}

static enum MHD_Result
request_webview(struct panel *panel, struct MHD_Connection *connection) {
    pthread_mutex_lock(&panel->mutex);
    const char *error = NULL;
    if (panel->closing || panel->webview == WEBVIEW_QUEUED || panel->webview == WEBVIEW_OPENING ||
        (panel->action != IDLE && (!atomic_load(&panel->attached) || atomic_load(&panel->stop))))
        error = "{\"error\":\"busy\"}";
    else if (panel->proxy.state != SERVICE_READY)
        error = "{\"error\":\"proxy\"}";
    else if (atomic_load(&panel->webview_route_state) != ROUTE_WATCHING)
        error = "{\"error\":\"webview_not_ready\"}";
    else
        panel->webview = WEBVIEW_QUEUED;
    pthread_mutex_unlock(&panel->mutex);
    return error ? json(connection, MHD_HTTP_CONFLICT, error) : json(connection, MHD_HTTP_ACCEPTED, "{}");
}

static enum MHD_Result
set_action(struct panel *panel, struct MHD_Connection *connection, const char *path, const char *body) {
    if (!strcmp(path, "/api/webview"))
        return request_webview(panel, connection);
    if (!strcmp(path, "/api/stop")) {
        pthread_mutex_lock(&panel->mutex);
        if (panel->action != IDLE)
            request_stop(panel);
        pthread_mutex_unlock(&panel->mutex);
        return json(connection, MHD_HTTP_ACCEPTED, "{}");
    }
    if (!strcmp(path, "/api/close")) {
        pthread_mutex_lock(&panel->mutex);
        panel->closing = 1;
        request_stop(panel);
        pthread_cond_signal(&panel->wake);
        pthread_mutex_unlock(&panel->mutex);
        return json(connection, MHD_HTTP_ACCEPTED, "{}");
    }
    enum action action;
    struct process target = {0};
    if (!strcmp(path, "/api/check")) {
        action = SELF_TEST;
    } else if (!strcmp(path, "/api/egress")) {
        action = HTTPS_TEST;
    } else if (!strcmp(path, "/api/download")) {
        action = DOWNLOAD_TEST;
    } else if (!strcmp(path, "/api/orbit")) {
        action = ORBIT;
    } else if (!strcmp(path, "/api/diagnostics")) {
        action = DIAGNOSTICS;
    } else if (!strcmp(path, "/api/restart")) {
        action = RESTART;
    } else if (!strcmp(path, "/api/start")) {
        if (body[0] < '0' || body[0] > '9')
            return json(connection, MHD_HTTP_BAD_REQUEST, "{\"error\":\"target\"}");
        char *end;
        errno = 0;
        long pid = strtol(body, &end, 10);
        char id[72];
        if (errno || pid <= 1 || pid > INT_MAX || *end != ':' ||
            process_select((pid_t)pid, &target) != 0)
            return json(connection, MHD_HTTP_CONFLICT, "{\"error\":\"target\"}");
        process_identity(&target, id, sizeof(id));
        if (strcmp(body, id))
            return json(connection, MHD_HTTP_CONFLICT, "{\"error\":\"target\"}");
        action = START;
    } else {
        return json(connection, MHD_HTTP_NOT_FOUND, "{\"error\":\"route\"}");
    }

    pthread_mutex_lock(&panel->mutex);
    if (panel->action != IDLE || panel->closing) {
        pthread_mutex_unlock(&panel->mutex);
        return json(connection, MHD_HTTP_CONFLICT, "{\"error\":\"busy\"}");
    }
    if (action != RESTART && panel->proxy.state != SERVICE_READY) {
        pthread_mutex_unlock(&panel->mutex);
        return json(connection, MHD_HTTP_CONFLICT, "{\"error\":\"proxy\"}");
    }
    if (action == START && target.pid == panel->proxy.pid) {
        pthread_mutex_unlock(&panel->mutex);
        return json(connection, MHD_HTTP_CONFLICT, "{\"error\":\"target\"}");
    }
    relay_reset();
    atomic_store(&panel->stop, 0);
    panel->error = NULL;
    panel->orbit_stalled = 0;
    panel->capture_attempt++;
    panel->target = target;
    panel->action = action;
    if (action == ORBIT || action == DIAGNOSTICS) {
        panel->webview = WEBVIEW_IDLE;
        atomic_store(&panel->webview_route_state, ROUTE_OFF);
        atomic_store(&panel->webview_route.failures, 0);
    }
    if (action == SELF_TEST || action == RESTART)
        panel->check_result = 0;
    if (action == HTTPS_TEST || action == RESTART)
        panel->egress_result = 0;
    if (action == DOWNLOAD_TEST || action == RESTART)
        panel->download_result = 0;
    pthread_cond_signal(&panel->wake);
    pthread_mutex_unlock(&panel->mutex);
    return json(connection, MHD_HTTP_ACCEPTED, "{}");
}

static enum MHD_Result
handle_request(void *arg, struct MHD_Connection *connection, const char *path,
               const char *method, const char *version, const char *upload,
               size_t *upload_size, void **opaque) {
    (void)version;
    struct panel *panel = arg;
    if (!*opaque) {
        *opaque = calloc(1, sizeof(struct request));
        return *opaque ? MHD_YES : MHD_NO;
    }
    struct request *request = *opaque;
    if (*upload_size != 0) {
        if (*upload_size > REQUEST_LIMIT - request->length) {
            request->too_long = 1;
        } else if (!request->too_long) {
            memcpy(request->body + request->length, upload, *upload_size);
            request->length += *upload_size;
        }
        *upload_size = 0;
        return MHD_YES;
    }
    if (!trusted_request(connection))
        return json(connection, MHD_HTTP_FORBIDDEN, "{\"error\":\"origin\"}");
    if (request->too_long)
        return json(connection, MHD_HTTP_CONTENT_TOO_LARGE, "{\"error\":\"size\"}");
    if (memchr(request->body, '\0', request->length))
        return json(connection, MHD_HTTP_BAD_REQUEST, "{\"error\":\"body\"}");

    if (!strcmp(method, "GET")) {
        for (size_t index = 0; index < sizeof(assets) / sizeof(assets[0]); index++) {
            const struct asset *asset = &assets[index];
            if (!strcmp(path, asset->path))
                return respond(connection, MHD_HTTP_OK, asset->type, asset->data,
                               asset->length, MHD_RESPMEM_PERSISTENT);
        }
    } else if (strcmp(method, "POST")) {
        return json(connection, MHD_HTTP_METHOD_NOT_ALLOWED, "{\"error\":\"method\"}");
    }
    const char *marker = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Relay-Panel");
    if (!marker || strcmp(marker, "1"))
        return json(connection, MHD_HTTP_FORBIDDEN, "{\"error\":\"origin\"}");
    if (!strcmp(method, "GET") && !strcmp(path, "/api/local-session")) {
        const union MHD_ConnectionInfo *info =
            MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CONNECTION_FD);
        if (!info || !panel_client_is_local(info->connect_fd))
            return json(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"auth\"}");
        char response[64];
        snprintf(response, sizeof(response), "{\"token\":\"%s\"}", panel->token);
        return json(connection, MHD_HTTP_OK, response);
    }
    if (!strcmp(method, "POST")) {
        if (!strcmp(path, "/api/login"))
            return sign_in(panel, connection, request->body);
        if (!strcmp(path, "/api/show-code")) {
            int64_t now = monotonic_ms();
            if (now < 0 || now < panel->notify_after)
                return json(connection, MHD_HTTP_TOO_MANY_REQUESTS, "{\"error\":\"wait\"}");
            panel->notify_after = now + 5000;
            show_address(panel);
            return json(connection, MHD_HTTP_OK, "{}");
        }
    }
    const char *token = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Relay-Token");
    if (!secret_matches(token, panel->token, TOKEN_LENGTH))
        return json(connection, MHD_HTTP_UNAUTHORIZED, "{\"error\":\"auth\"}");
    if (!strcmp(method, "POST"))
        return set_action(panel, connection, path, request->body);
    if (!strcmp(path, "/api/status"))
        return get_status(panel, connection);
    if (!strcmp(path, "/api/processes"))
        return get_processes(panel, connection);
    if (!strcmp(path, "/api/log"))
        return get_log(connection, RELAY_LOG, LOG_LIMIT);
    if (!strcmp(path, "/api/diagnostics"))
        return get_log(connection, DIAGNOSTICS_PATH, DIAGNOSTICS_LIMIT);
    return json(connection, MHD_HTTP_NOT_FOUND, "{\"error\":\"route\"}");
}

static void
request_done(void *arg, struct MHD_Connection *connection, void **opaque,
             enum MHD_RequestTerminationCode why) {
    (void)arg;
    (void)connection;
    (void)why;
    free(*opaque);
    *opaque = NULL;
}

static void
show_address(const struct panel *panel) {
    char address[INET_ADDRSTRLEN] = "";
    struct ifaddrs *list;
    if (getifaddrs(&list) == 0) {
        for (struct ifaddrs *entry = list; entry; entry = entry->ifa_next) {
            if (!entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET ||
                !(entry->ifa_flags & IFF_UP) || (entry->ifa_flags & IFF_LOOPBACK))
                continue;
            const struct sockaddr_in *local = (const struct sockaddr_in *)entry->ifa_addr;
            if (local->sin_addr.s_addr != htonl(INADDR_ANY) &&
                inet_ntop(AF_INET, &local->sin_addr, address, sizeof(address)))
                break;
        }
        freeifaddrs(list);
    }
    char message[112];
    snprintf(message, sizeof(message), "PS5 Network PIN %s\nhttp://%s:%d", panel->pin,
             address[0] ? address : "<PS5 IP>", PANEL_PORT);
    notify(message);
}

int
panel_run(void) {
    struct panel panel = {
        .mutex = PTHREAD_MUTEX_INITIALIZER, .wake = PTHREAD_COND_INITIALIZER,
        .proxy = {.control = -1, .state = SERVICE_STARTING}, .action = RESTART,
    };
    panel.webview_route.stop = &panel.stop;
    struct sigaction signal_action = {.sa_handler = terminate_panel};
    sigemptyset(&signal_action.sa_mask);
    if (sigaction(SIGTERM, &signal_action, NULL) != 0 ||
        sigaction(SIGINT, &signal_action, NULL) != 0 ||
        sigaction(SIGHUP, &signal_action, NULL) != 0 || init_credentials(&panel) != 0) {
        report_fail("PS5 Network could not initialize login or signals");
        return -1;
    }
    struct MHD_Daemon *server = MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD, PANEL_PORT, NULL, NULL, handle_request, &panel,
        MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int)8,
        MHD_OPTION_CONNECTION_LIMIT, (unsigned int)24,
        MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t)(16 * 1024),
        MHD_OPTION_NOTIFY_COMPLETED, request_done, NULL, MHD_OPTION_END);
    if (!server) {
        report_fail("PS5 Network could not open port %d", PANEL_PORT);
        return -1;
    }
    pthread_t worker;
    int error = pthread_create(&worker, NULL, relay_worker, &panel);
    if (error != 0) {
        MHD_stop_daemon(server);
        report_fail("PS5 Network worker failed: %s", strerror(error));
        return -1;
    }
    show_address(&panel);
    report_log("PS5 Network panel listening on port %d. Login code shown on PS5.", PANEL_PORT);
    struct orbit_watch watch = {0};
    for (;;) {
        const struct timespec pause = {.tv_nsec = 200 * 1000 * 1000};
        nanosleep(&pause, NULL);
        pthread_mutex_lock(&panel.mutex);
        if (terminate_requested)
            panel.closing = 1;
        if (!panel.closing && panel.action != RESTART &&
            panel.action != HTTPS_TEST && panel.action != DOWNLOAD_TEST) {
            proxy_poll(&panel.proxy);
            if (panel.proxy.state == SERVICE_ERROR && panel.action != IDLE)
                request_stop(&panel);
        }
        if (panel.closing) {
            request_stop(&panel);
            pthread_cond_signal(&panel.wake);
        }
        int done = panel.closing && panel.action == IDLE;
        int wake_tracer = panel.action == START && atomic_load(&panel.stop) && atomic_load(&panel.attached);
        pthread_mutex_unlock(&panel.mutex);
        if (done)
            break;
        if (wake_tracer)
            pthread_kill(worker, TRACE_WAKE_SIGNAL);
        else {
            monitor_orbit(&panel, &watch);
            open_webview_if_queued(&panel);
        }
    }
    pthread_join(worker, NULL);
    MHD_stop_daemon(server);
    proxy_stop(&panel.proxy);
    pthread_cond_destroy(&panel.wake);
    pthread_mutex_destroy(&panel.mutex);
    report_log("PS5 Network closed");
    return 0;
}

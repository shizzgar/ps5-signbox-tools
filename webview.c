/* SPDX-License-Identifier: MIT */
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "diagnostics.h"
#include "process.h"
#include "relay.h"
#include "report.h"
#include "trace.h"
#include "webview.h"
#include "webview-imports.h"

enum { WEBVIEW_TARGETS = 4, DISCOVERY_LIMIT = 96, BINDING_RETRY_MS = 300 };

struct browser_target {
    struct process process;
    struct webview_route *route;
    pthread_t thread;
    atomic_bool done;
    int running;
    int result;
    int64_t retry_at;
};

static int
is_webview(const struct process *process) {
    return strcmp(process->name, "SceNKNetworkProcess") == 0 ||
           strcmp(process->name, "SceNKNetworkProc") == 0;
}

static void *
trace_browser(void *argument) {
    struct browser_target *target = argument;
    struct webview_route *route = target->route;
    target->result = trace_webview(target->process.pid, &target->process, NULL, -1, route->stop,
                                   &route->armed, &route->config);
    if (target->result < 0 && !atomic_load(route->stop))
        atomic_fetch_add(&route->failures, 1);
    atomic_store(&target->done, 1);
    return NULL;
}

static void
report_browser_candidates(const struct process *list, size_t count, struct process *seen, size_t *used) {
    for (size_t i = 0; i < count && *used < DISCOVERY_LIMIT; i++) {
        const struct process *process = &list[i];
        if (!is_webview(process) && !strcasestr(process->name, "web") &&
            !strcasestr(process->name, "browser") && strncmp(process->name, "SceNK", 5) != 0 &&
            !strcasestr(process->name, "net"))
            continue;
        size_t prior = 0;
        while (prior < *used && (seen[prior].pid != process->pid ||
               seen[prior].start.tv_sec != process->start.tv_sec || seen[prior].start.tv_usec != process->start.tv_usec))
            prior++;
        if (prior != *used)
            continue;
        seen[(*used)++] = *process;
        report_diag("WebView process candidate name=%s PID=%d selected=%d", process->name,
                    (int)process->pid, is_webview(process));
    }
}

void *
webview_route_run(void *argument) {
    struct webview_route *route = argument;
    struct browser_target targets[WEBVIEW_TARGETS] = {0};
    struct process seen[DISCOVERY_LIMIT];
    size_t seen_count = 0;
    int snapshot_error = 0;
    const struct timespec pause = {.tv_nsec = 100 * 1000 * 1000};
    report_diag("WebView watcher started");
    while (!atomic_load(route->stop)) {
        int64_t now = monotonic_ms();
        for (size_t i = 0; i < WEBVIEW_TARGETS; i++) {
            struct browser_target *target = &targets[i];
            if (target->running && atomic_load(&target->done)) {
                pthread_join(target->thread, NULL);
                target->running = 0;
                if (target->result == TRACE_WEBVIEW_RETRY)
                    target->retry_at = now + BINDING_RETRY_MS;
            }
            if (!target->running && target->process.pid && !process_matches(&target->process))
                target->process.pid = 0;
        }

        struct process *list;
        size_t count;
        if (process_list(&list, &count) == 0) {
            snapshot_error = 0;
            report_browser_candidates(list, count, seen, &seen_count);
            for (size_t i = 0; i < count && !atomic_load(route->stop); i++) {
                if (!is_webview(&list[i]))
                    continue;
                struct browser_target *slot = NULL;
                for (size_t j = 0; j < WEBVIEW_TARGETS; j++) {
                    if (targets[j].process.pid == list[i].pid) {
                        slot = !targets[j].running && targets[j].retry_at && now >= targets[j].retry_at
                            ? &targets[j] : NULL;
                        break;
                    }
                    if (!targets[j].process.pid && !slot)
                        slot = &targets[j];
                }
                if (!slot || !webview_runtime_ready(list[i].pid))
                    continue;
                slot->process = list[i];
                slot->route = route;
                slot->retry_at = 0;
                atomic_store(&slot->done, 0);
                report_log("WebView network process: %s, PID %d", list[i].name, (int)list[i].pid);
                int error = pthread_create(&slot->thread, NULL, trace_browser, slot);
                if (error == 0) {
                    slot->running = 1;
                } else {
                    report_log("Cannot start WebView route (errno=%d)", error);
                    atomic_fetch_add(&route->failures, 1);
                }
            }
            free(list);
        } else if (errno != snapshot_error) {
            snapshot_error = errno;
            report_diag("WebView process snapshot failed errno=%d", snapshot_error);
        }
        nanosleep(&pause, NULL);
    }
    int pending;
    do {
        pending = 0;
        for (size_t i = 0; i < WEBVIEW_TARGETS; i++) {
            struct browser_target *target = &targets[i];
            if (!target->running)
                continue;
            if (atomic_load(&target->done)) {
                pthread_join(target->thread, NULL);
                target->running = 0;
            } else {
                // The syscall fallback can be waiting for an idle process in waitpid.
                pthread_kill(target->thread, TRACE_WAKE_SIGNAL);
                pending++;
            }
        }
        if (pending)
            nanosleep(&pause, NULL);
    } while (pending);
    report_diag("WebView watcher stopped, distinct candidates=%zu failed_routes=%d",
                seen_count, atomic_load(&route->failures));
    return NULL;
}

int
webview_open_check(void) {
    // Keep the native services loaded after the asynchronous browser launch.
    static void *system_service, *user_service;
    pthread_mutex_lock(&trace_kernel_access);
    if (!system_service)
        system_service = dlopen("libSceSystemService.sprx", RTLD_NOW | RTLD_LOCAL);
    if (!user_service)
        user_service = dlopen("libSceUserService.sprx", RTLD_NOW | RTLD_LOCAL);
    if (!system_service || !user_service) {
        pthread_mutex_unlock(&trace_kernel_access);
        report_log("WebView check: could not load PS5 browser services");
        report_diag("WebView browser check could not load native service libraries");
        return -1;
    }

    int (*initialize)(void *) = (int (*)(void *))dlsym(user_service, "sceUserServiceInitialize");
    int (*terminate)(void) = (int (*)(void))dlsym(user_service, "sceUserServiceTerminate");
    int (*launch)(const char *, void *) =
        (int (*)(const char *, void *))dlsym(system_service, "sceSystemServiceLaunchWebBrowser");
    pthread_mutex_unlock(&trace_kernel_access);
    if (!initialize || !terminate || !launch) {
        report_log("WebView check: could not resolve PS5 browser services");
        report_diag("WebView browser check could not resolve native launch functions");
        return -1;
    }

    int result = initialize(NULL);
    if (result != 0) {
        report_log("WebView check: sceUserServiceInitialize returned 0x%08x", (unsigned)result);
        return result;
    }
    const char *url = "https://ipv4.icanhazip.com/";
    result = launch(url, NULL);
    report_diag("WebView native browser launch result=%#x", (unsigned)result);
    if (result == 0)
        report_log("WebView check: PS5 accepted browser launch for %s", url);
    else
        report_log("WebView check: sceSystemServiceLaunchWebBrowser returned 0x%08x", (unsigned)result);
    int cleanup = terminate();
    if (cleanup != 0)
        report_log("WebView check: sceUserServiceTerminate returned 0x%08x", (unsigned)cleanup);
    return result;
}

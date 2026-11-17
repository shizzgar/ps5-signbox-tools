/* SPDX-License-Identifier: MIT */
#ifndef PS5_WEBVIEW_IMPORTS_H
#define PS5_WEBVIEW_IMPORTS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "webview-hook.h"

enum {
    WEBVIEW_IMPORT_LIMIT = 96,
    WEBVIEW_EXPORT_LIMIT = 8,
    WEBVIEW_IMPORT_CURL = 1,
    WEBVIEW_IMPORT_WEBKIT = 2,
    WEBVIEW_IMPORT_REQUIRED = WEBVIEW_IMPORT_CURL | WEBVIEW_IMPORT_WEBKIT,
};

struct webview_import {
    uintptr_t address;
    uintptr_t original;
    uintptr_t hook;
    unsigned module;
};

struct webview_imports {
    struct webview_import slots[WEBVIEW_IMPORT_LIMIT];
    uintptr_t exports[WEBVIEW_EXPORT_LIMIT];
    uintptr_t getpid_entry;
    size_t count;
    size_t export_count;
    struct webview_socket_api socket_api;
};

int webview_runtime_ready(pid_t pid);
int webview_find_imports(pid_t pid, struct webview_imports *imports);
int webview_find_exports(pid_t pid, struct webview_imports *imports);

#endif

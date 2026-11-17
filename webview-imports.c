/* SPDX-License-Identifier: MIT */
#include <elf.h>
#include <errno.h>
#include <ps5/kernel.h>
#include <ps5/nid.h>
#include <stdlib.h>
#include <string.h>

#include "diagnostics.h"
#include "orbit-wire.h"
#include "trace.h"
#include "webview-imports.h"

#ifndef R_X86_64_JUMP_SLOT
#define R_X86_64_JUMP_SLOT R_X86_64_JMP_SLOT
#endif

// Use the image span and dynamic table offsets from the SDK. The fields at
// 0x48 and 0x50 do not describe a user data span on firmware 12.20.
struct module_prefix {
    uint64_t next;
    uint64_t path;
    uint8_t reserved[0x20];
    uint64_t mapbase, mapsize;
    uint8_t rest[0x148 - 0x40];
    uint64_t dynsec;
};

struct dynamic_prefix {
    uint8_t reserved[0x28];
    uint64_t symtab, symtabsize, strtab, strtabsize, pltrela, pltrelasize, rela, relasize;
};

_Static_assert(offsetof(struct module_prefix, mapbase) == 0x30, "unexpected module base");
_Static_assert(offsetof(struct module_prefix, dynsec) == 0x148, "unexpected dynamic table pointer");
_Static_assert(offsetof(struct dynamic_prefix, rela) == 0x58, "unexpected relocation layout");

enum { PROCESS_DYNLIB = 0x3e8, MODULE_LIMIT = 256, TABLE_LIMIT = 8 * 1024 * 1024 };
static const char *const symbols[] = {"connect", "_connect"};
static const char webkit_module[] = "libSceNKWebKit.sprx";
static const char curl_module[] = "libcurl.sprx";

static int
user_function(uintptr_t address) {
    return address >= ORBIT_HOOK_PAGE && address < UINT64_C(0x0000800000000000);
}

int
webview_runtime_ready(pid_t pid) {
    uint32_t webkit, curl;
    pthread_mutex_lock(&trace_kernel_access);
    int ready = kernel_dynlib_handle(pid, webkit_module, &webkit) == 0 &&
                kernel_dynlib_handle(pid, curl_module, &curl) == 0;
    pthread_mutex_unlock(&trace_kernel_access);
    return ready;
}

static int
load_webview_exports(pid_t pid, struct webview_imports *imports) {
    uint32_t handle;
    if (kernel_dynlib_handle(pid, "libkernel_web.sprx", &handle) != 0) {
        errno = ENOENT;
        return -1;
    }

    static const struct { const char *name; size_t offset; } required[] = {
        {"socket", offsetof(struct webview_socket_api, socket)},
        {"connect", offsetof(struct webview_socket_api, connect)},
        {"getsockopt", offsetof(struct webview_socket_api, getsockopt)},
        {"sendto", offsetof(struct webview_socket_api, sendto)},
        {"recvfrom", offsetof(struct webview_socket_api, recvfrom)},
        {"poll", offsetof(struct webview_socket_api, poll)},
        {"close", offsetof(struct webview_socket_api, close)},
        {"__error", offsetof(struct webview_socket_api, error_location)},
    };
    // x86-64 stores a function pointer as one address in the shim's data page.
    _Static_assert(sizeof(void (*)(void)) == sizeof(uintptr_t), "unexpected function pointer ABI");
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        uintptr_t address = (uintptr_t)kernel_dynlib_dlsym(pid, handle, required[i].name);
        if (!user_function(address)) {
            report_diag("WebView PID=%d libkernel_web export missing name=%s", (int)pid, required[i].name);
            errno = ENOSYS;
            return -1;
        }
        memcpy((unsigned char *)&imports->socket_api + required[i].offset, &address, sizeof(address));
    }
    imports->getpid_entry = (uintptr_t)kernel_dynlib_dlsym(pid, handle, "getpid");
    if (!user_function(imports->getpid_entry)) {
        errno = ENOENT;
        return -1;
    }
    imports->exports[imports->export_count++] = (uintptr_t)imports->socket_api.connect;
    uintptr_t alternate = (uintptr_t)kernel_dynlib_dlsym(pid, handle, "_connect");
    if (user_function(alternate) && alternate != imports->exports[0])
        imports->exports[imports->export_count++] = alternate;
    report_diag("WebView PID=%d verified libkernel_web exports for the relay", (int)pid);
    return 0;
}

static int
kernel_range(uint64_t address, uint64_t size) {
    return address >= UINT64_C(0xffff800000000000) && size <= UINT64_MAX - address;
}

static int
symbol_matches(const char *name, size_t available, const char nids[][12]) {
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++) {
        size_t size = strlen(symbols[i]);
        if (available >= 11 && !memcmp(name, nids[i], 11))
            return 1;
        if (available > size && !memcmp(name, symbols[i], size) && name[size] == '\0')
            return 1;
    }
    return 0;
}

static int
collect_slots(const struct module_prefix *module, const struct dynamic_prefix *dynamic,
              uint64_t address, uint64_t size, const Elf64_Sym *symbols_table, const char *strings,
              const char nids[][12], struct webview_imports *imports) {
    if (!size)
        return 0;
    if (size > TABLE_LIMIT || size % sizeof(Elf64_Rela) || !kernel_range(address, size)) {
        errno = ENOEXEC;
        return -1;
    }
    Elf64_Rela *table = malloc((size_t)size);
    if (!table)
        return -1;
    int result = kernel_copyout((intptr_t)address, table, (size_t)size);
    if (result != 0) {
        free(table);
        errno = EIO;
        return -1;
    }
    const uint64_t max_offset = module->mapsize - sizeof(uint64_t);
    const uint64_t last_slot = module->mapbase + max_offset;
    for (size_t i = 0; i < size / sizeof(*table); i++) {
        unsigned type = ELF64_R_TYPE(table[i].r_info);
        size_t index = ELF64_R_SYM(table[i].r_info);
        if ((type != R_X86_64_JUMP_SLOT && type != R_X86_64_GLOB_DAT) ||
            table[i].r_addend ||
            index >= dynamic->symtabsize / sizeof(*symbols_table))
            continue;
        const Elf64_Sym *symbol = &symbols_table[index];
        if (symbol->st_shndx != SHN_UNDEF || symbol->st_name >= dynamic->strtabsize ||
            !symbol_matches(strings + symbol->st_name, dynamic->strtabsize - symbol->st_name, nids))
            continue;
        uint64_t target = table[i].r_offset;
        if (target < module->mapbase || target > last_slot) {
            if (target > max_offset)
                continue;
            target += module->mapbase;
        }
        if (target % sizeof(uint64_t))
            continue;
        size_t slot = 0;
        while (slot < imports->count && imports->slots[slot].address != target)
            slot++;
        if (slot < imports->count)
            continue;
        if (imports->count == WEBVIEW_IMPORT_LIMIT) {
            errno = E2BIG;
            result = -1;
            break;
        }
        imports->slots[imports->count++].address = (uintptr_t)target;
    }
    free(table);
    return result;
}

static int
module_slots(const struct module_prefix *module, const char nids[][12], struct webview_imports *imports) {
    const uint64_t user_limit = UINT64_C(0x0000800000000000);
    if (!module->dynsec || module->mapbase < ORBIT_HOOK_PAGE || module->mapbase >= user_limit ||
        module->mapsize < sizeof(uint64_t) || module->mapsize > user_limit - module->mapbase)
        return 0;
    struct dynamic_prefix dynamic;
    if (!kernel_range(module->dynsec, sizeof(dynamic)) ||
        kernel_copyout((intptr_t)module->dynsec, &dynamic, sizeof(dynamic)) != 0) {
        errno = EIO;
        return -1;
    }
    if (!dynamic.symtabsize || !dynamic.strtabsize || (!dynamic.relasize && !dynamic.pltrelasize))
        return 0;
    if (dynamic.symtabsize > TABLE_LIMIT || dynamic.symtabsize % sizeof(Elf64_Sym) ||
        dynamic.strtabsize > TABLE_LIMIT || !kernel_range(dynamic.symtab, dynamic.symtabsize) ||
        !kernel_range(dynamic.strtab, dynamic.strtabsize)) {
        errno = ENOEXEC;
        return -1;
    }
    Elf64_Sym *symtab = malloc((size_t)dynamic.symtabsize);
    char *strtab = malloc((size_t)dynamic.strtabsize);
    int result = -1;
    if (symtab && strtab) {
        if (kernel_copyout((intptr_t)dynamic.symtab, symtab, (size_t)dynamic.symtabsize) != 0 ||
            kernel_copyout((intptr_t)dynamic.strtab, strtab, (size_t)dynamic.strtabsize) != 0) {
            errno = EIO;
        } else if (collect_slots(module, &dynamic, dynamic.pltrela, dynamic.pltrelasize,
                                 symtab, strtab, nids, imports) == 0) {
            result = collect_slots(module, &dynamic, dynamic.rela, dynamic.relasize, symtab, strtab, nids, imports);
        }
    }
    free(symtab);
    free(strtab);
    return result;
}

static int
scan_modules(pid_t pid, const char nids[][12], struct webview_imports *imports) {
    intptr_t process = kernel_get_proc(pid);
    uint64_t dynlib = 0, address = 0;
    if (!process) {
        errno = ESRCH;
        return -1;
    }
    if (kernel_copyout(process + PROCESS_DYNLIB, &dynlib, sizeof(dynlib)) != 0 ||
        !kernel_range(dynlib, sizeof(address)) ||
        kernel_copyout((intptr_t)dynlib, &address, sizeof(address)) != 0) {
        errno = EIO;
        return -1;
    }
    for (unsigned i = 0; address && i < MODULE_LIMIT; i++) {
        struct module_prefix module;
        if (!kernel_range(address, sizeof(module)) ||
            kernel_copyout((intptr_t)address, &module, sizeof(module)) != 0) {
            errno = EIO;
            return -1;
        }
        size_t previous = imports->count;
        int result = module_slots(&module, nids, imports);
        int detail = errno;
        char path[160] = {0};
        if (!kernel_range(module.path, sizeof(path) - 1) ||
            kernel_copyout((intptr_t)module.path, path, sizeof(path) - 1) != 0)
            path[0] = '\0';
        const char *name = strrchr(path, '/');
        name = name ? name + 1 : path;
        unsigned source = 0;
        if (!strcmp(name, curl_module))
            source = WEBVIEW_IMPORT_CURL;
        else if (!strcmp(name, webkit_module))
            source = WEBVIEW_IMPORT_WEBKIT;
        for (size_t slot = previous; slot < imports->count; slot++)
            imports->slots[slot].module = source;
        report_diag("WebView PID=%d module=%u name=%.80s map=%#lx bytes=%lu imports_added=%zu errno=%d",
                    (int)pid, i, *name ? name : "?", (unsigned long)module.mapbase, (unsigned long)module.mapsize,
                    imports->count - previous, result == 0 ? 0 : detail);
        errno = detail;
        if (result != 0)
            return -1;
        address = module.next;
    }
    if (address) {
        errno = E2BIG;
        return -1;
    }
    return 0;
}

int
webview_find_exports(pid_t pid, struct webview_imports *imports) {
    pthread_mutex_lock(&trace_kernel_access);
    const char *names[] = {"libkernel.sprx", "libkernel_web.sprx", "libkernel_sys.sprx", "libSceNet.sprx"};
    const char *orbit_exports[] = {"connect", "_connect", "sceNetConnect"};
    uint32_t handles[] = {1, 0x2001, 0, 0, 0, 0};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        int result = kernel_dynlib_handle(pid, names[i], &handles[i + 2]);
        report_diag("WebView PID=%d native module %s handle=%#x result=%d", (int)pid, names[i], handles[i + 2], result);
    }
    for (size_t i = 0; i < sizeof(handles) / sizeof(handles[0]); i++) {
        if (!handles[i])
            continue;
        int repeated = 0;
        for (size_t j = 0; j < i; j++)
            repeated |= handles[i] == handles[j];
        if (repeated)
            continue;
        if (!imports->getpid_entry)
            imports->getpid_entry = (uintptr_t)kernel_dynlib_dlsym(pid, handles[i], "getpid");
        for (size_t j = 0; j < sizeof(orbit_exports) / sizeof(orbit_exports[0]); j++) {
            uintptr_t entry = (uintptr_t)kernel_dynlib_dlsym(pid, handles[i], orbit_exports[j]);
            if (!user_function(entry))
                continue;
            report_diag("WebView PID=%d native handle=%#x symbol=%s address=%#lx", (int)pid, handles[i], orbit_exports[j],
                        (unsigned long)entry);
            size_t k = 0;
            while (k < imports->export_count && imports->exports[k] != entry)
                k++;
            if (k == imports->export_count && k < WEBVIEW_EXPORT_LIMIT)
                imports->exports[imports->export_count++] = entry;
        }
    }
    pthread_mutex_unlock(&trace_kernel_access);
    if (!imports->export_count || !imports->getpid_entry) {
        report_diag("PID=%d native exports=%zu getpid=%#lx", (int)pid, imports->export_count,
                    (unsigned long)imports->getpid_entry);
        errno = ENOENT;
        return -1;
    }
    return 0;
}

int
webview_find_imports(pid_t pid, struct webview_imports *imports) {
    char nids[sizeof(symbols) / sizeof(symbols[0])][12];
    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++)
        nid_encode(symbols[i], nids[i]);
    pthread_mutex_lock(&trace_kernel_access);
    int result = load_webview_exports(pid, imports);
    if (result == 0)
        result = scan_modules(pid, nids, imports);
    int error = errno;
    pthread_mutex_unlock(&trace_kernel_access);
    report_diag("WebView PID=%d module scan imports=%zu exports=%zu getpid=%#lx result=%d errno=%d",
                (int)pid, imports->count, imports->export_count, (unsigned long)imports->getpid_entry,
                result, result == 0 ? 0 : error);
    if (result == 0 && !imports->count) {
        errno = ENOENT;
        return -1;
    }
    errno = error;
    return result;
}

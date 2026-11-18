/* SPDX-License-Identifier: MIT */
#ifndef PS5_ORBIT_SOURCE_H
#define PS5_ORBIT_SOURCE_H

#include "orbit-image.h"

#ifndef ORBIT_RUNTIME
#define ORBIT_RUNTIME "/data/orbit-store/orbit_store.elf"
#endif
#ifndef ORBIT_SANDBOX
#define ORBIT_SANDBOX "/mnt/sandbox"
#endif

int orbit_find_runtime_import(const struct orbit_region *regions, size_t count,
                              int (*read_memory)(void *, uintptr_t, void *, size_t), void *context,
                              uintptr_t *base, uintptr_t *slot);

#endif

/* SPDX-License-Identifier: MIT */
#ifndef PS5_ORBIT_IMAGE_H
#define PS5_ORBIT_IMAGE_H

#include <stddef.h>
#include "orbit-wire.h"

int orbit_image(const unsigned char *source, size_t source_size, const struct orbit_config *config, int gate,
                unsigned char **image, size_t *image_size);

struct orbit_region {
    uintptr_t start, end;
    unsigned protection;
};

int orbit_find_live_import(const unsigned char *source, size_t size,
                           const struct orbit_region *regions, size_t count,
                           int (*read_memory)(void *, uintptr_t, void *, size_t), void *context,
                           uintptr_t *base, uintptr_t *slot);

#endif

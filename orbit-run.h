/* SPDX-License-Identifier: MIT */
#ifndef PS5_ORBIT_RUN_H
#define PS5_ORBIT_RUN_H

#include <stddef.h>
#include <stdatomic.h>

int orbit_read_saved(unsigned char **source, size_t *size);
void orbit_probe_diagnostics(const atomic_bool *stop);

#endif

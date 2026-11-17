/* SPDX-License-Identifier: MIT */
#ifndef PS5_NETWORK_DIAGNOSTICS_H
#define PS5_NETWORK_DIAGNOSTICS_H

#include "report.h"

#define DIAGNOSTICS_PATH DATA_DIR "/diagnostics.txt"
enum { DIAGNOSTICS_LIMIT = 256 * 1024 };

int diagnostics_open(void);
void report_diag(const char *format, ...) __attribute__((format(printf, 1, 2)));

#endif

#pragma once

#include <stddef.h>

#ifndef DATA_DIR
#define DATA_DIR "/data/ps5-local-proxy"
#endif

#define PANEL_PROCESS_NAME "ps5-net-panel.elf"
#define PROXY_PROCESS_NAME "ps5-singbox.elf"

int prepare_data_dir(void);
int random_bytes(unsigned char *data, size_t size);
int report_begin(const char *path, int rotate);
void name_payload(const char *name);
void report_log(const char *format, ...) __attribute__((format(printf, 1, 2)));
void report_fail(const char *format, ...) __attribute__((format(printf, 1, 2)));
void notify(const char *message);

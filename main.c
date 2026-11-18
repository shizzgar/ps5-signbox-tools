/* SPDX-License-Identifier: MIT */
#include <errno.h>
#include <fcntl.h>
#include <ps5/kernel.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "diagnostics.h"
#include "panel.h"
#include "report.h"
#include "trace.h"

int
main(void) {
    if ((kernel_get_fw_version() >> 16) != 0x1220) {
        report_fail("PS5 Network supports PS5 firmware 12.20");
        return 1;
    }
    if (prepare_data_dir() != 0)
        return 1;
    int lock = open(DATA_DIR "/tcp-relay.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
    struct stat info;
    if (lock < 0 || fstat(lock, &info) != 0 || !S_ISREG(info.st_mode) ||
        flock(lock, LOCK_EX | LOCK_NB) != 0) {
        report_fail("PS5 Network could not lock relay. Close the running relay panel first.");
        if (lock >= 0)
            close(lock);
        return 1;
    }
    if (report_begin(RELAY_LOG, 1) != 0 || prepare_tracing() != 0) {
        report_fail("PS5 Network could not start the tracer");
        close(lock);
        return 1;
    }
    report_log("PS5 Network 0.22");
    name_payload(PANEL_PROCESS_NAME);
    if (diagnostics_open() != 0) {
        report_log("Could not open diagnostics: %s", strerror(errno));
    } else {
        report_diag("PS5 Network 0.22 firmware=%#x PID=%d local_page_size=%d", kernel_get_fw_version(),
                    (int)getpid(), getpagesize());
    }
    int result = panel_run();
    close(lock);
    return result == 0 ? 0 : 1;
}

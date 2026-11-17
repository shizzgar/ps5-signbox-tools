/* SPDX-License-Identifier: MIT */
#ifndef RELAY_PANEL_H
#define RELAY_PANEL_H

#include "report.h"

#ifndef PANEL_PORT
#define PANEL_PORT 8095
#endif
#define RELAY_LOG DATA_DIR "/tcp-relay.log"

int panel_run(void);

#endif

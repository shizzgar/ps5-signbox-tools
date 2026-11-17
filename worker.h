/* SPDX-License-Identifier: MIT */
#ifndef PS5_NETWORK_WORKER_H
#define PS5_NETWORK_WORKER_H

#define WORKER_MARKER "PS5NET-WORKER-21"
enum { WORKER_MARKER_SIZE = sizeof(WORKER_MARKER) - 1, WORKER_TOKEN_SIZE = 16 };

struct worker_ticket {
    unsigned char marker[WORKER_MARKER_SIZE];
    unsigned char port[2];
    unsigned char token[WORKER_TOKEN_SIZE];
};

struct worker_hello {
    unsigned char token[WORKER_TOKEN_SIZE];
    unsigned char pid[4];
};

#endif

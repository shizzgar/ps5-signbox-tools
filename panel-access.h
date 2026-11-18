/* SPDX-License-Identifier: MIT */
#ifndef PS5_PANEL_ACCESS_H
#define PS5_PANEL_ACCESS_H

int panel_request_is_trusted(int socket, const char *host, const char *origin);
int panel_client_is_local(int socket);

#endif

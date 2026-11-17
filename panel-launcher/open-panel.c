// SPDX-License-Identifier: GPL-3.0-or-later

#include <arpa/inet.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#define PANEL_PORT 8095
#define STRINGIFY_(value) #value
#define STRINGIFY(value) STRINGIFY_(value)

static const char panel_url[] = "http://127.0.0.1:" STRINGIFY(PANEL_PORT) "/";

int sceKernelSendNotificationRequest(int device, void *request, size_t length, int blocking);

static int fail(const char *message) {
    char notification[0xc30] = {0};
    snprintf(notification + 0x2d, sizeof(notification) - 0x2d, "%s", message);
    sceKernelSendNotificationRequest(0, notification, sizeof(notification), 0);
    fprintf(stderr, "%s\n", message);
    return 1;
}

static int panel_is_listening(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return 0;

    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(PANEL_PORT),
        .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
    };
#ifdef __FreeBSD__
    address.sin_len = sizeof(address);
#endif
    int listening = connect(fd, (const struct sockaddr *)&address, sizeof(address)) == 0;
    close(fd);
    return listening;
}

int main(void) {
    if (!panel_is_listening())
        return fail("PS5 Network: start the panel service first");

    void *system = dlopen("libSceSystemService.sprx", RTLD_NOW | RTLD_LOCAL);
    void *user = dlopen("libSceUserService.sprx", RTLD_NOW | RTLD_LOCAL);
    if (!system || !user)
        return fail("PS5 Network: browser services unavailable");

    int (*initialize)(void *) = (int (*)(void *))dlsym(user, "sceUserServiceInitialize");
    int (*terminate)(void) = (int (*)(void))dlsym(user, "sceUserServiceTerminate");
    int (*launch)(const char *, void *) =
        (int (*)(const char *, void *))dlsym(system, "sceSystemServiceLaunchWebBrowser");
    if (!initialize || !terminate || !launch)
        return fail("PS5 Network: browser functions unavailable");

    int result = initialize(NULL);
    if (result != 0) {
        fprintf(stderr, "sceUserServiceInitialize returned 0x%08x\n", (unsigned)result);
        return fail("PS5 Network: could not initialize the browser user");
    }

    result = launch(panel_url, NULL);
    terminate();
    if (result != 0) {
        fprintf(stderr, "sceSystemServiceLaunchWebBrowser returned 0x%08x\n", (unsigned)result);
        return fail("PS5 Network: could not open the panel");
    }

    return 0;
}

// SPDX-License-Identifier: MIT

#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TITLE_ID "PSNT08095"
#define TITLE_ROOT "/user/app/"
#define TITLE_DIR TITLE_ROOT TITLE_ID
#define ASSET_DIR TITLE_DIR "/sce_sys"
#define PARAM_PATH ASSET_DIR "/param.json"
#define ICON_PATH ASSET_DIR "/icon0.png"

extern const unsigned char media_param_start[], media_param_end[];
extern const unsigned char media_icon_start[], media_icon_end[];

int sceSysmoduleLoadModuleInternal(unsigned int id);
int sceKernelSendNotificationRequest(int device, void *request, size_t length, int blocking);

static void announce(const char *message) {
    char request[0xc30] = {0};
    snprintf(request + 0x2d, sizeof(request) - 0x2d, "%s", message);
    sceKernelSendNotificationRequest(0, request, sizeof(request), 0);
    puts(message);
}

static int write_asset(const char *path, const unsigned char *data, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0)
        return -1;

    while (length > 0) {
        ssize_t count = write(fd, data, length);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            int error = count == 0 ? EIO : errno;
            close(fd);
            errno = error;
            return -1;
        }
        data += count;
        length -= (size_t)count;
    }
    return close(fd);
}

static void remove_new_title(void) {
    unlink(ICON_PATH);
    unlink(PARAM_PATH);
    rmdir(ASSET_DIR);
    rmdir(TITLE_DIR);
}

static size_t asset_size(const unsigned char *begin, const unsigned char *end) {
    return (size_t)((uintptr_t)end - (uintptr_t)begin);
}

static int asset_matches(const char *path, const unsigned char *expected, size_t length) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return 0;

    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size != (off_t)length) {
        close(fd);
        return 0;
    }

    unsigned char buffer[512];
    while (length > 0) {
        size_t portion = length < sizeof(buffer) ? length : sizeof(buffer);
        ssize_t count = read(fd, buffer, portion);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0 || memcmp(buffer, expected, (size_t)count) != 0) {
            close(fd);
            return 0;
        }
        expected += count;
        length -= (size_t)count;
    }
    close(fd);
    return 1;
}

static int prepare_title(void) {
    if (mkdir(TITLE_DIR, 0755) != 0) {
        if (errno == EEXIST &&
            asset_matches(PARAM_PATH, media_param_start, asset_size(media_param_start, media_param_end)) &&
            asset_matches(ICON_PATH, media_icon_start, asset_size(media_icon_start, media_icon_end)))
            return 0;
        announce("PS5 Network could not prepare its title directory. Check the existing files.");
        return -1;
    }

    if (mkdir(ASSET_DIR, 0755) != 0) {
        rmdir(TITLE_DIR);
        announce("PS5 Network could not create its assets directory");
        return -1;
    }

    if (write_asset(PARAM_PATH, media_param_start, asset_size(media_param_start, media_param_end)) != 0 ||
        write_asset(ICON_PATH, media_icon_start, asset_size(media_icon_start, media_icon_end)) != 0) {
        remove_new_title();
        announce("PS5 Network could not write the shortcut files");
        return -1;
    }
    return 0;
}

int main(void) {
    int result = sceSysmoduleLoadModuleInternal(0x80000014u);
    if (result < 0) {
        fprintf(stderr, "PS5 application installer module returned 0x%08x\n", (unsigned)result);
        announce("PS5 Network could not initialize the application installer module");
        return 1;
    }

    void *installer = dlopen("libSceAppInstUtil.sprx", RTLD_NOW | RTLD_LOCAL);
    if (!installer) {
        announce("PS5 Network could not load the application installer");
        return 1;
    }

    int (*initialize)(void) = (int (*)(void))dlsym(installer, "sceAppInstUtilInitialize");
    int (*terminate)(void) = (int (*)(void))dlsym(installer, "sceAppInstUtilTerminate");
    int (*install_title)(const char *, const char *, void *) =
        (int (*)(const char *, const char *, void *))dlsym(installer, "sceAppInstUtilAppInstallTitleDir");
    int (*install_all)(void *) = (int (*)(void *))dlsym(installer, "sceAppInstUtilAppInstallAll");
    if (!initialize || !terminate || (!install_title && !install_all)) {
        announce("PS5 Network could not find the title registration function");
        return 1;
    }

    result = initialize();
    if (result != 0) {
        fprintf(stderr, "PS5 app installer initialization returned 0x%08x\n", (unsigned)result);
        announce("PS5 Network could not initialize the application installer");
        return 1;
    }

    if (prepare_title() != 0) {
        terminate();
        return 1;
    }

    if (install_title) {
        result = install_title(TITLE_ID, TITLE_ROOT, NULL);
    } else {
        announce("PS5 Network: refreshing the PS5 application catalog");
        result = install_all(NULL);
    }
    terminate();
    if (result != 0) {
        fprintf(stderr, "PS5 app installation returned 0x%08x\n", (unsigned)result);
        announce("PS5 Network registration did not finish. Keep the files and retry.");
        return 1;
    }

    announce("PS5 Network shortcut added to Media");
    return 0;
}

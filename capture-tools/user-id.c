// SPDX-License-Identifier: MIT
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

extern int sceUserServiceInitialize(void *);
extern int sceUserServiceGetForegroundUser(int32_t *);
extern int sceUserServiceGetLoginUserIdList(int32_t *);

int main(void) {
    if (sceUserServiceInitialize(NULL) != 0)
        return 1;
    int32_t user = -1, logged[4] = {-1, -1, -1, -1};
    int foreground_result = sceUserServiceGetForegroundUser(&user);
    int list_result = sceUserServiceGetLoginUserIdList(logged);
    int fd = open("/data/ps5-devloop-user.txt",
                  O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    struct stat info;
    if (fd < 0)
        return 1;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || ftruncate(fd, 0) != 0) {
        close(fd);
        return 1;
    }
    char text[256];
    int length = snprintf(text, sizeof(text),
        "foreground=0x%08x result=0x%08x\n"
        "logged=0x%08x,0x%08x,0x%08x,0x%08x result=0x%08x\n",
        (unsigned)user, (unsigned)foreground_result,
        (unsigned)logged[0], (unsigned)logged[1],
        (unsigned)logged[2], (unsigned)logged[3], (unsigned)list_result);
    int result = length > 0 && (size_t)length < sizeof(text) &&
                 write(fd, text, (size_t)length) == length ? 0 : 1;
    close(fd);
    return result;
}

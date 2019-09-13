#include "tuns.h"

#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int tun_alloc(char** dev)
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
        return fd;

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if ((err = ioctl(fd, TUNSETIFF, (void*) &ifr)) < 0) {
        close(fd);
        return err;
    }

    if (!(*dev = (char*) malloc(strlen(ifr.ifr_name) + 1))) {
        perror("Allocation failed");
        exit(1);
    }

    strcpy(*dev, ifr.ifr_name);
    return fd;
}

void tun_mirror(int fd, void (*logger)(int)) {
    int buf_sz = 2048;
    char* buf;

    if (!(buf = (char*) malloc(buf_sz))) {
        perror("Allocation failed");
        exit(1);
    }

    while (1) {
        int got_count = read(fd, buf, buf_sz);
        if (got_count < 0) {
            perror("Cannot read from the tunnel");
            return;
        }

        int written_count, pos = 0;
        while (pos < got_count) {
            written_count = write(fd, buf + pos, got_count - pos);
            if (written_count < 0) {
                perror("Cannot write to the tunnel");
                return;
            }

            pos += written_count;
        }

        logger(got_count);
    }
}

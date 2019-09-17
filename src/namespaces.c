#include "namespaces.h"

#define _GNU_SOURCE

#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>


int get_netns_fd()
{
    char path[1024];
    int pid = getpid();
    if (sprintf(path, "/proc/%d/ns/net", pid) <= 0) {
        return -1;
    }

    return open(path, O_RDONLY);
}

int new_netns()
{
    return unshare(CLONE_NEWNET);
}

int set_netns(int fd)
{
    return setns(fd, CLONE_NEWNET);
}

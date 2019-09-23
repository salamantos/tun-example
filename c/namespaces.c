#define _GNU_SOURCE

#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sched.h>
#include <wait.h>

#include "namespaces.h"


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

int disable_interrupting_signals()
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTERM);
    return pthread_sigmask(SIG_BLOCK, &set, NULL);
}

int wait_interrupting_signals()
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGTERM);
    int sig;
    if (!sigwait(&set, &sig))
        return sig;
    return -1;
}

int run_with_credentials(const char* cmd, uid_t uid, gid_t gid)
{
    pid_t fork_res = fork();
    if (fork_res == -1)
        return -1;

    if (fork_res)
        return fork_res;

    if (setgid(gid)) {
        perror("setgid");
        exit(1);
    }
    if (setuid(uid)) {
        perror("setuid");
        exit(1);
    }

    if (execl("/bin/sh", "sh", "-c", cmd, NULL)) {
        perror("execl");
        exit(1);
    }
}

int terminate_process(pid_t pid, int sig) {
    if (!pid)
        return 0;

    if (kill(pid, sig))
        return -1;
    if (waitpid(pid, NULL, 0) == -1)
        return -1;
    return 0;
}

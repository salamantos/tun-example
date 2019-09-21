#pragma once

#include <sys/types.h>

int get_netns_fd();

int new_netns();

int set_netns(int fd);

int disable_interrupting_signals();
int wait_interrupting_signals();

int run_with_credentials(const char*,uid_t,gid_t);
int terminate_process(pid_t pid);
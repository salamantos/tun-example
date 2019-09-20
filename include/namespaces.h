#pragma once


int get_netns_fd();

int new_netns();

int set_netns(int fd);

int disable_interrupting_signals();
int wait_interrupting_signals();

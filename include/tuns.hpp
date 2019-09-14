#pragma once

#include <cstdio>



int tun_alloc(char** dev);
void tun_mirror(int fd, void (*logger)(char*, size_t));

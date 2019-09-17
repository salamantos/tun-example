#pragma once

#include <stdio.h>



int tun_alloc(char** dev);
void tun_receive(int fd, void (* logger)(char*, size_t));

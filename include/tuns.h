#pragma once

int tun_alloc(char** dev);
void tun_mirror(int fd, void (*logger)(int));

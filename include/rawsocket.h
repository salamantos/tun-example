#pragma once

#include <sys/socket.h>
#include <netinet/in.h>

int prepare_ip_socket();
int safe_send(int fd, uint32_t addr, char* buf, size_t sz);
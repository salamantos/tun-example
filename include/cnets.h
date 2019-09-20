#pragma once


#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "ipv4h.h"

uint16_t raw_checksum(const void* addr, size_t count, uint64_t);

uint16_t checksum(struct IpHeader* header);
uint16_t tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                          const char* data, uint16_t len);
struct IpHeader* load_ip_header(char* buf);
struct TcpHeader* load_tcp_header(char* buf);

int init_server_socket(uint16_t port);
int init_client_socket(const char* bind_addr, const char* addr, uint16_t port);

// returns fd which is ready to accept connection
// or -fd, where fd is broken
// or very small negative number on some other error
// or 0 if timeout exceeded
int epoll_accept(int* fds, size_t count, int interruptor);
int epoll_interrupt(int interruptor);

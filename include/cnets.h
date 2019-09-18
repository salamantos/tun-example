#pragma once


#include <arpa/inet.h>
#include "ipv4h.h"

uint16_t raw_checksum(const void* addr, size_t count, uint32_t);

uint16_t checksum(struct IpHeader* header);
uint16_t tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                          const char* data, uint16_t len);
struct IpHeader* load_ip_header(char* buf);
struct TcpHeader* load_tcp_header(char* buf);

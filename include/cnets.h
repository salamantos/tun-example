#pragma once


#include <arpa/inet.h>
#include "ipv4h.h"

uint16_t raw_checksum(void* addr, size_t count);

uint16_t checksum(struct IpHeader* header);
struct IpHeader* load_ip_header(char* buf);

void ntoh(struct IpHeader* header);
void hton(struct IpHeader* header);
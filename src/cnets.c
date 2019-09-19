#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "cnets.h"



uint64_t sum_every_16bits(const void* addr, int count)
{
    uint64_t sum = 0;
    uint16_t* ptr = (uint16_t*) addr;

    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(uint8_t*) ptr;

    return sum;
}

uint16_t raw_checksum(const void* addr, size_t count, uint64_t start)
{
    uint64_t sum = start;

    sum += sum_every_16bits(addr, count);


    while (sum >> 16u)
        sum = (sum & 0xffffu) + (sum >> 16u);

    return ~sum;
}

uint16_t tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
                     const char* data, uint16_t len)
{
    uint64_t sum = 0;

    sum += saddr;
    sum += daddr;
    sum += htons(proto);
    sum += htons(len);

    return raw_checksum(data, len, sum);
}

uint16_t checksum(struct IpHeader* header)
{
    uint16_t old = header->csum;
    header->csum = 0;
    uint16_t csum = raw_checksum((void*) header, header->ihl * 4, 0);
    header->csum = old;
    return csum;
}


struct IpHeader* load_ip_header(char* buf)
{
    return (struct IpHeader*) buf;
}

struct TcpHeader* load_tcp_header(char* buf)
{
    return (struct TcpHeader*) buf;
}


void ntoh(struct IpHeader* header)
{
    header->len = ntohs(header->len);
    header->id = ntohs(header->id);
    header->frag_offset = ntohs(header->frag_offset);
    header->csum = ntohs(header->csum);
    header->saddr = ntohl(header->saddr);
    header->daddr = ntohl(header->daddr);
}


void hton(struct IpHeader* header)
{
    header->len = htons(header->len);
    header->id = htons(header->id);
    header->frag_offset = htons(header->frag_offset);
    header->saddr = htonl(header->saddr);
    header->daddr = htonl(header->daddr);
}

int init_server_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return fd;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) ||
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &val, sizeof(val))) {
        return -1;
    }

    if (bind(fd, (struct sockaddr*) &addr, sizeof(addr))) {
        return -1;
    }

    listen(fd, 3);
    return fd;
}

int init_client_socket(const char* addr_str, uint16_t port) {
    struct in_addr addr_struct;
    inet_pton(AF_INET, addr_str, &addr_struct);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = addr_struct.s_addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return fd;
    }

    if (connect(fd, (const struct sockaddr*) &addr, sizeof(struct sockaddr_in))) {
        return -1;
    }

    return fd;
}

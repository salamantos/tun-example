#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "cnets.h"



uint64_t sum_every_16bits(const void* addr, size_t count)
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

int init_client_socket(const char* bind_addr_str, const char* addr_str, uint16_t port) {
    struct in_addr addr_struct;
    if (!inet_pton(AF_INET, addr_str, &addr_struct))
        return -1;

    struct in_addr bind_addr_struct;
    if (!inet_pton(AF_INET, bind_addr_str, &bind_addr_struct))
        return -1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return fd;
    }

    int val = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, &val, sizeof(val))) {
        return -1;
    }

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_addr.s_addr = bind_addr_struct.s_addr;
    bind_addr.sin_family = AF_INET;

    if (bind(fd, (const struct sockaddr*) &bind_addr, sizeof(struct sockaddr_in)))
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = addr_struct.s_addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (connect(fd, (const struct sockaddr*) &addr, sizeof(struct sockaddr_in))) {
        return -1;
    }

    return fd;
}


// returns fd which is ready to accept connection
// or -fd, where fd is broken
// or 0 on some other error
int epoll_accept(int* fds, size_t count) {
    return fds[0];
}

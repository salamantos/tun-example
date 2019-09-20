#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>

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

    // TODO: think about it
//    if (bind(fd, (const struct sockaddr*) &bind_addr, sizeof(struct sockaddr_in)))
//        return -1;

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
// or very small negative number on some other error
// or 0 if was interrupted
int epoll_accept(int* fds, size_t count, int interruptor) {
    int epoll_fd = epoll_create(1);
    if (epoll_fd < 0)
        goto panic;

    if (interruptor > 0) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLONESHOT;
        ev.data.u64 = 0;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, interruptor, &ev))
            goto panic;
    }

    for (size_t i = 0; i < count; ++i) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLONESHOT;
        ev.data.u64 = fds[i];
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fds[i], &ev))
            goto panic;
    }

    struct epoll_event evs[32];
    int wait_res = epoll_wait(epoll_fd, evs, 32, -1);
    if (wait_res < 0)
        goto panic;
    close(epoll_fd);

    if (wait_res == 0)
        return 0;

    for (int i = 0; i < wait_res; ++i) {
        struct epoll_event ev = evs[i];
        if (ev.data.u64 == 0) {
            uint64_t val;
            if (read(interruptor, &val, 8) < 0)
                goto panic;
            // interrupted
            return 0;
        }
    }

    int bad_fd = -1;
    for (int i = 0; i < wait_res; ++i) {
        struct epoll_event ev = evs[i];
        if (ev.events & EPOLLIN)
            return ev.data.u64;

        bad_fd = ev.data.u64;
    }

    if (bad_fd > 0)
        return -bad_fd;
    return 0;

    panic:
        if (epoll_fd > 0)
            close(epoll_fd);
        return -(1u << (sizeof(int) - 2));
}

int epoll_interrupt(int event_fd) {
    uint64_t val = 1;
    int written = write(event_fd, &val, 8);
    if (written <= 0) {
        close(event_fd);
        return -1;
    }
    return 0;
}

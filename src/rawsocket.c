#include "rawsocket.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>



int prepare_ip_socket()
{
    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_socket < 0) {
        return raw_socket;
    }

    int val = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &val, sizeof(int))) {
        return -1;
    }

    return raw_socket;
}

int safe_send(int fd, uint32_t ip_addr, char* buf, size_t sz)
{
    int written_count;
    size_t pos = 0;

    while (pos < sz) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(struct sockaddr_in));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ip_addr;

        written_count = sendto(fd, buf + pos, sz - pos, 0, (const struct sockaddr*) &addr, sizeof(struct sockaddr_in));
        if (written_count < 0) {
            perror("Cannot write to fd");
            break;
        }

        pos += written_count;
    }

    return pos;
}

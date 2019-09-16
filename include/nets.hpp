#pragma once


#include <arpa/inet.h>

namespace net {
using addr_t = uint32_t;
using port_t = uint16_t;

uint32_t sum_every_16bits(void* addr, int count)
{
    uint32_t sum = 0;
    uint16_t* ptr = reinterpret_cast<uint16_t*>(addr);

    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(uint8_t*) ptr;

    return sum;
}

uint16_t checksum(void* addr, size_t count)
{
    uint32_t sum = 0;

    sum += sum_every_16bits(addr, count);


    while (sum >> 16u)
        sum = (sum & 0xffffu) + (sum >> 16u);

    return ~sum;
}


#pragma pack(push, 1)
struct IpHeader {
    uint8_t ihl : 4;
    uint8_t version : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint32_t saddr;
    uint32_t daddr;
    uint8_t data[];
};
#pragma pack(pop)


uint16_t checksum(IpHeader* header) {
    uint16_t old = header->csum;
    header->csum = 0;
    uint16_t csum = checksum((void*) header, header->ihl * 4);
    header->csum = old;
    return csum;
}


IpHeader* load_ip(char* buf)
{
    return reinterpret_cast<IpHeader*>(buf);
}

std::string addr_to_string(const addr_t addr)
{
    char res[16];
    struct in_addr addr_struct{};

    addr_struct.s_addr = addr;

    inet_ntop(AF_INET, &addr_struct, res, 16);
    return res;
}

void ntoh(IpHeader* header) {
    header->len = ntohs(header->len);
    header->id = ntohs(header->id);
    header->frag_offset = ntohs(header->frag_offset);
    header->csum = ntohs(header->csum);
    header->saddr = ntohl(header->saddr);
    header->daddr = ntohl(header->daddr);
}


void hton(IpHeader* header) {
    header->len = htons(header->len);
    header->id = htons(header->id);
    header->frag_offset = htons(header->frag_offset);
    header->saddr = htonl(header->saddr);
    header->daddr = htonl(header->daddr);
}

}

#include <arpa/inet.h>
#include "cnets.h"



uint32_t sum_every_16bits(void* addr, int count)
{
    uint32_t sum = 0;
    uint16_t* ptr = (uint16_t*) addr;

    while (count > 1) {
        sum += *ptr++;
        count -= 2;
    }

    if (count > 0)
        sum += *(uint8_t*) ptr;

    return sum;
}

uint16_t raw_checksum(void* addr, size_t count)
{
    uint32_t sum = 0;

    sum += sum_every_16bits(addr, count);


    while (sum >> 16u)
        sum = (sum & 0xffffu) + (sum >> 16u);

    return ~sum;
}

uint16_t checksum(struct IpHeader* header)
{
    uint16_t old = header->csum;
    header->csum = 0;
    uint16_t csum = raw_checksum((void*) header, header->ihl * 4);
    header->csum = old;
    return csum;
}


struct IpHeader* load_ip_header(char* buf)
{
    return (struct IpHeader*) buf;
}


void ntoh(struct IpHeader* header) {
    header->len = ntohs(header->len);
    header->id = ntohs(header->id);
    header->frag_offset = ntohs(header->frag_offset);
    header->csum = ntohs(header->csum);
    header->saddr = ntohl(header->saddr);
    header->daddr = ntohl(header->daddr);
}


void hton(struct IpHeader* header) {
    header->len = htons(header->len);
    header->id = htons(header->id);
    header->frag_offset = htons(header->frag_offset);
    header->saddr = htonl(header->saddr);
    header->daddr = htonl(header->daddr);
}
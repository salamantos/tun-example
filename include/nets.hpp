#pragma once


#include <arpa/inet.h>
// COPYPASTED from stackoverflow

namespace Net {
using addr_t = uint32_t;
using port_t = uint16_t;



struct ip_header_t {
    uint8_t ver_ihl;  // 4 bits version and 4 bits internet header length
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fo; // 3 bits flags and 13 bits fragment-offset
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    addr_t src_addr;
    addr_t dst_addr;

    uint8_t ihl() const;

    size_t size() const;
};


uint8_t ip_header_t::ihl() const
{
    return (ver_ihl & 0x0F);
}

size_t ip_header_t::size() const
{
    return ihl() * sizeof(uint32_t);
}

ip_header_t load_ip(std::istream& stream, bool ntoh = false)
{
    ip_header_t header;
    stream.read((char*) &header.ver_ihl, sizeof(header.ver_ihl));
    stream.read((char*) &header.tos, sizeof(header.tos));
    stream.read((char*) &header.total_length, sizeof(header.total_length));
    stream.read((char*) &header.id, sizeof(header.id));
    stream.read((char*) &header.flags_fo, sizeof(header.flags_fo));
    stream.read((char*) &header.ttl, sizeof(header.ttl));
    stream.read((char*) &header.protocol, sizeof(header.protocol));
    stream.read((char*) &header.checksum, sizeof(header.checksum));
    stream.read((char*) &header.src_addr, sizeof(header.src_addr));
    stream.read((char*) &header.dst_addr, sizeof(header.dst_addr));
    if (ntoh) {
        header.total_length = ntohs(header.total_length);
        header.id = ntohs(header.id);
        header.flags_fo = ntohs(header.flags_fo);
        header.checksum = ntohs(header.checksum);
        header.src_addr = ntohl(header.src_addr);
        header.dst_addr = ntohl(header.dst_addr);
    }
    return header;
}

std::string addr_to_string(const addr_t addr) {
    char res[16];
    struct in_addr addr_struct{};

    addr_struct.s_addr = addr;

    inet_ntop(AF_INET, &addr_struct, res, 16);
    return res;
}

}

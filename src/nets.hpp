#pragma once

#include <sstream>



namespace nets {

#include "ipv4h.h"



extern "C" {

#include "cnets.h"



}


class IPException : public std::runtime_error {
private:

public:
    IPException(const std::string& err)
        : std::runtime_error(err)
    {}
};


class IPv4Packet {
public:
    std::string container;
    IpHeader* raw;

    IPv4Packet()
        : raw(nullptr)
    {}

    IPv4Packet(char* buf)
        : raw(load_ip_header(buf))
    {
        std::ostringstream msg;
        if (raw->version != 0x04) {
            msg << "Version: " << static_cast<int>(raw->version) << ". Not IPv4";
            throw IPException(msg.str());
        }

        if (length() < 20 || raw->ihl < 5) {
            msg << "Corrupted";
            throw IPException(msg.str());
        }

        if (!ttl()) {
            msg << "Dead";
            throw IPException(msg.str());
        }

        uint16_t csum = checksum(raw);
        uint16_t provided_csum = raw->csum;
        if (csum != provided_csum) {
            msg << "Corrupted: " << provided_csum << " " << csum;
            throw IPException(msg.str());
        }

        container = {buf, length()};
        raw = load_ip_header(container.data());
    }


    IPv4Packet(const IPv4Packet& oth)
        : container(oth.container), raw(load_ip_header(container.data()))
    {}

    IPv4Packet& operator=(const IPv4Packet& oth)
    {
        container = oth.container;
        raw = load_ip_header(container.data());
        return *this;
    }

    uint16_t length() const
    {
        return ntohs(raw->len);
    }

    uint8_t ttl() const
    {
        return raw->ttl;
    }

    void decrease_ttl()
    {
        --raw->ttl;
        recompute_csum();
    }

    bool is_tcp() const {
        return raw_tcp() != nullptr;
    }

    std::string source_addr() const
    {
        return addr_to_string(raw->saddr);
    }

    std::string destination_addr() const
    {
        return addr_to_string(raw->daddr);
    }

    void set_source(const std::string addr)
    {
        in_addr addr_struct{};
        inet_pton(AF_INET, addr.c_str(), &addr_struct);
        raw->saddr = addr_struct.s_addr;
        recompute_csum();
    }

    void set_destination(const std::string addr)
    {
        in_addr addr_struct{};
        inet_pton(AF_INET, addr.c_str(), &addr_struct);
        raw->daddr = addr_struct.s_addr;
        recompute_csum();
    }

    char* raw_bytes()
    {
        return reinterpret_cast<char*>(raw);
    }
    const char* raw_bytes() const
    {
        return reinterpret_cast<const char*>(raw);
    }

    TcpHeader* raw_tcp() {
        if (raw->proto == PROTO_TCP) {
            return load_tcp_header(raw_bytes() + raw->ihl * 4);
        }
        return nullptr;
    }

    const TcpHeader* raw_tcp() const {
        if (raw->proto == PROTO_TCP) {
            return load_tcp_header(const_cast<char*>(raw_bytes()) + raw->ihl * 4);
        }
        return nullptr;
    }

    void recompute_tcp_csum()
    {
        raw_tcp()->csum = compute_tcp_checksum();
    }

private:
    uint16_t compute_tcp_checksum() {
        uint16_t offset = (raw->ihl) * 4;
        uint16_t len = length() - offset;
        uint16_t old = raw_tcp()->csum;
        raw_tcp()->csum = 0;
        uint16_t res = tcp_udp_checksum(raw->saddr, raw->daddr, raw->proto, raw_bytes() + offset, len);
        raw_tcp()->csum = old;
        return res;
    }

    std::string addr_to_string(const uint32_t addr) const
    {
        char res[16];
        in_addr addr_struct{};

        addr_struct.s_addr = addr;

        inet_ntop(AF_INET, &addr_struct, res, 16);
        return res;
    }

    void recompute_csum()
    {
        raw->csum = checksum(raw);
    }
};

}

#pragma once

#include <sstream>
#include <atomic>
#include <thread>



extern "C" {

#include <unistd.h>
}

namespace nets {

#include "ipv4h.h"



extern "C" {

#include "cnets.h"



}


class IPException : public std::runtime_error {
public:
    IPException(const std::string& err)
        : std::runtime_error(err)
    {}
};


class IPv4Packet {
private:
    std::unique_ptr<char[]> buffer;
    IpHeader* raw;

public:
    uint8_t origin_id;

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

        buffer = std::unique_ptr<char[]>(new char[length()]);
        std::copy(buf, buf + length(), buffer.get());
        raw = load_ip_header(buffer.get());
    }


    IPv4Packet(const IPv4Packet& oth)
        : buffer(new char[oth.length()]), raw(nullptr), origin_id{oth.origin_id}
    {
        std::copy(oth.buffer.get(), oth.buffer.get() + oth.length(), buffer.get());
        raw = load_ip_header(buffer.get());
    }

    IPv4Packet& operator=(const IPv4Packet& oth)
    {
        buffer = std::unique_ptr<char[]>(new char[oth.length()]);
        std::copy(oth.buffer.get(), oth.buffer.get() + oth.length(), buffer.get());
        raw = load_ip_header(buffer.get());
        origin_id = oth.origin_id;
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

    const char* raw_bytes() const
    {
        return reinterpret_cast<const char*>(raw);
    }


    bool is_tcp() const
    {
        return raw_tcp() != nullptr;
    }

    uint16_t validate_tcp() {
        if (compute_tcp_checksum() != raw_tcp()->csum)
            throw IPException{"TCP packet corrupted"};
        return raw_tcp()->csum;
    }

    bool is_tcp_handshake() const
    {
        return raw_tcp()->syn;
    }

    bool is_tcp_shutdown() const
    {
        return raw_tcp()->fin;
    }

    uint32_t tcp_seqnum() const
    {
        return ntohl(raw_tcp()->seq);
    }

    uint32_t tcp_acknum() const
    {
        return ntohl(raw_tcp()->ack_seq);
    }

    uint16_t tcp_sport() const
    {
        return ntohs(raw_tcp()->sport);
    }

    uint16_t tcp_dport() const
    {
        return ntohs(raw_tcp()->dport);
    }

    void set_seqnum(uint32_t seqnum)
    {
        raw_tcp()->seq = htonl(seqnum);
        recompute_tcp_csum();
    }

    void tcp_acknum(uint32_t acknum)
    {
        raw_tcp()->ack_seq = htonl(acknum);
        recompute_tcp_csum();
    }

    void set_source_port(uint16_t port)
    {
        raw_tcp()->sport = ntohs(port);
        recompute_tcp_csum();
    }

    void set_destination_port(uint16_t port)
    {
        raw_tcp()->dport = ntohs(port);
        recompute_tcp_csum();
    }

    bool flag_syn() const
    {
        return raw_tcp()->syn;
    }

    bool flag_ack() const
    {
        return raw_tcp()->ack;
    }

    bool flag_fin() const
    {
        return raw_tcp()->fin;
    }

private:
    void recompute_tcp_csum()
    {
        raw_tcp()->rsvd = 0;
        raw_tcp()->csum = compute_tcp_checksum();
    }

    char* raw_bytes()
    {
        return reinterpret_cast<char*>(raw);
    }

    TcpHeader* raw_tcp()
    {
        if (raw->proto == PROTO_TCP) {
            return load_tcp_header(raw_bytes() + raw->ihl * 4);
        }
        return nullptr;
    }

    const TcpHeader* raw_tcp() const
    {
        if (raw->proto == PROTO_TCP) {
            return load_tcp_header(const_cast<char*>(raw_bytes()) + raw->ihl * 4);
        }
        return nullptr;
    }

    uint16_t compute_tcp_checksum()
    {
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
        if (is_tcp())
            recompute_tcp_csum();
    }
};


class SocketPipe {
private:
    static constexpr size_t buf_sz = 2048;

    int server_sock = -1;
    int client_sock = -1;
    int server_client_sock = -1;

    std::string other_address;
    uint16_t other_port;

    std::atomic<int> stopped{0};

public:
    SocketPipe(const std::string& addr, uint16_t port)
        : other_address(addr), other_port(port)
    {
        server_sock = init_server_socket(port);
        if (server_sock < 0)
            throw std::runtime_error("Cannot initialize server socket");
    }

    void accept_client()
    {
        std::cout << 1 << std::endl;
        client_sock = init_client_socket(other_address.c_str(), other_port);
        if (client_sock < 0) {
            throw std::runtime_error("Cannot connect to the other side");
        }

        std::cout << 2 << std::endl;
        server_client_sock = accept(server_sock, NULL, 0);
        close(server_sock);
        if (server_client_sock < 0)
            throw std::runtime_error("Cannot accept connection");

        std::cout << 3 << std::endl;
    }

    void start_mirroring()
    {
        // TODO: use multiplexing
        std::thread{
            [this]() {
                mirror(server_client_sock, client_sock);
            }
        }.detach();
        std::thread{
            [this]() {
                mirror(client_sock, server_client_sock);
            }
        }.detach();
    }

    ~SocketPipe()
    {
        stopped.store(1);
        if (client_sock >= 0)
            close(client_sock);
        if (server_client_sock >= 0)
            close(server_client_sock);
        if (server_sock >= 0)
            close(server_sock);
    }

private:
    void mirror(int fd_from, int fd_to)
    {
        char buf[buf_sz];

        try {
            while (!stopped.load()) {
                int got_count = read(fd_from, buf, buf_sz);
                if (got_count < 0) {
                    throw std::runtime_error("Cannot read from the socket");
                }

                int written_count, pos = 0;
                while (pos < got_count) {
                    written_count = write(fd_to, buf + pos, got_count - pos);
                    if (written_count < 0) {
                        throw std::runtime_error("Cannot write to the socket");
                    }

                    pos += written_count;
                }
            }
        } catch (std::runtime_error& err) {
            if (!stopped.load())
                throw err;
        }
    }
};

}

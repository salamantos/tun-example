#pragma once

#include <sstream>
#include <atomic>
#include <set>
#include <thread>
#include <functional>

#include "multiplexing.hpp"

#include <unistd.h>


#include "ipv4h.h"



extern "C" {
#include "cnets.h"
}


namespace nets {

class IPException : public std::runtime_error {
public:
    IPException(const std::string& err)
        : std::runtime_error(err)
    {}
};


auto get_microsecond_timestamp()
{
    using std::chrono::microseconds;
    using std::chrono::system_clock;
    using std::chrono::duration_cast;
    return duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
}

std::string addr_to_string(const uint32_t addr)
{
    char res[16];
    in_addr addr_struct{};

    addr_struct.s_addr = addr;

    inet_ntop(AF_INET, &addr_struct, res, 16);
    return res;
}

uint32_t addr_to_inet(const std::string& addr)
{
    in_addr addr_struct{};
    if (!inet_pton(AF_INET, addr.c_str(), &addr_struct)) {
        throw IPException("Invalid address");
    }
    return addr_struct.s_addr;
}


class Subnet {
private:
    uint32_t address = 0; // network notation
    uint8_t mask_len = 0;

    Subnet(uint32_t addr, uint8_t len)
        : address(addr), mask_len(len)
    {}

public:
    Subnet() = default;

    explicit Subnet(const std::string& addr)
    {
        auto slash_pos = addr.find('/');
        try {
            if (slash_pos == std::string::npos) {
                mask_len = 0;
                address = addr_to_inet(addr);
            } else {
                mask_len = std::stoi(addr.substr(slash_pos + 1));
                address = addr_to_inet(addr.substr(0, slash_pos));
            }
        } catch (std::out_of_range&) {
            throw IPException("Invalid address");
        } catch (std::invalid_argument&) {
            throw IPException("Invalid address");
        }
    }

    std::string masquerade(const std::string& addr_str) const
    {
        uint32_t addr = ntohl(addr_to_inet(addr_str));
        uint32_t subnet = ntohl(address);
        uint32_t mask = get_mask();
        uint32_t res = (subnet & mask) | (addr & ~mask);
        return addr_to_string(htonl(res));
    }

    uint8_t mask_length() const
    {
        return mask_len;
    }

    uint32_t get_mask() const
    {
        return ~((1ul << (32u - mask_len)) - 1ul);
    }

    Subnet inversed() const
    {
        return Subnet{htonl(ntohl(address) ^ get_mask()), mask_len};
    }

    explicit operator std::string() const
    {
        return addr_to_string(address) + "/" + std::to_string(mask_len);
    }

    std::string address_only() const
    {
        return addr_to_string(address);
    }

    Subnet operator[](uint32_t index) const
    {
        if (index & get_mask())
            throw std::out_of_range("Subnet is too small");
        return Subnet{htonl((ntohl(address) & get_mask()) | index), mask_len};
    }
};


using ConnectionSideId = std::pair<std::string, int>;

bool operator<(const ConnectionSideId& a, const ConnectionSideId& b)
{
    return a.first < b.first || (a.first == b.first && a.second < b.second);
}


struct ConnectionId {
    std::string client_addr;
    ConnectionSideId server_side;
};

bool operator<(const ConnectionId& a, const ConnectionId& b)
{
    return a.client_addr < b.client_addr || (a.client_addr == b.client_addr && a.server_side < b.server_side);
}

std::istream& operator>>(std::istream& stream, ConnectionId& id)
{
    return stream >> id.client_addr >> id.server_side.first >> id.server_side.second;
}

std::ostream& operator<<(std::ostream& stream, const ConnectionId& id)
{
    return stream << id.client_addr << ' ' << id.server_side.first << ' ' << id.server_side.second;
}


class IPv4Packet {
private:
    std::unique_ptr<char[]> buffer;
    IpHeader* raw;

public:
    std::string origin_id;

    IPv4Packet()
        : raw(nullptr)
    {}

    IPv4Packet(char* buf, size_t maxlen)
        : raw(load_ip_header(buf))
    {
        std::ostringstream msg;
        if (maxlen < 20 || maxlen < length()) {
            msg << "Too short";
            throw IPException(msg.str());
        }

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

    uint8_t protocol() const
    {
        return raw->proto;
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

    bool is_valid_tcp()
    {
        uint16_t tcp_part_len = length() - raw->ihl * 4;
        return tcp_part_len >= 20 && compute_tcp_checksum() == raw_tcp()->csum;
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

    ConnectionSideId destination_side()
    {
        return {destination_addr(), tcp_dport()};
    }

    ConnectionSideId source_side()
    {
        return {source_addr(), tcp_sport()};
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

    void recompute_csum()
    {
        raw->csum = checksum(raw);
        if (is_tcp())
            recompute_tcp_csum();
    }
};


enum class DataDirection : uint8_t {
    TO_SERVER = 0, TO_CLIENT = 1
};

std::istream& operator>>(std::istream& stream, DataDirection& obj)
{
    int dir;
    stream >> dir;
    obj = static_cast<DataDirection>(dir);
    return stream;
}

std::ostream& operator<<(std::ostream& stream, const DataDirection& obj)
{
    return stream << static_cast<int>(obj);
}


struct DataPiece {
    std::string data;
    ConnectionId connection_id;
    DataDirection direction;
    uint64_t timestamp = 0;

    bool is_connection_shutdown() const
    {
        return data.empty();
    }
};


class PipeInterceptor {
public:
    using DataWriter = std::function<void(const DataPiece&)>;

    virtual void set_writer(DataWriter) = 0;

    virtual void put(const DataPiece&) = 0;

    virtual ~PipeInterceptor() = default;
};


class SocketPipe {
private:
    static constexpr size_t buf_sz = 2048;

    int client_sock = -1;
    int server_client_sock = -1;

    std::shared_ptr<PipeInterceptor> interceptor;
    ConnectionId connection_id;

    multiplexing::IoMultiplexer& mlpx;

    std::atomic<bool> shutdown_to[2] = {false, false};

public:
    SocketPipe(int server_client_fd, int client_fd, const ConnectionId& connection_id,
        std::shared_ptr<PipeInterceptor> interceptor, multiplexing::IoMultiplexer& mlpx)
        : client_sock(client_fd), server_client_sock(server_client_fd),
          interceptor(interceptor), connection_id(connection_id), mlpx(mlpx)
    {}

    void start_mirroring()
    {
        interceptor->set_writer([this](const DataPiece& p) { writer(p); });

        auto h_to_server = [this](multiplexing::Descriptor) {
            reader(server_client_sock, DataDirection::TO_SERVER);
        };
        mlpx.follow(
            multiplexing::Descriptor(server_client_sock)
                .set_read_handler(h_to_server)
                .set_error_handler(h_to_server)
        );

        auto h_to_client = [this](multiplexing::Descriptor) {
            reader(client_sock, DataDirection::TO_CLIENT);
        };
        mlpx.follow(
            multiplexing::Descriptor(client_sock)
                .set_read_handler(h_to_client)
                .set_error_handler(h_to_client)
        );
    }

    void stop_mirroring()
    {
        mlpx.unfollow(multiplexing::Descriptor(client_sock));
        mlpx.unfollow(multiplexing::Descriptor(server_client_sock));
        shutdown_connection(DataDirection::TO_SERVER);
        shutdown_connection(DataDirection::TO_CLIENT);
    }

    bool is_completely_shutdown() const
    {
        return shutdown_to[0].load() && shutdown_to[1].load();
    }

    ~SocketPipe()
    {
        interceptor.reset(); // insure all io is finished

        if (client_sock >= 0) {
            close(client_sock);
        }
        if (server_client_sock >= 0) {
            close(server_client_sock);
        }
    }

private:
    void writer(const DataPiece& piece)
    {
        try {
            if (piece.is_connection_shutdown()) {
                shutdown_connection(piece.direction);
                return;
            }

            int to_socket = (piece.direction == DataDirection::TO_SERVER ? client_sock : server_client_sock);

            const char* buf = piece.data.data();
            size_t len = piece.data.length();

            ssize_t written_count;
            size_t pos = 0;
            while (pos < len) {
                written_count = send(to_socket, buf + pos, len - pos, MSG_NOSIGNAL);
                if (written_count < 0) {
                    throw std::runtime_error("Cannot write to the socket");
                }

                pos += written_count;
            }
        } catch (std::runtime_error& err) {
            throw err;
        }
    }

    void shutdown_connection(DataDirection direction)
    {
        if (shutdown_to[static_cast<int>(direction)])
            return;
        shutdown_to[static_cast<int>(direction)] = true;

        if (direction == DataDirection::TO_SERVER) {
            shutdown(client_sock, SHUT_WR);
            shutdown(server_client_sock, SHUT_RD);
        }
        if (direction == DataDirection::TO_CLIENT) {
            shutdown(client_sock, SHUT_RD);
            shutdown(server_client_sock, SHUT_WR);
        }
    }

    void reader(int fd_from, DataDirection direction)
    {
        char buf[buf_sz];

        try {
            DataPiece piece = {
                .direction = direction,
                .connection_id = connection_id,
                .data = ""
            };

            ssize_t got_count = read(fd_from, buf, buf_sz);
            piece.timestamp = get_microsecond_timestamp();

            if (got_count <= 0) {
                interceptor->put(piece);
                mlpx.unfollow_later(multiplexing::Descriptor(fd_from));

                if (got_count < 0) {
                    throw std::runtime_error("Cannot read from the socket");
                }
                return;
            }

            piece.data = std::string(buf, got_count);
            interceptor->put(piece);
        } catch (std::runtime_error& err) {
            throw err;
        }
    }
};

}

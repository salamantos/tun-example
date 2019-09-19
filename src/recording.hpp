#pragma once

#include <map>
#include <variant>
#include <chrono>
#include <fstream>

#include "nets.hpp"
#include "bqueue.hpp"
#include "logging.hpp"



namespace playground {

class NoMoreData : public std::runtime_error {
public:
    NoMoreData()
        : runtime_error("No more data")
    {}
};


using ConnectionSideId = std::pair<std::string, int>;


struct ConnectionId {
    ConnectionSideId source;
    ConnectionSideId destination;

    ConnectionId revert() const
    {
        return {destination, source};
    }

    ConnectionId symmetric() const;

    ConnectionId halfed()
    {
        return {std::make_pair(source.first, 0), destination};
    }
};


bool operator<(const ConnectionSideId& a, const ConnectionSideId& b)
{
    return a.first < b.first || (a.first == b.first && a.second < b.second);
}

bool operator<(const ConnectionId& a, const ConnectionId& b)
{
    return a.source < b.source || (a.source == b.source && a.destination < b.destination);
}

ConnectionId ConnectionId::symmetric() const
{
    return std::min(*this, revert());
}

ConnectionId get_connection_id(const nets::IPv4Packet& packet)
{
    ConnectionSideId src_id = std::make_pair(packet.source_addr(), packet.tcp_sport());
    ConnectionSideId dst_id = std::make_pair(packet.destination_addr(), packet.tcp_dport());
    return {src_id, dst_id};
}


class Encoder {
private:
    std::ofstream file;

public:
    Encoder() = default;

    explicit Encoder(const std::string& path)
        : file(path)
    {}

    void write_next(const nets::IPv4Packet& packet)
    {
        using std::chrono::microseconds;
        using std::chrono::system_clock;
        using std::chrono::duration_cast;
        microseconds::rep us = duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();

        file << us << '\n';
        file << packet.length() << '\n';
        file.write(packet.raw_bytes(), packet.length());
    }
};


class Decoder {
private:
    std::ifstream file;

    std::deque<nets::IPv4Packet> non_tcp;
    std::map<ConnectionId, std::deque<nets::IPv4Packet>> tcp;

public:
    Decoder() = default;

    explicit Decoder(const std::string& path)
        : file(path)
    {}

    nets::IPv4Packet next_non_tcp()
    {
        while (non_tcp.empty())
            read_more();

        nets::IPv4Packet packet = non_tcp.back();
        non_tcp.pop_back();
        return packet;
    }

    nets::IPv4Packet next_tcp(const ConnectionId& id_)
    {
        auto id = id_.symmetric();
        while (tcp[id].empty())
            read_more();

        nets::IPv4Packet packet = tcp[id].back();
        tcp[id].pop_back();
        return packet;
    }

private:
    void read_more()
    {
        nets::IPv4Packet packet = read_next();
        if (!packet.is_tcp()) {
            non_tcp.push_front(packet);
        } else {
            tcp[get_connection_id(packet).symmetric()].push_front(packet);
        }
    }

    nets::IPv4Packet read_next()
    {
        using std::chrono::microseconds;
        using std::chrono::system_clock;
        using std::chrono::duration_cast;
        microseconds::rep us;
        size_t len;

        file >> us >> len;
        if (file.fail()) {
            throw NoMoreData{};
        }

        std::string dummy;
        std::getline(file, dummy);

        char* data = new char[len];
        file.read(data, len);
        nets::IPv4Packet packet = {data};
        delete[] data;

        if (file.fail()) {
            throw NoMoreData{};
        }

        return packet;
    }
};


class TrafficController {
public:
    using SendCallable = std::function<void(nets::IPv4Packet&)>;
    using RecvCallable = std::function<nets::IPv4Packet(void)>;

private:
    bool replay_mode;

    time_machine::BlockingQueue<nets::IPv4Packet> service_queue{};
    NetContainer service;
    std::vector<std::shared_ptr<nets::SocketPipe>> pipes;

    std::mutex reptable_lock;
    std::map<ConnectionSideId, std::string> addr_repair_table;

public:
    TrafficController(const std::string& file, bool replay_mode)
        : replay_mode(replay_mode), service{254, "dbus-launch gnome-terminal"}
    {
//        if (replay_mode) {
//            coder = Decoder{file};
//        } else {
//            coder = Encoder{file};
//        }
        service.serve(service_queue);
    }

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"

    void process_traffic(RecvCallable in, SendCallable out)
    {
        std::thread{
            [this, out]() {
                nets::IPv4Packet packet;
                while (service_queue.get(packet)) {
                    packet.decrease_ttl();

                    if (packet.is_tcp()) {
                        std::lock_guard lock(reptable_lock);
                        std::string from = addr_repair_table[get_connection_id(packet).destination];
                        if (!from.empty())
                            packet.set_source(from);

                        logging::tcp("From service:", packet);
                    } else {
                        logging::ip("From service, non-tcp:", packet);
                    }

                    out(packet);
                }
            }
        }.detach();

        try {
            std::future<std::shared_ptr<nets::SocketPipe>> wait_for_pipe_init;
            while (true) {
                std::shared_ptr<nets::SocketPipe> pipe;

                nets::IPv4Packet packet = in();
                packet.decrease_ttl();

                if (!packet.is_tcp()) {
                    logging::ip("Non-tcp, skipped:", packet);
                    continue;
                } else {
                    if (packet.source_addr() == "10.0.0.254") {
                        // routing shit
                        logging::tcp("Routing shit:", packet);
                        continue;
                    }

                    if (packet.is_tcp_handshake() && !packet.flag_ack()) {
                        logging::tcp("From users (newpipe):", packet);
                        {
                            std::lock_guard lock(reptable_lock);
                            addr_repair_table[get_connection_id(packet).source] = packet.destination_addr();
                        }
                        pipe = std::make_shared<nets::SocketPipe>(packet.destination_addr(), packet.tcp_dport());
                    } else {
                        logging::tcp("From users:", packet);
                    }
                }

                packet.set_destination("10.0.0.254");
                service.send(packet);

                if (pipe) {
                    std::thread([pipe, this]() {
                        pipe->accept_client();
                        pipe->start_mirroring();
                        {
                            std::lock_guard lock(reptable_lock);
                            pipes.push_back(pipe);
                        }
                    }).detach();
                }
            }
        } catch (NoMoreData&) {
            std::cerr << "No more data!" << std::endl;
        } catch (time_machine::QueueClosed&) {}
    }

#pragma clang diagnostic pop
};

}

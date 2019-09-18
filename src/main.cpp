#include <iostream>
#include <sstream>
#include <fstream>
#include <map>

#include "nets.hpp"
#include "bqueue.hpp"



extern "C" {
#include "tuns.h"
#include "rawsocket.h"
#include "namespaces.h"
#include "unistd.h"
}



using ConnectionSideId = std::pair<std::string, int>;

struct ConnectionId {
    ConnectionSideId source;
    ConnectionSideId destination;

    ConnectionId revert()
    {
        return {destination, source};
    }
};

bool operator <(const ConnectionSideId& a, const ConnectionSideId& b) {
    return a.first < b.first || (a.first == b.first && a.second < b.second);
}

bool operator <(const ConnectionId& a, const ConnectionId& b) {
    return a.source < b.source || (a.source == b.source && a.destination < b.destination);
}


std::map<ConnectionId, uint32_t> syn_offsets;

void mangle_tcp_header(nets::IPv4Packet& packet) {
    nets::TcpHeader* tcph = packet.raw_tcp();
    ConnectionSideId src_id = std::make_pair(packet.source_addr(), tcph->sport);
    ConnectionSideId dst_id = std::make_pair(packet.destination_addr(), tcph->dport);
    ConnectionId conn_id = {src_id, dst_id};

    if (tcph->syn && !tcph->ack) {
        // SYN
        syn_offsets[conn_id] = tcph->seq;
        tcph->seq = 0;
    }
    if (tcph->syn && tcph->ack) {
        // SYN-ACK
        syn_offsets[conn_id] = tcph->seq;
        tcph->seq = 0;
        tcph->ack_seq += syn_offsets[conn_id.revert()];
    }
    if (!tcph->syn) {
        // ESTABLISHED
        tcph->seq -= syn_offsets[conn_id];
        tcph->ack_seq += syn_offsets[conn_id.revert()];
    }

    packet.recompute_tcp_csum();
}


template <class... FArgs>
void run_cmd(const char* fmt, FArgs... args)
{
    std::string command;

    if (sizeof...(args) == 0) {
        command = fmt;
    } else {
        int len = std::snprintf(nullptr, 0, fmt, args...);
        if (len < 0) {
            throw std::runtime_error("snprintf");
        }

        char* buf = new char[len + 1];
        std::sprintf(buf, fmt, args...);

        command = buf;
        delete[] buf;
    }

    int rc = system(command.c_str());
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
        throw std::runtime_error("Command '" + command + "' failed");
    }
}


void logger(const nets::IPv4Packet& packet)
{
    std::cout << "From " << packet.source_addr()
              << " to " << packet.destination_addr() << '\n';
    std::cout << "TTL " << static_cast<int>(packet.ttl()) << '\n';
    std::cout << (packet.is_tcp() ? "TCP" : "Not TCP") << '\n';
    std::cout << "Total len " << static_cast<int>(packet.length()) << '\n' << std::endl;
}


class NetContainer {
private:
    static constexpr size_t BUF_SZ = 4096;

    int tun_fd;
    std::string tun_name;

    char buf[BUF_SZ]{};
    std::atomic<bool> finalize{false};

public:
    explicit NetContainer(int id, const char* cmd)
    {
        if (new_netns()) {
            throw std::runtime_error("Cannot create namespace");
        }

        char* dev_name;
        tun_fd = tun_alloc(&dev_name);
        tun_name = dev_name;
        free(dev_name);

        if (tun_fd < 0) {
            throw std::runtime_error("Cannot create tunnel");
        }

        std::cout << tun_name << std::endl;

        run_cmd("ip link set %s up", tun_name.c_str());
        run_cmd("ip link set lo up");
        run_cmd("ip addr add 10.0.0.%d/24 dev %s", id, tun_name.c_str());

        try {
            run_cmd("%s", cmd);
        } catch (std::runtime_error& exc) {
            std::cerr << exc.what() << std::endl;
        }
    }

    NetContainer(const NetContainer&) = delete;

    NetContainer& operator=(const NetContainer&) = delete;

    void serve(time_machine::BlockingQueue<nets::IPv4Packet>& queue)
    {
        std::thread{
            [&queue, this]() {
                while (!finalize.load()) {
                    std::string data = read_next();
                    for (size_t pos = 0; pos < data.length();) {
                        nets::IPv4Packet packet;
                        try {
                            packet = {data.data() + pos};
                        } catch (nets::IPException& exc) {
                            std::cout << exc.what() << ", ignoring" << '\n' << std::endl;
                            break;
                        }

                        pos += packet.length();
                        queue.put(packet);
                    }
                }
            }
        }.detach();
    }

    void send(nets::IPv4Packet packet)
    {
        size_t pos = 0;
        while (pos < packet.length()) {
            int written_count = write(tun_fd, packet.raw_bytes() + pos, packet.length() - pos);
            if (written_count < 0)
                throw std::runtime_error("Cannot write to the tunnel");

            pos += written_count;
        }
    }

    void stop()
    {
        finalize.store(true);
    }

private:
    std::string read_next()
    {
        int got_count = read(tun_fd, buf, BUF_SZ);
        if (got_count < 0) {
            throw std::runtime_error("Cannot read from the tunnel");
        }

        std::string string;
        return std::string(buf, got_count);
    }
};


int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: main system-terminal" << std::endl;
        return 1;
    }

    std::vector<std::shared_ptr<NetContainer>> containers;
    for (int i = 0; i < 2; ++i) {
        containers.emplace_back(std::make_shared<NetContainer>(i + 1, argv[1]));
    }

    time_machine::BlockingQueue<nets::IPv4Packet> queue;
    for (auto container : containers)
        container->serve(queue);

    while (true) {
        nets::IPv4Packet packet;
        if (!queue.get(packet)) {
            break;
        }

        logger(packet);
        packet.decrease_ttl();
        if (packet.is_tcp()) {
            mangle_tcp_header(packet);
        }

        for (auto container : containers) {
            container->send(packet);
        }
    }

    return 0;
}

#include <iostream>
#include <sstream>
#include <fstream>

#include "nets.hpp"
#include "bqueue.hpp"



extern "C" {
#include "tuns.h"
#include "rawsocket.h"
#include "namespaces.h"
#include "unistd.h"
}


int ipsock = -1;

void send_with_rawip(nets::IPv4Packet packet)
{
    if (ipsock < 0) {
        std::cerr << "Raw IP Socket is unavailable" << std::endl;
        return;
    }

    packet.decrease_ttl();
    packet.set_source("10.0.0.2");

    safe_send(ipsock, packet.raw->daddr, packet.raw_bytes(), packet.length());
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
//        std::ofstream dump_file("to" + packet.destination_addr() + ".ip");
//        dump_file.write(buf, count);
//        dump_file.close();

    std::cout << "From " << packet.source_addr()
              << " to " << packet.destination_addr() << '\n';
    std::cout << "TTL " << static_cast<int>(packet.ttl()) << '\n';
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
//        packet.set_source("10.0.0.2");
//        packet.set_destination("10.0.0.0");
        packet.decrease_ttl();

        for (auto container : containers) {
            container->send(packet);
        }
    }

    return 0;
}

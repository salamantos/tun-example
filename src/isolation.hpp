#pragma once


#include <sstream>

#include "nets.hpp"
#include "bqueue.hpp"



extern "C" {
#include <unistd.h>
}


namespace playground {

extern "C" {

#include "tuns.h"
#include "namespaces.h"



}

template <class... FArgs>
void run_cmd(const char* fmt, FArgs... args)
{
    std::string command;

    if constexpr (sizeof...(args) == 0) {
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


class NetContainer {
private:
    static constexpr size_t BUF_SZ = 4096;

    uint8_t id;
    int tun_fd;
    std::string tun_name;

    char buf[BUF_SZ]{};

public:
    explicit NetContainer(uint8_t id, const char* cmd)
        : id(id)
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
        run_cmd("ip addr add 10.0.0.%d/24 dev %s", static_cast<int>(id), tun_name.c_str());

        if (cmd)
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
                try {
                    while (true) {
                        std::string data = read_next();
                        for (size_t pos = 0; pos < data.length();) {
                            nets::IPv4Packet packet;
                            try {
                                packet = {data.data() + pos};
                            } catch (nets::IPException& exc) {
                                std::cout << exc.what() << ", ignoring" << '\n' << std::endl;
                                break;
                            }
                            packet.origin_id = id;

                            pos += packet.length();
                            queue.put(packet);
                        }
                    }
                } catch (time_machine::QueueClosed&) {}
            }
        }.detach();
    }

    void send(const nets::IPv4Packet& packet)
    {
        size_t pos = 0;
        const char* bytes = packet.raw_bytes();
        while (pos < packet.length()) {
            int written_count = write(tun_fd, bytes + pos, packet.length() - pos);
            if (written_count < 0)
                throw std::runtime_error("Cannot write to the tunnel");

            pos += written_count;
        }
    }

    const std::string& device_name() const
    {
        return tun_name;
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


class SocketPipeFactory : public NetContainer {
public:
    SocketPipeFactory()
        : NetContainer(254u, 0)
    {}

    SocketPipeFactory(const SocketPipeFactory& container) = delete;
    SocketPipeFactory& operator=(const SocketPipeFactory&) = delete;

    // TODO
};

} // namespace playground

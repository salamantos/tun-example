#pragma once

#include <sstream>
#include <map>

#include "nets.hpp"
#include "bqueue.hpp"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>



extern "C" {

#include "cnets.h"
#include "tuns.h"
#include "namespaces.h"

}


namespace playground {

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
        for (const std::string& addr : get_device_addresses())
            run_cmd("ip addr add %s dev %s", addr.c_str(), tun_name.c_str());

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
            ssize_t written_count = write(tun_fd, bytes + pos, packet.length() - pos);
            if (written_count < 0)
                throw std::runtime_error("Cannot write to the tunnel");

            pos += written_count;
        }
    }

    const std::string& device_name() const
    {
        return tun_name;
    }

    virtual std::vector<std::string> get_device_addresses() const
    {
        std::ostringstream res;
        res << "10.0.0." << static_cast<int>(id) << "/24";
        return {res.str()};
    }

    virtual ~NetContainer() = default;

private:
    std::string read_next()
    {
        ssize_t got_count = read(tun_fd, buf, BUF_SZ);
        if (got_count < 0) {
            throw std::runtime_error("Cannot read from the tunnel");
        }

        std::string string;
        return std::string(buf, got_count);
    }
};


class SocketPipeFactory : public NetContainer {
private:
    struct PipeRequest {
        nets::ConnectionId connection_id;
        uint16_t source_port;
        std::shared_ptr<nets::PipeInterceptor> interceptor;
    };

    std::vector<std::shared_ptr<nets::SocketPipe>> pipes;
    std::mutex lock;

    std::map<int, nets::ConnectionSideId> server_sockets;
    std::map<nets::ConnectionSideId, int> server_sockets_reversed;
    std::thread accepting_thread = std::thread{
        [this]() {
            while (true) { // TODO: make loop finite
                std::vector<int> sockets;
                {
                    std::lock_guard guard(lock);
                    for (const auto& entry : server_sockets)
                        sockets.push_back(entry.first);
                }

                int epoll_res = epoll_accept(sockets.data(), sockets.size());
                if (!epoll_res) {
                    throw std::runtime_error("Accept epoll failed");
                }

                if (epoll_res < 0) {
                    std::lock_guard guard(lock);
                    server_sockets_reversed.erase(server_sockets[-epoll_res]);
                    server_sockets.erase(-epoll_res);
                    continue;
                }

                sockaddr_in client_addr;
                socklen_t client_addr_len = sizeof(client_addr);
                int client_fd = accept(epoll_res, &client_addr, &client_addr_len);
                if (client_fd < 0) {
                    std::lock_guard guard(lock);
                    server_sockets_reversed.erase(server_sockets[epoll_res]);
                    server_sockets.erase(epoll_res);
                    continue;
                }

                // here we are done: client_fd

            }
        }
    };

public:
    SocketPipeFactory()
        : NetContainer(0, 0)
    {}

    SocketPipeFactory(const SocketPipeFactory& container) = delete;

    SocketPipeFactory& operator=(const SocketPipeFactory&) = delete;

    std::vector<std::string> get_device_addresses() const override
    {
        std::vector<std::string> res;
        for (int i = 1; i < 255; ++i) {
            std::ostringstream addr;
            addr << "10.0.0." << i << "/24";
            res.push_back(addr.str());
        }
        return res;
    }

    void request_new_pipe(const nets::ConnectionId& id, uint16_t sport,
                          std::shared_ptr<nets::PipeInterceptor> interceptor)
    {
        PipeRequest request{
            .connection_id = id,
            .source_port = sport,
            .interceptor = interceptor
        };

        {
            std::lock_guard guard(lock);
            if (server_sockets_reversed.find(id.server_side) == server_sockets_reversed.end()) {
                int sock_fd = init_server_socket(id.server_side.first, id.server_side.second);
                if (sock_fd < 0)
                    throw std::runtime_error("Cannot create server socket");

                server_sockets_reversed[]
            }
        }

        auto pipe = std::make_shared<nets::SocketPipe>(id, interceptor);
        std::thread([pipe, this]() {
            pipe->accept_client();
            pipe->start_mirroring();
            {
                std::lock_guard guard(lock);
                pipes.push_back(pipe);
            }
        }).detach();
    }

    ~SocketPipeFactory()
    {
        accepting_thread.join();
    }
};

} // namespace playground

#pragma once

#include <sstream>
#include <map>

#include "nets.hpp"
#include "bqueue.hpp"
#include "multiplexing.hpp"
#include "logging.hpp"



extern "C" {
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/eventfd.h>

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

        run_cmd("ip link set %s up", tun_name.c_str());
        run_cmd("ip link set lo up");

        if (cmd)
            try {
                run_cmd("%s", cmd);
            } catch (std::runtime_error& exc) {
                std::cerr << exc.what() << std::endl;
            }
    }

    NetContainer(const NetContainer&) = delete;

    NetContainer& operator=(const NetContainer&) = delete;

    void serve(time_machine::BlockingQueue<nets::IPv4Packet>& queue, multiplexing::IoMultiplexer& mlpx)
    {
        mlpx.follow(
            multiplexing::Descriptor(tun_fd)
                .set_read_handler([this, &queue](auto) {
                    receive(queue);
                })
                .set_error_handler([](auto) {
                    throw std::runtime_error("Broken tunnel");
                })
        );
    }

    void send(const nets::IPv4Packet& packet)
    {
        std::string dest = packet.destination_addr();
        for (const auto& addr : get_device_addresses()) {
            auto it = addr.find(dest);
            if (it == std::string::npos || (addr.size() > dest.size() && addr[dest.size()] != '/'))
                return;
        }

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

    virtual void assign_addresses() const
    {
        for (const std::string& addr : get_device_addresses()) {
            run_cmd("ip addr add %s dev %s", addr.c_str(), tun_name.c_str());
        }
    }

    virtual ~NetContainer() = default;

protected:
    virtual std::vector<std::string> get_device_addresses() const
    {
        std::ostringstream res;
        res << "10.0.0." << static_cast<int>(id) << "/24";
        return {res.str()};
    }

private:
    void receive(time_machine::BlockingQueue<nets::IPv4Packet>& queue)
    {
        ssize_t got_count = read(tun_fd, buf, BUF_SZ);
        if (got_count < 0) {
            throw std::runtime_error("Cannot read from the tunnel");
        }

        for (size_t pos = 0; pos < static_cast<size_t>(got_count);) {
            nets::IPv4Packet packet;
            try {
                packet = {buf + pos};
            } catch (nets::IPException& exc) {
                logging::text(exc.what());
                break;
            }
            packet.origin_id = id;

            pos += packet.length();
            queue.put(packet);
        }
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

    std::map<int, uint16_t> sock_to_port;
    std::map<uint16_t, int> port_to_sock;
    std::map<nets::ConnectionSideId, PipeRequest> requests;

    multiplexing::IoMultiplexer mlpx;
    std::vector<int> unfollow_later;

    std::thread accepting_thread;
    std::atomic<bool> stopped{false};

public:
    SocketPipeFactory()
        : NetContainer(0, nullptr)
    {
        start_accepting_thread();
    }

    SocketPipeFactory(const SocketPipeFactory& container) = delete;

    SocketPipeFactory& operator=(const SocketPipeFactory&) = delete;

    void request_new_pipe(const nets::ConnectionId& id, uint16_t sport,
                          std::shared_ptr<nets::PipeInterceptor> interceptor)
    {
        PipeRequest request{
            .connection_id = id,
            .source_port = sport,
            .interceptor = interceptor
        };

        int sock_fd = -1;
        {
            std::lock_guard guard(lock);
            if (port_to_sock.find(id.server_side.second) == port_to_sock.end()) {
                sock_fd = init_server_socket(id.server_side.second);
                if (sock_fd < 0)
                    throw std::runtime_error(std::string{"Cannot create server socket: "} + strerror(errno));

                port_to_sock[id.server_side.second] = sock_fd;
                sock_to_port[sock_fd] = id.server_side.second;
            }

            requests[std::make_pair(id.client_addr, sport)] = request;
        }

        if (sock_fd >= 0)
            mlpx.follow(
                multiplexing::Descriptor(sock_fd)
                    .set_read_handler([this](multiplexing::Descriptor d) {
                        accept_connection(d.fd);
                    })
                    .set_error_handler([this](multiplexing::Descriptor d) {
                        handle_socket_error(d.fd);
                    })
            );
    }

    ~SocketPipeFactory() override
    {
        stopped.store(true);
        std::vector<int> sockets;
        {
            std::lock_guard guard(lock);
            sockets.reserve(sock_to_port.size());
            for (auto entry : sock_to_port) {
                sockets.push_back(entry.first);
            }
        }
        for (int fd : sockets)
            mlpx.unfollow(multiplexing::Descriptor(fd));
        if (sockets.empty())
            mlpx.interrupt();

        accepting_thread.join();
    }

protected:
    std::vector<std::string> get_device_addresses() const override
    {
        std::vector<std::string> res;
        for (int i = 254;; --i) {
            std::ostringstream addr;
            addr << "10.0.0." << i << "/24";
            res.push_back(addr.str());
            break;
        }
        return res;
    }

private:
    void accept_connection(int sock_fd)
    {
        logging::text("Try accept");

        sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd = accept(sock_fd, (sockaddr*) &client_addr, &client_addr_len);
        if (client_fd < 0) {
            logging::text(std::string{"client_fd < 0 "} + strerror(errno));
            handle_socket_error(sock_fd);
            return;
        }

        PipeRequest request;
        nets::ConnectionSideId client_side = {
            nets::addr_to_string(client_addr.sin_addr.s_addr),
            ntohs(client_addr.sin_port)
        };

        {
            std::lock_guard guard(lock);

            auto it = requests.find(client_side);
            if (it == requests.end()) {
                close(client_fd);
                return;
            }

            request = it->second;
            requests.erase(it);
        }

        int oth_fd = init_client_socket(request.connection_id.client_addr.c_str(),
                                        request.connection_id.server_side.first.c_str(),
                                        request.connection_id.server_side.second);
        if (oth_fd < 0) {
            logging::text(std::string{"oth_fd < 0 "} + strerror(errno));
            close(client_fd);
            return;
        }

        {
            std::lock_guard guard(lock);

            pipes.emplace_back(new nets::SocketPipe{
                client_fd, oth_fd, request.connection_id, request.interceptor
            });
            pipes.back()->start_mirroring();
        }

        logging::text("Pipe created\n");
    }

    void handle_socket_error(int fd)
    {
        {
            std::lock_guard guard(lock);
            port_to_sock.erase(sock_to_port[fd]);
            sock_to_port.erase(fd);
        }
        unfollow_later.push_back(fd);
        close(fd);
    }

    void start_accepting_thread()
    {
        accepting_thread = std::thread{
            [this]() {
                while (!stopped.load()) {
                    try {
                        mlpx.wait();
                    } catch (std::runtime_error& err) {
                        logging::text(err.what());
                    }
                    for (int fd : unfollow_later)
                        mlpx.unfollow(multiplexing::Descriptor(fd));
                }

                std::lock_guard guard(lock);
                for (auto pipe : pipes)
                    pipe->stop_mirroring();
            }
        };
    }
};

} // namespace playground

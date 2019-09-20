#pragma once

#include <sstream>
#include <map>

#include "nets.hpp"
#include "bqueue.hpp"
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

    virtual void assign_addresses() const
    {
        for (const std::string& addr : get_device_addresses()) {
            run_cmd("ip addr add %s dev %s", addr.c_str(), tun_name.c_str());
        }
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
    std::condition_variable cv;

    std::map<int, uint16_t> sock_to_port;
    std::map<uint16_t, int> port_to_sock;
    std::map<nets::ConnectionSideId, PipeRequest> requests;

    std::atomic<int> interruptor_fd{-1};

    std::thread accepting_thread = std::thread{
        [this]() {
            int event_fd = eventfd(0, 0);
            if (event_fd < 0) {
                throw std::runtime_error("Accept epoll failed (eventfd)");
            }
            interruptor_fd.store(event_fd, std::memory_order::memory_order_relaxed);

            while (true) { // TODO: make loop finite
                std::vector<int> sockets;
                {
                    std::unique_lock guard(lock);
                    while (sock_to_port.empty())
                        cv.wait(guard);

                    for (const auto& entry : sock_to_port)
                        sockets.push_back(entry.first);
                }

                logging::text("epolling");
                int epoll_res = epoll_accept(sockets.data(), sockets.size(), event_fd);
                logging::text(std::string{"epolling finished "} + std::to_string(epoll_res));

                if (epoll_res < -static_cast<int>(sockets.size())) {
                    throw std::runtime_error("Accept epoll failed");
                }

                if (!epoll_res) {
                    continue;
                }

                if (epoll_res < 0) {
                    logging::text(std::string{"epoll_res < 0 "} + strerror(errno));
                    close(-epoll_res);

                    std::lock_guard guard(lock);
                    port_to_sock.erase(sock_to_port[-epoll_res]);
                    sock_to_port.erase(-epoll_res);
                    continue;
                }

                logging::text("epolling - 1");

                sockaddr_in client_addr;
                socklen_t client_addr_len = sizeof(client_addr);
                int client_fd = accept(epoll_res, (sockaddr*) &client_addr, &client_addr_len);
                if (client_fd < 0) {
                    logging::text(std::string{"client_fd < 0 "} + strerror(errno));
                    close(epoll_res);

                    std::lock_guard guard(lock);
                    port_to_sock.erase(sock_to_port[epoll_res]);
                    sock_to_port.erase(epoll_res);
                    continue;
                }

                logging::text("epolling - 2");

                // here we are done: client_fd
                PipeRequest request;
                nets::ConnectionSideId client_side = {
                    nets::addr_to_string(client_addr.sin_addr.s_addr),
                    ntohs(client_addr.sin_port)
                };

                logging::text(client_side.first + ":" + std::to_string(client_side.second));

                {
                    std::lock_guard guard(lock);

                    auto it = requests.find(client_side);
                    if (it == requests.end()) {
                        close(client_fd);
                        continue;
                    }

                    request = it->second;
                    requests.erase(it);
                }

                logging::text("epolling - 3");

                int oth_fd = init_client_socket(request.connection_id.client_addr.c_str(),
                                                request.connection_id.server_side.first.c_str(),
                                                request.connection_id.server_side.second);
                if (oth_fd < 0) {
                    logging::text(std::string{"oth_fd < 0 "} + strerror(errno));

                    close(client_fd);
                    continue;
                }

                logging::text("epolling - 4");

                {
                    std::lock_guard guard(lock);

                    pipes.emplace_back(new nets::SocketPipe{
                        client_fd, oth_fd, request.connection_id, request.interceptor
                    });
                    pipes.back()->start_mirroring();
                }

                logging::text("Pipe created\n");
            }

            // TODO: close event_fd
        }
    };

public:
    SocketPipeFactory()
        : NetContainer(0, nullptr)
    {}

    SocketPipeFactory(const SocketPipeFactory& container) = delete;

    SocketPipeFactory& operator=(const SocketPipeFactory&) = delete;

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

    void request_new_pipe(const nets::ConnectionId& id, uint16_t sport,
                          std::shared_ptr<nets::PipeInterceptor> interceptor)
    {
        PipeRequest request{
            .connection_id = id,
            .source_port = sport,
            .interceptor = interceptor
        };

        std::unique_lock guard(lock);
        if (port_to_sock.find(id.server_side.second) == port_to_sock.end()) {
            int sock_fd = init_server_socket(id.server_side.second);
            if (sock_fd < 0)
                throw std::runtime_error(std::string{"Cannot create server socket: "} + strerror(errno));

            std::cout << "Created server sock, bound to" << " :" << id.server_side.second << std::endl;
            port_to_sock[id.server_side.second] = sock_fd;
            sock_to_port[sock_fd] = id.server_side.second;

            cv.notify_one();
            int interr_fd = interruptor_fd.load(std::memory_order::memory_order_relaxed);
            if (interr_fd >= 0)
                epoll_interrupt(interr_fd);
        }

        logging::text("requests[" + id.client_addr + ":" + std::to_string(sport) + "]=...");
        requests[std::make_pair(id.client_addr, sport)] = request;
    }

    ~SocketPipeFactory() override
    {
        accepting_thread.join();
    }
};

} // namespace playground

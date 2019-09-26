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


class Process {
private:
    pid_t pid;
    int kill_signal;

public:
    Process(const std::string& cmd, uid_t uid, gid_t gid, int kill_via = 15)
        : kill_signal(kill_via)
    {
        if ((pid = run_with_credentials(cmd.c_str(), uid, gid)) == -1)
            throw std::runtime_error("Cannot execute command '" + cmd + "'");
    }

    Process(const Process&) = delete;

    Process& operator=(const Process&) = delete;

    Process(Process&& p) noexcept
        : pid(p.pid)
    {
        p.pid = 0;
    }

    Process& operator=(Process&& p) noexcept
    {
        terminate_process(pid, kill_signal);
        pid = p.pid;
        p.pid = 0;
        return *this;
    }

    ~Process()
    {
        terminate_process(pid, kill_signal);
    }
};


class NetContainer {
protected:
    nets::Subnet subnet;

private:
    static constexpr size_t BUF_SZ = 1ul << 16u;
    int tun_fd;
    std::string tun_name;

    multiplexing::MultiplexedWritingProvider<nets::IPv4Packet>& provider;

    char buf[BUF_SZ]{};

public:
    explicit NetContainer(nets::Subnet subnet, multiplexing::MultiplexedWritingProvider<nets::IPv4Packet>& provider)
        : subnet(subnet), provider(provider)
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
    }

    NetContainer(const NetContainer&) = delete;

    NetContainer& operator=(const NetContainer&) = delete;

    void serve(time_machine::BlockingQueue<nets::IPv4Packet>& queue)
    {
        provider.get_writer(tun_fd)
            .set_read_handler([this, &queue](auto) {
                receive(queue);
            })
            .set_error_handler([](auto) {
                throw std::runtime_error("Broken tunnel");
            });
    }

    void send(nets::IPv4Packet&& packet)
    {
        std::string dest = packet.destination_addr();
        bool for_us = false;
        for (const auto& addr : get_device_addresses()) {
            auto it = addr.find(dest);
            if (it != std::string::npos && (addr.size() == dest.size() || addr[dest.size()] == '/')) {
                for_us = true;
                break;
            }
        }
        if (!for_us)
            return;

        provider.get_writer(tun_fd) << std::move(packet);
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

    virtual ~NetContainer()
    {
        close(tun_fd);
    }

protected:
    virtual std::vector<std::string> get_device_addresses() const
    {
        return {static_cast<std::string>(subnet)};
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
                packet = {buf + pos, got_count - pos};
            } catch (nets::IPException& exc) {
                logging::text(exc.what());
                break;
            }
            packet.origin = subnet;

            pos += packet.length();
            queue.put(std::move(packet));
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

    multiplexing::IoMultiplexer mlpx;

    std::vector<std::shared_ptr<nets::SocketPipe>> pipes;
    std::mutex lock;

    std::map<int, uint16_t> sock_to_port;
    std::map<uint16_t, int> port_to_sock;
    std::map<nets::ConnectionSideId, PipeRequest> requests;

    std::thread accepting_thread;
    std::atomic<bool> stopped{false};

public:
    SocketPipeFactory(nets::Subnet subnet, multiplexing::MultiplexedWritingProvider<nets::IPv4Packet>& provider)
        : NetContainer(subnet, provider)
    {}

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
                    .set_read_handler([this](auto d) {
                        accept_connection(d.fd());
                    })
                    .set_error_handler([this](auto d) {
                        handle_socket_error(d.fd());
                    })
                    .set_clear_handler([](auto d) {
                        close(d.fd());
                    })
            );
    }

    void assign_addresses() const override
    {
        NetContainer::assign_addresses();
        run_cmd("ip route add default via %s dev %s", subnet[1].address_only().c_str(), device_name().c_str());
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
                    collect_garbage();
                }

                std::lock_guard guard(lock);
                for (auto pipe : pipes)
                    pipe->stop_mirroring();
            }
        };
    }

    ~SocketPipeFactory() override
    {
        stopped.store(true);
        mlpx.interrupt();

        if (accepting_thread.joinable())
            accepting_thread.join();
    }

protected:
    std::vector<std::string> get_device_addresses() const override
    {
        uint32_t count = ~(subnet.get_mask());
        if (count + 1 == 0)
            return {static_cast<std::string>(subnet)};

        std::vector<std::string> res;
        res.reserve(count - 2);
        for (uint32_t i = 1; i < count; ++i)
            res.push_back(static_cast<std::string>(subnet[i]));
        return res;
    }

private:
    void collect_garbage()
    {
        std::lock_guard guard(lock);
        for (auto it = pipes.begin(); it < pipes.end(); ++it) {
            if ((*it)->is_completely_shutdown()) {
                (*it)->stop_mirroring();
                pipes.erase(it--);
            }
        }
    }

    void accept_connection(int sock_fd)
    {
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

        int oth_fd = init_client_socket(subnet.masquerade(request.connection_id.client_addr).c_str(),
                                        request.connection_id.server_side.first.c_str(),
                                        request.connection_id.server_side.second);
        if (oth_fd < 0) {
            logging::text(std::string{"oth_fd < 0 "} + strerror(errno));
            close(client_fd);
            return;
        }

        mlpx.follow_later(
            multiplexing::Descriptor(oth_fd)
                .set_one_shot()
                .set_write_handler([this, client_fd, oth_fd, request](auto d) {
                    if (make_socket_blocking(oth_fd)) {
                        d.error();
                        return;
                    }

                    std::lock_guard guard(lock);

                    pipes.emplace_back(new nets::SocketPipe{
                        client_fd, oth_fd, request.connection_id, request.interceptor, mlpx
                    });
                    pipes.back()->start_mirroring();

                    logging::text("Pipe created\n");
                })
                .set_error_handler([this](auto) {
                    if (!stopped.load())
                        logging::text("Cannot connect");
                })
                .set_clear_handler([oth_fd, client_fd](auto) {
                    close(oth_fd);
                    close(client_fd);
                })
        );
    }

    void handle_socket_error(int fd)
    {
        std::lock_guard guard(lock);
        port_to_sock.erase(sock_to_port[fd]);
        sock_to_port.erase(fd);
        mlpx.unfollow_later(multiplexing::Descriptor(fd));
    }
};

} // namespace playground

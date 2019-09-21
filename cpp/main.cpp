#include <iostream>
#include <fstream>
#include <cstring>

#include "isolation.hpp"
#include "bqueue.hpp"
#include "logging.hpp"
#include "traffic.hpp"
#include "CLI11.hpp"



extern "C" {
#include "namespaces.h"
}


int main(int argc, char* argv[])
{
    CLI::App app{"Net Playground"};

    std::string subnet_str;
    nets::Subnet client_subnet;
    bool replay;

    uid_t exec_uid = getuid();
    gid_t exec_gid = getgid();

    app.add_option("--subnet,-s", subnet_str, "Subnet")
        ->required();
    app.add_flag("--replay{true},--record{false}", replay, "Operation mode")
        ->required();
    app.add_option("--uid,-u", exec_uid, "User id to execute commands");
    app.add_option("--gid,-g", exec_gid, "User id to execute commands");

    app.allow_extras();
    CLI11_PARSE(app, argc, argv)

    client_subnet = nets::Subnet{subnet_str};
    auto commands = app.remaining();
    if (commands.size() + 2 > ~client_subnet.get_mask() + 1) {
        std::cerr << "Two many commands for specified subnet size" << std::endl;
        return 1;
    }
    if (commands.empty()) {
        std::cerr << "Specify at least one command after arguments" << std::endl;
        return 1;
    }

    if (disable_interrupting_signals())
        throw std::runtime_error("Problems with signals");

    std::vector<std::shared_ptr<playground::NetContainer>> containers;
    std::vector<playground::Process> user_processes;
    for (size_t i = 0; i < commands.size(); ++i) {
        const auto& cmd = commands[i];
        containers.emplace_back(std::make_shared<playground::NetContainer>(client_subnet[i + 1]));
        containers.back()->assign_addresses();
        try {
            user_processes.emplace_back(cmd, exec_uid, exec_gid);
        } catch (const std::runtime_error& err) {
            std::cerr << err.what() << std::endl;
        }
    }

    time_machine::BlockingQueue<nets::IPv4Packet> queue;
    multiplexing::IoMultiplexer tun_mlpx;
    for (auto container : containers)
        container->serve(queue, tun_mlpx);

    playground::TrafficController tc{"test.traffic", replay, client_subnet, tun_mlpx};
    std::mutex out_lock;
    auto traffic_pass_thread = std::thread{
        [&tc, &queue, &containers, &out_lock]() {
            tc.process_traffic(
                [&queue]() {
                    nets::IPv4Packet packet;
                    if (!queue.get(packet)) {
                        throw playground::NoMoreData{};
                    }

                    return packet;
                },
                [&containers, &out_lock](nets::IPv4Packet& packet) {
                    std::lock_guard lock(out_lock);
                    for (auto container : containers) {
                        container->send(packet);
                    }
                }
            );
        }
    };
    auto tunnel_read_thread = std::thread{
        [&tun_mlpx, &queue]() {
            try {
                while (!queue.isClosed()) {
                    tun_mlpx.wait();
                }
            } catch (time_machine::QueueClosed&) {}
        }
    };

    wait_interrupting_signals();
    queue.close();
    tun_mlpx.interrupt();

    tunnel_read_thread.join();
    traffic_pass_thread.join();
    return 0;
}
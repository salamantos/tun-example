#include <iostream>
#include <fstream>
#include <cstring>

#include "isolation.hpp"
#include "bqueue.hpp"
#include "logging.hpp"
#include "recording.hpp"



extern "C" {
#include "namespaces.h"
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cerr << "Usage: main (replay | record) system-terminal" << std::endl;
        return 1;
    }

    bool replay = !strcmp("replay", argv[1]);

    if (disable_interrupting_signals())
        throw std::runtime_error("Problems with signals");

    std::vector<std::shared_ptr<playground::NetContainer>> containers;
    for (int i = 0; i < 4; ++i) {
        containers.emplace_back(std::make_shared<playground::NetContainer>(i + 1, argv[2]));
        containers.back()->assign_addresses();
    }

    time_machine::BlockingQueue<nets::IPv4Packet> queue;
    multiplexing::IoMultiplexer tun_mlpx;
    for (auto container : containers)
        container->serve(queue, tun_mlpx);

    playground::TrafficController tc{"test.traffic", replay, tun_mlpx};
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

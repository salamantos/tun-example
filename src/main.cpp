#include <iostream>
#include <fstream>
#include <cstring>

#include "isolation.hpp"
#include "bqueue.hpp"
#include "recording.hpp"


int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cerr << "Usage: main (replay | record) system-terminal" << std::endl;
        return 1;
    }

    bool replay = !strcmp("replay", argv[1]);

    std::vector<std::shared_ptr<playground::NetContainer>> containers;
    for (int i = 0; i < 4; ++i) {
        containers.emplace_back(std::make_shared<playground::NetContainer>(i + 1, argv[2]));
        containers.back()->assign_addresses();
    }

    time_machine::BlockingQueue<nets::IPv4Packet> queue;
    for (auto container : containers)
        container->serve(queue);

    playground::TrafficController tc{"test.traffic", replay};
    std::mutex out_lock;
    std::thread{
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
    }.detach();

    while (true) {
        std::string cmd;
        std::cin >> cmd;
        if (cmd == "stop") {
            queue.close();
            return 0;
        }
    }
}

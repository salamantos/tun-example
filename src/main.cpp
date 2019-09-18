#include <iostream>
#include <fstream>

#include "isolation.hpp"
#include "bqueue.hpp"
#include "recording.hpp"


void logger(const nets::IPv4Packet& packet)
{
    std::cout << "From " << packet.source_addr()
              << " to " << packet.destination_addr() << '\n';
    std::cout << "TTL " << static_cast<int>(packet.ttl()) << '\n';
    std::cout << (packet.is_tcp() ? "TCP" : "Not TCP") << '\n';
    std::cout << "Total len " << static_cast<int>(packet.length()) << '\n' << std::endl;
}


int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Usage: main system-terminal" << std::endl;
        return 1;
    }

    std::vector<std::shared_ptr<playground::NetContainer>> containers;
    for (int i = 0; i < 2; ++i) {
        containers.emplace_back(std::make_shared<playground::NetContainer>(i + 1, argv[1]));
    }

    time_machine::BlockingQueue<nets::IPv4Packet> queue;
    for (auto container : containers)
        container->serve(queue);

    playground::TcpTracker tracker;
    while (true) {
        nets::IPv4Packet packet;
        if (!queue.get(packet)) {
            break;
        }

        logger(packet);
        packet.decrease_ttl();
        if (packet.is_tcp()) {
            tracker.mangle_tcp_header(packet);
        }

        for (auto container : containers) {
            container->send(packet);
        }
    }

    return 0;
}

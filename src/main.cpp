#include <iostream>
#include <sstream>
#include <fstream>

#include "nets.hpp"

extern "C" {
#include "tuns.h"
#include "rawsocket.h"
}


int ipsock = -1;

void send_with_rawip(nets::IPv4Packet packet) {
    if (ipsock < 0) {
        std::cerr << "Raw IP Socket is unavailable" << std::endl;
        return;
    }

    packet.decrease_ttl();
    packet.set_source("10.0.0.2");

    safe_send(ipsock, packet.raw->daddr, packet.raw_bytes(), packet.length());
}

template <class... FArgs>
void run_cmd_or_die(const char *fmt, FArgs... args)
{
    int len = std::snprintf(nullptr, 0, fmt, args...);
    if (len < 0) {
        std::cerr << "snprintf" << std::endl;
        std::terminate();
    }

    char* buf = new char[len + 1];
    std::sprintf(buf, fmt, args...);


    int rc = system(buf);
    if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0) {
        std::cerr << "Command '" << buf << "' failed" << std::endl;
        std::terminate();
    }

    delete[] buf;
}


void logger(char* buf, size_t count)
{
    std::cout << "Got and sent " << count << " bytes" << '\n';

    for (char* b = buf; b - buf < count;) {
        nets::IPv4Packet packet;
        try {
            packet = {b};
        } catch (nets::IPException& exc) {
            std::cout << exc.what() << ", ignoring" << '\n' << std::endl;
            return;
        }

//        std::ofstream dump_file("to" + packet.destination_addr() + ".ip");
//        dump_file.write(buf, count);
//        dump_file.close();

        std::cout << "From " << packet.source_addr()
                  << " to " << packet.destination_addr() << '\n';
        std::cout << "TTL " << static_cast<int>(packet.ttl()) << '\n';
        std::cout << "Total len " << static_cast<int>(packet.length()) << '\n' << std::endl;

        send_with_rawip(packet);
    }
}

int main()
{
    char* dev_name;
    int fd = tun_alloc(&dev_name);

    if (fd < 0) {
        std::cerr << "Cannot create tunnel" << std::endl;
        return 1;
    }

    run_cmd_or_die("ip link set %s up", dev_name);
    run_cmd_or_die("ip addr add %s dev %s", "10.0.0.0/24", dev_name);

    std::cout << dev_name << std::endl;
    free(dev_name);

    ipsock = prepare_ip_socket();

    tun_receive(fd, logger);

    return 0;
}

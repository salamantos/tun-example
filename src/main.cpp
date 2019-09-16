#include <iostream>
#include <sstream>
#include <fstream>



extern "C" {
#include "tuns.h"
}

#include "nets.hpp"


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
        net::IpHeader* header = net::load_ip(b);

        if (header->version != 0x04) {
            std::cout << "Version: " << static_cast<int>(header->version) << ". Not IPv4, ignoring" << '\n' << std::endl;
            return;
        }

        if (header->len < 20 || header->ihl < 5) {
            std::cout << "Corrupted, ignoring" << '\n' << std::endl;
            return;
        }

        uint16_t csum = net::checksum(header);
        uint16_t provided_csum = header->csum;

        if (csum != provided_csum) {
            std::cout << "Corrupted: " << provided_csum << " " << csum << ", ignoring\n" << std::endl;
            return;
        }

        net::ntoh(header);
        b += header->len;

        std::cout << "From " << net::addr_to_string(header->saddr)
                  << " to " << net::addr_to_string(header->daddr) << '\n';
        std::cout << "TTL " << static_cast<int>(header->ttl) << '\n';
        std::cout << "Total len " << static_cast<int>(header->len) << '\n' << std::endl;

        net::hton(header);

        std::ofstream dump_file("to" + net::addr_to_string(header->daddr) + ".ip");
        dump_file.write(buf, count);
        dump_file.close();
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

    tun_mirror(fd, logger);

    return 0;
}

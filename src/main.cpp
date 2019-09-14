#include <iostream>
#include <sstream>
#include "tuns.hpp"
#include "nets.hpp"

void logger(char* buf, size_t count) {
    std::cout << "Got and sent " << count << " bytes" << '\n';

    // assuming that buf always contains exactly one whole package
    std::istringstream stream{std::string{buf, count}};
    const Net::ip_header_t header = Net::load_ip(stream);

    std::cout << "From " << Net::addr_to_string(header.src_addr)
              << " to " << Net::addr_to_string(header.dst_addr) << '\n';
    std::cout << "Length " << ntohs(header.total_length) << '\n' << std::endl;
}

int main() {
    char* dev_name;
    int fd = tun_alloc(&dev_name);

    if (fd < 0) {
        std::cerr << "Cannot create tunnel" << std::endl;
        return 1;
    }

    std::cout << dev_name << std::endl;
    tun_mirror(fd, logger);

    return 0;
}

#include <iostream>
#include "tuns.h"
//#include "nets.hpp"

void logger(int count) {
    std::cout << "Got and sent " << count << " bytes" << std::endl;
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

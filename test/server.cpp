#include <iostream>

#include "cpp/CLI11.hpp"
#include "cpp/multiplexing.hpp"



extern "C" {
#include "include/cnets.h"
}

using namespace multiplexing;

static constexpr size_t bufsz = 1 << 17;
static IoMultiplexer mlpx;

void mirror_data(int fd) {
    char buf[bufsz];

    ssize_t got_count = read(fd, buf, bufsz);
    if (got_count < 0) {
        perror("Problems with client");
        mlpx.unfollow_later(Descriptor(fd));
        return;
    }

    if (got_count == 0) {
        mlpx.unfollow_later(Descriptor(fd));
        return;
    }

    size_t pos = 0;
    while (pos < got_count) {
        ssize_t written = send(fd, buf + pos, got_count - pos, MSG_NOSIGNAL);
        if (written < 0) {
            perror("Problems with client");
            mlpx.unfollow_later(Descriptor(fd));
            return;
        }
        pos += written;
    }
}


void mirror(int fd)
{
    mlpx.follow_later(
        Descriptor(fd)
            .set_clear_handler([](auto d) {
                close(d.fd);
            })
            .set_error_handler([](auto d) {
                mirror_data(d.fd);
            })
            .set_read_handler([](auto d) {
                mirror_data(d.fd);
            })
    );
}

void create_server(uint16_t port)
{
    int fd = init_server_socket(port);
    if (fd < 0) {
        perror("Cannot create server");
        std::terminate();
    }

    mlpx.follow_later(
        Descriptor(fd)
            .set_error_handler([](auto d) {
                std::cerr << "Problems with fd " << d.fd << std::endl;
                mlpx.unfollow_later(d);
            })
            .set_clear_handler([](auto d) {
                close(d.fd);
            })
            .set_read_handler([](auto d) {
                int fd = accept(d.fd, NULL, 0);
                if (fd < 0) {
                    perror("Cannot accept client");
                    return;
                }
                mirror(fd);
            })
    );
}


int main(int argc, char* argv[])
{
    std::vector<uint16_t> ports;
    CLI::App app{"Net Playground Test Server"};

    app.add_option("-p", ports);

    CLI11_PARSE(app, argc, argv)

    for (auto p : ports)
        create_server(p);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    while (true) {
        mlpx.wait();
    }
#pragma clang diagnostic pop
}

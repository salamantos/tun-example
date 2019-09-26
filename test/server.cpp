#include <iostream>
#include <deque>
#include <mutex>

#include "cpp/CLI11.hpp"
#include "cpp/multiplexing.hpp"



extern "C" {
#include "include/cnets.h"
#include <fcntl.h>
}

using namespace multiplexing;


class MultiplexedMirror;


static constexpr size_t bufsz = 1 << 17;
static IoMultiplexer mlpx;
static std::vector<std::shared_ptr<MultiplexedMirror>> mirrors;


class MultiplexedMirror : public std::enable_shared_from_this<MultiplexedMirror> {
private:
    std::deque<std::pair<const char*, size_t>> data;
    size_t pos = 0;
    IoMultiplexer& mlpx;
    Descriptor descriptor;

    bool reads_followed;
    size_t total = 0;

public:
    MultiplexedMirror(int fd, IoMultiplexer& mlpx)
        : descriptor(fd), mlpx(mlpx)
    {}

    void subscribe()
    {
        descriptor
            .set_clear_handler([self = weak_from_this()](auto) mutable {
                printf("clear\n");
                std::shared_ptr<MultiplexedMirror> self_sh = self.lock();
                close(self_sh->descriptor.fd());
                mirrors.erase(std::find(mirrors.begin(), mirrors.end(), self_sh));
            })
            .set_error_handler([self = weak_from_this()](auto) {
                self.lock()->perform_read();
            });

        follow_reads();
    }

    ~MultiplexedMirror()
    {
        printf("Destructed\n");
        while (!data.empty()) {
            delete[] data.front().first;
            data.pop_front();
        }
    }

private:
    void perform_read()
    {
        char* buf = new char[bufsz];

        ssize_t got_count = read(descriptor.fd(), buf, bufsz);
        if (got_count < 0) {
            perror("Problems with client (read)");
            mlpx.unfollow_later(Descriptor(descriptor.fd()));
            delete[] buf;
            return;
        }

        if (got_count == 0) {
            mlpx.unfollow_later(Descriptor(descriptor.fd()));
            delete[] buf;
            return;
        }

        if (data.empty())
            follow_writes();
        data.emplace_back(buf, got_count);
        total += got_count;

        speeddown_control();
    }

    bool perform_write()
    {
        if (data.empty())
            return false;

        auto& d = data.front();

        while (pos < d.second) {
            int written = send(descriptor.fd(), d.first, d.second - pos, MSG_NOSIGNAL);
            if (written < 0) {
                if (errno == EAGAIN) {
                    return true;
                } else {
                    perror("Problems with client (write)");
                    return false;
                }
            }
            pos += written;
            speeddown_control();
        }

        total -= pos;
        pos = 0;
        data.pop_front();
        delete[] d.first;
        return !data.empty();
    }

    void follow_writes()
    {
        descriptor.set_write_handler([self = weak_from_this()](auto) {
            self.lock()->on_write_available();
        });
        mlpx.follow_later(descriptor);
    }

    void unfollow_writes()
    {
        descriptor.set_write_handler({});
        mlpx.follow_later(descriptor);
    }

    void speeddown_control() {
        size_t total_exact = total - pos;
        if (reads_followed && total_exact > 10 * 1024)
            unfollow_reads();
        if (!reads_followed && total_exact <= 10 * 1024)
            follow_reads();
    }

    void follow_reads()
    {
        descriptor.set_read_handler([self = weak_from_this()](auto) {
            self.lock()->perform_read();
        });
        mlpx.follow_later(descriptor);
        reads_followed = true;
    }

    void unfollow_reads()
    {
        descriptor.set_read_handler({});
        mlpx.follow_later(descriptor);
        reads_followed = false;
    }

    void on_write_available()
    {
        bool need_more = perform_write();
        if (!need_more)
            unfollow_writes();
    }
};


void mirror(int fd)
{
    int ops = fcntl(fd, F_GETFL);
    if (ops == -1) {
        perror("fcntl");
        return;
    }

    ops |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, ops) == -1) {
        perror("fcntl");
        return;
    }

    mirrors.emplace_back(new MultiplexedMirror(fd, mlpx))->subscribe();
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
                std::cerr << "Problems with fd " << d.fd() << std::endl;
                mlpx.unfollow_later(d);
            })
            .set_clear_handler([](auto d) {
                close(d.fd());
            })
            .set_read_handler([](auto d) {
                int fd = accept(d.fd(), NULL, 0);
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

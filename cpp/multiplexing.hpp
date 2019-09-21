#pragma once

#include <mutex>
#include <condition_variable>

extern "C" {
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <unistd.h>
}


namespace multiplexing {

class CError : public std::runtime_error {
public:
    CError(const std::string& prefix)
        : runtime_error(prefix + ": " + strerror(errno))
    {
        errno = 0;
    }
};

class Descriptor;
class IoMultiplexer;

using WriteHandler = std::function<void (Descriptor)>;
using ReadHandler = std::function<void (Descriptor)>;
using ErrorHandler = std::function<void (Descriptor)>;

class Descriptor {
private:
    WriteHandler w_handler;
    ReadHandler r_handler;
    ErrorHandler e_handler;
    bool one_shot{false};

public:
    const int fd;

    explicit Descriptor(int fd)
        : fd(fd)
    {}

    Descriptor& set_write_handler(const WriteHandler& wHandler)
    {
        w_handler = wHandler;
        return *this;
    }

    Descriptor& set_read_handler(const ReadHandler& rHandler)
    {
        r_handler = rHandler;
        return *this;
    }

    Descriptor& set_error_handler(const ErrorHandler& eHandler)
    {
        e_handler = eHandler;
        return *this;
    }

    void set_one_shot() {
        one_shot = true;
    }

private:
    void read() {
        if (r_handler)
            r_handler(*this);
    }
    void write() {
        if (w_handler)
            w_handler(*this);
    }
    void error() {
        if (e_handler)
            e_handler(*this);
    }

    friend class IoMultiplexer;
};

class IoMultiplexer {
private:
    int epoll_fd = -1;
    int interrupter_fd = -1;
    std::map<int, std::shared_ptr<Descriptor>> descriptors;
    std::mutex lock;

    std::condition_variable wait_changes_done;
    std::atomic<bool> changes_requested{false};

    std::vector<Descriptor> unfollow_list;

public:
    IoMultiplexer() {
        epoll_fd = epoll_create(1);
        if (epoll_fd < 0) {
            throw CError("Cannot create epoll");
        }

        interrupter_fd = eventfd(0, 0);
        if (interrupter_fd < 0) {
            close(epoll_fd);
            throw CError("Cannot create epoll interceptor");
        }

        add_fd(interrupter_fd, true, false, nullptr);
    }

    void follow(const Descriptor& descriptor) {
        internal_interrupt();
        std::lock_guard guard(lock);
        changes_finished();

        auto it = descriptors.find(descriptor.fd);
        if (it != descriptors.end())
            throw std::logic_error("Descriptor is already followed");

        auto shared = descriptors[descriptor.fd] = std::make_shared<Descriptor>(descriptor);
        add_fd(descriptor.fd,
            static_cast<bool>(descriptor.r_handler), static_cast<bool>(descriptor.w_handler), shared.get());
    }

    void unfollow(const Descriptor& descriptor) {
        internal_interrupt();
        std::lock_guard guard(lock);
        changes_finished();

        internal_unfollow(descriptor);
    }

    void wait() {
        std::unique_lock guard(lock);
        for (const auto& descriptor : unfollow_list)
            internal_unfollow(descriptor);
        unfollow_list.clear();

        while (changes_requested.load())
            wait_changes_done.wait(guard);

        epoll_event evs[32];
        int wait_res = epoll_wait(epoll_fd, evs, 32, -1);
        if (wait_res < 0)
            throw CError("Epoll failed");

        for (int i = 0; i < wait_res; ++i) {
            process_event(evs[i]);
        }
    }

    // Intended for use from Read/Write/Error handlers
    // When normal unfollow will cause dead lock
    void unfollow_later(const Descriptor& descriptor) {
        unfollow_list.push_back(descriptor);
    }

    void interrupt() {
        internal_interrupt();
        changes_finished();
    }

    ~IoMultiplexer() {
        if (epoll_fd >= 0)
            close(epoll_fd);
        if (interrupter_fd >= 0)
            close(interrupter_fd);
    }

private:
    void process_event(const epoll_event& ev) {
        if (!ev.data.ptr) {
            clear_interrupter();
            return;
        }

        auto* descriptor = static_cast<Descriptor*>(ev.data.ptr);

        if (ev.events & (EPOLLIN | EPOLLRDHUP))
            descriptor->read();
        if (ev.events & EPOLLOUT)
            descriptor->write();
        if (ev.events & (EPOLLERR | EPOLLPRI))
            descriptor->error();

        if (descriptor->one_shot)
            descriptors.erase(descriptor->fd);
    }

    void add_fd(int fd, bool readable, bool writable, Descriptor* descriptor) {
        epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLPRI | EPOLLERR
            | (readable ? (EPOLLIN | EPOLLRDHUP) : 0) | (writable ? EPOLLOUT : 0)
            | ((descriptor && descriptor->one_shot) ? EPOLLONESHOT : 0);

        ev.data.ptr = descriptor;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev)) {
            throw CError("Cannot add descriptor to epoll set");
        }
    }

    void delete_fd(int fd) {
        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL))
            throw CError("Cannot delete descriptor from epoll set");
    }

    void internal_interrupt() {
        changes_requested.store(true);
        uint64_t val = 1;
        int written = write(interrupter_fd, &val, 8);
        if (written < 0)
            throw CError("Cannot interrupt epoll");
    }

    void internal_unfollow(const Descriptor& descriptor)
    {
        auto it = descriptors.find(descriptor.fd);
        if (it == descriptors.end())
            return;

        auto save = it->second;
        descriptors.erase(it);
        delete_fd(descriptor.fd);
    }

    void changes_finished() {
        changes_requested.store(false);
        wait_changes_done.notify_one();
    }

    void clear_interrupter() {
        uint64_t val;
        int got = read(interrupter_fd, &val, 8);
        if (got < 0)
            throw CError("Cannot clear epoll interrupter");
    }
};

}

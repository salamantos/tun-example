#pragma once

#include <mutex>
#include <vector>
#include <map>
#include <memory>

extern "C" {
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
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


using DescriptorHandler = std::function<void(Descriptor)>;


class Descriptor {
private:
    DescriptorHandler w_handler;
    DescriptorHandler r_handler;
    DescriptorHandler e_handler;
    DescriptorHandler c_handler;
    bool one_shot{false};

public:
    const int fd;

    explicit Descriptor(int fd)
        : fd(fd)
    {}

    Descriptor& set_write_handler(const DescriptorHandler& wHandler)
    {
        w_handler = wHandler;
        return *this;
    }

    Descriptor& set_read_handler(const DescriptorHandler& rHandler)
    {
        r_handler = rHandler;
        return *this;
    }

    Descriptor& set_error_handler(const DescriptorHandler& eHandler)
    {
        e_handler = eHandler;
        return *this;
    }

    Descriptor& set_clear_handler(const DescriptorHandler& eHandler)
    {
        e_handler = eHandler;
        return *this;
    }

    Descriptor& set_one_shot()
    {
        one_shot = true;
        return *this;
    }

    void read()
    {
        if (r_handler)
            r_handler(*this);
    }

    void write()
    {
        if (w_handler)
            w_handler(*this);
    }

    void error()
    {
        if (e_handler)
            e_handler(*this);
    }

    void clear()
    {
        if (c_handler)
            c_handler(*this);
    }

    friend class IoMultiplexer;
};


class IoMultiplexer {
private:
    int epoll_fd = -1;
    int interrupter_fd = -1;
    std::map<int, std::shared_ptr<Descriptor>> descriptors;

    std::mutex lock;
    std::vector<Descriptor> unfollow_list;
    std::vector<Descriptor> follow_list;

public:
    IoMultiplexer()
    {
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

    void follow(const Descriptor& descriptor)
    {
        follow_later(descriptor);
        internal_interrupt();
    }

    void unfollow(const Descriptor& descriptor)
    {
        unfollow_later(descriptor);
        internal_interrupt();
    }

    void wait()
    {
        {
            std::unique_lock guard(lock);
            for (const auto& descriptor : unfollow_list)
                internal_unfollow(descriptor);
            unfollow_list.clear();
            for (const auto& descriptor : follow_list)
                internal_follow(descriptor);
            follow_list.clear();
        }

        internal_wait();
    }

    void follow_later(const Descriptor& descriptor) {
        std::lock_guard guard(lock);
        follow_list.push_back(descriptor);
    }

    void unfollow_later(const Descriptor& descriptor)
    {
        std::lock_guard guard(lock);
        unfollow_list.push_back(descriptor);
    }

    void interrupt()
    {
        internal_interrupt();
    }

    std::vector<Descriptor> get_descriptors() const {
        std::vector<Descriptor> res;
        for (const auto& entry : descriptors) {
            res.push_back(*entry.second);
        }
        return res;
    }

    ~IoMultiplexer()
    {
        if (epoll_fd >= 0)
            close(epoll_fd);
        if (interrupter_fd >= 0)
            close(interrupter_fd);

        for (const auto& entry : descriptors) {
            entry.second->clear();
        }
    }

private:
    void process_event(const epoll_event& ev)
    {
        if (!ev.data.ptr) {
            clear_interrupter();
            return;
        }

        auto* descriptor = static_cast<Descriptor*>(ev.data.ptr);

        try {
            if (ev.events & (EPOLLIN | EPOLLRDHUP))
                descriptor->read();
            if (ev.events & EPOLLOUT)
                descriptor->write();
            if (ev.events & (EPOLLERR | EPOLLPRI))
                descriptor->error();
        } catch (...) {
            if (descriptor->one_shot) {
                unfollow_later(*descriptor);
            }
            std::rethrow_exception(std::current_exception());
        }

        if (descriptor->one_shot) {
            unfollow_later(*descriptor);
        }
    }

    void add_fd(int fd, bool readable, bool writable, Descriptor* descriptor)
    {
        epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLERR
                    | (readable ? (EPOLLIN | EPOLLRDHUP) : 0) | (writable ? EPOLLOUT : 0)
                    | ((descriptor && descriptor->one_shot) ? EPOLLONESHOT : 0);

        ev.data.ptr = descriptor;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev)) {
            throw CError("Cannot add descriptor to epoll set");
        }
    }

    void delete_fd(int fd)
    {
        if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL))
            throw CError("Cannot delete descriptor from epoll set");
    }

    void internal_interrupt()
    {
        uint64_t val = 1;
        int written = write(interrupter_fd, &val, 8);
        if (written < 0)
            throw CError("Cannot interrupt epoll");
    }

    void internal_follow(const Descriptor& descriptor)
    {
        auto it = descriptors.find(descriptor.fd);
        if (it != descriptors.end())
            throw std::logic_error("Descriptor is already followed");

        auto shared = descriptors[descriptor.fd] = std::make_shared<Descriptor>(descriptor);
        add_fd(descriptor.fd,
               static_cast<bool>(descriptor.r_handler), static_cast<bool>(descriptor.w_handler), shared.get());
    }

    void internal_unfollow(const Descriptor& descriptor)
    {
        auto it = descriptors.find(descriptor.fd);
        if (it == descriptors.end())
            return;

        it->second->clear();
        descriptors.erase(it);
        delete_fd(descriptor.fd);
    }

    void internal_wait()
    {
        epoll_event evs[32];
        int wait_res = epoll_wait(epoll_fd, evs, 32, -1);
        if (wait_res < 0)
            throw CError("Epoll failed");

        for (int i = 0; i < wait_res; ++i) {
            process_event(evs[i]);
        }
    }

    void clear_interrupter()
    {
        uint64_t val;
        int got = read(interrupter_fd, &val, 8);
        if (got < 0)
            throw CError("Cannot clear epoll interrupter");
    }
};

}

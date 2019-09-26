#pragma once

#include <mutex>
#include <deque>
#include <vector>
#include <map>
#include <set>
#include <memory>



extern "C" {
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
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

    int fd_;

public:
    explicit Descriptor(int fd)
        : fd_(fd)
    {}

    Descriptor()
        : fd_(-1)
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

    int fd() const
    {
        return fd_;
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

        add_fd(interrupter_fd, true, false, nullptr, true);
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

    void follow_later(const Descriptor& descriptor)
    {
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

    std::vector<Descriptor> get_descriptors() const
    {
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

    void add_fd(int fd, bool readable, bool writable, Descriptor* descriptor, bool is_new)
    {
        epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLERR
                    | (readable ? (EPOLLIN | EPOLLRDHUP) : 0) | (writable ? EPOLLOUT : 0)
                    | ((descriptor && descriptor->one_shot) ? EPOLLONESHOT : 0);

        ev.data.ptr = descriptor;
        if (epoll_ctl(epoll_fd, (is_new ? EPOLL_CTL_ADD : EPOLL_CTL_MOD), fd, &ev)) {
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
        auto it = descriptors.find(descriptor.fd());
        if (it != descriptors.end()) {
            *(it->second) = descriptor;
            add_fd(descriptor.fd(), static_cast<bool>(descriptor.r_handler), static_cast<bool>(descriptor.w_handler),
                   it->second.get(), false);
        } else {
            auto shared = descriptors[descriptor.fd()] = std::make_shared<Descriptor>(descriptor);
            add_fd(descriptor.fd(), static_cast<bool>(descriptor.r_handler), static_cast<bool>(descriptor.w_handler),
                   shared.get(), true);
        }
    }

    void internal_unfollow(const Descriptor& descriptor)
    {
        auto it = descriptors.find(descriptor.fd());
        if (it == descriptors.end())
            return;

        it->second->clear();
        descriptors.erase(it);
        delete_fd(descriptor.fd());
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


template <class Data>
class MultiplexedWritingProvider;


template <class Data>
class MultiplexedWriter;


template <class Data>
using WriterHandler = std::function<void(MultiplexedWriter<Data>&)>;

template <class Data>
using WriterDataMapper = std::function<std::pair<const char*, size_t>(const Data&)>;


template <class Data>
class MultiplexedWriter : public std::enable_shared_from_this<MultiplexedWriter<Data>> {
private:
    MultiplexedWritingProvider<Data>& provider;
    Descriptor descriptor;

    WriterHandler<Data> r_handler;
    WriterHandler<Data> e_handler;
    WriterHandler<Data> c_handler;

    std::deque<Data> data;
    size_t pos = 0;

public:
    MultiplexedWriter(MultiplexedWritingProvider<Data>& provider, int fd)
        : provider(provider), descriptor(fd)
    {}

    int fd() const
    {
        return descriptor.fd();
    }

    void destroy()
    {
        provider.unregister();
    }

    MultiplexedWriter& operator<<(Data&& d)
    {
        if (data.empty()) {
            set_follow_writes(true);
        }
        data.emplace_back(std::move(d));
        return *this;
    }

    MultiplexedWriter<Data>& set_read_handler(const WriterHandler<Data>& rHandler)
    {
        if (static_cast<bool>(rHandler) != static_cast<bool>(r_handler)) {
            set_follow_reads(static_cast<bool>(rHandler));
        }
        r_handler = rHandler;
        return *this;
    }

    MultiplexedWriter<Data>& set_error_handler(const WriterHandler<Data>& eHandler)
    {
        if (static_cast<bool>(eHandler) != static_cast<bool>(e_handler)) {
            set_follow_errors(static_cast<bool>(eHandler));
        }
        e_handler = eHandler;
        return *this;
    }

    MultiplexedWriter<Data>& set_clear_handler(const WriterHandler<Data>& eHandler)
    {
        e_handler = eHandler;
        return *this;
    }

private:
    bool perform_write()
    {
        if (data.empty())
            return false;

        auto d = provider.mapper(data.front());

        while (pos < d.second) {
            int written;
            if (provider.send_flags)
                written = send(descriptor.fd(), d.first, d.second - pos, provider.send_flags);
            else
                written = write(descriptor.fd(), d.first, d.second - pos);

            if (written < 0) {
                if (errno == EAGAIN) {
                    return true;
                } else {
                    throw CError("Cannot write to descriptor");
                }
            }
            pos += written;
        }

        pos = 0;
        data.pop_front();
        return !data.empty();
    }

    void initialize()
    {
        descriptor
            .set_clear_handler([self = this->weak_from_this()](auto) mutable {
                auto self_sh = self.lock();
                self_sh->handle_clear();
                self_sh->provider.clear_writer(self_sh->fd());
                close(self_sh->descriptor.fd());
            });
    }

    void set_follow_reads(bool do_follow)
    {
        if (do_follow) {
            descriptor
                .set_read_handler([self = this->weak_from_this()](auto) {
                    self.lock()->handle_read();
                });
        } else {
            descriptor.set_read_handler({});
        }
        provider.reregister(descriptor);
    }

    void set_follow_errors(bool do_follow)
    {
        if (do_follow) {
            descriptor
                .set_error_handler([self = this->weak_from_this()](auto) {
                    self.lock()->handle_error();
                });
        } else {
            descriptor.set_error_handler({});
        }
        provider.reregister(descriptor);
    }

    void set_follow_writes(bool do_follow)
    {
        if (do_follow) {
            descriptor
                .set_write_handler([self = this->weak_from_this()](auto) {
                    self.lock()->on_write_available();
                });
        } else {
            descriptor.set_error_handler({});
        }
        provider.reregister(descriptor);
    }

    void handle_read()
    {
        if (r_handler)
            r_handler(*this);
    }

    void handle_error()
    {
        if (e_handler)
            e_handler(*this);
    }

    void handle_clear()
    {
        if (c_handler)
            c_handler(*this);
    }

    void on_write_available()
    {
        bool need_more = perform_write();
        if (!need_more)
            set_follow_writes(false);
    }


    friend class MultiplexedWritingProvider<Data>;
};


template <class Data>
class MultiplexedWritingProvider {
private:
    IoMultiplexer mlpx;
    std::map<int, std::shared_ptr<MultiplexedWriter<Data>>> writers;
    std::map<int, Descriptor> changes;

    WriterDataMapper<Data> mapper;
    int send_flags;

public:
    explicit MultiplexedWritingProvider(WriterDataMapper<Data> mapper, int flags = 0)
        : mapper(std::move(mapper)), send_flags(flags)
    {}

    MultiplexedWriter<Data>& get_writer(int fd)
    {
        std::shared_ptr<MultiplexedWriter<Data>>& ptr = writers[fd];
        if (!ptr) {
            ptr = std::shared_ptr<MultiplexedWriter<Data>>(new MultiplexedWriter<Data>(*this, fd));
            ptr->initialize();
        }
        return *ptr;
    }

    void wait()
    {
        for (const auto& entry : changes)
            mlpx.follow_later(entry.second);
        changes.clear();
        mlpx.wait();
    }

    void interrupt()
    {
        mlpx.interrupt();
    }

private:
    void clear_writer(int fd)
    {
        writers.erase(fd);
    }

    void reregister(const Descriptor& d)
    {
        changes[d.fd()] = d;
    }

    void unregister(const Descriptor& d)
    {
        mlpx.unfollow_later(d);
    }


    friend class MultiplexedWriter<Data>;
};

}

#pragma once

#include <atomic>
#include <condition_variable>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>



namespace time_machine {

class QueueClosed : public std::runtime_error {
public:
    QueueClosed()
        : std::runtime_error("Queue closed for Puts")
    {}
};


template <typename T, class Container = std::deque<T>>
class BlockingQueue {
public:
    explicit BlockingQueue() = default;

    // throws QueueClosed exception after Close
    template <typename U>
    void put(U&& item)
    {
        std::unique_lock<std::mutex> lock(lock_);

        if (closed_) {
            throw QueueClosed();
        }

        items_.push_back(std::forward<U>(item));
        consumer_cv_.notify_one();
    }

    // returns false if queue is empty and closed
    bool get(T& item)
    {
        std::unique_lock<std::mutex> lock(lock_);

        while (!closed_ && isEmpty())
            consumer_cv_.wait(lock);

        if (isEmpty())
            return false;

        item = std::move(items_.front());
        items_.pop_front();

        return true;
    }

    bool get(std::vector<T>& out_items, size_t max_count, bool require_at_least_one)
    {
        if (!max_count)
            return true;

        std::unique_lock<std::mutex> lock(lock_);

        if (require_at_least_one) {
            while (!closed_ && isEmpty())
                consumer_cv_.wait(lock);

            if (isEmpty())
                return false;
        }

        const size_t count = std::min(max_count, items_.size());
        for (size_t i = 0; i < count; ++i) {
            out_items.push_back(std::move(items_.front()));
            items_.pop_front();
        }

        return true;
    }

    void close()
    {
        std::unique_lock<std::mutex> lock(lock_);

        closed_ = true;
        consumer_cv_.notify_all();
    }

    bool isClosed()
    {
        std::lock_guard lock(lock_);
        return closed_;
    }

private:
    Container items_;
    bool closed_{false};
    std::mutex lock_;
    std::condition_variable consumer_cv_;

    bool isEmpty()
    {
        return items_.empty();
    }
};

}

#pragma once

#include <atomic>
#include <cstddef>
#include <mutex>
#include <vector>

#include <sentcore/core/event.hpp>

namespace sentcore
{

// A bounded queue with storage allocated once at startup. The lock is intentional:
// collectors are relatively low-rate in v0.1 and predictable memory usage is more
// valuable than introducing a complex lock-free MPMC structure prematurely.
class EventQueue final
{
  public:
    explicit EventQueue(std::size_t capacity) : buffer_(capacity)
    {
    }

    [[nodiscard]] bool try_push(Event event) noexcept
    {
        std::scoped_lock lock(mutex_);
        if (size_ == buffer_.size())
        {
            dropped_.fetch_add(1U, std::memory_order_relaxed);
            return false;
        }

        buffer_[tail_] = std::move(event);
        tail_ = (tail_ + 1U) % buffer_.size();
        ++size_;
        return true;
    }

    [[nodiscard]] bool try_pop(Event& event) noexcept
    {
        std::scoped_lock lock(mutex_);
        if (size_ == 0U)
        {
            return false;
        }

        event = std::move(buffer_[head_]);
        head_ = (head_ + 1U) % buffer_.size();
        --size_;
        return true;
    }

    [[nodiscard]] std::uint64_t dropped() const noexcept
    {
        return dropped_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::size_t capacity() const noexcept
    {
        return buffer_.size();
    }

  private:
    std::vector<Event> buffer_;
    mutable std::mutex mutex_;
    std::size_t head_{0U};
    std::size_t tail_{0U};
    std::size_t size_{0U};
    std::atomic<std::uint64_t> dropped_{0U};
};

} // namespace sentcore

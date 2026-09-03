#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <utility>
#include <vector>

#include <sentcore/core/event.hpp>

namespace sentcore
{

// Bounded MPMC queue backed by a single startup allocation.
//
// The mutex is deliberate: it keeps the implementation simple, predictable and
// correct while collector rates remain well below the point where lock contention
// justifies a substantially more complex lock-free queue. Ring-buffer indices use
// branch-based wrapping to avoid modulo operations on the hot path.
class EventQueue final
{
  public:
    explicit EventQueue(std::size_t capacity) : buffer_(capacity)
    {
    }

    EventQueue(const EventQueue&) = delete;
    EventQueue& operator=(const EventQueue&) = delete;
    EventQueue(EventQueue&&) = delete;
    EventQueue& operator=(EventQueue&&) = delete;

    // Lvalue overload: exactly one copy into the preallocated ring buffer.
    [[nodiscard]] bool try_push(const Event& event) noexcept
    {
        std::scoped_lock lock(mutex_);
        return push_unlocked(event);
    }

    // Rvalue overload: allows callers to transfer an event without the
    // pass-by-value copy that the previous implementation required.
    [[nodiscard]] bool try_push(Event&& event) noexcept
    {
        std::scoped_lock lock(mutex_);
        return push_unlocked(std::move(event));
    }

    [[nodiscard]] bool try_pop(Event& event) noexcept
    {
        std::scoped_lock lock(mutex_);

        if (size_ == 0U)
        {
            return false;
        }

        event = std::move(buffer_[head_]);
        advance(head_);
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

    [[nodiscard]] std::size_t size() const noexcept
    {
        std::scoped_lock lock(mutex_);
        return size_;
    }

  private:
    template <typename EventLike>
    [[nodiscard]] bool push_unlocked(EventLike&& event) noexcept
    {
        if (size_ == buffer_.size())
        {
            dropped_.fetch_add(1U, std::memory_order_relaxed);
            return false;
        }

        buffer_[tail_] = std::forward<EventLike>(event);
        advance(tail_);
        ++size_;
        return true;
    }

    void advance(std::size_t& index) noexcept
    {
        ++index;

        if (index == buffer_.size())
        {
            index = 0U;
        }
    }

    std::vector<Event> buffer_;
    mutable std::mutex mutex_;

    // Protected by mutex_.
    std::size_t head_{0U};
    std::size_t tail_{0U};
    std::size_t size_{0U};

    // Readable without acquiring mutex_; relaxed ordering is sufficient for
    // telemetry because the counter does not synchronize any other state.
    std::atomic<std::uint64_t> dropped_{0U};
};

} // namespace sentcore

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <stop_token>
#include <unordered_set>

#include <sentcore/core/event_queue.hpp>

namespace sentcore
{

class ProcessCollector final
{
  public:
    ProcessCollector(EventQueue& queue,
                     std::atomic<std::uint64_t>& sequence,
                     std::chrono::milliseconds interval) noexcept;

    void run(std::stop_token stop_token);

  private:
    void establish_baseline();
    void scan_once();

    EventQueue& queue_;
    std::atomic<std::uint64_t>& sequence_;
    std::chrono::milliseconds interval_;
    std::unordered_set<std::int32_t> known_pids_{};
};

} // namespace sentcore

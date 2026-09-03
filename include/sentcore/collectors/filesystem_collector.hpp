#pragma once

#include <atomic>
#include <cstdint>
#include <stop_token>

#include <sentcore/core/event_queue.hpp>

namespace sentcore
{

class FilesystemCollector final
{
  public:
    FilesystemCollector(EventQueue& queue, std::atomic<std::uint64_t>& sequence) noexcept;

    void run(std::stop_token stop_token);

  private:
    EventQueue& queue_;
    std::atomic<std::uint64_t>& sequence_;
};

} // namespace sentcore

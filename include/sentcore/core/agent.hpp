#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>

#include <sentcore/core/event_queue.hpp>

namespace sentcore
{

struct AgentOptions final
{
    std::size_t queue_capacity{2048U};
    std::chrono::milliseconds process_poll_interval{250};
    std::string event_log{"events.jsonl"};
    std::string alert_log{"alerts.jsonl"};
};

class Agent final
{
  public:
    explicit Agent(AgentOptions options);

    [[nodiscard]] int run();

  private:
    AgentOptions options_;
    EventQueue queue_;
    std::atomic<std::uint64_t> sequence_{1U};
};

} // namespace sentcore

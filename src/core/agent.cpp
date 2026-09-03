#include <sentcore/core/agent.hpp>

#include <atomic>
#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

#include <sentcore/collectors/filesystem_collector.hpp>
#include <sentcore/collectors/process_collector.hpp>
#include <sentcore/detection/detection_engine.hpp>
#include <sentcore/output/jsonl_writer.hpp>

namespace sentcore
{
namespace
{

std::atomic_bool g_stop_requested{false};

extern "C" void signal_handler(int) noexcept
{
    g_stop_requested.store(true, std::memory_order_relaxed);
}

} // namespace

Agent::Agent(AgentOptions options) : options_(std::move(options)), queue_(options_.queue_capacity)
{
}

int Agent::run()
{
    g_stop_requested.store(false, std::memory_order_relaxed);
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    JsonlWriter writer(options_.event_log, options_.alert_log);
    if (!writer.ready())
    {
        std::cerr << "[sentcore] failed to open output files\n";
        return 2;
    }

    DetectionEngine detector{};
    ProcessCollector process_collector(queue_, sequence_, options_.process_poll_interval);
    FilesystemCollector filesystem_collector(queue_, sequence_);

    std::jthread process_thread([&process_collector](std::stop_token token) {
        process_collector.run(token);
    });
    std::jthread filesystem_thread([&filesystem_collector](std::stop_token token) {
        filesystem_collector.run(token);
    });

    std::cout << "SentCore monitoring started. Press Ctrl+C to stop.\n";
    std::cout << "Queue capacity: " << queue_.capacity() << " events\n";

    Event event{};
    while (!g_stop_requested.load(std::memory_order_relaxed))
    {
        if (!queue_.try_pop(event))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }

        writer.write_event(event);
        const auto detections = detector.evaluate(event);
        for (std::size_t index = 0U; index < detections.count; ++index)
        {
            const auto& alert = detections.alerts[index];
            writer.write_alert(alert);
            std::cout << '[' << to_string(alert.severity) << "] " << alert.rule_id.view() << " - "
                      << alert.title.view();
            if (!alert.event.path.empty())
            {
                std::cout << " | " << alert.event.path.view();
            }
            std::cout << '\n';
        }
    }

    process_thread.request_stop();
    filesystem_thread.request_stop();

    std::cout << "SentCore stopped. Dropped events: " << queue_.dropped() << '\n';
    return 0;
}

} // namespace sentcore

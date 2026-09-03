#include <chrono>
#include <cstddef>
#include <iomanip>
#include <iostream>

#include <sentcore/core/event.hpp>
#include <sentcore/detection/detection_engine.hpp>

int main()
{
    constexpr std::size_t iterations = 1'000'000U;
    constexpr std::size_t queue_capacity = 2048U;

    sentcore::DetectionEngine engine{};
    sentcore::Event event{};
    event.source = sentcore::EventSource::Procfs;

    auto& process = event.emplace_process();
    process.executable.assign("/usr/bin/python3");
    process.command.assign("python3 worker.py");

    std::size_t alert_count{0U};

    const auto start = std::chrono::steady_clock::now();

    for (std::size_t index = 0U; index < iterations; ++index)
    {
        event.sequence = index;
        alert_count += engine.evaluate(event).count;
    }

    const auto elapsed = std::chrono::steady_clock::now() - start;
    const auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count();

    const double seconds = static_cast<double>(nanoseconds) / 1'000'000'000.0;
    const double rate = static_cast<double>(iterations) / seconds;

    constexpr std::size_t queue_bytes = sizeof(sentcore::Event) * queue_capacity;
    constexpr double bytes_per_mib = 1024.0 * 1024.0;

    std::cout << "Event layout\n"
              << "------------\n"
              << "Event size: " << sizeof(sentcore::Event) << " bytes\n"
              << "Event alignment: " << alignof(sentcore::Event) << " bytes\n"
              << "Process payload: " << sizeof(sentcore::ProcessPayload) << " bytes\n"
              << "File payload: " << sizeof(sentcore::FilePayload) << " bytes\n"
              << "Internal payload: " << sizeof(sentcore::InternalPayload) << " bytes\n"
              << "Queue @ " << queue_capacity << ": " << queue_bytes << " bytes ("
              << std::fixed << std::setprecision(2)
              << static_cast<double>(queue_bytes) / bytes_per_mib << " MiB)\n\n"
              << "Benchmark\n"
              << "---------\n"
              << "Iterations: " << iterations << '\n'
              << "Elapsed: " << std::setprecision(6) << seconds << " s\n"
              << "Throughput: " << std::setprecision(3) << rate << " events/s\n"
              << "Alerts: " << alert_count << '\n';

    return 0;
}
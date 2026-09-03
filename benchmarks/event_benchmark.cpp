#include <chrono>
#include <cstddef>
#include <iostream>

#include <sentcore/core/event.hpp>
#include <sentcore/detection/detection_engine.hpp>

int main()
{
    constexpr std::size_t iterations = 1'000'000U;
    sentcore::DetectionEngine engine{};
    sentcore::Event event{};
    event.type = sentcore::EventType::ProcessStart;
    event.path.assign("/usr/bin/python3");
    event.command.assign("python3 worker.py");

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

    std::cout << "Event size: " << sizeof(sentcore::Event) << " bytes\n";
    std::cout << "Iterations: " << iterations << '\n';
    std::cout << "Elapsed: " << seconds << " s\n";
    std::cout << "Throughput: " << rate << " events/s\n";
    std::cout << "Alerts: " << alert_count << '\n';
    return 0;
}
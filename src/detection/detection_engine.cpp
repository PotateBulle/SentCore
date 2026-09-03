#include <sentcore/detection/detection_engine.hpp>

#include <string_view>

namespace sentcore
{
namespace
{

[[nodiscard]] bool starts_with_temp(std::string_view path) noexcept
{
    return path.starts_with("/tmp/") || path.starts_with("/var/tmp/") ||
           path.starts_with("/dev/shm/");
}

[[nodiscard]] bool is_file_event(EventType type) noexcept
{
    return type == EventType::FileCreated || type == EventType::FileModified ||
           type == EventType::FileMoved;
}

} // namespace

DetectionBatch DetectionEngine::evaluate(const Event& event) const noexcept
{
    DetectionBatch batch{};
    const auto path = event.path.view();
    const auto command = event.command.view();

    if (event.type == EventType::ProcessStart && starts_with_temp(path))
    {
        batch.add("SC-LNX-001",
                  "Process executed from a temporary directory",
                  Severity::High,
                  "T1059",
                  event);
    }

    if (event.type == EventType::ProcessStart)
    {
        const bool downloader = command.find("curl ") != std::string_view::npos ||
                                command.find("wget ") != std::string_view::npos;
        const bool shell_pipe = command.find("| sh") != std::string_view::npos ||
                                command.find("| bash") != std::string_view::npos;

        if (downloader && shell_pipe)
        {
            batch.add("SC-LNX-002",
                      "Download-and-execute shell chain",
                      Severity::Critical,
                      "T1105/T1059",
                      event);
        }

        if (command.find("/dev/tcp/") != std::string_view::npos)
        {
            batch.add("SC-LNX-003",
                      "Shell command references /dev/tcp",
                      Severity::High,
                      "T1059.004",
                      event);
        }

        const bool base64 = command.find("base64") != std::string_view::npos;
        const bool decode = command.find(" -d") != std::string_view::npos ||
                            command.find("--decode") != std::string_view::npos;
        if (base64 && decode)
        {
            batch.add("SC-LNX-004",
                      "Base64 decoding observed in process command line",
                      Severity::Medium,
                      "T1140",
                      event);
        }
    }

    if (is_file_event(event.type) && path.starts_with("/etc/systemd/system/"))
    {
        batch.add("SC-LNX-005",
                  "Systemd persistence path modified",
                  Severity::High,
                  "T1543.002",
                  event);
    }

    if (is_file_event(event.type) && path.ends_with("/.ssh/authorized_keys"))
    {
        batch.add("SC-LNX-006",
                  "SSH authorized_keys modified",
                  Severity::High,
                  "T1098.004",
                  event);
    }

    if (is_file_event(event.type) && starts_with_temp(path) && (event.mode & 0111U) != 0U)
    {
        batch.add("SC-LNX-007",
                  "Executable file created in a temporary directory",
                  Severity::High,
                  "T1105",
                  event);
    }

    return batch;
}

} // namespace sentcore

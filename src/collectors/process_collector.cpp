#include <sentcore/collectors/process_collector.hpp>

#include <charconv>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace sentcore
{
namespace
{

[[nodiscard]] bool parse_pid(std::string_view text, std::int32_t& pid) noexcept
{
    const auto* begin = text.data();
    const auto* end = begin + text.size();
    const auto result = std::from_chars(begin, end, pid);
    return result.ec == std::errc{} && result.ptr == end && pid > 0;
}

[[nodiscard]] std::string read_cmdline(std::int32_t pid)
{
    std::ifstream stream("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    if (!stream)
    {
        return {};
    }

    std::string data((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

    for (char& value : data)
    {
        if (value == '\0')
        {
            value = ' ';
        }
    }

    while (!data.empty() && data.back() == ' ')
    {
        data.pop_back();
    }

    return data;
}

[[nodiscard]] std::string read_executable(std::int32_t pid)
{
    std::error_code error;
    const auto link = std::filesystem::read_symlink("/proc/" + std::to_string(pid) + "/exe", error);
    return error ? std::string{} : link.string();
}

void read_status(std::int32_t pid, std::int32_t& ppid, std::uint32_t& uid)
{
    std::ifstream stream("/proc/" + std::to_string(pid) + "/status");
    std::string line;

    while (std::getline(stream, line))
    {
        if (line.starts_with("PPid:"))
        {
            const auto value = std::string_view(line).substr(5);
            const auto first = value.find_first_not_of(" \t");

            if (first != std::string_view::npos)
            {
                const auto clean = value.substr(first);
                std::int32_t parsed{-1};
                const auto result =
                    std::from_chars(clean.data(), clean.data() + clean.size(), parsed);

                if (result.ec == std::errc{})
                {
                    ppid = parsed;
                }
            }
        }
        else if (line.starts_with("Uid:"))
        {
            const auto value = std::string_view(line).substr(4);
            const auto first = value.find_first_not_of(" \t");

            if (first != std::string_view::npos)
            {
                const auto clean = value.substr(first);
                std::uint32_t parsed{0U};
                const auto result =
                    std::from_chars(clean.data(), clean.data() + clean.size(), parsed);

                if (result.ec == std::errc{})
                {
                    uid = parsed;
                }
            }
        }
    }
}

} // namespace

ProcessCollector::ProcessCollector(EventQueue& queue,
                                   std::atomic<std::uint64_t>& sequence,
                                   std::chrono::milliseconds interval) noexcept
    : queue_(queue), sequence_(sequence), interval_(interval)
{
}

void ProcessCollector::establish_baseline()
{
    known_pids_.clear();

    std::error_code error;
    std::filesystem::directory_iterator iterator("/proc", error);
    if (error)
    {
        return;
    }

    for (const auto& entry : iterator)
    {
        std::int32_t pid{-1};
        if (parse_pid(entry.path().filename().string(), pid))
        {
            known_pids_.insert(pid);
        }
    }
}

void ProcessCollector::scan_once()
{
    std::unordered_set<std::int32_t> current;
    current.reserve(known_pids_.size() + 64U);

    std::error_code error;
    std::filesystem::directory_iterator iterator("/proc", error);
    if (error)
    {
        return;
    }

    for (const auto& entry : iterator)
    {
        std::int32_t pid{-1};
        if (!parse_pid(entry.path().filename().string(), pid))
        {
            continue;
        }

        current.insert(pid);

        if (known_pids_.contains(pid))
        {
            continue;
        }

        Event event{};
        event.sequence = sequence_.fetch_add(1U, std::memory_order_relaxed);
        event.timestamp_ns = now_unix_ns();
        event.source = EventSource::Procfs;

        auto& process = event.emplace_process();
        process.pid = pid;

        read_status(pid, process.ppid, process.uid);
        process.executable.assign(read_executable(pid));
        process.command.assign(read_cmdline(pid));

        static_cast<void>(queue_.try_push(std::move(event)));
    }

    known_pids_.swap(current);
}

void ProcessCollector::run(std::stop_token stop_token)
{
    establish_baseline();

    while (!stop_token.stop_requested())
    {
        scan_once();
        std::this_thread::sleep_for(interval_);
    }
}}
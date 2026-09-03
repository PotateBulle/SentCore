#include <sentcore/collectors/filesystem_collector.hpp>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <unordered_map>

#include <poll.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

namespace sentcore
{
namespace
{

constexpr std::uint32_t kWatchMask = IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_DELETE |
                                     IN_MOVED_TO | IN_MOVED_FROM | IN_ATTRIB | IN_Q_OVERFLOW;

[[nodiscard]] EventType map_event_type(std::uint32_t mask) noexcept
{
    if ((mask & IN_CREATE) != 0U)
    {
        return EventType::FileCreated;
    }
    if ((mask & (IN_MOVED_TO | IN_MOVED_FROM)) != 0U)
    {
        return EventType::FileMoved;
    }
    if ((mask & IN_DELETE) != 0U)
    {
        return EventType::FileDeleted;
    }
    return EventType::FileModified;
}

[[nodiscard]] std::uint32_t read_mode(const std::string& path) noexcept
{
    struct stat info
    {
    };
    if (::stat(path.c_str(), &info) != 0)
    {
        return 0U;
    }
    return static_cast<std::uint32_t>(info.st_mode);
}

} // namespace

FilesystemCollector::FilesystemCollector(EventQueue& queue,
                                         std::atomic<std::uint64_t>& sequence) noexcept
    : queue_(queue), sequence_(sequence)
{
}

void FilesystemCollector::run(std::stop_token stop_token)
{
    const int descriptor = ::inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (descriptor < 0)
    {
        return;
    }

    std::unordered_map<int, std::string> watches;
    const auto add_watch = [&](const std::string& path) {
        if (!std::filesystem::exists(path))
        {
            return;
        }
        const int watch = ::inotify_add_watch(descriptor, path.c_str(), kWatchMask);
        if (watch >= 0)
        {
            watches.emplace(watch, path);
        }
    };

    add_watch("/tmp");
    add_watch("/var/tmp");
    add_watch("/dev/shm");
    add_watch("/etc/systemd/system");

    if (const char* home = std::getenv("HOME"); home != nullptr)
    {
        add_watch(std::string(home) + "/.ssh");
        add_watch(std::string(home) + "/.config/systemd/user");
    }

    alignas(inotify_event) std::array<char, 64U * 1024U> buffer{};
    struct pollfd poll_descriptor
    {
        descriptor, POLLIN, 0
    };

    while (!stop_token.stop_requested())
    {
        const int poll_result = ::poll(&poll_descriptor, 1, 250);
        if (poll_result <= 0 || (poll_descriptor.revents & POLLIN) == 0)
        {
            continue;
        }

        const ssize_t bytes = ::read(descriptor, buffer.data(), buffer.size());
        if (bytes <= 0)
        {
            continue;
        }

        std::size_t offset{0U};
        const auto byte_count = static_cast<std::size_t>(bytes);
        while (offset < byte_count)
        {
            const auto* raw = buffer.data() + offset;
            const auto* notification = reinterpret_cast<const inotify_event*>(raw);
            offset += sizeof(inotify_event) + notification->len;

            if ((notification->mask & IN_Q_OVERFLOW) != 0U)
            {
                Event event{};
                event.sequence = sequence_.fetch_add(1U, std::memory_order_relaxed);
                event.timestamp_ns = now_unix_ns();
                event.type = EventType::Internal;
                event.source.assign("inotify");
                event.command.assign("inotify queue overflow");
                static_cast<void>(queue_.try_push(std::move(event)));
                continue;
            }

            const auto watch = watches.find(notification->wd);
            if (watch == watches.end())
            {
                continue;
            }

            std::string path = watch->second;
            if (notification->len > 0U && notification->name[0] != '\0')
            {
                path += '/';
                path += notification->name;
            }

            Event event{};
            event.sequence = sequence_.fetch_add(1U, std::memory_order_relaxed);
            event.timestamp_ns = now_unix_ns();
            event.type = map_event_type(notification->mask);
            event.uid = static_cast<std::uint32_t>(::getuid());
            event.mode = read_mode(path);
            event.source.assign("inotify");
            event.path.assign(path);
            static_cast<void>(queue_.try_push(std::move(event)));
        }
    }

    ::close(descriptor);
}

} // namespace sentcore

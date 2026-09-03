#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

#include <sentcore/core/fixed_string.hpp>

namespace sentcore
{

enum class EventType : std::uint8_t
{
    ProcessStart,
    FileCreated,
    FileModified,
    FileDeleted,
    FileMoved,
    Internal
};

enum class Severity : std::uint8_t
{
    Info,
    Low,
    Medium,
    High,
    Critical
};

struct Event final
{
    std::uint64_t sequence{0U};
    std::uint64_t timestamp_ns{0U};
    std::int32_t pid{-1};
    std::int32_t ppid{-1};
    std::uint32_t uid{0U};
    std::uint32_t mode{0U};
    EventType type{EventType::Internal};
    FixedString<64> source{};
    FixedString<384> path{};
    FixedString<768> command{};
};

[[nodiscard]] inline std::uint64_t now_unix_ns() noexcept
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

[[nodiscard]] constexpr std::string_view to_string(EventType type) noexcept
{
    switch (type)
    {
        case EventType::ProcessStart:
            return "process_start";
        case EventType::FileCreated:
            return "file_created";
        case EventType::FileModified:
            return "file_modified";
        case EventType::FileDeleted:
            return "file_deleted";
        case EventType::FileMoved:
            return "file_moved";
        case EventType::Internal:
            return "internal";
    }

    return "unknown";
}

[[nodiscard]] constexpr std::string_view to_string(Severity severity) noexcept
{
    switch (severity)
    {
        case Severity::Info:
            return "info";
        case Severity::Low:
            return "low";
        case Severity::Medium:
            return "medium";
        case Severity::High:
            return "high";
        case Severity::Critical:
            return "critical";
    }

    return "unknown";
}

} // namespace sentcore

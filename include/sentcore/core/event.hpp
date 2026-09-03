#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>

#include <sentcore/core/fixed_string.hpp>

namespace sentcore
{

// Deliberately bounded telemetry fields.
//
// These capacities are tuned for SentCore's hot-path event representation.
// Oversized input is safely truncated by FixedString rather than allocating.
inline constexpr std::size_t kEventSourceCapacity{16U};
inline constexpr std::size_t kEventPathCapacity{256U};
inline constexpr std::size_t kEventCommandCapacity{512U};

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
    // Hot metadata is grouped first to keep alignment predictable.
    std::uint64_t sequence{0U};
    std::uint64_t timestamp_ns{0U};

    std::int32_t pid{-1};
    std::int32_t ppid{-1};
    std::uint32_t uid{0U};
    std::uint32_t mode{0U};

    EventType type{EventType::Internal};

    // Inline bounded strings avoid per-event heap allocation.
    FixedString<kEventSourceCapacity> source{};
    FixedString<kEventPathCapacity> path{};
    FixedString<kEventCommandCapacity> command{};
};

static_assert(std::is_nothrow_move_constructible_v<Event>);
static_assert(std::is_nothrow_move_assignable_v<Event>);

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

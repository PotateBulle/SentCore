#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>
#include <type_traits>
#include <variant>

#include <sentcore/core/fixed_string.hpp>

namespace sentcore
{

// Capacities are deliberately bounded to keep endpoint telemetry predictable.
//
// Process command lines receive the largest buffer because they are commonly
// inspected by behavioral rules. Filesystem paths retain a larger independent
// capacity without forcing every process event to carry that storage.
inline constexpr std::size_t kProcessExecutableCapacity{192U};
inline constexpr std::size_t kProcessCommandCapacity{448U};
inline constexpr std::size_t kFilePathCapacity{384U};
inline constexpr std::size_t kInternalMessageCapacity{192U};

enum class EventType : std::uint8_t
{
    ProcessStart,
    FileCreated,
    FileModified,
    FileDeleted,
    FileMoved,
    Internal
};

enum class EventSource : std::uint8_t
{
    Unknown,
    Procfs,
    Inotify,
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

// Process-only telemetry. Keeping these fields out of the common Event header
// prevents filesystem events from paying for process metadata and command-line
// storage they never use.
struct ProcessPayload final
{
    std::int32_t pid{-1};
    std::int32_t ppid{-1};
    std::uint32_t uid{0U};
    FixedString<kProcessExecutableCapacity> executable{};
    FixedString<kProcessCommandCapacity> command{};
};

// Filesystem-only telemetry.
struct FilePayload final
{
    std::uint32_t uid{0U};
    std::uint32_t mode{0U};
    FixedString<kFilePathCapacity> path{};
};

// Internal health/diagnostic telemetry.
struct InternalPayload final
{
    FixedString<kInternalMessageCapacity> message{};
};

using EventPayload = std::variant<std::monostate, ProcessPayload, FilePayload, InternalPayload>;

struct Event final
{
    std::uint64_t sequence{0U};
    std::uint64_t timestamp_ns{0U};
    EventType type{EventType::Internal};
    EventSource source{EventSource::Unknown};
    EventPayload payload{};

    [[nodiscard]] ProcessPayload& emplace_process()
    {
        type = EventType::ProcessStart;
        return payload.emplace<ProcessPayload>();
    }

    [[nodiscard]] FilePayload& emplace_file(EventType file_type)
    {
        type = file_type;
        return payload.emplace<FilePayload>();
    }

    [[nodiscard]] InternalPayload& emplace_internal()
    {
        type = EventType::Internal;
        return payload.emplace<InternalPayload>();
    }

    [[nodiscard]] const ProcessPayload* process() const noexcept
    {
        return std::get_if<ProcessPayload>(&payload);
    }

    [[nodiscard]] ProcessPayload* process() noexcept
    {
        return std::get_if<ProcessPayload>(&payload);
    }

    [[nodiscard]] const FilePayload* file() const noexcept
    {
        return std::get_if<FilePayload>(&payload);
    }

    [[nodiscard]] FilePayload* file() noexcept
    {
        return std::get_if<FilePayload>(&payload);
    }

    [[nodiscard]] const InternalPayload* internal() const noexcept
    {
        return std::get_if<InternalPayload>(&payload);
    }

    [[nodiscard]] InternalPayload* internal() noexcept
    {
        return std::get_if<InternalPayload>(&payload);
    }

    // Unified read-only views keep detection/output code compact while the
    // underlying storage remains strongly typed.
    [[nodiscard]] std::string_view path_view() const noexcept
    {
        if (const auto* process_payload = process(); process_payload != nullptr)
        {
            return process_payload->executable.view();
        }

        if (const auto* file_payload = file(); file_payload != nullptr)
        {
            return file_payload->path.view();
        }

        return {};
    }

    [[nodiscard]] std::string_view command_view() const noexcept
    {
        if (const auto* process_payload = process(); process_payload != nullptr)
        {
            return process_payload->command.view();
        }

        return {};
    }

    [[nodiscard]] std::string_view message_view() const noexcept
    {
        if (const auto* internal_payload = internal(); internal_payload != nullptr)
        {
            return internal_payload->message.view();
        }

        return {};
    }

    [[nodiscard]] std::int32_t pid() const noexcept
    {
        if (const auto* process_payload = process(); process_payload != nullptr)
        {
            return process_payload->pid;
        }

        return -1;
    }

    [[nodiscard]] std::int32_t ppid() const noexcept
    {
        if (const auto* process_payload = process(); process_payload != nullptr)
        {
            return process_payload->ppid;
        }

        return -1;
    }

    [[nodiscard]] std::uint32_t uid() const noexcept
    {
        if (const auto* process_payload = process(); process_payload != nullptr)
        {
            return process_payload->uid;
        }

        if (const auto* file_payload = file(); file_payload != nullptr)
        {
            return file_payload->uid;
        }

        return 0U;
    }

    [[nodiscard]] std::uint32_t mode() const noexcept
    {
        if (const auto* file_payload = file(); file_payload != nullptr)
        {
            return file_payload->mode;
        }

        return 0U;
    }
};

static_assert(std::is_nothrow_move_constructible_v<Event>);
static_assert(std::is_nothrow_move_assignable_v<Event>);

[[nodiscard]] inline std::uint64_t now_unix_ns() noexcept
{
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

[[nodiscard]] constexpr bool is_file_event(EventType type) noexcept
{
    return type == EventType::FileCreated || type == EventType::FileModified ||
           type == EventType::FileDeleted || type == EventType::FileMoved;
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

[[nodiscard]] constexpr std::string_view to_string(EventSource source) noexcept
{
    switch (source)
    {
        case EventSource::Unknown:
            return "unknown";
        case EventSource::Procfs:
            return "procfs";
        case EventSource::Inotify:
            return "inotify";
        case EventSource::Internal:
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
}}
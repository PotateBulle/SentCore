#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <type_traits>

namespace sentcore
{

// Compact, bounded, allocation-free string for the event hot path.
//
// The size field automatically uses the smallest unsigned integer type able to
// represent the configured capacity. This keeps each instance as small as
// possible while preserving predictable memory usage and NUL termination.
template <std::size_t Capacity>
class FixedString final
{
    static_assert(Capacity > 1U, "FixedString capacity must reserve space for a NUL terminator.");

    using SizeType = std::conditional_t<
        (Capacity <= (static_cast<std::size_t>(std::numeric_limits<std::uint8_t>::max()) + 1U)),
        std::uint8_t,
        std::conditional_t<
            (Capacity <= (static_cast<std::size_t>(std::numeric_limits<std::uint16_t>::max()) + 1U)),
            std::uint16_t,
            std::uint32_t>>;

    static_assert(Capacity - 1U <= static_cast<std::size_t>(std::numeric_limits<SizeType>::max()));

  public:
    constexpr FixedString() noexcept = default;

    explicit FixedString(std::string_view value) noexcept
    {
        assign(value);
    }

    void assign(std::string_view value) noexcept
    {
        const auto length = std::min(value.size(), Capacity - 1U);
        size_ = static_cast<SizeType>(length);

        if (length != 0U)
        {
            std::copy_n(value.data(), length, storage_.data());
        }

        storage_[length] = '\0';
    }

    void clear() noexcept
    {
        size_ = 0U;
        storage_[0] = '\0';
    }

    [[nodiscard]] std::string_view view() const noexcept
    {
        return {storage_.data(), static_cast<std::size_t>(size_)};
    }

    [[nodiscard]] const char* c_str() const noexcept
    {
        return storage_.data();
    }

    [[nodiscard]] std::size_t size() const noexcept
    {
        return static_cast<std::size_t>(size_);
    }

    [[nodiscard]] static consteval std::size_t capacity() noexcept
    {
        return Capacity;
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return size_ == 0U;
    }

  private:
    std::array<char, Capacity> storage_{};
    SizeType size_{0U};
};

} // namespace sentcore

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <string_view>

namespace sentcore
{

// A bounded, allocation-free string intended for the event hot path.
// The object always remains NUL-terminated and truncates oversized input.
template <std::size_t Capacity>
class FixedString final
{
    static_assert(Capacity > 0, "FixedString capacity must be greater than zero.");

  public:
    constexpr FixedString() noexcept = default;

    explicit FixedString(std::string_view value) noexcept
    {
        assign(value);
    }

    void assign(std::string_view value) noexcept
    {
        size_ = std::min(value.size(), Capacity - 1U);
        std::copy_n(value.data(), size_, storage_.data());
        storage_[size_] = '\0';
    }

    [[nodiscard]] std::string_view view() const noexcept
    {
        return {storage_.data(), size_};
    }

    [[nodiscard]] const char* c_str() const noexcept
    {
        return storage_.data();
    }

    [[nodiscard]] std::size_t size() const noexcept
    {
        return size_;
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return size_ == 0U;
    }

  private:
    std::array<char, Capacity> storage_{};
    std::size_t size_{0U};
};

} // namespace sentcore

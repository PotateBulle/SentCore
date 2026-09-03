#pragma once

#include <array>
#include <cstddef>
#include <string_view>

#include <sentcore/core/event.hpp>
#include <sentcore/core/fixed_string.hpp>

namespace sentcore
{

struct Alert final
{
    FixedString<32> rule_id{};
    FixedString<128> title{};
    FixedString<32> mitre_technique{};
    Severity severity{Severity::Info};
    Event event{};
};

struct DetectionBatch final
{
    static constexpr std::size_t kMaxAlerts = 8U;

    std::array<Alert, kMaxAlerts> alerts{};
    std::size_t count{0U};

    void add(std::string_view rule_id,
             std::string_view title,
             Severity severity,
             std::string_view technique,
             const Event& event) noexcept
    {
        if (count >= alerts.size())
        {
            return;
        }

        auto& alert = alerts[count++];
        alert.rule_id.assign(rule_id);
        alert.title.assign(title);
        alert.mitre_technique.assign(technique);
        alert.severity = severity;
        alert.event = event;
    }
};

} // namespace sentcore

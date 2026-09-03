#pragma once

#include <sentcore/core/event.hpp>
#include <sentcore/detection/alert.hpp>

namespace sentcore
{

class DetectionEngine final
{
  public:
    [[nodiscard]] DetectionBatch evaluate(const Event& event) const noexcept;
};

} // namespace sentcore

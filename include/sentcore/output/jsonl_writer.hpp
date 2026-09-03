#pragma once

#include <fstream>
#include <string>
#include <string_view>

#include <sentcore/core/event.hpp>
#include <sentcore/detection/alert.hpp>

namespace sentcore
{

class JsonlWriter final
{
  public:
    JsonlWriter(std::string event_path, std::string alert_path);

    [[nodiscard]] bool ready() const noexcept;
    void write_event(const Event& event);
    void write_alert(const Alert& alert);

  private:
    static void write_escaped(std::ostream& stream, std::string_view value);

    std::ofstream events_;
    std::ofstream alerts_;
};

} // namespace sentcore

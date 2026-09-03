#include <sentcore/output/jsonl_writer.hpp>

#include <iomanip>
#include <ostream>

namespace sentcore
{

JsonlWriter::JsonlWriter(std::string event_path, std::string alert_path)
    : events_(std::move(event_path), std::ios::app), alerts_(std::move(alert_path), std::ios::app)
{
}

bool JsonlWriter::ready() const noexcept
{
    return events_.good() && alerts_.good();
}

void JsonlWriter::write_escaped(std::ostream& stream, std::string_view value)
{
    stream << '"';
    for (const char raw_character : value)
    {
        const auto character = static_cast<unsigned char>(raw_character);
        switch (character)
        {
            case '"':
                stream << "\\\"";
                break;
            case '\\':
                stream << "\\\\";
                break;
            case '\n':
                stream << "\\n";
                break;
            case '\r':
                stream << "\\r";
                break;
            case '\t':
                stream << "\\t";
                break;
            default:
                if (character < 0x20U)
                {
                    stream << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                           << static_cast<unsigned int>(character) << std::dec << std::setfill(' ');
                }
                else
                {
                    stream << static_cast<char>(character);
                }
        }
    }
    stream << '"';
}

void JsonlWriter::write_event(const Event& event)
{
    events_ << "{\"sequence\":" << event.sequence << ",\"timestamp_ns\":" << event.timestamp_ns
            << ",\"type\":";
    write_escaped(events_, to_string(event.type));
    events_ << ",\"pid\":" << event.pid << ",\"ppid\":" << event.ppid << ",\"uid\":"
            << event.uid << ",\"source\":";
    write_escaped(events_, event.source.view());
    events_ << ",\"path\":";
    write_escaped(events_, event.path.view());
    events_ << ",\"command\":";
    write_escaped(events_, event.command.view());
    events_ << "}\n";
}

void JsonlWriter::write_alert(const Alert& alert)
{
    alerts_ << "{\"rule_id\":";
    write_escaped(alerts_, alert.rule_id.view());
    alerts_ << ",\"title\":";
    write_escaped(alerts_, alert.title.view());
    alerts_ << ",\"severity\":";
    write_escaped(alerts_, to_string(alert.severity));
    alerts_ << ",\"mitre\":";
    write_escaped(alerts_, alert.mitre_technique.view());
    alerts_ << ",\"event_sequence\":" << alert.event.sequence << ",\"path\":";
    write_escaped(alerts_, alert.event.path.view());
    alerts_ << ",\"command\":";
    write_escaped(alerts_, alert.event.command.view());
    alerts_ << "}\n";
}

} // namespace sentcore

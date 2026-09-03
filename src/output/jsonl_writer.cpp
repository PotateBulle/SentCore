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
    events_ << ",\"source\":";
    write_escaped(events_, to_string(event.source));

    if (const auto* process = event.process(); process != nullptr)
    {
        events_ << ",\"pid\":" << process->pid << ",\"ppid\":" << process->ppid << ",\"uid\":"
                << process->uid << ",\"executable\":";
        write_escaped(events_, process->executable.view());
        events_ << ",\"command\":";
        write_escaped(events_, process->command.view());
    }
    else if (const auto* file = event.file(); file != nullptr)
    {
        events_ << ",\"uid\":" << file->uid << ",\"mode\":" << file->mode << ",\"path\":";
        write_escaped(events_, file->path.view());
    }
    else if (const auto* internal = event.internal(); internal != nullptr)
    {
        events_ << ",\"message\":";
        write_escaped(events_, internal->message.view());
    }

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
    alerts_ << ",\"event_sequence\":" << alert.event.sequence << ",\"type\":";
    write_escaped(alerts_, to_string(alert.event.type));
    alerts_ << ",\"source\":";
    write_escaped(alerts_, to_string(alert.event.source));

    const auto path = alert.event.path_view();
    if (!path.empty())
    {
        alerts_ << ",\"path\":";
        write_escaped(alerts_, path);
    }

    const auto command = alert.event.command_view();
    if (!command.empty())
    {
        alerts_ << ",\"command\":";
        write_escaped(alerts_, command);
    }

    alerts_ << "}\n";
}}
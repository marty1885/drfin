#include <misfin/gemmail.hpp>
#include <misfin/url.hpp>

#include <array>
#include <algorithm>
#include <cctype>
#include <cstdio>

namespace drfin
{
namespace
{
std::string_view trim(std::string_view value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())))
        value.remove_prefix(1);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())))
        value.remove_suffix(1);
    return value;
}

std::optional<GemmailAddress> parseSender(std::string_view line)
{
    line = trim(line.substr(1));
    const auto space = line.find_first_of(" \t");
    const auto address = line.substr(0, space);
    if (!parseMisfinRecipient(address))
        return std::nullopt;
    return GemmailAddress{std::string{address},
                          space == std::string_view::npos
                              ? std::string{}
                              : std::string{trim(line.substr(space + 1))}};
}

std::optional<std::vector<std::string>> parseRecipients(std::string_view line)
{
    std::vector<std::string> recipients;
    line.remove_prefix(1);
    if (line.empty() || !std::isspace(static_cast<unsigned char>(line.front())))
        return std::nullopt;
    while (!(line = trim(line)).empty())
    {
        const auto space = line.find_first_of(" \t");
        const auto address = line.substr(0, space);
        if (!parseMisfinRecipient(address))
            return std::nullopt;
        recipients.emplace_back(address);
        if (space == std::string_view::npos)
            break;
        line.remove_prefix(space + 1);
    }
    return recipients;
}

std::optional<GemmailAddress> parseCAddress(std::string_view value, bool allowBlurb)
{
    value = trim(value);
    if (value.find('\t') != std::string_view::npos) return std::nullopt;
    const auto space = value.find(' ');
    const auto address = value.substr(0, space);
    if (!parseMisfinRecipient(address)) return std::nullopt;
    if (space == std::string_view::npos) return GemmailAddress{std::string{address}, {}};
    if (!allowBlurb || space + 1 == value.size() || value[space + 1] == ' ') return std::nullopt;
    const auto blurb = value.substr(space + 1);
    if (blurb.find_first_of(",@") != std::string_view::npos) return std::nullopt;
    return GemmailAddress{std::string{address}, std::string{blurb}};
}

bool isIso8601Utc(std::string_view value)
{
    int year, month, day, hour, minute, second;
    char trailing;
    const std::string text{value};
    if (text.size() != 20) return false;
    if (std::sscanf(text.c_str(), "%4d-%2d-%2dT%2d:%2d:%2dZ%c",
                    &year, &month, &day, &hour, &minute, &second, &trailing) != 6)
        return false;
    if (month < 1 || month > 12 || hour < 0 || hour > 23 || minute < 0 || minute > 59 ||
        second < 0 || second > 60)
        return false;
    static constexpr std::array days{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    const int maximumDay = days[static_cast<std::size_t>(month - 1)] + (month == 2 && leap ? 1 : 0);
    return day >= 1 && day <= maximumDay;
}

std::vector<std::string_view> splitCMetadata(std::string_view line)
{
    std::vector<std::string_view> items;
    if (line.empty()) return items;
    std::size_t offset = 0;
    while (offset <= line.size())
    {
        const auto comma = line.find(',', offset);
        const auto item = trim(line.substr(offset, comma == std::string_view::npos
                                                       ? std::string_view::npos
                                                       : comma - offset));
        if (item.empty()) return {};
        items.push_back(item);
        if (comma == std::string_view::npos) break;
        offset = comma + 1;
    }
    return items;
}

bool isHeading(std::string_view line)
{
    if (line.empty() || line.front() != '#')
        return false;
    const auto text = line.find_first_not_of('#');
    if (text == std::string_view::npos || text > 3)
        return false;
    return line[text] == ' ';
}

std::string sanitizeMetadata(std::string_view value)
{
    std::string sanitized{value};
    std::replace(sanitized.begin(), sanitized.end(), '\r', ' ');
    std::replace(sanitized.begin(), sanitized.end(), '\n', ' ');
    return sanitized;
}
}  // namespace

std::expected<Gemmail, std::string> Gemmail::parse(std::string_view text)
{
    if (text.find('\r') != std::string_view::npos)
        return std::unexpected("Gemmail must use LF line endings");

    Gemmail message;
    std::string body;
    size_t start = 0;
    while (start <= text.size())
    {
        const auto end = text.find('\n', start);
        const auto line = text.substr(start, end == std::string_view::npos ? end : end - start);
        bool metadata = false;
        if (!message.sender && line.starts_with('<'))
        {
            const auto sender = parseSender(line);
            if (!sender)
                return std::unexpected("invalid Gemmail sender line");
            message.sender = *sender;
            metadata = true;
        }
        else if (message.recipients.empty() && line.starts_with(':'))
        {
            const auto recipients = parseRecipients(line);
            if (!recipients || recipients->empty())
                return std::unexpected("invalid Gemmail recipients line");
            message.recipients = *recipients;
            metadata = true;
        }
        else if (!message.timestamp && line.starts_with('@'))
        {
            if (line.size() == 1 || !std::isspace(static_cast<unsigned char>(line[1])))
                return std::unexpected("invalid Gemmail timestamp line");
            const auto timestamp = trim(line.substr(1));
            if (timestamp.empty())
                return std::unexpected("invalid Gemmail timestamp line");
            message.timestamp = std::string{timestamp};
            metadata = true;
        }
        if (!metadata)
        {
            body.append(line);
            if (end != std::string_view::npos)
                body.push_back('\n');
        }
        if (end == std::string_view::npos)
            break;
        start = end + 1;
    }
    message.body = std::move(body);
    return message;
}

std::expected<Gemmail, std::string> Gemmail::parseC(std::string_view text)
{
    if (text.empty() || text.back() != '\n')
        return std::unexpected("Misfin(C) message must end with a line terminator");
    std::size_t rawLineStart = 0;
    for (std::size_t line = 0; line < 3; ++line)
    {
        const auto end = text.find('\n', rawLineStart);
        if (end == std::string_view::npos)
            return std::unexpected("Misfin(C) message is missing metadata lines");
        if (end - rawLineStart + 1 > 1024)
            return std::unexpected("Misfin(C) metadata line exceeds 1024 bytes");
        rawLineStart = end + 1;
    }
    std::string normalized;
    normalized.reserve(text.size());
    for (std::size_t index = 0; index < text.size(); ++index)
    {
        if (text[index] == '\r')
        {
            if (index + 1 >= text.size() || text[index + 1] != '\n')
                return std::unexpected("Misfin(C) message contains a bare CR");
            continue;
        }
        normalized.push_back(text[index]);
    }
    text = normalized;
    std::array<std::string_view, 3> lines;
    std::size_t offset = 0;
    for (auto &line : lines)
    {
        const auto end = text.find('\n', offset);
        if (end == std::string_view::npos)
            return std::unexpected("Misfin(C) message is missing metadata lines");
        line = text.substr(offset, end - offset);
        offset = end + 1;
    }
    const auto senders = splitCMetadata(lines[0]);
    const auto recipients = splitCMetadata(lines[1]);
    const auto timestamps = splitCMetadata(lines[2]);
    if ((!lines[0].empty() && senders.empty()) || (!lines[1].empty() && recipients.empty()) ||
        (!lines[2].empty() && timestamps.empty()))
        return std::unexpected("invalid Misfin(C) metadata list");

    Gemmail output;
    for (const auto item : senders)
    {
        const auto sender = parseCAddress(item, true);
        if (!sender) return std::unexpected("invalid Misfin(C) sender metadata");
        if (!output.sender) output.sender = *sender;
    }
    for (const auto item : recipients)
    {
        const auto recipient = parseCAddress(item, true);
        if (!recipient) return std::unexpected("invalid Misfin(C) recipient metadata");
        output.recipients.push_back(std::move(recipient->address));
    }
    for (const auto item : timestamps)
    {
        if (!isIso8601Utc(item)) return std::unexpected("invalid Misfin(C) timestamp metadata");
        if (!output.timestamp) output.timestamp = std::string{item};
    }
    output.body = std::string{text.substr(offset)};
    return output;
}

std::string Gemmail::str() const
{
    std::string text;
    if (sender)
    {
        text += "< " + sanitizeMetadata(sender->address);
        if (!sender->blurb.empty())
            text += " " + sanitizeMetadata(sender->blurb);
        text += '\n';
    }
    if (!recipients.empty())
    {
        text += ": ";
        for (size_t i = 0; i < recipients.size(); ++i)
        {
            if (i != 0)
                text += ' ';
            text += sanitizeMetadata(recipients[i]);
        }
        text += '\n';
    }
    if (timestamp)
        text += "@ " + sanitizeMetadata(*timestamp) + "\n";
    return text + body;
}

std::string Gemmail::strC() const
{
    std::string text;
    if (sender)
    {
        text += sanitizeMetadata(sender->address);
        if (!sender->blurb.empty() && sender->blurb.find_first_of(",@") == std::string::npos)
            text += " " + sanitizeMetadata(sender->blurb);
    }
    text += '\n';
    if (!recipients.empty())
    {
        for (size_t index = 0; index < recipients.size(); ++index)
        {
            if (index != 0) text += ", ";
            text += sanitizeMetadata(recipients[index]);
        }
    }
    text += '\n';
    if (timestamp) text += sanitizeMetadata(*timestamp);
    text += '\n';
    text += body;
    if (!text.ends_with('\n')) text.push_back('\n');
    return text;
}

std::optional<std::string> Gemmail::subject() const
{
    size_t start = 0;
    bool preformatted = false;
    while (start < body.size())
    {
        const auto end = body.find('\n', start);
        const auto line = std::string_view{body}.substr(start, end == std::string::npos ? end : end - start);
        if (line.starts_with("```"))
            preformatted = !preformatted;
        else if (!preformatted && isHeading(line))
            return std::string{line.substr(line.find(' ') + 1)};
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    return std::nullopt;
}
}  // namespace drfin

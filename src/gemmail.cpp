#include <misfin/gemmail.hpp>
#include <misfin/url.hpp>

#include <cctype>
#include <array>

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
    const auto space = value.find_first_of(" \t");
    const auto address = value.substr(0, space);
    if (!parseMisfinRecipient(address)) return std::nullopt;
    return GemmailAddress{std::string{address}, allowBlurb && space != std::string_view::npos
                                                    ? std::string{trim(value.substr(space + 1))}
                                                    : std::string{}};
}

std::optional<std::string_view> cMetadata(std::string_view line, char marker)
{
    line = trim(line);
    if (line.empty()) return line;
    if (line.front() != marker) return std::nullopt;
    return trim(line.substr(1));
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
}  // namespace

std::expected<Gemmail, std::string> Gemmail::parse(std::string_view text)
{
    if (text.find('\r') != std::string_view::npos)
        return std::unexpected("Gemmail must use LF line endings");

    Gemmail message;
    std::string body;
    size_t start = 0;
    bool metadataSection = true;
    while (start <= text.size())
    {
        const auto end = text.find('\n', start);
        const auto line = text.substr(start, end == std::string_view::npos ? end : end - start);
        bool metadata = false;
        if (metadataSection && !message.sender && line.starts_with('<'))
        {
            const auto sender = parseSender(line);
            if (!sender)
                return std::unexpected("invalid Gemmail sender line");
            message.sender = *sender;
            metadata = true;
        }
        else if (metadataSection && message.recipients.empty() && line.starts_with(':'))
        {
            const auto recipients = parseRecipients(line);
            if (!recipients || recipients->empty())
                return std::unexpected("invalid Gemmail recipients line");
            message.recipients = *recipients;
            metadata = true;
        }
        else if (metadataSection && !message.timestamp && line.starts_with('@'))
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
            metadataSection = false;
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
    if (text.find('\r') != std::string_view::npos)
        return std::unexpected("Gemmail must use LF line endings");
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
    const auto senders = cMetadata(lines[0], '<');
    const auto recipients = cMetadata(lines[1], ':');
    const auto timestamps = cMetadata(lines[2], '@');
    if (!senders || !recipients || !timestamps)
        return std::unexpected("invalid Misfin(C) metadata line");

    Gemmail output;
    if (!senders->empty())
    {
        const auto comma = senders->find(',');
        const auto sender = parseCAddress(senders->substr(0, comma), true);
        if (!sender) return std::unexpected("invalid Misfin(C) sender metadata");
        output.sender = *sender;
    }
    std::size_t recipientOffset = 0;
    while (recipientOffset < recipients->size())
    {
        const auto comma = recipients->find(',', recipientOffset);
        const auto recipient = parseCAddress(recipients->substr(recipientOffset, comma - recipientOffset), false);
        if (!recipient) return std::unexpected("invalid Misfin(C) recipient metadata");
        output.recipients.push_back(std::move(recipient->address));
        if (comma == std::string_view::npos) break;
        recipientOffset = comma + 1;
    }
    if (!timestamps->empty())
    {
        const auto comma = timestamps->find(',');
        const auto timestamp = trim(timestamps->substr(0, comma));
        if (timestamp.empty()) return std::unexpected("invalid Misfin(C) timestamp metadata");
        output.timestamp = std::string{timestamp};
    }
    output.body = std::string{text.substr(offset)};
    return output;
}

std::string Gemmail::str() const
{
    std::string text;
    if (sender)
    {
        text += "< " + sender->address;
        if (!sender->blurb.empty())
            text += " " + sender->blurb;
        text += '\n';
    }
    if (!recipients.empty())
    {
        text += ": ";
        for (size_t i = 0; i < recipients.size(); ++i)
        {
            if (i != 0)
                text += ' ';
            text += recipients[i];
        }
        text += '\n';
    }
    if (timestamp)
        text += "@ " + *timestamp + "\n";
    return text + body;
}

std::string Gemmail::strC() const
{
    std::string text;
    if (sender)
    {
        text += "< " + sender->address;
        if (!sender->blurb.empty()) text += " " + sender->blurb;
    }
    text += '\n';
    if (!recipients.empty())
    {
        text += ": ";
        for (size_t index = 0; index < recipients.size(); ++index)
        {
            if (index != 0) text += ", ";
            text += recipients[index];
        }
    }
    text += '\n';
    if (timestamp) text += "@ " + *timestamp;
    text += '\n';
    return text + body;
}

std::optional<std::string> Gemmail::subject() const
{
    size_t start = 0;
    while (start < body.size())
    {
        const auto end = body.find('\n', start);
        const auto line = std::string_view{body}.substr(start, end == std::string::npos ? end : end - start);
        if (isHeading(line))
            return std::string{line.substr(line.find(' ') + 1)};
        if (end == std::string::npos)
            break;
        start = end + 1;
    }
    return std::nullopt;
}
}  // namespace drfin

#include <misfin/url.hpp>
#include <misfin/utils.hpp>

#include <charconv>
#include <cctype>
#include <limits>

namespace drfin
{
namespace
{
bool isScheme(std::string_view value)
{
    if (value.empty() || !std::isalpha(static_cast<unsigned char>(value.front())))
        return false;
    for (const auto character : value.substr(1))
    {
        if (!std::isalnum(static_cast<unsigned char>(character)) && character != '+' &&
            character != '-' && character != '.')
            return false;
    }
    return true;
}

bool hasForbiddenCharacter(std::string_view value);

bool isHost(std::string_view value)
{
    if (value.size() >= 2 && value.front() == '[' && value.back() == ']')
        return value.size() > 2 && !hasForbiddenCharacter(value.substr(1, value.size() - 2));
    if (value.empty() || value.front() == '.' || value.back() == '.' || value.size() > 253)
        return false;
    size_t start = 0;
    while (start < value.size())
    {
        const auto end = value.find('.', start);
        const auto label = value.substr(start, end == std::string_view::npos ? end : end - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-')
            return false;
        for (const auto character : label)
        {
            if (!std::isalnum(static_cast<unsigned char>(character)) && character != '-')
                return false;
        }
        if (end == std::string_view::npos)
            break;
        start = end + 1;
    }
    return true;
}

bool isMailbox(std::string_view value)
{
    if (value.empty())
        return false;
    for (const auto character : value)
    {
        if (std::iscntrl(static_cast<unsigned char>(character)) ||
            std::isspace(static_cast<unsigned char>(character)) || character == '@' ||
            character == ':' || character == '/' || character == '?' || character == '#' ||
            character == '[' || character == ']')
            return false;
    }
    return true;
}

bool hasForbiddenCharacter(std::string_view value)
{
    for (const auto character : value)
    {
        if (std::iscntrl(static_cast<unsigned char>(character)) ||
            std::isspace(static_cast<unsigned char>(character)))
            return true;
    }
    return false;
}
}  // namespace

std::optional<Url> Url::parse(std::string_view text)
{
    if (text.empty() || hasForbiddenCharacter(text))
        return std::nullopt;
    const auto colon = text.find(':');
    if (colon == std::string_view::npos || !isScheme(text.substr(0, colon)) ||
        text.substr(colon, 3) != "://")
        return std::nullopt;

    Url url;
    url.scheme_ = text.substr(0, colon);
    text.remove_prefix(colon + 3);
    const auto authorityEnd = text.find_first_of("/?#");
    auto authority = text.substr(0, authorityEnd);
    if (authority.empty())
        return std::nullopt;
    if (const auto at = authority.find('@'); at != std::string_view::npos)
    {
        if (at == 0 || authority.find('@', at + 1) != std::string_view::npos)
            return std::nullopt;
        url.userInfo_ = authority.substr(0, at);
        authority.remove_prefix(at + 1);
    }
    // The authority may have consisted solely of user info (for example,
    // "misfin://user@").  Check before inspecting its first character.
    if (authority.empty())
        return std::nullopt;
    if (authority.front() == '[')
    {
        const auto closingBracket = authority.find(']');
        if (closingBracket == std::string_view::npos)
            return std::nullopt;
        if (closingBracket + 1 < authority.size())
        {
            if (authority[closingBracket + 1] != ':')
                return std::nullopt;
            const auto portText = authority.substr(closingBracket + 2);
            unsigned int port = 0;
            const auto parsed = std::from_chars(portText.data(), portText.data() + portText.size(), port);
            if (portText.empty() || parsed.ec != std::errc{} || parsed.ptr != portText.end() || port == 0 ||
                port > std::numeric_limits<unsigned short>::max())
                return std::nullopt;
            url.port_ = static_cast<unsigned short>(port);
        }
        authority = authority.substr(0, closingBracket + 1);
    }
    else if (const auto portSeparator = authority.rfind(':'); portSeparator != std::string_view::npos)
    {
        const auto portText = authority.substr(portSeparator + 1);
        unsigned int port = 0;
        const auto parsed = std::from_chars(portText.data(), portText.data() + portText.size(), port);
        if (portText.empty() || parsed.ec != std::errc{} || parsed.ptr != portText.end() || port == 0 ||
            port > std::numeric_limits<unsigned short>::max())
            return std::nullopt;
        url.port_ = static_cast<unsigned short>(port);
        authority = authority.substr(0, portSeparator);
    }
    if (!isHost(authority))
        return std::nullopt;
    url.host_ = authority;
    if (authorityEnd == std::string_view::npos)
        return url;

    text.remove_prefix(authorityEnd);
    const auto pathEnd = text.find_first_of("?#");
    url.path_ = text.substr(0, pathEnd);
    if (pathEnd == std::string_view::npos)
        return url;
    text.remove_prefix(pathEnd);
    if (text.front() == '?')
    {
        text.remove_prefix(1);
        const auto fragment = text.find('#');
        url.query_ = text.substr(0, fragment);
        if (fragment == std::string_view::npos)
            return url;
        text.remove_prefix(fragment);
    }
    if (text.front() == '#')
        url.fragment_ = text.substr(1);
    return url;
}

std::string Url::str() const
{
    std::string text = scheme_ + "://";
    if (!userInfo_.empty())
        text += userInfo_ + "@";
    text += host_;
    if (port_)
        text += ":" + std::to_string(*port_);
    text += path_;
    if (!query_.empty())
        text += "?" + query_;
    if (!fragment_.empty())
        text += "#" + fragment_;
    return text;
}

std::optional<Url> parseMisfinRecipient(std::string_view recipient)
{
    if (!isValidUtf8(recipient))
        return std::nullopt;
    const auto url = recipient.starts_with("misfin://")
                         ? Url::parse(recipient)
                         : Url::parse("misfin://" + std::string{recipient});
    if (!url || url->scheme() != "misfin" || !isMailbox(url->userInfo()) ||
        !url->path().empty() || !url->query().empty() ||
        !url->fragment().empty())
        return std::nullopt;
    return url;
}
}  // namespace drfin

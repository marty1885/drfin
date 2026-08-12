#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace drfin
{
// A strict, non-decoding URL parser adapted from tlgsutils/url_parser.
class Url
{
  public:
    static std::optional<Url> parse(std::string_view text);

    const std::string &scheme() const noexcept { return scheme_; }
    const std::string &userInfo() const noexcept { return userInfo_; }
    const std::string &host() const noexcept { return host_; }
    const std::string &path() const noexcept { return path_; }
    const std::string &query() const noexcept { return query_; }
    const std::string &fragment() const noexcept { return fragment_; }
    std::optional<unsigned short> port() const noexcept { return port_; }
    std::string str() const;

  private:
    std::string scheme_;
    std::string userInfo_;
    std::string host_;
    std::optional<unsigned short> port_;
    std::string path_;
    std::string query_;
    std::string fragment_;
};

// Parses mailbox@hostname or misfin://mailbox@hostname.
std::optional<Url> parseMisfinRecipient(std::string_view recipient);
}  // namespace drfin

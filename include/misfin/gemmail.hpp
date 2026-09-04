#pragma once

#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace drfin
{
struct GemmailAddress
{
    std::string address;
    std::string blurb;
};

// A Gemtext message with Misfin's optional mail metadata. Body uses LF line
// endings; CR is reserved for the Misfin request terminator.
struct Gemmail
{
    std::optional<GemmailAddress> sender;
    std::vector<std::string> recipients;
    std::optional<std::string> timestamp;
    std::string body;

    static std::expected<Gemmail, std::string> parse(std::string_view text);
    // Misfin(C) reserves its first three LF-terminated lines for sender,
    // recipient, and timestamp metadata, even when a line is empty.
    static std::expected<Gemmail, std::string> parseC(std::string_view text);

    // Produces canonical Gemmail: metadata first, followed by the body.
    std::string str() const;
    // Produces the Misfin(C) form with exactly three unprefixed metadata lines.
    // C uses comma-separated lists rather than B's marker-prefixed lines.
    std::string strC() const;

    // Returns the first Gemtext heading from the message body, if present.
    std::optional<std::string> subject() const;
};
}  // namespace drfin

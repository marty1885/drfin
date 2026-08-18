#include <misfin/utils.hpp>

#include <cctype>

namespace drfin
{
bool isMisfinResponseStatus(int status) noexcept
{
    return status >= 20 && status <= 69;
}

bool isValidUtf8(std::string_view value) noexcept
{
    std::size_t index = 0;
    while (index < value.size())
    {
        const auto first = static_cast<unsigned char>(value[index++]);
        if (first < 0x80) continue;
        const auto continuation = [&value, &index]() -> std::optional<unsigned char> {
            if (index == value.size()) return std::nullopt;
            const auto byte = static_cast<unsigned char>(value[index++]);
            if ((byte & 0xc0) != 0x80) return std::nullopt;
            return byte;
        };
        if (first < 0xc2 || first > 0xf4) return false;
        const auto second = continuation();
        if (!second) return false;
        if ((first == 0xe0 && *second < 0xa0) || (first == 0xed && *second >= 0xa0) ||
            (first == 0xf0 && *second < 0x90) || (first == 0xf4 && *second >= 0x90))
            return false;
        if (first >= 0xe0 && !continuation()) return false;
        if (first >= 0xf0 && !continuation()) return false;
    }
    return true;
}

std::string normalizeFingerprint(std::string_view fingerprint)
{
    std::string normalized;
    normalized.reserve(fingerprint.size());
    for (const auto character : fingerprint)
    {
        const auto value = static_cast<unsigned char>(character);
        if (std::isalnum(value))
            normalized.push_back(static_cast<char>(std::tolower(value)));
    }
    return normalized;
}
}  // namespace drfin

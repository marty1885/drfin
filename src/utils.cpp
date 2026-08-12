#include <misfin/utils.hpp>

#include <cctype>

namespace drfin
{
bool isMisfinResponseStatus(int status) noexcept
{
    return status >= 20 && status <= 69;
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

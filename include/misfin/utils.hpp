#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace drfin
{
inline constexpr size_t kMaxMisfinRequestSize = 2048;
inline constexpr size_t kMaxMisfinResponseSize = 2048;
inline constexpr unsigned short kMisfinPort = 1958;
inline constexpr double kMisfinTransactionTimeout = 60.0;

bool isMisfinResponseStatus(int status) noexcept;
std::string normalizeFingerprint(std::string_view fingerprint);
}  // namespace drfin

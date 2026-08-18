#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace drfin
{
inline constexpr size_t kMaxMisfinRequestSize = 2048;
inline constexpr size_t kMaxMisfinCHeaderSize = 1024;
inline constexpr size_t kMaxMisfinCContentSize = 16384;
inline constexpr size_t kMaxMisfinResponseSize = 2048;
inline constexpr unsigned short kMisfinPort = 1958;
inline constexpr double kMisfinTransactionTimeout = 60.0;

bool isMisfinResponseStatus(int status) noexcept;
bool isValidUtf8(std::string_view value) noexcept;
std::string normalizeFingerprint(std::string_view fingerprint);
}  // namespace drfin

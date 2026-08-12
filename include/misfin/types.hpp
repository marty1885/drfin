#pragma once

#include <expected>
#include <string>

namespace drfin
{
struct Credentials
{
    std::string certificatePem;
    std::string privateKeyPem;
};

struct Request
{
    // mailbox@hostname or misfin://mailbox@hostname
    std::string recipient;
    std::string message;
};

struct Response
{
    int status;
    std::string meta;
    std::string serverFingerprint;

    bool delivered() const noexcept { return status / 10 == 2; }
};

using Result = std::expected<Response, std::string>;
}  // namespace drfin

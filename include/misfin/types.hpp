#pragma once

#include <expected>
#include <optional>
#include <string>

namespace drfin
{
struct Credentials
{
    std::string certificatePem;
    std::string privateKeyPem;
};

enum class MisfinVersion { B, C };

struct Request
{
    // mailbox@hostname or misfin://mailbox@hostname
    std::string recipient;
    std::string message;
    // nullopt selects B when it fits and C otherwise. Receivers always set
    // this to the observed wire version.
    std::optional<MisfinVersion> version;
};

struct Response
{
    int status;
    std::string meta;
    std::string serverFingerprint;

    bool delivered() const noexcept { return status / 10 == 2; }
};

using Result = std::expected<Response, std::string>;

// A transport failure after requestTransmissionStarted is ambiguous: a peer
// may have accepted the request before its response was lost. Callers that
// need at-most-once delivery must not retry that outcome automatically.
struct DeliveryOutcome
{
    Result result;
    bool requestTransmissionStarted = false;
};
}  // namespace drfin

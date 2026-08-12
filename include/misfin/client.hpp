#pragma once

#include <drogon/utils/coroutine.h>
#include <misfin/async.hpp>
#include <misfin/types.hpp>
#include <trantor/net/Certificate.h>

#include <functional>

namespace trantor
{
class EventLoop;
}

namespace drfin
{
using SendCallback = std::function<void(Result)>;

using ServerTrustDecision = std::function<void(bool accept)>;

// May save its decision callback and invoke it asynchronously. Inputs are
// owned values so they remain valid across suspension. The request is sent
// only after it accepts the server certificate.
using ServerTrust = std::function<void(std::string endpoint,
                                        trantor::CertificatePtr certificate,
                                        ServerTrustDecision decide)>;

inline const ServerTrust kNoVerification =
    [](std::string, trantor::CertificatePtr, ServerTrustDecision decide) {
        decide(true);
    };

// The callback executes on Drogon's main event-loop thread.
void sendMail(Request request,
              Credentials credentials,
              SendCallback callback,
              ServerTrust trust = kNoVerification,
              trantor::EventLoop *loop = nullptr);

drogon::Task<Result> sendMailCoro(Request request,
                                  Credentials credentials,
                                  ServerTrust trust = kNoVerification,
                                  trantor::EventLoop *loop = nullptr);
}  // namespace drfin

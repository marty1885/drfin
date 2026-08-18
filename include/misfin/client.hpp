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
using DeliveryOutcomeCallback = std::function<void(DeliveryOutcome)>;

using ServerTrustDecision = std::function<void(bool accept)>;
using ConnectionPolicy = std::function<bool(std::string endpoint, std::string resolvedAddress)>;

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

inline const ConnectionPolicy kAllowConnection =
    [](std::string, std::string) { return true; };

// The callback executes on Drogon's main event-loop thread.
void sendMail(Request request,
              Credentials credentials,
              SendCallback callback,
              ServerTrust trust = kNoVerification,
              ConnectionPolicy connectionPolicy = kAllowConnection,
              trantor::EventLoop *loop = nullptr);

// Like sendMail(), but preserves whether request bytes may have reached the
// peer. This is additive; the original API deliberately remains unchanged.
void sendMailDetailed(Request request,
                      Credentials credentials,
                      DeliveryOutcomeCallback callback,
                      ServerTrust trust = kNoVerification,
                      ConnectionPolicy connectionPolicy = kAllowConnection,
                      trantor::EventLoop *loop = nullptr);

drogon::Task<Result> sendMailCoro(Request request,
                                  Credentials credentials,
                                  ServerTrust trust = kNoVerification,
                                  ConnectionPolicy connectionPolicy = kAllowConnection,
                                  trantor::EventLoop *loop = nullptr);

drogon::Task<DeliveryOutcome> sendMailDetailedCoro(Request request,
                                                    Credentials credentials,
                                                    ServerTrust trust = kNoVerification,
                                                    ConnectionPolicy connectionPolicy = kAllowConnection,
                                                    trantor::EventLoop *loop = nullptr);
}  // namespace drfin

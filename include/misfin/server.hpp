#pragma once

#include <misfin/async.hpp>
#include <misfin/types.hpp>
#include <misfin/utils.hpp>
#include <trantor/net/Certificate.h>

#include <functional>
#include <memory>
#include <string>

namespace drfin
{
// Everything needed to make a recipient-scoped TOFU decision. In particular,
// the same sender certificate may be trusted by one local mailbox and unknown
// or rejected by another.
struct TrustRequest
{
    trantor::CertificatePtr sender;
    std::string recipient;
    std::string serverName;
};

struct IncomingMessage
{
    Request request;
    trantor::CertificatePtr sender;
    std::string serverName;
};

using ServerIdentityReply = std::function<void(std::shared_ptr<const Credentials>)>;
// The provider may load a credential asynchronously. It must invoke reply once;
// nullptr rejects the TLS handshake.
using ServerIdentityProvider =
    std::function<void(std::string serverName, ServerIdentityReply reply)>;

using TofuDecision = std::function<void(bool accept)>;
// The status and meta are validated before being sent. For a 2x response the
// server substitutes its TLS certificate fingerprint as required by Misfin(B).
using DeliveryDecision = std::function<void(int status, std::string meta)>;

// Both handlers may save their decision callback and invoke it asynchronously.
// Inputs are passed by value so they remain valid across suspension.
using TofuHandler = std::function<void(TrustRequest, TofuDecision)>;
using DeliveryHandler = std::function<void(IncomingMessage, DeliveryDecision)>;

class Server
{
  public:
    Server();
    ~Server();
    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;

    // Starts one reuse-port TLS listener on each Drogon IO loop. Must be called
    // before drogon::app().run().
    void listen(Credentials identity,
                TofuHandler tofuHandler,
                DeliveryHandler deliveryHandler,
                std::string address = "0.0.0.0",
                unsigned short port = kMisfinPort);
    // The provider runs synchronously during the TLS handshake and may be
    // called concurrently. Return nullptr to reject the handshake.
    void listen(ServerIdentityProvider identityProvider,
                TofuHandler tofuHandler,
                DeliveryHandler deliveryHandler,
                std::string address = "0.0.0.0",
                unsigned short port = kMisfinPort);
    void stop();

  private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};
}  // namespace drfin

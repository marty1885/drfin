#pragma once

#include <misfin/async.hpp>
#include <misfin/types.hpp>
#include <misfin/utils.hpp>
#include <trantor/net/Certificate.h>

#include <functional>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>

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

// Called directly from the TLS handshake. It must only select credentials that
// are already in memory; nullptr rejects the handshake.
using ServerIdentityProvider =
    std::function<std::shared_ptr<const Credentials>(std::string serverName)>;

// A bool accepts or declines the sender certificate; declined senders receive
// a permanent 63. Conditions the sender should retry, such as local rate
// limits, use temporaryFailure() with a 4x status instead.
struct TofuVerdict
{
    TofuVerdict(bool accept) : accepted{accept} {}
    static TofuVerdict temporaryFailure(int status, std::string meta)
    {
        TofuVerdict verdict{false};
        verdict.status = status;
        verdict.meta = std::move(meta);
        return verdict;
    }

    bool accepted;
    int status = 63;
    std::string meta = "certificate declined";
};

using TofuDecision = std::function<void(TofuVerdict verdict)>;
// The status and meta are validated before being sent. For every 20 response,
// meta must be the recipient mailbox certificate fingerprint; the TLS server
// certificate is not necessarily the recipient identity.
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
                unsigned short port = kMisfinPort,
                std::size_t maxConnections = 256);
    // The provider runs synchronously during the TLS handshake and may be
    // called concurrently. Return nullptr to reject the handshake.
    void listen(ServerIdentityProvider identityProvider,
                TofuHandler tofuHandler,
                DeliveryHandler deliveryHandler,
                std::string address = "0.0.0.0",
                unsigned short port = kMisfinPort,
                std::size_t maxConnections = 256);
    void stop();

  private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};
}  // namespace drfin

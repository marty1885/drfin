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
struct IncomingMessage
{
    Request request;
    trantor::CertificatePtr sender;
};

using TofuDecision = std::function<void(bool accept)>;
using DeliveryDecision = std::function<void(bool accept)>;

// Both handlers may save their decision callback and invoke it asynchronously.
// Inputs are passed by value so they remain valid across suspension.
using TofuHandler = std::function<void(trantor::CertificatePtr, TofuDecision)>;
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
    void stop();

  private:
    class Impl;
    std::shared_ptr<Impl> impl_;
};
}  // namespace drfin

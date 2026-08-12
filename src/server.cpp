#include <misfin/server.hpp>
#include <misfin/url.hpp>
#include <misfin/utils.hpp>

#include <drogon/drogon.h>

#include <trantor/net/EventLoop.h>
#include <trantor/net/InetAddress.h>
#include <trantor/net/TcpConnection.h>
#include <trantor/net/TcpServer.h>
#include <trantor/net/TLSPolicy.h>
#include <trantor/utils/Logger.h>
#include <trantor/utils/MsgBuffer.h>

#include <optional>
#include <stdexcept>
#include <atomic>
#include <mutex>
#include <utility>
#include <vector>

namespace drfin
{
namespace
{
std::string certificateFingerprint(const trantor::CertificatePtr &certificate)
{
    if (!certificate)
    {
        LOG_ERROR << "Misfin server has no local TLS certificate";
        return {};
    }
    const auto fingerprint = normalizeFingerprint(certificate->sha256Fingerprint());
    if (fingerprint.empty())
        LOG_ERROR << "Misfin server certificate has no SHA-256 fingerprint";
    return fingerprint;
}

void validateIdentity(const Credentials &identity)
{
    if (!trantor::Certificate::fromPem(identity.certificatePem))
        throw std::invalid_argument("Misfin server requires a valid certificate PEM");
    const auto &keyPem = identity.privateKeyPem.empty()
                             ? identity.certificatePem
                             : identity.privateKeyPem;
    if (keyPem.find("PRIVATE KEY-----") == std::string::npos)
        throw std::invalid_argument("Misfin server requires a private key PEM");
}

std::string certificateBundle(const Credentials &identity)
{
    if (identity.privateKeyPem.empty() || identity.privateKeyPem == identity.certificatePem)
        return identity.certificatePem;
    return identity.certificatePem + identity.privateKeyPem;
}

std::optional<Request> parseRequest(const std::string &line)
{
    constexpr std::string_view scheme{"misfin://"};
    if (!line.starts_with(scheme) || line.find('\r') != std::string::npos)
        return std::nullopt;
    const auto space = line.find(' ', scheme.size());
    if (space == std::string::npos || space == scheme.size())
        return std::nullopt;
    const std::string recipient = line.substr(scheme.size(), space - scheme.size());
    if (!parseMisfinRecipient(recipient))
        return std::nullopt;
    return Request{recipient, line.substr(space + 1)};
}

struct ConnectionState
{
    std::weak_ptr<trantor::TcpConnection> connection;
    std::string fingerprint;
    std::string serverName;
    bool replied = false;
};

using DecisionOnce = std::shared_ptr<std::atomic_bool>;

bool claimDecision(const DecisionOnce &decision)
{
    bool expected = false;
    if (decision->compare_exchange_strong(
            expected, true, std::memory_order_relaxed, std::memory_order_relaxed))
        return true;
    LOG_ERROR << "Misfin handler invoked a decision callback more than once";
    return false;
}

void reply(const std::shared_ptr<ConnectionState> &state,
           int status,
           const std::string &meta)
{
    if (state->replied)
        return;
    std::string responseMeta = meta;
    if (!isMisfinResponseStatus(status) || responseMeta.find_first_of("\r\n") != std::string::npos)
    {
        LOG_ERROR << "Misfin server attempted an invalid response";
        status = 50;
        responseMeta = "internal server error";
    }
    std::string response = std::to_string(status) + " " + responseMeta + "\r\n";
    if (response.size() > kMaxMisfinResponseSize)
    {
        LOG_WARN << "Misfin server response exceeds " << kMaxMisfinResponseSize << " bytes";
        response = "50 internal server error\r\n";
    }
    state->replied = true;
    if (const auto connection = state->connection.lock())
    {
        connection->send(response);
        connection->clearContext();
    }
}
}  // namespace

class Listener : public std::enable_shared_from_this<Listener>
{
  public:
    Listener(trantor::EventLoop &loop,
             TofuHandler tofuHandler,
             DeliveryHandler deliveryHandler)
        : loop_(loop), tofuHandler_(std::move(tofuHandler)),
          deliveryHandler_(std::move(deliveryHandler))
    {
    }

    void listen(ServerIdentityProvider identityProvider,
                std::string address,
                unsigned short port)
    {
        server_ = std::make_unique<trantor::TcpServer>(
            &loop_, trantor::InetAddress(address, port), "misfin-server", true, true);

        // Request, but do not TLS-validate, sender certificates. Misfin's
        // asynchronous TOFU handler decides trust after the handshake.
        auto policy = trantor::TLSPolicy::defaultServerPolicy("", "");
        policy->setServerCertificateCallback([identityProvider = std::move(identityProvider)](
                                                  const std::string &serverName) {
            const auto identity = identityProvider(serverName);
            return identity ? certificateBundle(*identity) : std::string{};
        });
        policy->setPeerCertificateRequest(false)
            .setCertificateVerification(false);
        server_->enableSSL(std::move(policy));
        const std::weak_ptr<Listener> weak = shared_from_this();
        server_->setRecvMessageCallback([weak](const auto &connection, auto *buffer) {
            if (const auto self = weak.lock())
                self->receive(connection, buffer);
        });
        server_->start();
        loop_.runOnQuit([weak] {
            if (const auto self = weak.lock())
                self->stopInLoop();
        });
    }

    void stop()
    {
        if (loop_.isInLoopThread())
        {
            stopInLoop();
            return;
        }
        const std::weak_ptr<Listener> weak = shared_from_this();
        loop_.queueInLoop([weak] {
            if (const auto self = weak.lock())
                self->stopInLoop();
        });
    }

  private:
    void stopInLoop()
    {
        if (!server_)
            return;
        server_->stop();
        server_.reset();
    }

    void receive(const trantor::TcpConnectionPtr &connection,
                 trantor::MsgBuffer *buffer)
    {
        auto state = connection->getContext<ConnectionState>();
        if (!state)
        {
            state = std::make_shared<ConnectionState>();
            state->connection = connection;
            connection->setContext(state);
        }
        if (state->replied)
            return;
        if (buffer->readableBytes() > kMaxMisfinRequestSize)
            return reply(state, 59, "request exceeds 2048 bytes");
        const auto *crlf = buffer->findCRLF();
        if (crlf == nullptr)
            return;
        const std::string line{buffer->peek(), static_cast<size_t>(crlf - buffer->peek())};
        buffer->retrieveUntil(crlf + 2);
        const auto request = parseRequest(line);
        if (!request)
            return reply(state, 59, "bad request");

        const auto peer = connection->peerCertificate();
        if (!peer)
            return reply(state, 60, "certificate required");
        state->fingerprint = certificateFingerprint(connection->localCertificate());
        if (state->fingerprint.empty())
            return reply(state, 50, "internal server error");
        state->serverName = connection->sniName();

        const auto deliveryPeer = peer;
        const auto tofuDecision = std::make_shared<std::atomic_bool>(false);
        const std::weak_ptr<Listener> weak = shared_from_this();
        tofuHandler_(peer, [weak, tofuDecision, state, request = *request, peer = std::move(deliveryPeer)](
                               bool accepted) mutable {
            const auto self = weak.lock();
            if (!self || !claimDecision(tofuDecision))
                return;
            self->loop_.queueInLoop([weak, state, request = std::move(request), peer = std::move(peer), accepted] {
                const auto self = weak.lock();
                if (!self)
                    return;
                if (!accepted)
                    return reply(state, 63, "certificate declined");
                const auto deliveryDecision = std::make_shared<std::atomic_bool>(false);
                self->deliveryHandler_(
                    {std::move(request), std::move(peer), state->serverName},
                    [weak, deliveryDecision, state](bool delivered) {
                        const auto self = weak.lock();
                        if (!self || !claimDecision(deliveryDecision))
                            return;
                        self->loop_.queueInLoop([weak, state, delivered] {
                            const auto self = weak.lock();
                            if (!self)
                                return;
                            if (delivered)
                                reply(state, 20, state->fingerprint);
                            else
                                reply(state, 51, "mailbox does not exist");
                        });
                    });
            });
        });
    }

    trantor::EventLoop &loop_;
    std::unique_ptr<trantor::TcpServer> server_;
    TofuHandler tofuHandler_;
    DeliveryHandler deliveryHandler_;
};

class Server::Impl : public std::enable_shared_from_this<Server::Impl>
{
  public:
    void listen(Credentials identity,
                TofuHandler tofuHandler,
                DeliveryHandler deliveryHandler,
                std::string address,
                unsigned short port)
    {
        validateIdentity(identity);
        auto sharedIdentity = std::make_shared<const Credentials>(std::move(identity));
        listen([sharedIdentity](const std::string &) { return sharedIdentity; },
               std::move(tofuHandler), std::move(deliveryHandler),
               std::move(address), port);
    }

    void listen(ServerIdentityProvider identityProvider,
                TofuHandler tofuHandler,
                DeliveryHandler deliveryHandler,
                std::string address,
                unsigned short port)
    {
        if (!identityProvider)
            throw std::invalid_argument("Misfin server requires an identity provider");
        if (started_)
            throw std::logic_error("Misfin server is already listening");
        started_ = true;
        const std::weak_ptr<Impl> weak = shared_from_this();
        drogon::app().registerBeginningAdvice(
            [weak,
              identityProvider = std::move(identityProvider),
              tofuHandler = std::move(tofuHandler),
             deliveryHandler = std::move(deliveryHandler),
             address = std::move(address),
             port] {
                const auto self = weak.lock();
                if (!self || self->stopped_.load(std::memory_order_relaxed))
                    return;
                for (size_t i = 0; i < drogon::app().getThreadNum(); ++i)
                {
                    auto *loop = drogon::app().getIOLoop(i);
                    loop->queueInLoop([weak,
                                       loop,
                                        identityProvider,
                                       tofuHandler,
                                       deliveryHandler,
                                       address,
                                       port] {
                        const auto self = weak.lock();
                        if (!self || self->stopped_.load(std::memory_order_relaxed))
                            return;
                        auto listener = std::make_shared<Listener>(
                            *loop, tofuHandler, deliveryHandler);
                        listener->listen(identityProvider, address, port);
                        std::lock_guard<std::mutex> lock{self->mutex_};
                        self->listeners_.push_back(std::move(listener));
                    });
                }
            });
    }

    void stop()
    {
        stopped_.store(true, std::memory_order_relaxed);
        std::vector<std::shared_ptr<Listener>> listeners;
        {
            std::lock_guard<std::mutex> lock{mutex_};
            listeners.swap(listeners_);
        }
        for (const auto &listener : listeners)
            listener->stop();
    }

  private:
    std::mutex mutex_;
    std::vector<std::shared_ptr<Listener>> listeners_;
    bool started_ = false;
    std::atomic_bool stopped_{false};
};

Server::Server() : impl_(std::make_shared<Impl>()) {}
Server::~Server() = default;

void Server::listen(Credentials identity,
                     TofuHandler tofuHandler,
                     DeliveryHandler deliveryHandler,
                     std::string address,
                     unsigned short port)
{
    impl_->listen(std::move(identity), std::move(tofuHandler), std::move(deliveryHandler),
                    std::move(address), port);
}

void Server::listen(ServerIdentityProvider identityProvider,
                    TofuHandler tofuHandler,
                    DeliveryHandler deliveryHandler,
                    std::string address,
                    unsigned short port)
{
    impl_->listen(std::move(identityProvider),
                  std::move(tofuHandler), std::move(deliveryHandler),
                  std::move(address), port);
}

void Server::stop()
{
    impl_->stop();
}
}  // namespace drfin

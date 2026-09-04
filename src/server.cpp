#include <misfin/server.hpp>
#include <misfin/gemmail.hpp>
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
#include <charconv>
#include <stdexcept>
#include <atomic>
#include <mutex>
#include <utility>
#include <vector>

namespace drfin
{
namespace
{
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

std::optional<Request> parseBRequest(const std::string &line)
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
    return Request{recipient, line.substr(space + 1), MisfinVersion::B};
}

struct CHeader
{
    std::string recipient;
    std::size_t contentSize;
};

std::optional<CHeader> parseCHeader(const std::string &line)
{
    constexpr std::string_view scheme{"misfin://"};
    if (!line.starts_with(scheme) || line.find('\r') != std::string::npos)
        return std::nullopt;
    const auto tab = line.find('\t', scheme.size());
    if (tab == std::string::npos || tab == scheme.size() || line.find('\t', tab + 1) != std::string::npos)
        return std::nullopt;
    const std::string recipient = line.substr(scheme.size(), tab - scheme.size());
    if (!parseMisfinRecipient(recipient)) return std::nullopt;
    std::size_t contentSize{};
    const auto length = std::string_view{line}.substr(tab + 1);
    const auto [end, error] = std::from_chars(length.data(), length.data() + length.size(), contentSize);
    if (error != std::errc{} || end != length.data() + length.size() || contentSize == 0 ||
        contentSize > kMaxMisfinCContentSize)
        return std::nullopt;
    return CHeader{recipient, contentSize};
}

struct ConnectionState
{
    std::weak_ptr<trantor::TcpConnection> connection;
    std::string serverName;
    bool processing = false;
    bool replied = false;
    std::optional<CHeader> cHeader;
    MisfinVersion version = MisfinVersion::B;
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
    bool invalidSuccessFingerprint = false;
    if (status == 20 && state->version == MisfinVersion::B)
    {
        invalidSuccessFingerprint = !isValidSha256Fingerprint(responseMeta);
        if (!invalidSuccessFingerprint) responseMeta = normalizeFingerprint(responseMeta);
    }
    else if (status == 20)
    {
        invalidSuccessFingerprint = responseMeta.size() != 64 ||
            std::ranges::any_of(responseMeta, [](unsigned char character) {
                return !std::isdigit(character) && !(character >= 'a' && character <= 'f');
            });
    }
    if (!isMisfinResponseStatus(status) || responseMeta.find_first_of("\r\n") != std::string::npos ||
        invalidSuccessFingerprint)
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
    state->processing = false;
    if (const auto connection = state->connection.lock())
    {
        connection->send(response);
        // Misfin is exactly one request and one response per TLS connection.
        // shutdown() flushes the queued response, then sends close_notify and
        // closes the write side; clients must not wait indefinitely for EOF.
        connection->shutdown();
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
        server_->kickoffIdleConnections(static_cast<size_t>(kMisfinTransactionTimeout));

        // Request, but do not TLS-validate, sender certificates. Misfin's
        // asynchronous TOFU handler decides trust after the handshake.
        auto policy = trantor::TLSPolicy::defaultServerPolicy("", "");
        policy->setServerCertificateProvider(
            [identityProvider = std::move(identityProvider)](std::string serverName) {
                const auto identity = identityProvider(std::move(serverName));
                if (!identity)
                    return trantor::ServerCertificate{};
                return trantor::ServerCertificate{identity->certificatePem, identity->privateKeyPem};
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
        loop_.runInLoop([weak] {
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
        // Misfin permits exactly one request per connection.  The request may
        // be awaiting asynchronous certificate or delivery work, but it has
        // already consumed this connection's sole request slot.
        if (state->processing)
            return reply(state, 59, "multiple requests on one connection");
        std::optional<Request> request;
        if (state->cHeader)
        {
            if (buffer->readableBytes() > state->cHeader->contentSize)
                return reply(state, 59, "Misfin(C) content exceeds declared length");
            if (buffer->readableBytes() < state->cHeader->contentSize)
                return;
            std::string content{buffer->peek(), state->cHeader->contentSize};
            buffer->retrieve(state->cHeader->contentSize);
            bool bareCr = false;
            for (std::size_t index = 0; index < content.size(); ++index)
                if (content[index] == '\r' &&
                    (index + 1 == content.size() || content[index + 1] != '\n'))
                    bareCr = true;
            if (bareCr || !isValidUtf8(content))
                return reply(state, 59, "invalid Misfin(C) content");
            if (!Gemmail::parseC(content))
                return reply(state, 59, "malformed Misfin(C) message");
            request = Request{std::move(state->cHeader->recipient), std::move(content), MisfinVersion::C};
            state->cHeader.reset();
        }
        else
        {
            const auto *crlf = buffer->findCRLF();
            if (crlf == nullptr)
            {
                if (buffer->readableBytes() > kMaxMisfinRequestSize)
                    return reply(state, 59, "request header exceeds 2048 bytes");
                return;
            }
            const std::string line{buffer->peek(), static_cast<size_t>(crlf - buffer->peek())};
            constexpr std::string_view scheme{"misfin://"};
            const auto separator = line.find_first_of(" \t", scheme.size());
            if (separator != std::string::npos && line[separator] == '\t')
            {
                if (line.size() + 2 > kMaxMisfinCHeaderSize)
                    return reply(state, 59, "Misfin(C) header exceeds 1024 bytes");
                const auto header = parseCHeader(line);
                if (!header)
                    return reply(state, 59, "bad Misfin(C) request");
                buffer->retrieveUntil(crlf + 2);
                state->cHeader = *header;
                return receive(connection, buffer);
            }
            if (line.size() + 2 > kMaxMisfinRequestSize || buffer->readableBytes() != line.size() + 2)
                return reply(state, 59, "request exceeds 2048 bytes");
            buffer->retrieveUntil(crlf + 2);
            request = parseBRequest(line);
            if (!request)
                return reply(state, 59, "bad request");
            if (!isValidUtf8(request->message))
                return reply(state, 59, "invalid UTF-8 message");
        }

        state->processing = true;

        const auto peer = connection->peerCertificate();
        if (!peer)
            return reply(state, 60, "certificate required");
        state->serverName = connection->sniName();
        state->version = *request->version;

        const auto deliveryPeer = peer;
        // Materialize the recipient before moving the request into the
        // asynchronous delivery continuation. Function-argument evaluation
        // order is not a safe ownership boundary here: moving first leaves
        // the TOFU callback with an empty recipient and makes it reject every
        // otherwise valid sender certificate.
        auto recipient = request->recipient;
        auto incomingRequest = std::move(*request);
        const auto tofuDecision = std::make_shared<std::atomic_bool>(false);
        const std::weak_ptr<Listener> weak = shared_from_this();
        try
        {
            tofuHandler_(
                {peer, std::move(recipient), state->serverName},
                [weak, tofuDecision, state, request = std::move(incomingRequest), peer = std::move(deliveryPeer)](
                    bool accepted) mutable {
                const auto self = weak.lock();
            if (!self || !claimDecision(tofuDecision))
                return;
            self->loop_.runInLoop([weak,
                                     state,
                                     request = std::move(request),
                                     peer = std::move(peer),
                                     accepted] {
                const auto self = weak.lock();
                if (!self)
                    return;
                // The connection may have been rejected for receiving more
                // data while this asynchronous decision was outstanding.
                // Do not start delivery after that rejection.
                if (!state->processing)
                    return;
                if (!accepted)
                    return reply(state, 63, "certificate declined");
                const auto deliveryDecision = std::make_shared<std::atomic_bool>(false);
                try
                {
                    self->deliveryHandler_(
                        {std::move(request), std::move(peer), state->serverName},
                        [weak, deliveryDecision, state](int status, std::string meta) {
                        const auto self = weak.lock();
                        if (!self || !claimDecision(deliveryDecision))
                            return;
                        self->loop_.runInLoop([weak,
                                              state,
                                              status,
                                              meta = std::move(meta)] {
                            const auto self = weak.lock();
                            if (!self)
                                return;
                            reply(state, status, meta);
                        });
                        });
                }
                catch (const std::exception &error)
                {
                    LOG_ERROR << "Misfin delivery handler threw exception: " << error.what();
                    reply(state, 50, "internal server error");
                }
                catch (...)
                {
                    LOG_ERROR << "Misfin delivery handler threw an unknown exception";
                    reply(state, 50, "internal server error");
                }
            });
                });
        }
        catch (const std::exception &error)
        {
            LOG_ERROR << "Misfin TOFU handler threw exception: " << error.what();
            reply(state, 50, "internal server error");
        }
        catch (...)
        {
            LOG_ERROR << "Misfin TOFU handler threw an unknown exception";
            reply(state, 50, "internal server error");
        }
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
        listen([sharedIdentity](std::string) { return sharedIdentity; },
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
        const auto startListeners =
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
                    loop->runInLoop([weak,
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
            };
        if (drogon::app().isRunning())
            startListeners();
        else
            drogon::app().registerBeginningAdvice(startListeners);
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

#include <misfin/client.hpp>
#include <misfin/url.hpp>
#include <misfin/utils.hpp>

#include <drogon/drogon.h>

#include <trantor/net/EventLoop.h>
#include <trantor/net/InetAddress.h>
#include <trantor/net/Resolver.h>
#include <trantor/net/TcpClient.h>
#include <trantor/net/TLSPolicy.h>
#include <trantor/utils/Logger.h>
#include <trantor/utils/MsgBuffer.h>

#include <memory>
#include <optional>
#include <charconv>
#include <exception>
#include <utility>

namespace drfin
{
namespace
{
std::expected<Response, std::string> parseResponse(const std::string &line,
                                                    const std::string &fingerprint)
{
    if (line.size() < 3 || line[2] != ' ')
        return std::unexpected("server sent an invalid Misfin response");
    int status = 0;
    const auto [end, error] = std::from_chars(line.data(), line.data() + 2, status);
    if (error != std::errc{} || end != line.data() + 2 || !isMisfinResponseStatus(status))
        return std::unexpected("server sent an invalid Misfin response");
    const auto meta = line.substr(3);
    if (status == 20)
    {
        const auto deliveredTo = normalizeFingerprint(meta);
        if (fingerprint.empty() || deliveredTo.empty() || deliveredTo != fingerprint)
            return std::unexpected("server response fingerprint does not match its TLS certificate");
    }
    return Response{status, meta, fingerprint};
}

class Operation : public std::enable_shared_from_this<Operation>
{
  public:
    Operation(trantor::EventLoop &loop,
               Request request,
               Credentials credentials,
               SendCallback callback,
               ServerTrust trust)
        : loop_(loop), request_(std::move(request)), credentials_(std::move(credentials)),
          callback_(std::move(callback)), trust_(std::move(trust))
    {
    }

    void start()
    {
        keepAlive_ = shared_from_this();
        timeout_ = loop_.runAfter(kMisfinTransactionTimeout, [weak = weak_from_this()] {
            if (const auto self = weak.lock())
                self->finish(std::unexpected("Misfin transaction timed out"));
        });
        try
        {
            startInLoop();
        }
        catch (const std::exception &error)
        {
            finish(std::unexpected(error.what()));
        }
        catch (...)
        {
            finish(std::unexpected("failed to start Misfin transaction"));
        }
    }

  private:
    void startInLoop()
    {
        const auto recipient = parseMisfinRecipient(request_.recipient);
        if (!recipient)
            return finish(std::unexpected("recipient must be mailbox@hostname or misfin://mailbox@hostname"));
        if (request_.message.find('\r') != std::string::npos)
            return finish(std::unexpected("message must not contain CR; use LF line endings"));

        recipient_ = recipient->userInfo() + "@" + recipient->host();
        requestLine_ = "misfin://" + recipient_ + " " + request_.message + "\r\n";
        if (requestLine_.size() > kMaxMisfinRequestSize)
            return finish(std::unexpected("Misfin request exceeds 2048 bytes"));

        policy_ = trantor::TLSPolicy::defaultClientPolicy(recipient->host());
        policy_->setValidate(false)
            .setCertificatePem(credentials_.certificatePem, credentials_.privateKeyPem);
        endpoint_ = recipient->host() + ":" + std::to_string(kMisfinPort);
        auto ip = trantor::InetAddress(recipient->host(), kMisfinPort);
        if (!ip.isUnspecified())
            return sendInLoop(std::move(ip));
        if (recipient->host().size() > 2 && recipient->host().front() == '[' &&
            recipient->host().back() == ']')
        {
            ip = trantor::InetAddress(recipient->host().substr(1, recipient->host().size() - 2),
                                      kMisfinPort,
                                      true);
            if (!ip.isUnspecified())
                return sendInLoop(std::move(ip));
        }
        resolver_ = trantor::Resolver::newResolver(&loop_);
        resolver_->resolve(
            recipient->host(),
            trantor::Resolver::Callback{[weak = weak_from_this()](const auto &address) {
                if (const auto self = weak.lock())
                    self->sendInLoop(address);
            }});
    }

    void sendInLoop(trantor::InetAddress address)
    {
        try
        {
            sendInLoopImpl(std::move(address));
        }
        catch (const std::exception &error)
        {
            finish(std::unexpected(error.what()));
        }
        catch (...)
        {
            finish(std::unexpected("failed to connect Misfin transaction"));
        }
    }

    void sendInLoopImpl(trantor::InetAddress address)
    {
        if (address.family() != AF_INET && address.family() != AF_INET6)
            return finish(std::unexpected("DNS lookup failed"));
        // TcpClient::connect() uses shared_from_this() internally.
        client_ = std::make_shared<trantor::TcpClient>(&loop_, std::move(address), "misfin-client");
        client_->enableSSL(std::move(policy_));
        const auto weak = weak_from_this();
        client_->setConnectionErrorCallback([weak] {
            if (const auto self = weak.lock())
                self->finish(std::unexpected("TCP connection failed"));
        });
        client_->setSSLErrorCallback([weak](trantor::SSLError) {
            if (const auto self = weak.lock())
                self->finish(std::unexpected("TLS handshake failed"));
        });
        client_->setConnectionCallback([weak](const auto &connection) {
            const auto self = weak.lock();
            if (!self)
                return;
            if (!connection->connected())
            {
                self->finish(std::unexpected("server closed before sending a response"));
                return;
            }
            if (self->trustStarted_)
                return;
            const auto certificate = connection->peerCertificate();
            if (!certificate)
                return self->finish(std::unexpected("server did not provide a certificate"));
            self->trustStarted_ = true;
            self->serverFingerprint_ = normalizeFingerprint(certificate->sha256Fingerprint());
            const auto decision = std::make_shared<std::atomic_bool>(false);
            const std::weak_ptr<trantor::TcpConnection> weakConnection = connection;
            try
            {
                self->trust_(self->endpoint_,
                             certificate,
                             [weak, weakConnection, decision](bool accepted) {
                                 const auto self = weak.lock();
                                 if (!self)
                                     return;
                                 bool expected = false;
                                 if (!decision->compare_exchange_strong(
                                         expected,
                                         true,
                                         std::memory_order_relaxed,
                                         std::memory_order_relaxed))
                                 {
                                     LOG_ERROR << "Misfin server trust callback invoked more than once";
                                     return;
                                 }
                                 self->loop_.runInLoop([weak, weakConnection, accepted] {
                                     const auto self = weak.lock();
                                     if (!self)
                                         return;
                                     if (!accepted)
                                     {
                                         if (const auto client = self->client_)
                                             client->disconnect();
                                         return self->finish(
                                             std::unexpected("server certificate declined"));
                                     }
                                     self->sent_ = true;
                                     if (const auto connection = weakConnection.lock())
                                         connection->send(self->requestLine_);
                                     else
                                         self->finish(std::unexpected(
                                             "server closed before trust completed"));
                                 });
                             });
            }
            catch (const std::exception &error)
            {
                self->finish(std::unexpected(error.what()));
            }
            catch (...)
            {
                self->finish(std::unexpected("server trust callback failed"));
            }
        });
        client_->setMessageCallback([weak](const auto &connection, auto *buffer) {
            const auto self = weak.lock();
            if (!self)
                return;
            if (buffer->readableBytes() > kMaxMisfinResponseSize)
                return self->finish(std::unexpected("server response exceeds 2048 bytes"));
            const auto *crlf = buffer->findCRLF();
            if (crlf == nullptr)
                return;
            const std::string line{buffer->peek(), static_cast<size_t>(crlf - buffer->peek())};
            buffer->retrieveUntil(crlf + 2);
            connection->shutdown();
            self->finish(parseResponse(line, self->serverFingerprint_));
        });
        client_->connect();
    }

    void finish(Result result)
    {
        if (finished_)
            return;
        finished_ = true;
        loop_.invalidateTimer(timeout_);
        auto self = shared_from_this();
        loop_.runInLoop([self, result = std::move(result)]() mutable {
            self->client_.reset();
            self->resolver_.reset();
            if (self->callback_)
                self->callback_(std::move(result));
            else
                LOG_ERROR << "Misfin transaction completed without a callback";
            self->keepAlive_.reset();
        });
    }

    trantor::EventLoop &loop_;
    Request request_;
    Credentials credentials_;
    SendCallback callback_;
    ServerTrust trust_;
    std::shared_ptr<trantor::TcpClient> client_;
    std::shared_ptr<trantor::Resolver> resolver_;
    std::shared_ptr<trantor::TLSPolicy> policy_;
    std::shared_ptr<Operation> keepAlive_;
    std::string requestLine_;
    std::string recipient_;
    std::string serverFingerprint_;
    std::string endpoint_;
    trantor::TimerId timeout_ = trantor::InvalidTimerId;
    bool trustStarted_ = false;
    bool sent_ = false;
    bool finished_ = false;
};
}  // namespace

void sendMail(Request request,
              Credentials credentials,
              SendCallback callback,
              ServerTrust trust,
              trantor::EventLoop *loop)
{
    if (!loop)
        loop = drogon::app().getLoop();
    auto operation = std::make_shared<Operation>(*loop,
                                                  std::move(request),
                                                  std::move(credentials),
                                                  std::move(callback),
                                                  std::move(trust));
    loop->runInLoop([operation] { operation->start(); });
}

drogon::Task<Result> sendMailCoro(Request request,
                                  Credentials credentials,
                                  ServerTrust trust,
                                  trantor::EventLoop *loop)
{
    struct State
    {
        std::optional<Result> result;
    };
    struct Awaiter
    {
        Request request;
        Credentials credentials;
        ServerTrust trust;
        trantor::EventLoop *loop;
        std::shared_ptr<State> state;

        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> continuation)
        {
            const std::weak_ptr<State> weak = state;
            sendMail(std::move(request),
                     std::move(credentials),
                     [weak, continuation](Result received) mutable {
                         if (const auto state = weak.lock())
                         {
                             state->result.emplace(std::move(received));
                             continuation.resume();
                         }
                      },
                     std::move(trust),
                     loop);
        }
        Result await_resume() { return std::move(*state->result); }
    };
    auto state = std::make_shared<State>();
    co_return co_await Awaiter{
        std::move(request), std::move(credentials), std::move(trust), loop, std::move(state)};
}
}  // namespace drfin

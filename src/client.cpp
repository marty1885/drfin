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

#include <algorithm>
#include <memory>
#include <optional>
#include <charconv>
#include <cctype>
#include <exception>
#include <utility>
#include <vector>

namespace drfin
{
namespace
{
std::expected<Response, std::string> parseResponse(const std::string &line,
                                                    const std::string &fingerprint,
                                                    MisfinVersion version)
{
    if (line.size() < 3 || line[2] != ' ')
        return std::unexpected("server sent an invalid Misfin response");
    int status = 0;
    const auto [end, error] = std::from_chars(line.data(), line.data() + 2, status);
    if (error != std::errc{} || end != line.data() + 2 || !isMisfinResponseStatus(status))
        return std::unexpected("server sent an invalid Misfin response");
    const auto meta = line.substr(3);
    if (status == 20 && version == MisfinVersion::B)
    {
        // Misfin(B) returns the recipient mailbox certificate fingerprint, not
        // necessarily the TLS server certificate fingerprint. Hosted mailboxes
        // commonly use a different certificate for each recipient.
        if (!isValidSha256Fingerprint(meta))
            return std::unexpected("server sent an invalid recipient certificate fingerprint");
    }
    return Response{status, meta, fingerprint};
}

class Operation : public std::enable_shared_from_this<Operation>
{
  public:
    Operation(trantor::EventLoop &loop,
               Request request,
               Credentials credentials,
               DeliveryOutcomeCallback callback,
               ServerTrust trust,
               ConnectionPolicy connectionPolicy)
        : loop_(loop), request_(std::move(request)), credentials_(std::move(credentials)),
                callback_(std::move(callback)), trust_(std::move(trust)), connectionPolicy_(std::move(connectionPolicy))
    {
    }

    void start()
    {
        keepAlive_ = shared_from_this();
        timeout_ = loop_.runAfter(kMisfinTransactionTimeout, [weak = weak_from_this()] {
            if (const auto self = weak.lock())
                self->finish(std::unexpected("Misfin transaction timed out while " + self->stage_));
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
        if (!isValidUtf8(request_.message))
            return finish(std::unexpected("message must be valid UTF-8"));

        recipient_ = recipient->userInfo() + "@" + recipient->host();
        if (recipient->port()) recipient_ += ":" + std::to_string(*recipient->port());
        const std::string bRequest = "misfin://" + recipient_ + " " + request_.message + "\r\n";
        const auto version = request_.version.value_or(
            bRequest.size() <= kMaxMisfinRequestSize ? MisfinVersion::B : MisfinVersion::C);
        version_ = version;
        if (version == MisfinVersion::B)
        {
            if (bRequest.size() > kMaxMisfinRequestSize)
                return finish(std::unexpected("Misfin(B) request exceeds 2048 bytes"));
            requestBytes_ = bRequest;
        }
        else
        {
            if (request_.message.size() > kMaxMisfinCContentSize)
                return finish(std::unexpected("Misfin(C) content exceeds 16384 bytes"));
            const auto header = "misfin://" + recipient_ + "\t" + std::to_string(request_.message.size()) + "\r\n";
            if (header.size() > kMaxMisfinCHeaderSize)
                return finish(std::unexpected("Misfin(C) header exceeds 1024 bytes"));
            requestBytes_ = header + request_.message;
        }

        const auto port = recipient->port().value_or(kMisfinPort);
        tlsServerName_ = recipient->host();
        endpoint_ = recipient->host() + ":" + std::to_string(port);
        auto ip = trantor::InetAddress(recipient->host(), port);
        if (!ip.isUnspecified())
            return startCandidates({std::move(ip)});
        if (recipient->host().size() > 2 && recipient->host().front() == '[' &&
            recipient->host().back() == ']')
        {
            ip = trantor::InetAddress(recipient->host().substr(1, recipient->host().size() - 2),
                                      port,
                                      true);
            if (!ip.isUnspecified())
                return startCandidates({std::move(ip)});
        }
        resolver_ = trantor::Resolver::newResolver(&loop_);
        stage_ = "resolving DNS";
        resolver_->resolve(
            recipient->host(),
            trantor::Resolver::ResolverResultsCallback{
                [weak = weak_from_this(), port](const std::vector<trantor::InetAddress> &addresses) {
                    // NormalResolver invokes callbacks from its worker thread. TcpClient
                    // and its Connector must only be created on the owning event loop.
                    if (const auto self = weak.lock())
                    {
                        std::vector<trantor::InetAddress> endpoints;
                        endpoints.reserve(addresses.size());
                        for (const auto &address : addresses)
                        {
                            if (address.family() == AF_INET || address.family() == AF_INET6)
                                endpoints.emplace_back(address.toIp(), port, address.isIpV6());
                        }
                        self->loop_.queueInLoop([weak, endpoints = std::move(endpoints)]() mutable {
                            if (const auto operation = weak.lock())
                                operation->startCandidates(std::move(endpoints));
                        });
                    }
                }});
    }

    [[nodiscard]] std::shared_ptr<trantor::TLSPolicy> makePolicy() const
    {
        auto policy = trantor::TLSPolicy::defaultClientPolicy(tlsServerName_);
        const auto &keyPem = credentials_.privateKeyPem.empty()
                                 ? credentials_.certificatePem
                                 : credentials_.privateKeyPem;
        policy->setValidate(false)
            .setCertificatePem(credentials_.certificatePem, keyPem);
        return policy;
    }

    void startCandidates(std::vector<trantor::InetAddress> addresses)
    {
        if (addresses.empty())
            return finish(std::unexpected("DNS lookup failed"));

        std::vector<trantor::InetAddress> ipv6;
        std::vector<trantor::InetAddress> ipv4;
        for (auto &address : addresses)
        {
            if (address.family() == AF_INET6)
                ipv6.push_back(std::move(address));
            else if (address.family() == AF_INET)
                ipv4.push_back(std::move(address));
        }
        candidates_.clear();
        candidates_.reserve(ipv4.size() + ipv6.size());
        for (std::size_t index = 0; index < std::max(ipv6.size(), ipv4.size()); ++index)
        {
            if (index < ipv6.size()) candidates_.push_back(std::move(ipv6[index]));
            if (index < ipv4.size()) candidates_.push_back(std::move(ipv4[index]));
        }
        if (candidates_.empty())
            return finish(std::unexpected("DNS lookup returned no Internet address"));

        candidateStates_.assign(candidates_.size(), CandidateState::Pending);
        clients_.resize(candidates_.size());
        candidateTimers_.resize(candidates_.size(), trantor::InvalidTimerId);
        startCandidate(0);
        for (std::size_t index = 1; index < candidates_.size(); ++index)
        {
            candidateTimers_[index] = loop_.runAfter(
                0.25 * static_cast<double>(index), [weak = weak_from_this(), index] {
                    if (const auto self = weak.lock()) self->startCandidate(index);
                });
        }
    }

    void startCandidate(std::size_t index)
    {
        if (finished_ || winner_ || index >= candidates_.size() || candidateStates_[index] != CandidateState::Pending)
            return;
        const auto &address = candidates_[index];
        candidateStates_[index] = CandidateState::Connecting;
        if (!connectionPolicy_(endpoint_, address.toIp()))
            return candidateFailed(index, "destination address is not permitted");
        stage_ = "connecting to recipient";
        // TcpClient::connect() uses shared_from_this() internally.
        auto client = std::make_shared<trantor::TcpClient>(&loop_, address, "misfin-client");
        clients_[index] = client;
        client->enableSSL(makePolicy());
        const auto weak = weak_from_this();
        client->setConnectionErrorCallback([weak, index] {
            if (const auto self = weak.lock()) self->candidateFailed(index, "TCP connection failed");
        });
        client->setSSLErrorCallback([weak, index](trantor::SSLError) {
            if (const auto self = weak.lock()) self->candidateFailed(index, "TLS handshake failed");
        });
        client->setConnectionCallback([weak, index](const auto &connection) {
            const auto self = weak.lock();
            if (!self || self->finished_)
                return;
            if (!connection->connected())
            {
                if (self->winner_ && *self->winner_ == index)
                    return self->finish(std::unexpected("connection closed by server"));
                self->candidateFailed(index, "server closed during TLS handshake");
                return;
            }
            if (self->winner_)
                return;
            self->winner_ = index;
            self->candidateStates_[index] = CandidateState::Winner;
            self->cancelCandidateTimers();
            self->disconnectLosers(index);
            const auto certificate = connection->peerCertificate();
            if (!certificate)
                return self->finish(std::unexpected("server did not provide a certificate"));
            self->stage_ = "checking server certificate";
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
                                     if (!self || self->finished_ || !self->winner_)
                                         return;
                                     if (!accepted)
                                     {
                                         if (const auto &client = self->clients_[*self->winner_])
                                             client->disconnect();
                                         return self->finish(
                                             std::unexpected("server certificate declined"));
                                     }
                                     self->stage_ = "sending request";
                                     if (const auto connection = weakConnection.lock())
                                     {
                                         self->sent_ = true;
                                         connection->send(self->requestBytes_);
                                         self->stage_ = "waiting for server response";
                                     }
                                     else
                                         self->finish(std::unexpected("server closed before trust completed"));
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
        client->setMessageCallback([weak](const auto &connection, auto *buffer) {
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
            self->finish(parseResponse(line, self->serverFingerprint_, self->version_));
        });
        client->connect();
    }

    void candidateFailed(std::size_t index, std::string reason)
    {
        if (finished_ || winner_ || index >= candidateStates_.size() ||
            candidateStates_[index] != CandidateState::Connecting)
            return;
        candidateStates_[index] = CandidateState::Failed;
        clients_[index].reset();
        lastCandidateFailure_ = std::move(reason);
        for (std::size_t next = 0; next < candidateStates_.size(); ++next)
        {
            if (candidateStates_[next] == CandidateState::Pending)
            {
                startCandidate(next);
                return;
            }
        }
        if (std::all_of(candidateStates_.begin(), candidateStates_.end(), [](CandidateState state) {
                return state == CandidateState::Failed;
            }))
            finish(std::unexpected(lastCandidateFailure_));
    }

    void cancelCandidateTimers()
    {
        for (const auto timer : candidateTimers_)
        {
            if (timer != trantor::InvalidTimerId)
                loop_.invalidateTimer(timer);
        }
        candidateTimers_.clear();
    }

    void disconnectLosers(std::size_t winner)
    {
        for (std::size_t index = 0; index < clients_.size(); ++index)
        {
            if (index != winner && clients_[index])
                clients_[index]->disconnect();
        }
    }

    void finish(Result result)
    {
        if (finished_)
            return;
        finished_ = true;
        loop_.invalidateTimer(timeout_);
        cancelCandidateTimers();
        auto self = shared_from_this();
        loop_.runInLoop([self, result = std::move(result)]() mutable {
            self->clients_.clear();
            self->resolver_.reset();
            if (self->callback_)
                self->callback_({std::move(result), self->sent_});
            else
                LOG_ERROR << "Misfin transaction completed without a callback";
            self->keepAlive_.reset();
        });
    }

    trantor::EventLoop &loop_;
    Request request_;
    Credentials credentials_;
    DeliveryOutcomeCallback callback_;
    ServerTrust trust_;
    ConnectionPolicy connectionPolicy_;
    std::shared_ptr<trantor::Resolver> resolver_;
    std::shared_ptr<Operation> keepAlive_;
    enum class CandidateState
    {
        Pending,
        Connecting,
        Failed,
        Winner,
    };
    std::vector<trantor::InetAddress> candidates_;
    std::vector<CandidateState> candidateStates_;
    std::vector<std::shared_ptr<trantor::TcpClient>> clients_;
    std::vector<trantor::TimerId> candidateTimers_;
    std::optional<std::size_t> winner_;
    std::string lastCandidateFailure_ = "all recipient addresses failed";
    std::string requestBytes_;
    std::string recipient_;
    std::string serverFingerprint_;
    std::string tlsServerName_;
    std::string endpoint_;
    std::string stage_ = "starting transaction";
    trantor::TimerId timeout_ = trantor::InvalidTimerId;
    bool trustStarted_ = false;
    MisfinVersion version_ = MisfinVersion::B;
    bool sent_ = false;
    bool finished_ = false;
};
}  // namespace

void sendMail(Request request,
              Credentials credentials,
              SendCallback callback,
              ServerTrust trust,
              ConnectionPolicy connectionPolicy,
              trantor::EventLoop *loop)
{
    if (!loop)
        loop = drogon::app().getLoop();
    sendMailDetailed(std::move(request), std::move(credentials),
                     [callback = std::move(callback)](DeliveryOutcome outcome) mutable {
                         callback(std::move(outcome.result));
                     },
                     std::move(trust), std::move(connectionPolicy), loop);
}

void sendMailDetailed(Request request,
                      Credentials credentials,
                      DeliveryOutcomeCallback callback,
                      ServerTrust trust,
                      ConnectionPolicy connectionPolicy,
                      trantor::EventLoop *loop)
{
    if (!loop)
        loop = drogon::app().getLoop();
    auto operation = std::make_shared<Operation>(*loop,
                                                  std::move(request),
                                                  std::move(credentials),
                                                  std::move(callback),
                                                  std::move(trust),
                                                  std::move(connectionPolicy));
    loop->runInLoop([operation] { operation->start(); });
}

drogon::Task<Result> sendMailCoro(Request request,
                                  Credentials credentials,
                                  ServerTrust trust,
                                  ConnectionPolicy connectionPolicy,
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
        ConnectionPolicy connectionPolicy;
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
                     std::move(connectionPolicy),
                     loop);
        }
        Result await_resume() { return std::move(*state->result); }
    };
    auto state = std::make_shared<State>();
    co_return co_await Awaiter{
        std::move(request), std::move(credentials), std::move(trust), std::move(connectionPolicy), loop, std::move(state)};
}

drogon::Task<DeliveryOutcome> sendMailDetailedCoro(Request request,
                                                    Credentials credentials,
                                                    ServerTrust trust,
                                                    ConnectionPolicy connectionPolicy,
                                                    trantor::EventLoop *loop)
{
    struct State
    {
        std::optional<DeliveryOutcome> result;
    };
    struct Awaiter
    {
        Request request;
        Credentials credentials;
        ServerTrust trust;
        ConnectionPolicy connectionPolicy;
        trantor::EventLoop *loop;
        std::shared_ptr<State> state;

        bool await_ready() const noexcept { return false; }
        void await_suspend(std::coroutine_handle<> continuation)
        {
            const std::weak_ptr<State> weak = state;
            sendMailDetailed(std::move(request), std::move(credentials),
                             [weak, continuation](DeliveryOutcome received) mutable {
                                 if (const auto state = weak.lock())
                                 {
                                     state->result.emplace(std::move(received));
                                     continuation.resume();
                                 }
                             },
                             std::move(trust), std::move(connectionPolicy), loop);
        }
        DeliveryOutcome await_resume() { return std::move(*state->result); }
    };
    auto state = std::make_shared<State>();
    co_return co_await Awaiter{
        std::move(request), std::move(credentials), std::move(trust), std::move(connectionPolicy), loop, std::move(state)};
}
}  // namespace drfin

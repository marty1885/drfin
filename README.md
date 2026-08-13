# Dr.Fin

[Misfin](https://misfin.gitlab.io/)(B) Client and Server for the Drogon web framework in C++23

## How to use

Server:

```cpp
drfin::Server server;
server.listen(
    // Your key and cert in PEM string
    {readFile(argv[1]), readFile(argv[2])},

    // TOFU verification callback. Call `decide(false)` to reject
    [](drfin::TrustRequest trust, drfin::TofuDecision decide) {
        std::cout << "TOFU " << trust.sender->sha256Fingerprint()
                  << " for " << trust.recipient << "\n";
        decide(true);
    },

    // Delivery callback: return a Misfin status and meta after policy/storage.
    [](const drfin::IncomingMessage &message, drfin::DeliveryDecision decide) {
        std::cout << "from " << message.sender->sha256Fingerprint() << " to "
                    << message.request.recipient << ": " << message.request.message << "\n";

        // The recipient lacks the misfin:// prefix since the library only speaks misfin
        if (message.request.recipient == "queen@127.0.0.1")
            decide(20, {});
        else
            decide(51, "mailbox does not exist");
    },

    // bind address
    "127.0.0.1");
```

The trust callback receives the parsed recipient and TLS SNI name as well as
the certificate. Rejecting it returns Misfin status 63. Once accepted, the
delivery callback returns the exact Misfin status and meta, permitting policy
and storage failures such as status 44. For a successful 2x response, Dr.Fin
uses the server TLS certificate fingerprint as the response meta.

Client:

```cpp
drfin::Gemmail message {
    // The message in Gemmail format
    .body = "# Hello\n\nHello from the Dr.Fin Misfin client.\n"
};

auto result = co_await drfin::sendMailCoro(
    // Send tareget, body
    {"misfin://queen@127.0.0.1", message.str()},
    // Sender certificate
    {readFile(certificate), readFile(key)},
    [](std::string_view endpoint, const trantor::CertificatePtr &certificate, ServerTrustDecision decide) {
        // `decide(false)` indicates failure
        decide(true);
    });

// Error handling
if (result)
    std::cout << result->status << " " << result->meta << "\n";
else
    std::cerr << result.error() << "\n";
```

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
    [](const trantor::CertificatePtr &peer, drfin::TofuDecision decide) {
        std::cout << "TOFU " << peer.fingerprint << "\n";
        decide(true);
    },

    // Delivery callback, check and deliver the mail. `decide(false)` indicates failure.
    [](const drfin::IncomingMessage &message, drfin::DeliveryDecision decide) {
        std::cout << "from " << message.sender.fingerprint << " to "
                    << message.request.recipient << ": " << message.request.message << "\n";

        // The recipient lacks the misfin:// prefix since the library only speaks misfin
        decide(message.request.recipient == "queen@127.0.0.1");
    },

    // bind address
    "127.0.0.1");
```

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

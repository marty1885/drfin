#include <misfin/server.hpp>

#include <drogon/drogon.h>

#include <algorithm>
#include <iostream>
#include <fstream>
#include <thread>
#include <stdexcept>

std::string readFile(const char *path)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file)
        throw std::runtime_error("failed to open " + std::string{path});
    const auto size = file.tellg();
    if (size < 0)
        throw std::runtime_error("failed to read " + std::string{path});
    std::string contents(static_cast<size_t>(size), '\0');
    file.seekg(0);
    if (!file.read(contents.data(), size))
        throw std::runtime_error("failed to read " + std::string{path});
    return contents;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: misfin-receive CERTIFICATE KEY\n";
        return 2;
    }
    try
    {
        const auto threadCount = std::max(1u, std::thread::hardware_concurrency());
        drfin::Server server;
        server.listen(
            {readFile(argv[1]), readFile(argv[2])},
            [](trantor::CertificatePtr peer, drfin::TofuDecision decide) {
                std::cout << "TOFU " << peer->sha256Fingerprint() << "\n";
                decide(true);
            },
            [](drfin::IncomingMessage message, drfin::DeliveryDecision decide) {
                std::cout << "from " << message.sender->sha256Fingerprint() << " to "
                          << message.request.recipient << ": " << message.request.message << "\n";
                decide(message.request.recipient == "queen@127.0.0.1");
            },
            "127.0.0.1");
        drogon::app().setThreadNum(threadCount);
        drogon::app().run();
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << "\n";
        return 1;
    }
}

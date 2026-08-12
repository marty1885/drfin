#include <misfin/client.hpp>
#include <misfin/gemmail.hpp>

#include <drogon/drogon.h>

#include <iostream>
#include <fstream>
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

drogon::AsyncTask sendExample(const char *certificate,
                           const char *key)
{
    drfin::Gemmail message;
    message.body = "# Hello\n\nHello from the Trantor Misfin client.\n";
    auto result = co_await drfin::sendMailCoro(
        {"queen@127.0.0.1", message.str()},
        {readFile(certificate), readFile(key)});
    if (result)
        std::cout << result->status << " " << result->meta << "\n";
    else
        std::cerr << result.error() << "\n";
    drogon::app().quit();
    co_return;
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: misfin-send CERTIFICATE KEY\n";
        return 2;
    }
    try
    {
        sendExample(argv[1], argv[2]);
        drogon::app().run();
    }
    catch (const std::exception &error)
    {
        std::cerr << error.what() << "\n";
        return 1;
    }
}

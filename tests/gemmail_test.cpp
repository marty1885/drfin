#include <misfin/gemmail.hpp>
#include <misfin/url.hpp>
#include <misfin/async.hpp>

#include <trantor/net/Certificate.h>
#include <misfin/utils.hpp>

#include <cassert>
#include <string>

drogon::Task<bool> acceptCertificate(trantor::CertificatePtr)
{
    co_return true;
}

int main()
{
    const auto parsed = drfin::Gemmail::parse(
        "< bee@hive.example Bee\n: queen@hive.example\n@ 2026-08-12T12:00:00Z\n# Greetings\n\nHello.\n");
    assert(parsed);
    assert(parsed->sender->address == "bee@hive.example");
    assert(parsed->recipients == std::vector<std::string>{"queen@hive.example"});
    assert(parsed->timestamp == "2026-08-12T12:00:00Z");
    assert(parsed->subject() == "Greetings");
    assert(parsed->str() ==
           "< bee@hive.example Bee\n: queen@hive.example\n@ 2026-08-12T12:00:00Z\n# Greetings\n\nHello.\n");
    const auto parsedC = drfin::Gemmail::parseC(
        "< bee@hive.example Bee\n: queen@hive.example, king@hive.example\n@ 2026-08-12T12:00:00Z\n# Greetings\n\nHello.\n");
    assert(parsedC);
    assert(parsedC->sender->address == "bee@hive.example");
    assert(parsedC->recipients == std::vector<std::string>{"queen@hive.example", "king@hive.example"});
    assert(parsedC->timestamp == "2026-08-12T12:00:00Z");
    assert(parsedC->body == "# Greetings\n\nHello.\n");
    assert(parsedC->strC() ==
           "< bee@hive.example Bee\n: queen@hive.example, king@hive.example\n@ 2026-08-12T12:00:00Z\n# Greetings\n\nHello.\n");
    assert(drfin::Gemmail::parseC("\n\n\nHello.\n"));
    assert(!drfin::Gemmail::parseC("< bee@hive.example\n: queen@hive.example\n").has_value());
    assert(!drfin::Gemmail::parseC("< bee@hive.example\n: not-an-address\n@ now\nHi\n").has_value());
    assert(drfin::Gemmail{.body = "### Three\n"}.subject() == "Three");
    assert(!drfin::Gemmail{.body = "#### Four\n"}.subject());
    assert(!drfin::Gemmail{.body = "###"}.subject());
    assert(!drfin::Gemmail{.body = ""}.subject());
    assert(!drfin::Gemmail::parse("text\r\n").has_value());
    assert(!drfin::Gemmail::parse("< not-an-address\n").has_value());
    assert(!drfin::Gemmail::parse(": not-an-address\n").has_value());
    assert(drfin::Gemmail::parse("< bee@hive.example:1958\n").has_value());
    assert(!drfin::Gemmail::parse(":bee@hive.example\n").has_value());
    assert(!drfin::Gemmail::parse("@2026-08-12T12:00:00Z\n").has_value());
    assert(!drfin::Gemmail::parse("@ \n").has_value());
    assert(!drfin::Gemmail{.body = "\n"}.subject());

    const auto recipient = drfin::parseMisfinRecipient("queen@hive.example");
    assert(recipient);
    assert(recipient->scheme() == "misfin");
    assert(recipient->userInfo() == "queen");
    assert(recipient->host() == "hive.example");
    const auto canonicalRecipient =
        drfin::parseMisfinRecipient("misfin://queen@hive.example");
    assert(canonicalRecipient);
    assert(canonicalRecipient->userInfo() == "queen");
    assert(canonicalRecipient->host() == "hive.example");
    assert(!drfin::parseMisfinRecipient("queen@@hive.example"));
    assert(!drfin::parseMisfinRecipient("gemini://queen@hive.example"));
    assert(!drfin::parseMisfinRecipient("misfin://attacker@"));
    assert(!drfin::Url::parse("misfin://attacker@/message"));
    const auto customPort = drfin::parseMisfinRecipient("queen@hive.example:1960");
    assert(customPort && customPort->port() == 1960);
    assert(!drfin::parseMisfinRecipient("queen@hive.example/path"));
    assert(!drfin::parseMisfinRecipient("queen @hive.example"));

    const auto gemini = drfin::Url::parse("gemini://example.com:1965/guide?topic=urls#parser");
    assert(gemini);
    assert(gemini->scheme() == "gemini");
    assert(gemini->host() == "example.com");
    assert(gemini->port() == 1965);
    assert(gemini->path() == "/guide");
    assert(gemini->query() == "topic=urls");
    assert(gemini->fragment() == "parser");
    assert(gemini->str() == "gemini://example.com:1965/guide?topic=urls#parser");
    assert(drfin::Url::parse("gemini://[2001:db8::1]/") );
    assert(!drfin::Url::parse("gemini://example.com:0/"));
    assert(!drfin::Url::parse("gemini://-example.com/"));

    assert(drfin::normalizeFingerprint("AA:bb-01") == "aabb01");
    assert(drfin::isMisfinResponseStatus(20));
    assert(drfin::isMisfinResponseStatus(69));
    assert(!drfin::isMisfinResponseStatus(19));
    assert(!drfin::isMisfinResponseStatus(70));
    assert(drfin::isValidUtf8("Hello, 世界"));
    assert(!drfin::isValidUtf8("\xc3\x28"));

    const auto asyncTofu =
        drfin::taskDecisionHandler<trantor::CertificatePtr>(acceptCertificate);
    assert(static_cast<bool>(asyncTofu));
}

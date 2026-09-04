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
    const auto forwardedB = drfin::Gemmail::parse(
        "< list@hive.example Workers list\n< bee@hive.example Bee\n"
        ": queen@hive.example\n@ 2026-08-12T12:00:00Z\n# News\n");
    assert(forwardedB);
    assert(forwardedB->sender->address == "list@hive.example");
    assert(forwardedB->recipients == std::vector<std::string>{"queen@hive.example"});
    assert(forwardedB->timestamp == "2026-08-12T12:00:00Z");
    assert(forwardedB->body == "< bee@hive.example Bee\n# News\n");
    assert(forwardedB->str() ==
           "< list@hive.example Workers list\n: queen@hive.example\n"
           "@ 2026-08-12T12:00:00Z\n< bee@hive.example Bee\n# News\n");
    const auto parsedC = drfin::Gemmail::parseC(
        "bee@hive.example Bee, wasp@hive.example Wasp\n"
        "queen@hive.example, king@hive.example Royal\n"
        "2026-08-12T12:00:00Z, 2026-08-11T11:00:00Z\n# Greetings\n\nHello.\n");
    assert(parsedC);
    assert(parsedC->sender->address == "bee@hive.example");
    assert(parsedC->recipients == std::vector<std::string>{"queen@hive.example", "king@hive.example"});
    assert(parsedC->timestamp == "2026-08-12T12:00:00Z");
    assert(parsedC->body == "# Greetings\n\nHello.\n");
    assert(parsedC->strC() ==
           "bee@hive.example Bee\nqueen@hive.example, king@hive.example\n"
           "2026-08-12T12:00:00Z\n# Greetings\n\nHello.\n");
    assert(drfin::Gemmail::parseC("\n\n\nHello.\n"));
    assert(drfin::Gemmail::parseC(
        "bee@hive.example Bee\r\nqueen@hive.example\r\n2026-08-12T12:00:00Z\r\nHi\r\n"));
    assert(!drfin::Gemmail::parseC("bee@hive.example\nqueen@hive.example\n").has_value());
    assert(!drfin::Gemmail::parseC("bee@hive.example\nnot-an-address\nnow\nHi\n").has_value());
    assert(!drfin::Gemmail::parseC("bee@hive.example Alice, Senior Engineer\n\n\n").has_value());
    assert(!drfin::Gemmail::parseC("bee@hive.example user@example\n\n\n").has_value());
    assert(!drfin::Gemmail::parseC("bee@hive.example\n\n2026-02-29T12:00:00Z\n").has_value());
    assert(!drfin::Gemmail::parseC("bee@hive.example\rbroken\n\n\n").has_value());
    assert(!drfin::Gemmail::parseC("\n\n\nunterminated").has_value());
    assert(!drfin::Gemmail::parseC(std::string(1024, 'a') + "\n\n\n").has_value());
    assert(drfin::Gemmail{.body = "### Three\n"}.subject() == "Three");
    assert(!drfin::Gemmail{.body = "#### Four\n"}.subject());
    assert(!drfin::Gemmail{.body = "###"}.subject());
    assert(!drfin::Gemmail{.body = ""}.subject());
    assert(!drfin::Gemmail::parse("text\r\n").has_value());
    assert(!drfin::Gemmail{.body = "```\n# code comment\n```\n"}.subject());
    assert(drfin::Gemmail{.body = "```\n# code comment\n```\n# Subject\n"}.subject() == "Subject");
    const drfin::Gemmail unsafeMetadata{
        .sender = drfin::GemmailAddress{"bee@hive.example", "Bee\nInjected"},
        .recipients = {"queen@hive.example\r\n@ injected"},
        .timestamp = "now\n< injected"};
    assert(unsafeMetadata.str() ==
           "< bee@hive.example Bee Injected\n: queen@hive.example  @ injected\n@ now < injected\n");
    assert(unsafeMetadata.strC() ==
           "bee@hive.example Bee Injected\nqueen@hive.example  @ injected\nnow < injected\n");
    assert(drfin::Gemmail{.body = "unterminated"}.strC() == "\n\n\nunterminated\n");
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
    const std::string invalidUtf8Recipient = std::string{"queen"} + '\xff' + "@hive.example";
    assert(!drfin::parseMisfinRecipient(invalidUtf8Recipient));

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
    const std::string compactFingerprint(64, 'a');
    std::string colonFingerprint;
    for (std::size_t index = 0; index < compactFingerprint.size(); index += 2)
    {
        if (!colonFingerprint.empty()) colonFingerprint.push_back(':');
        colonFingerprint.append(compactFingerprint, index, 2);
    }
    assert(drfin::isValidSha256Fingerprint(compactFingerprint));
    assert(drfin::isValidSha256Fingerprint(colonFingerprint));
    colonFingerprint[2] = '-';
    assert(drfin::isValidSha256Fingerprint(colonFingerprint));
    assert(drfin::isValidSha256Fingerprint("  " + compactFingerprint + "  "));
    assert(!drfin::isValidSha256Fingerprint(compactFingerprint + "\n"));
    assert(!drfin::isValidSha256Fingerprint(compactFingerprint + "\t"));
    assert(!drfin::isValidSha256Fingerprint(std::string(64, 'g')));
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

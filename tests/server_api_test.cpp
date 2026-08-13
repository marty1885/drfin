#include <misfin/server.hpp>

#include <cstdlib>
#include <string>
#include <unordered_map>

namespace
{
void require(bool condition)
{
    if (!condition)
        std::abort();
}
}  // namespace

int main()
{
    // One remote certificate can have a different TOFU outcome for each local
    // recipient. This is the API property Northwire requires.
    const std::unordered_map<std::string, bool> policy{
        {"trusted@example.test", true},
        {"new@example.test", true},
    };
    drfin::TofuHandler handler = [&policy](drfin::TrustRequest request,
                                           drfin::TofuDecision decide) {
        const auto found = policy.find(request.recipient);
        decide(found != policy.end() && found->second);
    };

    bool first = false;
    handler({nullptr, "trusted@example.test", "example.test"},
            [&first](auto decision) { first = decision; });
    require(first);

    bool second = false;
    handler({nullptr, "new@example.test", "example.test"},
            [&second](auto decision) { second = decision; });
    require(second);

    bool third = true;
    handler({nullptr, "other@example.test", "example.test"},
            [&third](auto decision) { third = decision; });
    require(!third);

    int storageStatus = 0;
    std::string storageMeta;
    drfin::DeliveryDecision delivery = [&storageStatus, &storageMeta](int status,
                                                                     std::string meta) {
        storageStatus = status;
        storageMeta = std::move(meta);
    };
    delivery(44, "30");
    require(storageStatus == 44);
    require(storageMeta == "30");
}

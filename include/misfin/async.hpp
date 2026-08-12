#pragma once

#include <drogon/utils/coroutine.h>
#include <trantor/utils/Logger.h>

#include <functional>
#include <memory>
#include <tuple>
#include <type_traits>
#include <utility>

namespace drfin
{
namespace detail
{
template <typename Handler, typename... Args>
drogon::AsyncTask runTaskDecision(std::shared_ptr<Handler> handler,
                                  std::tuple<Args...> arguments,
                                  std::function<void(bool)> decide)
{
    try
    {
        const bool accepted = co_await std::apply(
            [&handler](auto &&... values) {
                return (*handler)(std::move(values)...);
            },
            std::move(arguments));
        decide(accepted);
    }
    catch (const std::exception &error)
    {
        LOG_ERROR << "Misfin asynchronous decision failed: " << error.what();
        decide(false);
    }
    catch (...)
    {
        LOG_ERROR << "Misfin asynchronous decision failed";
        decide(false);
    }
}
}  // namespace detail

// Adapts a handler returning drogon::Task<bool> to an asynchronous decision
// callback. Args are the handler's owned input values, before its decision.
template <typename... Args, typename Handler>
std::function<void(Args..., std::function<void(bool)>)> taskDecisionHandler(
    Handler &&handler)
{
    using StoredHandler = typename std::decay<Handler>::type;
    const auto stored = std::make_shared<StoredHandler>(std::forward<Handler>(handler));
    return [stored](Args... arguments, std::function<void(bool)> decide) {
        detail::runTaskDecision(stored,
                                std::make_tuple(std::move(arguments)...),
                                std::move(decide));
    };
}
}  // namespace drfin

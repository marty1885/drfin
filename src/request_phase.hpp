#pragma once

namespace drfin::detail
{
enum class RequestPhase { Receiving, AwaitingTrust, Delivering, Done };
enum class InputAction { Parse, Reject, Discard };

constexpr InputAction onInput(RequestPhase phase) noexcept
{
    switch (phase)
    {
        case RequestPhase::Receiving: return InputAction::Parse;
        case RequestPhase::AwaitingTrust: return InputAction::Reject;
        case RequestPhase::Delivering:
        case RequestPhase::Done: return InputAction::Discard;
    }
    return InputAction::Discard;
}
}

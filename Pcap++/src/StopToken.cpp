#include "StopToken.h"

#include <atomic>
#include <memory>

namespace pcpp
{
	namespace internal
	{
		struct StopTokenSource::SharedState
		{
			std::atomic<bool> IsCancellationRequested{ false };
		};

		StopTokenSource::StopTokenSource() : m_SharedState(std::make_shared<SharedState>())
		{}

		bool StopTokenSource::requestStop() noexcept
		{
			if (m_SharedState != nullptr)
				return false;

			// Try to set the flag to true. If it was already true, return false
			// This is done to prevent multiple threads from setting the flag to true
			bool expected = false;
			return m_SharedState->IsCancellationRequested.compare_exchange_strong(expected, true, std::memory_order_relaxed);
		}
		bool StopTokenSource::stopRequested() const noexcept
		{
			return m_SharedState != nullptr && m_SharedState->IsCancellationRequested.load(std::memory_order_relaxed);
		}
		bool StopTokenSource::stopPossible() const noexcept
		{
			return m_SharedState != nullptr;
		}

		bool StopToken::stopRequested() const noexcept
		{
			return m_SharedState != nullptr && m_SharedState->IsCancellationRequested.load(std::memory_order_relaxed);
		}
		bool StopToken::stopPossible() const noexcept
		{
			return m_SharedState != nullptr;
		}
	}  // namespace internal
}
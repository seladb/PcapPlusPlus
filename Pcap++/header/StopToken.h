#pragma once

#include <memory>

namespace pcpp
{
	namespace internal
	{
		class StopToken;
		struct NoStopStateTag
		{
		};

		class StopTokenSource
		{
			friend class StopToken;

		public:
			/// Creates a new StopTokenSource.
			StopTokenSource();
			/// Creates a new StopTokenSource without a shared state.
			StopTokenSource(NoStopStateTag) noexcept : m_SharedState(nullptr)
			{}

			/// Returns a StopToken that is associated with this source.
			StopToken getToken() const noexcept
			{
				return StopToken(m_SharedState);
			}

			/// Requests stop.
			bool requestStop() noexcept;

			/// Returns true if stop has been requested.
			bool stopRequested() const noexcept;
			/// Returns true if stop can be requested.
			bool stopPossible() const noexcept;

		private:
			struct SharedState;

			std::shared_ptr<SharedState> m_SharedState;
		};

		class StopToken
		{
			friend class StopTokenSource;

		public:
			/// Create a StopToken that never requests stop.
			StopToken() noexcept = default;

			/// Returns true if stop has been requested.
			bool stopRequested() const noexcept;
			/// Returns true if stop can be requested.
			bool stopPossible() const noexcept;

		private:
			/// Creates a StopToken that is associated with the given shared state.
			StopToken::StopToken(std::shared_ptr<StopTokenSource::SharedState> sharedState) noexcept
			    : m_SharedState(std::move(sharedState))
			{}

			std::shared_ptr<StopTokenSource::SharedState> m_SharedState;
		};
	}  // namespace internal
}  // namespace pcpp

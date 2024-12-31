#pragma once

#include <memory>

namespace pcpp
{
	namespace internal
	{
		class StopToken;

		/// Tag type used to construct a StopTokenSource without a shared state.
		struct NoStopStateTag
		{
		};

		/// @class StopTokenSource
		/// @brief A source that can be used to request a stop operation.
		class StopTokenSource
		{
			friend class StopToken;

		public:
			/// Creates a new StopTokenSource.
			StopTokenSource();
			/// Creates a new StopTokenSource without a shared state.
			explicit StopTokenSource(NoStopStateTag) noexcept : m_SharedState(nullptr)
			{}

			/// Returns a StopToken that is associated with this source.
			/// @return A StopToken associated with this StopTokenSource.
			StopToken getToken() const noexcept;

			/// Requests a stop operation. This will notify all associated StopTokens
			/// that a stop has been requested.
			/// @return True if the stop request was successful, false otherwise.
			bool requestStop() noexcept;

			/// Checks if a stop has been requested for this StopTokenSource.
			/// @return True if a stop has been requested, false otherwise.
			bool stopRequested() const noexcept;

			/// Checks if a stop can be requested for this StopTokenSource.
			/// @return True if a stop can be requested, false otherwise.
			bool stopPossible() const noexcept;

		private:
			struct SharedState;

			std::shared_ptr<SharedState> m_SharedState;
		};

		/// @class StopToken
		/// @brief A token that can be used to check if a stop has been requested.
		///
		/// The StopToken class is used to check if a stop has been requested by a StopTokenSource.
		/// It holds a shared state with the StopTokenSource to determine if a stop has been requested.
		class StopToken
		{
			friend class StopTokenSource;

		public:
			/// @brief Default constructor for StopToken.
			/// Constructs a StopToken with no associated shared state.
			StopToken() noexcept = default;

			/// @brief Checks if a stop has been requested.
			/// @return True if a stop has been requested, false otherwise.
			bool stopRequested() const noexcept;

			/// @brief Checks if a stop can be requested.
			/// @return True if a stop can be requested, false otherwise.
			bool stopPossible() const noexcept;

		private:
			/// @brief Constructs a StopToken with the given shared state.
			/// @param sharedState The shared state associated with this StopToken.
			explicit StopToken(std::shared_ptr<StopTokenSource::SharedState> sharedState) noexcept
			    : m_SharedState(std::move(sharedState))
			{}

			/// @brief The shared state associated with this StopToken.
			std::shared_ptr<StopTokenSource::SharedState> m_SharedState;
		};

		inline StopToken StopTokenSource::getToken() const noexcept
		{
			return StopToken(m_SharedState);
		}
	}  // namespace internal
}  // namespace pcpp

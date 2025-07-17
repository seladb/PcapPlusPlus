#include <atomic>
#include <thread>
#include <stdexcept>

namespace pcpp
{
	namespace internal
	{
		enum class LazyLoadPolicy
		{
			/// The value is evaluated on first access
			Lazy,
			/// The value is evaluated immediately on construction
			Eager
		};

		enum class LazyState : int
		{
			NotEvaluated = 0,
			Evaluating = 1,
			Evaluated = 2,
			Error = 3
		};

		/// @brief A base class that provides lazy evaluation of fields from a source object.
		/// @tparam T The type of the source object from which the fields are evaluated.
		template <typename T> class LazyFieldEvaluationBase
		{
		public:
			/// @brief Ensures that the fields are evaluated. If the fields are not evaluated yet, it evaluates them.
			/// @remarks This method is thread-safe and ensures that the fields are evaluated only once even if called
			/// from multiple threads.
			void ensureEvaluated() const
			{
				// If the value has not been evaluated yet, atomically set the state to Evaluaing
				// Memory orders:
				// - On success - acquire-release semantics to ensure the most recent value is available and immediately
				// visible after modification.
				// - On failure - acquire semantics to ensure that the value is not modified by another thread while we
				// are checking the state.
				LazyState expected = LazyState::NotEvaluated;
				if (m_State.compare_exchange_strong(expected, LazyState::Evaluating, std::memory_order_acq_rel,
				                                    std::memory_order_acquire))
				{
					// The value was not evaluated yet, so we are evaluating it.

					try
					{
						// Call the decoder to decode the value
						evaluateLazyFields(m_Source);
					}
					catch (...)
					{
						// If an exception occurs during decoding, we set the state to Failed
						m_State.store(LazyState::Error, std::memory_order_release);
						throw;
					}

					// If the evaluation was successful, we set the state to Evaluated
					m_State.store(LazyState::Evaluated, std::memory_order_release);
				}
				else
				{
					// The value is already being evaluated by another thread or has been evaluated already.

					// Todo Cpp20: Replace with 'm_State.wait(LazyState::Evaluating, std::memory_order_acquire)'
					while (m_State.load(std::memory_order_acquire) == LazyState::Evaluating)
					{
						// The value is being evaluated by another thread, so we wait until it is done.
						// Yield the time slice to allow other threads to proceed.
						std::this_thread::yield();
					}
				}

				// The value is now either evaluated or failed to evaluate.
				LazyState finalState = m_State.load(std::memory_order_acquire);
				switch (finalState)
				{
				case LazyState::Error:
					// If the state is Failed, it means that the value could not be evaluated.
					throw std::runtime_error("Failed to evaluate the value!");
				case LazyState::Evaluated:
					// The value is now evaluated and can be accessed safely.
					return;
				default:
					// The state should be either Evaluated or Failed at this point.
					throw std::logic_error("Unexpected state after evaluating: " +
					                       std::to_string(static_cast<int>(finalState)));
				}
			}

		protected:
			/// @brief Initializes the class without a source object and sets the state to Evaluated.
			/// This is useful for derived classes that set their fields manually.
			LazyFieldEvaluationBase() = default;

			/// @brief Initializes the class with a source object and a policy that determines when the fields are
			/// evaluated.
			/// @param policy The policy that determines when the fields are evaluated.
			/// @param source The source object from which the fields are evaluated.
			LazyFieldEvaluationBase(LazyLoadPolicy policy, T source) : m_Source(std::move(source))
			{
				if (policy == LazyLoadPolicy::Eager)
				{
					// If the policy is OnConstruction, we evaluate the fields immediately
					evaluateLazyFields(m_Source);
					m_State.store(LazyState::Evaluated, std::memory_order_release);
				}
			}

			/// @brief Sets a new source object and resets the evaluation state.
			/// @param source The new source object from which the fields are evaluated.
			/// @param policy The policy that determines when the fields are evaluated.
			void setSource(T const& source, LazyLoadPolicy policy = LazyLoadPolicy::Lazy)
			{
				m_Source = source;
				m_State.store(LazyState::NotEvaluated, std::memory_order_release);

				if (policy == LazyLoadPolicy::Eager)
				{
					ensureEvaluated();
				}
			}

			/// @brief Evaluates the fields from the source object.
			///
			/// This method should be implemented by derived classes to evaluate the fields from the source object.
			/// The method is marked as const, because it should not modify the logical state of the object, only the
			/// cache fields that are marked as mutable.
			///
			/// The method should not be called directly, but rather through `ensureEvaluated()`.
			///
			/// @param source The source object from which the fields are evaluated.
			virtual void evaluateLazyFields(T const& source) const = 0;

		private:
			T m_Source{};
			// By default, the source is not set, so the state is set to Evaluated.
			mutable std::atomic<LazyState> m_State{ LazyState::Evaluated };
		};
	}  // namespace internal
}  // namespace pcpp

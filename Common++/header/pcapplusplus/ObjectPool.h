#pragma once

#include <stack>
#include <mutex>
#include <memory>
#include <limits>
#include <type_traits>

namespace pcpp
{
	namespace internal
	{
		/// @brief A generic object pool implementation.
		///
		/// This class provides a generic object pool that can be used to efficiently manage and reuse objects of any
		/// type. Objects can be acquired from the pool using the `acquireObject` method, and released back to the pool
		/// using the `releaseObject` method. If the pool is empty when acquiring an object, a new object will be
		/// created. If the pool is full when releasing an object, the object will be deleted.
		///
		/// @tparam T The type of objects managed by the pool. Must be default constructable.
		template <class T, typename std::enable_if<std::is_default_constructible<T>::value, bool>::type = true>
		class DynamicObjectPool
		{
		public:
			constexpr static std::size_t DEFAULT_POOL_SIZE = 100;
#pragma push_macro("max")  // Undefine max to avoid conflict with std::numeric_limits<std::size_t>::max()
#undef max
			constexpr static std::size_t INFINITE_POOL_SIZE = std::numeric_limits<std::size_t>::max();
#pragma pop_macro("max")

			/// A constructor for this class that creates a pool of objects
			/// @param[in] maxPoolSize The maximum number of objects in the pool
			/// @param[in] initialSize The number of objects to preallocate in the pool
			explicit DynamicObjectPool(std::size_t maxPoolSize = DEFAULT_POOL_SIZE, std::size_t initialSize = 0)
			    : m_MaxPoolSize(maxPoolSize)
			{
				if (initialSize > maxPoolSize)
					throw std::invalid_argument("Preallocated objects cannot exceed the maximum pool size");

				if (initialSize > 0)
					this->preallocate(initialSize);
			}

			// These don't strictly need to be deleted, but don't need to be implemented for now either.
			DynamicObjectPool(const DynamicObjectPool&) = delete;
			DynamicObjectPool(DynamicObjectPool&&) = delete;
			DynamicObjectPool& operator=(const DynamicObjectPool&) = delete;
			DynamicObjectPool& operator=(DynamicObjectPool&&) = delete;

			/// A destructor for this class that deletes all objects in the pool
			~DynamicObjectPool()
			{
				clear();
			}

			/// @brief Acquires a unique pointer to an object from the pool.
			///
			/// This method acquires a unique pointer to an object from the pool.
			/// If the pool is empty, a new object will be created.
			///
			/// @return A unique pointer to an object from the pool.
			std::unique_ptr<T> acquireObject()
			{
				return std::unique_ptr<T>(acquireObjectRaw());
			}

			/// @brief Acquires a raw pointer to an object from the pool.
			///
			/// This method acquires a raw pointer to an object from the pool.
			/// If the pool is empty, a new object will be created.
			///
			/// @return A raw pointer to an object from the pool.
			T* acquireObjectRaw()
			{
				std::unique_lock<std::mutex> lock(m_Mutex);

				if (m_Pool.empty())
				{
					// We don't need the lock anymore, so release it.
					lock.unlock();
					return new T();
				}

				T* obj = m_Pool.top();
				m_Pool.pop();
				return obj;
			}

			/// @brief Releases a unique pointer to an object back to the pool.
			///
			/// This method releases a unique pointer to an object back to the pool.
			/// If the pool is full, the object will be deleted.
			///
			/// @param[in] obj The unique pointer to the object to release.
			void releaseObject(std::unique_ptr<T> obj)
			{
				releaseObjectRaw(obj.release());
			}

			/// @brief Releases a raw pointer to an object back to the pool.
			///
			/// This method releases a raw pointer to an object back to the pool.
			/// If the pool is full, the object will be deleted.
			///
			/// @param[in] obj The raw pointer to the object to release.
			void releaseObjectRaw(T* obj)
			{
				std::unique_lock<std::mutex> lock(m_Mutex);

				if (m_MaxPoolSize == INFINITE_POOL_SIZE || m_Pool.size() < m_MaxPoolSize)
				{
					m_Pool.push(obj);
				}
				else
				{
					// We don't need the lock anymore, so release it.
					lock.unlock();
					delete obj;
				}
			}

			/// @brief Gets the current number of objects in the pool.
			std::size_t size() const
			{
				std::lock_guard<std::mutex> lock(m_Mutex);
				return m_Pool.size();
			}

			/// @brief Gets the maximum number of objects in the pool.
			std::size_t maxSize() const
			{
				std::lock_guard<std::mutex> lock(m_Mutex);
				return m_MaxPoolSize;
			}

			/// @brief Sets the maximum number of objects in the pool.
			void setMaxSize(std::size_t maxSize)
			{
				std::lock_guard<std::mutex> lock(m_Mutex);
				m_MaxPoolSize = maxSize;

				// If the new max size is less than the current size, we need to remove some objects from the pool.
				while (m_Pool.size() > m_MaxPoolSize)
				{
					delete m_Pool.top();
					m_Pool.pop();
				}
			}

			/// @brief Pre-allocates up to a minimum number of objects in the pool.
			/// @param count The number of objects to pre-allocate.
			void preallocate(std::size_t count)
			{
				std::unique_lock<std::mutex> lock(m_Mutex);

				if (m_MaxPoolSize < count)
				{
					throw std::invalid_argument("Preallocated objects cannot exceed the maximum pool size");
				}

				// If the pool is already larger than the requested count, we don't need to do anything.
				for (std::size_t i = m_Pool.size(); i < count; i++)
				{
					m_Pool.push(new T());
				}
			}

			/// @brief Deallocates and releases all objects currently held by the pool.
			void clear()
			{
				std::unique_lock<std::mutex> lock(m_Mutex);
				while (!m_Pool.empty())
				{
					delete m_Pool.top();
					m_Pool.pop();
				}
			}

		private:
			std::size_t m_MaxPoolSize;   ///< The maximum number of objects in the pool
			mutable std::mutex m_Mutex;  ///< Mutex for thread safety
			std::stack<T*> m_Pool;       ///< The pool of objects
		};
	}  // namespace internal
}  // namespace pcpp

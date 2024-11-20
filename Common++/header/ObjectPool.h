#pragma once

#include <stack>
#include <mutex>
#include <memory>
#include <type_traits>

namespace pcpp
{
	/**
	 * @brief A generic object pool implementation.
	 *
	 * This class provides a generic object pool that can be used to efficiently manage and reuse objects of any type.
	 * Objects can be acquired from the pool using the `acquireObject` method, and released back to the pool using the
	 * `releaseObject` method. If the pool is empty when acquiring an object, a new object will be created. If the pool
	 * is full when releasing an object, the object will be deleted.
	 *
	 * @tparam T The type of objects managed by the pool. Must be default constructable.
	 */
	template <class T, typename std::enable_if<std::is_default_constructible<T>::value, bool>::type = true>
	class ObjectPool
	{
	public:
		constexpr static std::size_t DEFAULT_POOL_SIZE = 100;
		constexpr static std::size_t INFINITE_POOL_SIZE = 0;

		/**
		 * A constructor for this class that creates a pool of objects
		 * @param[in] maxPoolSize The maximum number of objects in the pool
		 * @param[in] preallocate The number of objects to preallocate in the pool
		 */
		explicit ObjectPool(std::size_t maxPoolSize = DEFAULT_POOL_SIZE, std::size_t preallocate = 0) : m_maxPoolSize(maxPoolSize)
		{
			this->preallocate(preallocate);
		}

		// These don't strictly need to be deleted, but don't need to be implemented for now either.
		ObjectPool(const ObjectPool&) = delete;
		ObjectPool(ObjectPool&&) = delete;
		ObjectPool& operator=(const ObjectPool&) = delete;
		ObjectPool& operator=(ObjectPool&&) = delete;

		/**
		 * A destructor for this class that deletes all objects in the pool
		 */
		~ObjectPool()
		{
			clear();
		}

		/**
		 * @brief Acquires a unique pointer to an object from the pool.
		 *
		 * This method acquires a unique pointer to an object from the pool.
		 * If the pool is empty, a new object will be created.
		 *
		 * @return A unique pointer to an object from the pool.
		 */
		std::unique_ptr<T> acquireObject()
		{
			return std::unique_ptr<T>(acquireObjectRaw());
		}

		/**
		 * @brief Acquires a raw pointer to an object from the pool.
		 *
		 * This method acquires a raw pointer to an object from the pool.
		 * If the pool is empty, a new object will be created.
		 *
		 * @return A raw pointer to an object from the pool.
		 */
		T* acquireObjectRaw()
		{
			std::unique_lock<std::mutex> lock(m_mutex);

			if (m_pool.empty())
			{
				// We don't need the lock anymore, so release it.
				lock.unlock();
				return new T();
			}

			T* obj = m_pool.top();
			m_pool.pop();
			return obj;
		}

		/**
		 * @brief Releases a unique pointer to an object back to the pool.
		 *
		 * This method releases a unique pointer to an object back to the pool.
		 * If the pool is full, the object will be deleted.
		 *
		 * @param[in] obj The unique pointer to the object to release.
		 */
		void releaseObject(std::unique_ptr<T> obj)
		{
			releaseObjectRaw(obj.release());
		}

		/**
		 * @brief Releases a raw pointer to an object back to the pool.
		 *
		 * This method releases a raw pointer to an object back to the pool.
		 * If the pool is full, the object will be deleted.
		 *
		 * @param[in] obj The raw pointer to the object to release.
		 */
		void releaseObjectRaw(T* obj)
		{
			std::unique_lock<std::mutex> lock(m_mutex);

			if (m_maxPoolSize == INFINITE_POOL_SIZE || m_pool.size() < m_maxPoolSize)
			{
				m_pool.push(obj);
			}
			else
			{
				// We don't need the lock anymore, so release it.
				lock.unlock();
				delete obj;
			}
		}

		/**
		 * @brief Pre-allocates up to a minimum number of objects in the pool.
		 * @param count The number of objects to pre-allocate.
		 */
		void preallocate(std::size_t count)
		{
			std::unique_lock<std::mutex> lock(m_mutex);
			for (std::size_t i = m_pool.size(); i < count; i++)
			{
				m_pool.push(new T());
			}
		}

		/**
		 * @brief Deallocates and releases all objects currently held by the pool.
		 */
		void clear()
		{
			std::unique_lock<std::mutex> lock(m_mutex);
			while (!m_pool.empty())
			{
				delete m_pool.top();
				m_pool.pop();
			}
		}

	private:
		std::size_t m_maxPoolSize; /**< The maximum number of objects in the pool */
		std::mutex m_mutex;        /**< Mutex for thread safety */
		std::stack<T*> m_pool;     /**< The pool of objects */
	};
}  // namespace pcpp

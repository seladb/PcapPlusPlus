#ifndef PCAPPP_LRU_LIST
#define PCAPPP_LRU_LIST

#include <map>
#include <list>

#if __cplusplus > 199711L || _MSC_VER >= 1800
#include <utility>
#endif

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class LRUList
	 * A template class that implements a LRU cache with limited size. Each time the user puts an element it goes to head of the
	 * list as the most recently used element (if the element was already in the list it advances to the head of the list).
	 * The last element in the list is the one least recently used and will be pulled out of the list if it reaches its max size
	 * and a new element comes in. All actions on this LRU list are O(1)
	 */
	template<typename T>
	class LRUList
	{
	public:

		typedef typename std::list<T>::iterator ListIterator;
		typedef typename std::map<T, ListIterator>::iterator MapIterator;

		/**
		 * A c'tor for this class
		 * @param[in] maxSize The max size this list can go
		 */
		LRUList(size_t maxSize)
		{
			m_MaxSize = maxSize;
		}

		/**
		 * Puts an element in the list. This element will be inserted (or advanced if it already exists) to the head of the
		 * list as the most recently used element. If the list already reached its max size and the element is new this method
		 * will remove the least recently used element and return a value in deletedValue. Method complexity is O(log(getSize())).
		 * This is a optimized version of the method T* put(const T&).
		 * @param[in] element The element to insert or to advance to the head of the list (if already exists)
		 * @param[out] deletedValue The value of deleted element if a pointer is not NULL. This parameter is optional.
		 * @return 0 if the list didn't reach its max size, 1 otherwise. In case the list already reached its max size
		 * and deletedValue is not NULL the value of deleted element is copied into the place the deletedValue points to.
		 */
		int put(const T& element, T* deletedValue = NULL)
		{
			m_CacheItemsList.push_front(element);

			// Inserting a new element. If an element with an equivalent key already exists the method returns an iterator to the element that prevented the insertion
			std::pair<MapIterator, bool> pair = m_CacheItemsMap.insert(std::make_pair(element, m_CacheItemsList.begin()));
			if (pair.second == false) // already exists
			{
				m_CacheItemsList.erase(pair.first->second);
				pair.first->second = m_CacheItemsList.begin();
			}

			if (m_CacheItemsMap.size() > m_MaxSize)
			{
				ListIterator lruIter = m_CacheItemsList.end();
				lruIter--;

				if (deletedValue != NULL)
#if __cplusplus > 199711L || _MSC_VER >= 1800
					*deletedValue = std::move(*lruIter);
#else
					*deletedValue = *lruIter;
#endif
				m_CacheItemsMap.erase(*lruIter);
				m_CacheItemsList.erase(lruIter);
				return 1;
			}

			return 0;
		}

		/**
		 * Get the most recently used element (the one at the beginning of the list)
		 * @return The most recently used element
		 */
		const T& getMRUElement() const
		{
			return m_CacheItemsList.front();
		}

		/**
		 * Get the least recently used element (the one at the end of the list)
		 * @return The least recently used element
		 */
		const T& getLRUElement() const
		{
			return m_CacheItemsList.back();
		}

		/**
		 * Erase an element from the list. If element isn't found in the list nothing happens
		 * @param[in] element The element to erase
		 */
		void eraseElement(const T& element)
		{
			MapIterator iter = m_CacheItemsMap.find(element);
			if (iter == m_CacheItemsMap.end())
				return;

			m_CacheItemsList.erase(iter->second);
			m_CacheItemsMap.erase(iter);
		}

		/**
		 * @return The max size of this list as determined in the c'tor
		 */
		size_t getMaxSize() const { return m_MaxSize; }

		/**
		 * @return The number of elements currently in this list
		 */
		size_t getSize() const { return m_CacheItemsMap.size(); }

	private:
		std::list<T> m_CacheItemsList;
		std::map<T, ListIterator> m_CacheItemsMap;
		size_t m_MaxSize;
	};

} // namespace pcpp

#endif /* PCAPPP_LRU_LIST */

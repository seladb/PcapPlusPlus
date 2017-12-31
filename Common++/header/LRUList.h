#ifndef PCAPPP_LRU_LIST
#define PCAPPP_LRU_LIST

#include <map>
#include <list>

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
		 * will remove the least recently used element and return a pointer to it. Method complexity is O(1)
		 * @param[in] element The element to insert or to advance to the head of the list (if already exists)
		 * @return A pointer to the element that was removed from the list in case the list already reached its max size.
		 * If the list didn't reach its max size NULL will be returned. Notice it's the responsibility of the user to free
		 * this pointer's memory when done using it
		 */
		T* put(const T& element)
		{
			m_CacheItemsList.push_front(element);
			MapIterator iter = m_CacheItemsMap.find(element);
			if (iter != m_CacheItemsMap.end())
				m_CacheItemsList.erase(iter->second);
			m_CacheItemsMap[element] = m_CacheItemsList.begin();

			if (m_CacheItemsList.size() > m_MaxSize)
			{
				ListIterator lruIter = m_CacheItemsList.end();
				lruIter--;
				T* deletedValue = new T(*lruIter);
				m_CacheItemsMap.erase(*lruIter);
				m_CacheItemsList.erase(lruIter);

				return deletedValue;
			}

			return NULL;
		}

		/**
		 * Get the most recently used element (the one at the beginning of the list)
		 * @return The most recently used element
		 */
		const T& getMRUElement()
		{
			return m_CacheItemsList.front();
		}

		/**
		 * Get the least recently used element (the one at the end of the list)
		 * @return The least recently used element
		 */
		const T& getLRUElement()
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
			m_CacheItemsMap.erase(element);
		}

		/**
		 * @return The max size of this list as determined in the c'tor
		 */
		inline size_t getMaxSize() { return m_MaxSize; }

		/**
		 * @return The number of elements currently in this list
		 */
		inline size_t getSize() { return m_CacheItemsMap.size(); }

	private:
		std::list<T> m_CacheItemsList;
		std::map<T, ListIterator> m_CacheItemsMap;
		size_t m_MaxSize;
	};

} // namespace pcpp

#endif /* PCAPPP_LRU_LIST */

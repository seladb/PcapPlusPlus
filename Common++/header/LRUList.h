#ifndef PCAPPP_LRU_LIST
#define PCAPPP_LRU_LIST

#include <map>
#include <unordered_map>
#include <list>

template<typename T>
class LRUList
{
public:

	typedef typename std::list<T>::iterator ListIterator;
	typedef typename std::map<T, ListIterator>::iterator MapIterator;

	LRUList(size_t maxSize)
	{
		m_MaxSize = maxSize;
	}

	T* put(const T& element)
	{
		m_CacheItemsList.push_front(T);
		MapIterator iter = m_CacheItemsMap.find(element);
		if (iter != m_CacheItemsMap.end())
			m_CacheItemsList.erase(iter->second);
		m_CacheItemsMap[T] = m_CacheItemsList.front();

		if (m_CacheItemsList.size() > m_MaxSize)
		{
			std::list<T>::const_iterator lruIter = m_CacheItemsList.end();
			lruIter--;
			T* deletedValue = new T(*lruIter);
			m_CacheItemsMap.erase(lruIter);
			return deletedValue;
		}

		return NULL;
	}

	const T& getLRUElement()
	{
		return m_CacheItemsList.front();
	}

private:
	std::list<T> m_CacheItemsList;
	std::map<T, ListIterator> m_CacheItemsMap;
	size_t m_MaxSize;
};


#endif /* PCAPPP_LRU_LIST */

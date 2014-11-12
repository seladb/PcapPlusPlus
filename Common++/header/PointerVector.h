#ifndef PCAPPP_POINTER_VECTOR
#define PCAPPP_POINTER_VECTOR

#include <stdio.h>
#include <stdint.h>
#include <vector>

template<typename T>
class PointerVector
{
public:
	typedef typename std::vector<T*>::iterator VectorIterator;

	PointerVector() { }
	~PointerVector()
	{
		for (VectorIterator iter = m_Vector.begin(); iter != m_Vector.end(); iter++)
		{
			delete (*iter);
		}
	}

	void clear()
	{
		for (VectorIterator iter = m_Vector.begin(); iter != m_Vector.end(); iter++)
		{
			delete (*iter);
		}

		m_Vector.clear();
	}

	inline void pushBack(T* element) { m_Vector.push_back(element); }
	inline VectorIterator begin() { return m_Vector.begin(); }
	inline VectorIterator end() { return m_Vector.end(); }
	inline size_t size() { return m_Vector.size(); }

private:
	std::vector<T*> m_Vector;
};

#endif /* PCAPPP_POINTER_VECTOR */

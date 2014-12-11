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
	typedef typename std::vector<T*>::const_iterator ConstVectorIterator;

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
	inline ConstVectorIterator begin() const { return m_Vector.begin(); }
	inline VectorIterator end() { return m_Vector.end(); }
	inline ConstVectorIterator end() const { return m_Vector.end(); }
	inline size_t size() { return m_Vector.size(); }
	inline size_t size() const { return m_Vector.size(); }
	inline T* front() { return m_Vector.front(); }

	inline VectorIterator erase(VectorIterator position)
	{
		delete (*position);
		return m_Vector.erase(position);
	}

	inline T* getAndRemoveFromVector(VectorIterator& position)
	{
		T* result = (*position);
		VectorIterator tempPos = position;
		tempPos = m_Vector.erase(tempPos);
		position = tempPos;
		return result;
	}

private:
	std::vector<T*> m_Vector;
};

#endif /* PCAPPP_POINTER_VECTOR */

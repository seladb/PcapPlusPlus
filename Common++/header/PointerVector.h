#ifndef PCAPPP_POINTER_VECTOR
#define PCAPPP_POINTER_VECTOR

#include <stdio.h>
#include <stdint.h>
#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/**
	 * @class PointerVector
	 * A template class for representing a std::vector of pointers. Once (a pointer to) an element is added to this vector,
	 * the element responsibility moves to the vector, meaning the PointerVector will free the object once it's removed from the vector
	 * This class wraps std::vector and adds the capability of freeing objects once they're removed from it
	 */
	template<typename T>
	class PointerVector
	{
	public:
		/**
		 * Iterator object that is used for iterating all elements in the vector
		 */
		typedef typename std::vector<T*>::iterator VectorIterator;

		/**
		 * Const iterator object that is used for iterating all elements in a constant vector
		 */
		typedef typename std::vector<T*>::const_iterator ConstVectorIterator;

		/**
		 * A constructor that create an empty instance of this object
		 */
		PointerVector() { }

		/**
		 * A destructor for this class. The destructor frees all elements that are binded to the vector
		 */
		~PointerVector()
		{
			for (VectorIterator iter = m_Vector.begin(); iter != m_Vector.end(); iter++)
			{
				delete (*iter);
			}
		}

		/**
		 * Copy constructor. Once a vector is copied from another vector, all elements inside it are copied,
		 * meaning the new vector will contain pointers to copied elements, not pointers to the elements of the original vector
		 */
		PointerVector(const PointerVector& other)
		{
			for (ConstVectorIterator iter = other.begin(); iter != other.end(); iter++)
			{
				T* objCopy = new T(**iter);
				m_Vector.push_back(objCopy);
			}
		}

		/**
		 * Clears all elements of the vector while freeing them
		 */
		void clear()
		{
			for (VectorIterator iter = m_Vector.begin(); iter != m_Vector.end(); iter++)
			{
				delete (*iter);
			}

			m_Vector.clear();
		}

		/**
		 * Add a new (pointer to an) element to the vector
		 */
		inline void pushBack(T* element) { m_Vector.push_back(element); }

		/**
		 * Get the first element of the vector
		 * @return An iterator object pointing to the first element of the vector
		 */
		inline VectorIterator begin() { return m_Vector.begin(); }

		/**
		 * Get the first element of a constant vector
		 * @return A const iterator object pointing to the first element of the vector
		 */
		inline ConstVectorIterator begin() const { return m_Vector.begin(); }

		/**
		 * Get the last element of the vector
		 * @return An iterator object pointing to the last element of the vector
		 */
		inline VectorIterator end() { return m_Vector.end(); }

		/**
		 * Get the last element of a constant vector
		 * @return A const iterator object pointing to the last element of the vector
		 */
		inline ConstVectorIterator end() const { return m_Vector.end(); }


		//inline size_t size() { return m_Vector.size(); }

		/**
		 * Get number of elements in the vector
		 * @return The number of elements in the vector
		 */
		inline size_t size() const { return m_Vector.size(); }

		/**
		 * Returns a pointer of the first element in the vector
		 * @return A pointer of the first element in the vector
		 */
		inline T* front() { return m_Vector.front(); }

		/**
		 * Removes from the vector a single element (position). Once the element is erased, it's also freed
		 * @param[in] position The position of the element to erase
		 * @return An iterator pointing to the new location of the element that followed the last element erased by the function call
		 */
		inline VectorIterator erase(VectorIterator position)
		{
			delete (*position);
			return m_Vector.erase(position);
		}

		/**
		 * Remove an element from the vector without freeing it
		 * param[in] position The position of the element to remove from the vector
		 * @return A pointer to the element which is no longer managed by the vector. It's user responsibility to free it
		 */
		inline T* getAndRemoveFromVector(VectorIterator& position)
		{
			T* result = (*position);
			VectorIterator tempPos = position;
			tempPos = m_Vector.erase(tempPos);
			position = tempPos;
			return result;
		}

		/**
		 * Return a pointer to the element in a certain index
		 * @param[in] index The index to retrieve the element from
		 * @return The element at the specified position in the vector
		 */
		inline T* at(int index)
		{
			return m_Vector.at(index);
		}

	private:
		std::vector<T*> m_Vector;
	};

} // namespace pcpp

#endif /* PCAPPP_POINTER_VECTOR */

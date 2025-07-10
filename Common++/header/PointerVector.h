#pragma once

#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <stdexcept>
#include <vector>
#include <memory>
#include <type_traits>

#include "DeprecationUtils.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	namespace internal
	{
		/// @brief A helper struct to facilitate the creation of a copy of an object.
		/// @tparam T The type of object to copy.
		/// @tparam Enable Helper parameter for SFINAE.
		template <class T, class Enable = void> struct Copier
		{
			std::unique_ptr<T> operator()(const T& obj) const
			{
				return std::make_unique<T>(obj);
			}
		};

		/// @brief A specialization of Copier to facilitate the safe copying of polymorphic objects via clone() method.
		/// @tparam T The type of object to copy.
		template <class T> struct Copier<T, typename std::enable_if<std::is_polymorphic<T>::value>::type>
		{
			std::unique_ptr<T> operator()(const T& obj) const
			{
				// Clone can return unique_ptr or raw pointer.
				return std::unique_ptr<T>(std::move(obj.clone()));
			}
		};
	}  // namespace internal

	/// @class PointerVector
	/// A template class for representing a std::vector of pointers. Once (a pointer to) an element is added to this
	/// vector, the element responsibility moves to the vector, meaning the PointerVector will free the object once it's
	/// removed from the vector This class wraps std::vector and adds the capability of freeing objects once they're
	/// removed from it
	template <typename T, typename Deleter = std::default_delete<T>> class PointerVector
	{
	public:
		/// Iterator object that is used for iterating all elements in the vector
		using VectorIterator = typename std::vector<T*>::iterator;

		/// Const iterator object that is used for iterating all elements in a constant vector
		using ConstVectorIterator = typename std::vector<T*>::const_iterator;

		/// A constructor that create an empty instance of this object
		PointerVector() = default;

		/// Copies the vector along with all elements inside it.
		/// All elements inside the copied vector are duplicates and the originals remain unchanged.
		/// @param[in] other The vector to copy from.
		/// @remarks As the vector is copied via deep copy, all pointers obtained from the copied vector
		/// reference the duplicates and not the originals.
		PointerVector(const PointerVector& other) : m_Vector(deepCopyUnsafe(other.m_Vector))
		{}

		/// Move constructor. All elements along with their ownership is transferred to the new vector.
		/// @param[in] other The vector to move from.
		PointerVector(PointerVector&& other) noexcept : m_Vector(std::move(other.m_Vector))
		{
			other.m_Vector.clear();
		}

		/// A destructor for this class. The destructor frees all elements that are binded to the vector
		~PointerVector()
		{
			freeVectorUnsafe(m_Vector);
		}

		/// A copy assignment operator. Replaces the contents with a copy of the contents of other.
		/// See copy constructor for more information on the specific copy procedure.
		/// @param[in] other The vector to copy from.
		/// @return A reference to the current object.
		PointerVector& operator=(const PointerVector& other)
		{
			// Self-assignment check.
			if (this == &other)
			{
				return *this;
			}

			// Saves a copy of the old pointer to defer cleanup.
			auto oldValues = m_Vector;
			try
			{
				m_Vector = deepCopyUnsafe(other.m_Vector);
			}
			// If an exception is thrown during the copy operation, restore old values and rethrow.
			catch (const std::exception&)
			{
				m_Vector = std::move(oldValues);
				throw;
			}
			// Free old values as the new ones have been successfully assigned.
			freeVectorUnsafe(oldValues);
			return *this;
		}

		/// A move assignment operator. Replaces the contents with those of other via move semantics.
		/// The other vector is left empty.
		/// @param[in] other The vector to move from.
		/// @return A reference to the current object.
		PointerVector& operator=(PointerVector&& other) noexcept
		{
			if (this == &other)
			{
				return *this;
			}

			// Releases all current elements.
			clear();
			// Moves the elements of the other vector.
			m_Vector = std::move(other.m_Vector);
			// Explicitly clear the other vector as the standard only guarantees an unspecified valid state after move.
			other.m_Vector.clear();
			return *this;
		}

		/// Clears all elements of the vector while freeing them
		void clear()
		{
			freeVectorUnsafe(m_Vector);
			m_Vector.clear();
		}

		/// Adding a nullptr to the vector is not allowed.
		void pushBack(std::nullptr_t element, bool freeElementOnError = true) = delete;

		/// Add a new (pointer to an) element to the vector
		/// @param[in] element A pointer to an element to assume ownership of.
		/// @param[in] freeElementOnError If set to true, the element is freed if an exception is thrown during the
		/// push.
		/// @throws std::invalid_argument The provided pointer is a nullptr.
		void pushBack(T* element, bool freeElementOnError = true)
		{
			if (element == nullptr)
			{
				throw std::invalid_argument("Element is nullptr");
			}

			try
			{
				m_Vector.push_back(element);
			}
			catch (const std::exception&)
			{
				if (freeElementOnError)
				{
					Deleter{}(element);
				}
				throw;
			}
		}

		/// Add a new element to the vector that has been managed by an unique pointer.
		/// @param[in] element A unique pointer holding an element.
		/// @throws std::invalid_argument The provided pointer is a nullptr.
		/// @remarks If pushBack throws the element is freed immediately.
		void pushBack(std::unique_ptr<T> element)
		{
			if (!element)
			{
				throw std::invalid_argument("Element is nullptr");
			}

			// Release is called after the raw pointer is already inserted into the vector to prevent
			// a memory leak if push_back throws.
			// cppcheck-suppress danglingLifetime
			m_Vector.push_back(element.get());
			element.release();
		}

		/// Get the first element of the vector
		/// @return An iterator object pointing to the first element of the vector
		VectorIterator begin()
		{
			return m_Vector.begin();
		}

		/// Get the first element of a constant vector
		/// @return A const iterator object pointing to the first element of the vector
		ConstVectorIterator begin() const
		{
			return m_Vector.begin();
		}

		/// Get the last element of the vector
		/// @return An iterator object pointing to the last element of the vector
		VectorIterator end()
		{
			return m_Vector.end();
		}

		/// Get the last element of a constant vector
		/// @return A const iterator object pointing to the last element of the vector
		ConstVectorIterator end() const
		{
			return m_Vector.end();
		}

		/// Get number of elements in the vector
		/// @return The number of elements in the vector
		size_t size() const
		{
			return m_Vector.size();
		}

		/// @brief Get the current capacity of the vector.
		/// @return The number of elements that can be held in the vector without requiring a reallocation.
		size_t capacity() const
		{
			return m_Vector.capacity();
		}

		/// @brief Reserve storage for the vector.
		/// @param[in] size The number of elements to reserve space for.
		/// @remarks This method ensures that the vector can hold at least the specified number of elements
		/// without requiring a reallocation.
		void reserve(size_t size)
		{
			m_Vector.reserve(size);
		}

		/// @return A pointer of the first element in the vector
		T* front() const
		{
			return m_Vector.front();
		}

		/// @return A pointer to the last element in the vector
		T* back() const
		{
			return m_Vector.back();
		}

		/// Removes from the vector a single element (position). Once the element is erased, it's also freed
		/// @param[in] position The position of the element to erase
		/// @return An iterator pointing to the new location of the element that followed the last element erased by the
		/// function call
		VectorIterator erase(VectorIterator position)
		{
			Deleter{}(*position);
			return m_Vector.erase(position);
		}

		/// Removes a range of elements from the vector and frees them.
		/// @param[in] first An iterator pointing to the first element in the range to erase.
		/// @param[in] last An iterator pointing to one past the last element in the range to erase.
		/// @return An iterator pointing to the new location of the element that followed the last element erased by the
		/// function call.
		VectorIterator erase(ConstVectorIterator first, ConstVectorIterator last)
		{
			for (auto iter = first; iter != last; ++iter)
			{
				Deleter{}(*iter);
			}
			return m_Vector.erase(first, last);
		}

		/// Remove an element from the vector without freeing it
		/// @param[in, out] position The position of the element to remove from the vector.
		/// The iterator is shifted to the following element after the removal is completed.
		/// @return A pointer to the element which is no longer managed by the vector. It's user responsibility to free
		/// it
		/// @deprecated Deprecated in favor of 'getAndDetach' as that function provides memory safety.
		PCPP_DEPRECATED("Please use the memory safe 'getAndDetach' instead.")
		T* getAndRemoveFromVector(VectorIterator& position)
		{
			T* result = *position;
			position = m_Vector.erase(position);
			return result;
		}

		/// Removes an element from the vector and transfers ownership to the returned unique pointer.
		/// @param[in] index The index of the element to detach.
		/// @return An unique pointer that holds ownership of the detached element.
		std::unique_ptr<T> getAndDetach(size_t index)
		{
			return getAndDetach(m_Vector.begin() + index);
		}

		/// Removes an element from the vector and transfers ownership to the returned unique pointer.
		/// @param[in, out] position An iterator pointing to the element to detach.
		/// The iterator is shifted to the following element after the detach completes.
		/// @return An unique pointer that holds ownership of the detached element.
		std::unique_ptr<T> getAndDetach(VectorIterator& position)
		{
			std::unique_ptr<T> result(*position);
			position = m_Vector.erase(position);
			return result;
		}

		/// Removes an element from the vector and transfers ownership to the returned unique pointer.
		/// @param[in] position An iterator pointing to the element to detach.
		/// @return An unique pointer that holds ownership of the detached element.
		std::unique_ptr<T> getAndDetach(const VectorIterator& position)
		{
			std::unique_ptr<T> result(*position);
			m_Vector.erase(position);
			return result;
		}

		/// Return a pointer to the element in a certain index
		/// @param[in] index The index to retrieve the element from
		/// @return The element at the specified position in the vector
		T* at(int index) const
		{
			return m_Vector.at(index);
		}

	private:
		/// Performs a copy of the vector along with its elements.
		/// The caller is responsible of freeing the copied elements.
		/// @return A vector of pointers to the newly copied elements.
		static std::vector<T*> deepCopyUnsafe(const std::vector<T*>& origin)
		{
			std::vector<T*> copyVec;
			// Allocate the vector initially to ensure no exceptions are thrown during push_back.
			copyVec.reserve(origin.size());

			try
			{
				for (const auto iter : origin)
				{
					std::unique_ptr<T> objCopy = internal::Copier<T>()(*iter);
					// There shouldn't be a memory leak as the vector is reserved.
					copyVec.push_back(objCopy.release());
				}
			}
			catch (const std::exception&)
			{
				freeVectorUnsafe(copyVec);
				throw;
			}

			return copyVec;
		}

		/// Frees all elements inside the vector.
		/// Calling this function with non-heap allocated pointers is UB.
		/// @param[in] origin The vector of elements to free.
		/// @remarks The vector's contents are not cleared and will point to invalid locations in memory.
		static void freeVectorUnsafe(const std::vector<T*>& origin)
		{
			for (auto& obj : origin)
			{
				Deleter{}(obj);
			}
		}

		std::vector<T*> m_Vector;
	};

}  // namespace pcpp

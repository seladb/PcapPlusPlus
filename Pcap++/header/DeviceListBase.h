#pragma once
#include "PointerVector.h"

namespace pcpp
{
	namespace internal
	{
		/// @brief A base class for device lists, providing common functionality for managing a list of devices.
		template <typename T, typename Deleter = std::default_delete<T>> class DeviceListBase
		{
		protected:
			DeviceListBase() = default;

			explicit DeviceListBase(PointerVector<T, Deleter> devices) : m_DeviceList(std::move(devices))
			{}

			DeviceListBase(DeviceListBase const&) = default;
			DeviceListBase(DeviceListBase&&) = default;
			// Protected destructor to disallow deletion of derived class through a base class pointer
			~DeviceListBase() = default;

			DeviceListBase& operator=(DeviceListBase const&) = default;
			DeviceListBase& operator=(DeviceListBase&&) = default;

		public:
			using size_type = std::size_t;

			using iterator = typename PointerVector<T, Deleter>::VectorIterator;
			using const_iterator = typename PointerVector<T, Deleter>::ConstVectorIterator;

			/// @brief Get an iterator to the beginning of the device list
			iterator begin()
			{
				return m_DeviceList.begin();
			}

			/// @brief Get an iterator to the beginning of the device list
			const_iterator begin() const
			{
				return m_DeviceList.begin();
			}

			/// @brief Get a const iterator to the beginning of the device list
			const_iterator cbegin() const
			{
				return m_DeviceList.cbegin();
			}

			/// @brief Get an iterator to the end of the device list
			iterator end()
			{
				return m_DeviceList.end();
			}

			/// @brief Get an iterator to the end of the device list
			const_iterator end() const
			{
				return m_DeviceList.end();
			}

			/// @brief Get a const iterator to the end of the device list
			const_iterator cend() const
			{
				return m_DeviceList.cend();
			}

			/// @brief Check if the device list is empty
			/// @return True if the device list is empty, false otherwise
			bool empty() const
			{
				return m_DeviceList.empty();
			}

			/// @brief Get the number of devices in the list
			/// @return The number of devices in the list
			size_type size() const
			{
				return m_DeviceList.size();
			}

		protected:
			PointerVector<T, Deleter> m_DeviceList;
		};
	}  // namespace internal
}  // namespace pcpp

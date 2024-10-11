#pragma once

/// @file

#include "PointerVector.h"

namespace pcpp
{
	namespace internal
	{
		/**
		 * @class DeviceListBase
		 * A base class for all device lists in PcapPlusPlus. This class is used to store a list of devices and provide
		 * access to them
		 */
		template <class DeviceType, class DeviceDeleter = std::default_delete<DeviceType>> class DeviceListBase
		{
		protected:
			PointerVector<DeviceType, DeviceDeleter> m_DeviceList;

			DeviceListBase() = default;
			explicit DeviceListBase(PointerVector<DeviceType, DeviceDeleter> devices) : m_DeviceList(std::move(devices))
			{}
			DeviceListBase(DeviceListBase const&) = default;
			DeviceListBase(DeviceListBase&&) = default;
			// Protected destructor to disallow deletion of derived class through a base class pointer
			~DeviceListBase() = default;

			DeviceListBase& operator=(DeviceListBase const&) = default;
			DeviceListBase& operator=(DeviceListBase&&) = default;

		public:
			using value_type = DeviceType*;
			using size_type = std::size_t;
			using difference_type = std::ptrdiff_t;

			/**
			 * Iterator object that can be used to iterate all devices.
			 */
			using iterator = typename PointerVector<DeviceType>::VectorIterator;

			/**
			 * Const iterator object that can be used to iterate all devices.
			 */
			using const_iterator = typename PointerVector<DeviceType>::ConstVectorIterator;

			/**
			 * @brief Returns a pointer to the device at the specified position in the container.
			 * @param pos The position of the device.
			 * @return A pointer to the specified device.
			 */
			DeviceType* at(size_type pos)
			{
				return m_DeviceList.at(pos);
			}

			/**
			 * @brief Returns a pointer to the device at the specified position in the container.
			 * @param pos The position of the device.
			 * @return A pointer to the specified device.
			 */
			DeviceType const* at(size_type pos) const
			{
				return m_DeviceList.at(pos);
			}

			/**
			 * @brief Returns a pointer to first device.
			 * @return A pointer to the specified device.
			 */
			DeviceType* front()
			{
				return m_DeviceList.front();
			}
			/**
			 * @brief Returns a pointer to first device.
			 * @return A pointer to the specified device.
			 */
			DeviceType const* front() const
			{
				return m_DeviceList.front();
			}

			/**
			 * @brief Returns a pointer to last device.
			 * @return A pointer to the specified device.
			 */
			DeviceType* back()
			{
				return m_DeviceList.back();
			}

			/**
			 * @brief Returns a pointer to last device.
			 * @return A pointer to the specified device.
			 */
			DeviceType const* back() const
			{
				return m_DeviceList.back();
			}

			/**
			 * @brief Returns an iterator to the first device.
			 * @return An iterator to the specified device.
			 */
			iterator begin()
			{
				return m_DeviceList.begin();
			}

			/**
			 * @brief Returns an iterator to the first device.
			 * @return An iterator to the specified device.
			 */
			const_iterator begin() const
			{
				return cbegin();
			}

			/**
			 * @brief Returns an iterator to the first device.
			 * @return An iterator to the specified device.
			 */
			const_iterator cbegin() const
			{
				return m_DeviceList.begin();
			}

			/**
			 * @brief Returns an iterator past the last device.
			 * @return An iterator past the last device.
			 */
			iterator end()
			{
				return m_DeviceList.end();
			}

			/**
			 * @brief Returns an iterator past the last device.
			 * @return An iterator past the last device.
			 */
			const_iterator end() const
			{
				return cend();
			}

			/**
			 * @brief Returns an iterator past the last device.
			 * @return An iterator past the last device.
			 */
			const_iterator cend() const
			{
				return m_DeviceList.end();
			}

			/**
			 * @brief Checks if the container is empty.
			 * @return True if the container is empty, false otherwise.
			 */
			bool empty() const
			{
				return m_DeviceList.size() == 0;
			}

			/**
			 * @brief Returns the number of devices.
			 * @return The number of devices in the container.
			 */
			size_type size() const
			{
				return m_DeviceList.size();
			}
		};
	}  // namespace internal
}  // namespace pcpp

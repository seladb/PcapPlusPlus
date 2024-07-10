#pragma once

// GCOVR_EXCL_START

#include "PfRingDevice.h"
#include "PointerVector.h"
#include "DeprecationUtils.h"

/// @file

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

	/**
	 * @class PfRingDeviceList
	 * A singleton class that holds all available PF_RING devices. Through this class the user can iterate all PF_RING devices or find a specific
	 * device by name
	 */
	class PfRingDeviceList
	{
	private:
		PointerVector<PfRingDevice> m_PfRingDeviceList;
		std::vector<PfRingDevice*> m_PfRingDeviceListView;
		std::string m_PfRingVersion;

		PfRingDeviceList();
	public:
		/**
		 * Iterator object that can be used for iterating all PfRingDevice in list
		 */
		using iterator = PointerVector<PfRingDevice>::VectorIterator;

		/**
		 * Const iterator object that can be used for iterating all PfRingDevice in a constant list
		 */
		using const_iterator = PointerVector<PfRingDevice>::ConstVectorIterator;

		PfRingDeviceList(const PfRingDeviceList&) = delete;
		PfRingDeviceList(PfRingDeviceList&&) noexcept = delete;
		PfRingDeviceList& operator=(const PfRingDeviceList&) = delete;
		PfRingDeviceList& operator=(PfRingDeviceList&&) noexcept = delete;

		/**
		 * A static method that returns the singleton object for PfRingDeviceList
		 * @return PfRingDeviceList singleton
		 */
		static PfRingDeviceList& getInstance()
		{
			static PfRingDeviceList instance;
			return instance;
		}

		/**
		 * Return a list of all available PF_RING devices
		 * @return a list of all available PF_RING devices
		 * @deprecated This method has been deprecated in favor of begin/end iteration API.
		 */
		PCPP_DEPRECATED("Deprecated in favor of begin/end iteration API")
		const std::vector<PfRingDevice*>& getPfRingDevicesList() const { return m_PfRingDeviceListView; }

		/**
		 * Get a PF_RING device by name. The name is the Linux interface name which appears in ifconfig
		 * (e.g eth0, eth1, etc.)
		 * @return A pointer to the PF_RING device
		 */
		PfRingDevice* getPfRingDeviceByName(const std::string &devName) const;

		/**
		 * Get installed PF_RING version
		 * @return A string representing PF_RING version
		 */
		std::string getPfRingVersion() const { return m_PfRingVersion; }

		/**
		 * @return An iterator object pointing to the first device in the list
		 */
		iterator begin()
		{
			return m_PfRingDeviceList.begin();
		}

		/**
		 * @return A constant iterator object pointing to the first device in the list
		 */
		const_iterator begin() const
		{
			return m_PfRingDeviceList.begin();
		}

		/**
		 * @return An iterator object pointing to the last device in the list
		 */
		iterator end()
		{
			return m_PfRingDeviceList.end();
		}

		/**
		 * @return A constant iterator object pointing to the last device in the list
		 */
		const_iterator end() const
		{
			return m_PfRingDeviceList.end();
		}
	};

} // namespace pcpp

// GCOVR_EXCL_STOP

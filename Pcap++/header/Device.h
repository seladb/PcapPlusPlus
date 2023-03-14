#ifndef PCAPPP_DEVICE
#define PCAPPP_DEVICE

/// @file

#include "PointerVector.h"
#include "RawPacket.h"
#include "PcapFilter.h"

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{
	/** A vector of pointers to RawPacket */
	typedef PointerVector<RawPacket> RawPacketVector;

	/**
	 * @class IDevice
	 * An abstract interface representing all packet processing devices. It stands as the root class for all devices.
	 * This is an abstract class that cannot be instantiated
	 */
	class IDevice
	{
	protected:
		bool m_DeviceOpened;

		// c'tor should not be public
		IDevice() : m_DeviceOpened(false) {}

	public:

		virtual ~IDevice() {}

		/**
		 * Open the device
		 * @return True if device was opened successfully, false otherwise
		 */
		virtual bool open() = 0;

		/**
		 * Close the device
		 * @return No return value
		 */
		virtual void close() = 0;

		/**
		 * @return True if the file is opened, false otherwise
		 */
		inline bool isOpened() { return m_DeviceOpened; }
	};


	/**
	 * @class IFilterableDevice
	 * An abstract interface representing all devices that have BPF (Berkeley Packet Filter) filtering capabilities,
	 * meaning devices that can filter packets based on the BPF filtering syntax.
	 * This is an abstract class that cannot be instantiated
	 */
	class IFilterableDevice
	{
	protected:

		// c'tor should not be public
		IFilterableDevice() {}

	public:

		virtual ~IFilterableDevice() {}

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be received
		 * @param[in] filter The filter to be set in PcapPlusPlus' GeneralFilter format
		 * @return True if filter set successfully, false otherwise
		 */
		virtual bool setFilter(GeneralFilter& filter)
		{
			std::string filterAsString;
			filter.parseToString(filterAsString);
			return setFilter(filterAsString);
		}

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be received
		 * @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		virtual bool setFilter(std::string filterAsString) = 0;

		/**
		 * Clear the filter currently set on the device
		 * @return True if filter was removed successfully or if no filter was set, false otherwise
		 */
		virtual bool clearFilter() = 0;
	};
}

#endif // PCAPPP_DEVICE

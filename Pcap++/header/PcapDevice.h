#ifndef PCAPPP_PCAP_DEVICE
#define PCAPPP_PCAP_DEVICE

#include "Device.h"

// forward declaration for the pcap descriptor defined in pcap.h
struct pcap;
typedef pcap pcap_t;
struct pcap_pkthdr;

/// @file

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{
	//Forward Declaration - required for IPcapDevice::matchPacketWithFilter
	class GeneralFilter;

	/**
	 * @class IPcapDevice
	 * An abstract class representing all libpcap-based packet capturing devices: files, libPcap, WinPcap/Npcap and RemoteCapture.
	 * This class is abstract and cannot be instantiated
	 */
	class IPcapDevice : public IDevice, public IFilterableDevice
	{
	protected:
		pcap_t* m_PcapDescriptor;

		// c'tor should not be public
		IPcapDevice() : IDevice() { m_PcapDescriptor = NULL; }

	public:

		/**
		 * @struct PcapStats
		 * A container for pcap device statistics
		 */
		struct PcapStats
		{
			/** Number of packets received */
			uint64_t packetsRecv;
			/** Number of packets dropped */
			uint64_t packetsDrop;
			/** number of packets dropped by interface (not supported on all platforms) */
			uint64_t packetsDropByInterface;
		};


		virtual ~IPcapDevice();

		/**
		 * Get statistics from the device
		 * @param[out] stats An object containing the stats
		 * @return No return value
		 */
		virtual void getStatistics(PcapStats& stats) const = 0;

		/**
		 * A static method for retrieving pcap lib (libpcap/WinPcap/etc.) version information. This method is actually
		 * a wrapper for [pcap_lib_version()](https://www.tcpdump.org/manpages/pcap_lib_version.3pcap.html)
		 * @return A string containing the pcap lib version information
		 */
		static std::string getPcapLibVersionInfo();

		/**
		* Match a raw packet with a given BPF filter. Notice this method is static which means you don't need any device instance
		* in order to perform this match
		* @param[in] filter A filter class to test against
		* @param[in] rawPacket A pointer to the raw packet to match the filter with
		* @return True if raw packet matches the filter or false otherwise
		*/
		static bool matchPacketWithFilter(GeneralFilter& filter, RawPacket* rawPacket);


		// implement abstract methods

		using IFilterableDevice::setFilter;

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be received.
		 * Please note that when the device is closed the filter is reset so when reopening the device you need to call this
		 * method again in order to reactivate the filter
		 * @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		virtual bool setFilter(std::string filterAsString);

		/**
		 * Clear the filter currently set on device
		 * @return True if filter was removed successfully or if no filter was set, false otherwise
		 */
		bool clearFilter();
	};

} // namespace pcpp

#endif // PCAPPP_PCAP_DEVICE

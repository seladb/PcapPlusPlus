#ifndef PCAPPP_PCAP_DEVICE
#define PCAPPP_PCAP_DEVICE

#include "Device.h"

/**
 * Next define is ncessery in MinGw environment build context.
 * The "-std" flag causes a lot of bugs and incompatibilities on older platforms one of them
 * is that "-DWIN32" flag is not properly passed from pcpp build system. 
 * But libpcap is strongly depends on definition of "WIN32" macro on Windows platform.
 * Next lines represents manual handling of this situation.
 * Better solutions are accepted via PR on: https://github.com/seladb/PcapPlusPlus/issues
 */
#if defined(PCAPPP_MINGW_ENV) && !defined(WIN32)
#	define WIN32
#endif
#include <pcap.h>

/// @file

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{
	/**
	 * @class IPcapDevice
	 * An abstract class representing all libpcap-based packet capturing devices: files, libPcap, WinPcap and RemoteCapture.
	 * This class is abstract and cannot be instantiated
	 */
	class IPcapDevice : public IDevice, public IFilterableDevice
	{
	protected:
		pcap_t* m_PcapDescriptor;

		// c'tor should not be public
		IPcapDevice() : IDevice() { m_PcapDescriptor = NULL; }

	public:
		virtual ~IPcapDevice();

		/**
		 * Get statistics from device:
		 * - pcap_stat#ps_recv: number of packets received
		 * - pcap_stat#ps_drop: number of packets dropped
		 * - pcap_stat#ps_ifdorp: number of packets dropped by interface
		 * @param[out] stats The stats struct where stats are returned
		 */
		virtual void getStatistics(pcap_stat& stats) = 0;

		/**
		 * A static method for retreiving pcap lib (libpcap/WinPcap/etc.) version information. This method is actually
		 * a wrapper for [pcap_lib_version()](https://www.tcpdump.org/manpages/pcap_lib_version.3pcap.html)
		 * @return A string containing the pcap lib version information
		 */
		static std::string getPcapLibVersionInfo();

		/**
		 * Verify a filter is valid
		 * @param[in] filterAsString The filter in Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html)
		 * @return True if the filter is valid or false otherwise
		 */
		static bool verifyFilter(std::string filterAsString);

		/**
		 * Match a raw packet with a given BPF filter. Notice this method is static which means you don't need any device instance
		 * in order to perform this match
		 * @param[in] filterAsString The BPF filter
		 * @param[in] rawPacket A pointer to the raw packet to match the BPF filter with
		 * @return True if raw packet matches the BPF filter or false otherwise
		 */
		static bool matchPacketWithFilter(std::string filterAsString, RawPacket* rawPacket);


		// implement abstract methods

		using IFilterableDevice::setFilter;

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be received
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

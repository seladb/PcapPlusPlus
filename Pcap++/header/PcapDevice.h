#pragma once

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
	// Forward Declaration - required for IPcapDevice::matchPacketWithFilter
	class GeneralFilter;

	namespace internal
	{
		/// @class PcapHandle
		/// @brief A wrapper class for pcap_t* which is the libpcap packet capture descriptor.
		/// This class is used to manage the lifecycle of the pcap_t* object
		class PcapHandle
		{
		public:
			/// @brief Creates an empty handle.
			PcapHandle() = default;
			/// @brief Creates a handle from the provided pcap descriptor.
			/// @param pcapDescriptor The pcap descriptor to wrap.
			explicit PcapHandle(pcap_t* pcapDescriptor);

			PcapHandle(const PcapHandle&) = delete;
			PcapHandle(PcapHandle&& other) noexcept;

			PcapHandle& operator=(const PcapHandle&) = delete;
			PcapHandle& operator=(PcapHandle&& other) noexcept;
			PcapHandle& operator=(std::nullptr_t) noexcept;

			~PcapHandle();

			/// @brief Check if the handle is not null.
			/// @return True if the handle is not null, false otherwise.
			bool isValid() const
			{
				return m_PcapDescriptor != nullptr;
			}

			/// @brief Access the underlying pcap descriptor.
			/// @return The pcap descriptor.
			pcap_t* get() const
			{
				return m_PcapDescriptor;
			}

			/// @brief Releases ownership of the handle and returns the pcap descriptor.
			/// @return The pcap descriptor or nullptr if no handle is owned.
			pcap_t* release();

			/// @brief Helper function to retrieve the last error string for this handle.
			/// @return The last error string.
			std::string getLastError() const;

			/// @brief Helper function to retrieve a view of the last error string for this handle.
			/// @return A view of the last error string.
			/// @remarks This function is more efficient than getLastError() as it does not copy the string.
			char const* getLastErrorView() const;

			/// @brief Implicit conversion to bool.
			/// @return True if the handle is not null, false otherwise.
			operator bool() const
			{
				return isValid();
			}

			bool operator==(std::nullptr_t) const
			{
				return !isValid();
			}
			bool operator!=(std::nullptr_t) const
			{
				return isValid();
			}

		private:
			void closeHandle() noexcept;

			pcap_t* m_PcapDescriptor = nullptr;
		};
	}  // namespace internal

	/**
	 * @class IPcapDevice
	 * An abstract class representing all libpcap-based packet capturing devices: files, libPcap, WinPcap/Npcap and
	 * RemoteCapture. This class is abstract and cannot be instantiated
	 */
	class IPcapDevice : public IDevice, public IFilterableDevice
	{
	protected:
		internal::PcapHandle m_PcapDescriptor;

		// c'tor should not be public
		IPcapDevice() : IDevice()
		{}

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
		 */
		virtual void getStatistics(PcapStats& stats) const = 0;

		/**
		 * A static method for retrieving pcap lib (libpcap/WinPcap/etc.) version information. This method is actually
		 * a wrapper for [pcap_lib_version()](https://www.tcpdump.org/manpages/pcap_lib_version.3pcap.html)
		 * @return A string containing the pcap lib version information
		 */
		static std::string getPcapLibVersionInfo();

		/**
		 * Match a raw packet with a given BPF filter. Notice this method is static which means you don't need any
		 * device instance in order to perform this match
		 * @param[in] filter A filter class to test against
		 * @param[in] rawPacket A pointer to the raw packet to match the filter with
		 * @return True if raw packet matches the filter or false otherwise
		 */
		static bool matchPacketWithFilter(GeneralFilter& filter, RawPacket* rawPacket);

		// implement abstract methods

		using IFilterableDevice::setFilter;

		/**
		 * Set a filter for the device. When implemented by the device, only packets that match the filter will be
		 * received. Please note that when the device is closed the filter is reset so when reopening the device you
		 * need to call this method again in order to reactivate the filter
		 * @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax
		 * (http://biot.com/capstats/bpf.html)
		 * @return True if filter set successfully, false otherwise
		 */
		virtual bool setFilter(std::string filterAsString);

		/**
		 * Clear the filter currently set on device
		 * @return True if filter was removed successfully or if no filter was set, false otherwise
		 */
		bool clearFilter();
	};

}  // namespace pcpp

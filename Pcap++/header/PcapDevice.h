#pragma once

#include "Device.h"

// forward declaration for the pcap descriptor defined in pcap.h
struct pcap;
typedef pcap pcap_t;
struct pcap_pkthdr;

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
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
			constexpr PcapHandle() noexcept = default;
			/// @brief Creates a handle from the provided pcap descriptor.
			/// @param pcapDescriptor The pcap descriptor to wrap.
			explicit PcapHandle(pcap_t* pcapDescriptor) noexcept;

			PcapHandle(const PcapHandle&) = delete;
			PcapHandle(PcapHandle&& other) noexcept;

			PcapHandle& operator=(const PcapHandle&) = delete;
			PcapHandle& operator=(PcapHandle&& other) noexcept;
			PcapHandle& operator=(std::nullptr_t) noexcept;

			~PcapHandle();

			/// @return True if the handle is not null, false otherwise.
			bool isValid() const noexcept
			{
				return m_PcapDescriptor != nullptr;
			}

			/// @return The underlying pcap descriptor.
			pcap_t* get() const noexcept
			{
				return m_PcapDescriptor;
			}

			/// @brief Releases ownership of the handle and returns the pcap descriptor.
			/// @return The pcap descriptor or nullptr if no handle is owned.
			pcap_t* release() noexcept;

			/// @brief Replaces the managed handle with the provided one.
			/// @param pcapDescriptor A new pcap descriptor to manage.
			/// @remarks If the handle contains a non-null descriptor it will be closed.
			void reset(pcap_t* pcapDescriptor = nullptr) noexcept;

			/// @brief Helper function to retrieve a view of the last error string for this handle.
			/// @return A null-terminated view of the last error string.
			/// @remarks The returned view is only valid until the next call to a pcap function.
			char const* getLastError() const noexcept;

			/// @brief Sets a filter on the handle. Only packets that match the filter will be captured by the handle.
			///
			/// The filter uses Berkeley Packet Filter (BPF) syntax (http://biot.com/capstats/bpf.html).
			///
			/// @param[in] filter The filter to set in Berkeley Packet Filter (BPF) syntax.
			/// @return True if the filter was set successfully, false otherwise.
			bool setFilter(std::string const& filter);

			/// @brief Clears the filter currently set on the handle.
			/// @return True if the filter was removed successfully or if no filter was set, false otherwise.
			bool clearFilter();

			/// @return True if the handle is not null, false otherwise.
			explicit operator bool() const noexcept
			{
				return isValid();
			}

			bool operator==(std::nullptr_t) const noexcept
			{
				return !isValid();
			}
			bool operator!=(std::nullptr_t) const noexcept
			{
				return isValid();
			}

		private:
			pcap_t* m_PcapDescriptor = nullptr;
		};
	}  // namespace internal

	/// @class IPcapDevice
	/// An abstract class representing all libpcap-based packet capturing devices: files, libPcap, WinPcap/Npcap and
	/// RemoteCapture. This class is abstract and cannot be instantiated
	class IPcapDevice : public IDevice, public IFilterableDevice
	{
	protected:
		internal::PcapHandle m_PcapDescriptor;

		// c'tor should not be public
		IPcapDevice() : IDevice()
		{}

	public:
		/// @struct PcapStats
		/// A container for pcap device statistics
		struct PcapStats
		{
			/// Number of packets received
			uint64_t packetsRecv;
			/// Number of packets dropped
			uint64_t packetsDrop;
			/// number of packets dropped by interface (not supported on all platforms)
			uint64_t packetsDropByInterface;
		};

		virtual ~IPcapDevice();

		/// Get statistics from the device
		/// @param[out] stats An object containing the stats
		virtual void getStatistics(PcapStats& stats) const = 0;

		/// A static method for retrieving pcap lib (libpcap/WinPcap/etc.) version information. This method is actually
		/// a wrapper for [pcap_lib_version()](https://www.tcpdump.org/manpages/pcap_lib_version.3pcap.html)
		/// @return A string containing the pcap lib version information
		static std::string getPcapLibVersionInfo();

		/// Match a raw packet with a given BPF filter. Notice this method is static which means you don't need any
		/// device instance in order to perform this match
		/// @param[in] filter A filter class to test against
		/// @param[in] rawPacket A pointer to the raw packet to match the filter with
		/// @return True if raw packet matches the filter or false otherwise
		static bool matchPacketWithFilter(GeneralFilter& filter, RawPacket* rawPacket);

		// implement abstract methods

		using IFilterableDevice::setFilter;

		/// Set a filter for the device. When implemented by the device, only packets that match the filter will be
		/// received. Please note that when the device is closed the filter is reset so when reopening the device you
		/// need to call this method again in order to reactivate the filter
		/// @param[in] filterAsString The filter to be set in Berkeley Packet Filter (BPF) syntax
		/// (http://biot.com/capstats/bpf.html)
		/// @return True if filter set successfully, false otherwise
		bool setFilter(std::string filterAsString) override;

		/// Clear the filter currently set on device
		/// @return True if filter was removed successfully or if no filter was set, false otherwise
		bool clearFilter() override;
	};
}  // namespace pcpp

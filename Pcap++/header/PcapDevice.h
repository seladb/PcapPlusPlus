#pragma once

#include <cstdint>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
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

	/// @brief An interface for providing Pcap-based device statistics
	class IPcapStatisticsProvider
	{
	public:
		virtual ~IPcapStatisticsProvider() = default;

		/// @brief Get statistics from the device
		/// @return An object containing the stats
		PcapStats getStatistics() const;

		/// Get statistics from the device
		/// @param[out] stats An object containing the stats
		virtual void getStatistics(PcapStats& stats) const = 0;
	};
}  // namespace pcpp

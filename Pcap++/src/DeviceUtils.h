#pragma once

/// @file

#include <memory>
#include "IpAddress.h"
#include "PcapUtils.h"

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @cond PCPP_INTERNAL

	namespace internal
	{
		/// Fetches a list of all network devices on the local machine that LibPcap/WinPcap/NPcap can find.
		/// @return A smart pointer to an interface list structure.
		/// @throws std::runtime_error The system encountered an error fetching the devices.
		std::unique_ptr<pcap_if_t, PcapFreeAllDevsDeleter> getAllLocalPcapDevices();
	}  // namespace internal

	/// @endcond
}  // namespace pcpp

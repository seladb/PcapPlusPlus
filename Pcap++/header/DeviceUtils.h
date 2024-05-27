#pragma once

/// @file

#include <memory>
#include "IpAddress.h"
#include "MemoryUtils.h"

// Forward declaration
struct pcap_rmtauth;

namespace pcpp
{
	namespace internal
	{
		/** 
		 * Fetches a list of all network devices on the local machine that LibPcap/WinPcap/NPcap can find.
		 * @return A smart pointer to an interface list structure.
		 * @throws std::runtime_error The system encountered an error fetching the devices.
		 */
		std::unique_ptr<pcap_if_t, PcapFreeAllDevsDeleter> getAllLocalPcapDevices();
#ifdef _WIN32
		/**
		 * Fetches a list of all network devices on a remote machine that WinPcap/NPcap can find.
		 * @param[in] ipAddress IP address of the remote machine.
		 * @param[in] port Port to use when connecting to the remote machine.
		 * @param[in] pRmAuth Pointer to an authentication structure to use when connecting to the remote machine. Nullptr if no authentication is required.
		 * @return A smart pointer to an interface list structure.
		 * @throws std::runtime_error The system encountered an error fetching the devices.
		 */
		std::unique_ptr<pcap_if_t, PcapFreeAllDevsDeleter> getAllRemotePcapDevices(const IPAddress& ipAddress, uint16_t port, pcap_rmtauth* pRmAuth = nullptr);
#endif // _WIN32
	}
}
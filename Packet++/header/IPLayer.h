#pragma once

#include "IpAddress.h"
#include "Layer.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class IPLayer
	/// This is an interface (abstract class) implemented in the IP layers (IPv4Layer and IPv6Layer).
	/// It provides methods to fetch the source and destination IP addresses in an abdtract way
	/// that hides the IP type (IPv4 or IPv6). This is useful for use-cases in which the IP type doesn't matter.
	/// For example: if you're only interested in printing the IP address the IP type shouldn't matter.
	class IPLayer
	{
	protected:
		IPLayer() = default;

	public:
		/// An abstract method to get the source IP address
		/// @return An IPAddress object containing the source address
		virtual IPAddress getSrcIPAddress() const = 0;

		/// An abstract method to get the destination IP address
		/// @return An IPAddress object containing the destination address
		virtual IPAddress getDstIPAddress() const = 0;

		/// An empty destructor
		virtual ~IPLayer() = default;

		/// @brief Get the IP version of a given packet data.
		///
		/// The buffer is expected to start with the IP header and contain at least the first byte of it.
		/// The method will recognize IPv4 and IPv6 headers and return the respective protocol constant.
		/// If the IP version is not recognized or the buffer is malformed, UnknownProtocol will be returned.
		///
		/// @param[in] data A pointer to the packet data
		/// @param[in] dataLen The length of the packet data in bytes
		/// @return A ProtocolType representing the IP version of the packet data.
		static ProtocolType getIPVersion(uint8_t const* data, size_t dataLen);
	};
}  // namespace pcpp

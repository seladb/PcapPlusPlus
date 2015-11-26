#ifndef PCAPPP_NETWORK_UTILS
#define PCAPPP_NETWORK_UTILS

#include "MacAddress.h"
#include "IpAddress.h"
#include "PcapLiveDevice.h"


/// @file

/**
 * @class NetworkUtils
 * This class bundles several network utilities that are very common and useful. These utilities use Pcap++ and Packet++ packet
 * crafting and processing capabilities. This class is a singleton and can be access by getInstance() only
 */
class NetworkUtils
{
public:

	/**
	 * The access method to the singleton
	 * @return The singleton instance of this class
	 */
	static NetworkUtils& getInstance()
	{
		static NetworkUtils instance;
		return instance;
	}

	/**
	 * Resolve the MAC address for a given IPv4 address. It's done using the ARP protocol: send an ARP request and interpret the response
	 * @param[in] ipAddr The IPv4 address to resolve MAC address to
	 * @param[in] device The interface to send and receive the ARP packets on
	 * @param[out] arpResponseTimeMS An output parameter that will contain the time in milliseconds that took the ARP response to arrive
	 * @param[in] sourceMac An optional parameter to set the source MAC address that will be sent with the ARP request
	 * if this parameter isn't set or set with MacAddress#Zero the MAC address of the interface will be used
	 * @param[in] sourceIP An optional parameter to set the source IPv4 address that will be sent with the ARP request
	 * if this parameter isn't set or set with IPv4Address#Zero the default IPv4 address of the interface will be used
	 * @param[in] arpTimeout An optional parameter to set the timeout to wait for the ARP response to return.
	 * If this parameter isn't set or set with a number smaller than 0, a default timeout of 5 seconds will be set
	 * @return The resolved MAC address or MacAddress#Zero if an error occurred or address could not be resolved. Errors will be printed
	 * to log
	 */
	MacAddress getMacAddress(IPv4Address ipAddr, PcapLiveDevice* device, double& arpResponseTimeMS,
			MacAddress sourceMac = MacAddress::Zero, IPv4Address sourceIP = IPv4Address::Zero, int arpTimeout = -1);

private:

	// private c'tor
	NetworkUtils() {}
};


#endif /* PCAPPP_NETWORK_UTILS */

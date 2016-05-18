#ifndef PCAPPP_NETWORK_UTILS
#define PCAPPP_NETWORK_UTILS

#include "MacAddress.h"
#include "IpAddress.h"
#include "PcapLiveDevice.h"


/// @file

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

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
		 * Default timeout used for several utilities. Currently set to 5 seconds
		 */
		static const int DefaultTimeout;

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


		/**
		 * Resolve an IPv4 address for a given hostname. Resolving is done in multiple phases: first resolving the LAN gateway MAC address
		 * (or default gateway if a gateway isn't provided) using ARP protocol (by using NetworkUtils#getMacAddress() ). Then a DNS request
		 * is sent to a DNS server (if specified) or to the LAN gateway (if DNS server is not specified). The DNS response is decoded and
		 * the IPv4 address is determined. In addition the method outputs the time it took the DNS response to arrive and the DNS TTL
		 * written on the DNS response. If DNS response doesn't contain an IPv4 address resolving an IPv4Address#Zero will be returned.
		 * @param[in] hostname The hostname to resolve
		 * @param[in] device The interface to send and receive packets on
		 * @param[out] dnsResponseTimeMS When method returns successfully will contain the time it took to receive the DNS response
		 * (in milli-seconds)
		 * @param[out] dnsTTL When method returns successfully will contain The DNS TTL written in the DNS response
		 * @param[in] dnsTimeout An optional parameter to specify the timeout to wait for a DNS response. If not specified the default timeout
		 * is 5 sec
		 * @param[in] dnsServerIP An optional parameter to specify the DNS server IP to send the DNS request to. If not specified
		 * or specified with IPv4Address#Zero the DNS request will be sent to the default DNS server configured in the system
		 * @param[in] gatewayIP An optional parameter to specify the LAN gateway to send the DNS request through. If not specified
		 * or specified with IPv4Address#Zero the interface's default gateway will be used
		 * @return The resolved IPv4 address or IPv4Address#Zero if something went wrong (in this case an error will be printed to log)
		 */
		IPv4Address getIPv4Address(std::string hostname, PcapLiveDevice* device, double& dnsResponseTimeMS, uint32_t& dnsTTL,
				int dnsTimeout = -1, IPv4Address dnsServerIP = IPv4Address::Zero, IPv4Address gatewayIP = IPv4Address::Zero);

	private:

		// private c'tor
		NetworkUtils() {}
	};

} // namespace pcpp

#endif /* PCAPPP_NETWORK_UTILS */

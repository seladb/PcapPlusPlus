#pragma once

#include "IpAddress.h"
#include "PcapLiveDevice.h"
#include <vector>
#include <memory>


/// @file

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{

	/**
	 * @class PcapLiveDeviceList
	 * A singleton class that creates, stores and provides access to all PcapLiveDevice (on Linux) or WinPcapLiveDevice (on Windows) instances. All live
	 * devices are initialized on startup and wrap the network interfaces installed on the machine. This class enables access to them through
	 * their IP addresses or get a vector of all of them so the user can search them in some other way
	 */
	class PcapLiveDeviceList
	{
	private:
		std::vector<std::shared_ptr<PcapLiveDevice>> m_LiveDeviceList;
		// Vector of raw device pointers to keep the signature of getPcapLiveDevicesList, as it returns a reference.
		mutable std::vector<PcapLiveDevice*> m_LiveDeviceListView;

		std::vector<IPv4Address> m_DnsServers;

		// private c'tor
		PcapLiveDeviceList();
		// private copy c'tor
		PcapLiveDeviceList( const PcapLiveDeviceList& other );
		PcapLiveDeviceList& operator=(const PcapLiveDeviceList& other);

		void init();

		void setDnsServers();

		void updateLiveDeviceListView() const;
	public:
		/*
		 * @class smart_ptr_tag
		 * Helper tag to disambiguate smart pointer api.
		 */
		struct smart_ptr_api_tag {};
		const smart_ptr_api_tag smart_ptr_api{};

		/**
		 * The access method to the singleton
		 * @return The singleton instance of this class
		 */
		static PcapLiveDeviceList& getInstance()
		{
			static PcapLiveDeviceList instance;
			return instance;
		}

		/**
		 * @return A vector containing pointers to all live devices currently installed on the machine
		 */
		const std::vector<PcapLiveDevice*>& getPcapLiveDevicesList() const;

		/**
		 * Get a pointer to the live device by its IP address. IP address can be both IPv4 or IPv6
		 * @param[in] ipAddr The IP address defined for the device
		 * @return A pointer to the live device if this IP address exists. NULL otherwise
		 */
		PcapLiveDevice* getPcapLiveDeviceByIp(const IPAddress& ipAddr) const;
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIp(const IPAddress& ipAddr, smart_ptr_api_tag) const;

		/**
		 * Get a pointer to the live device by its IPv4 address
		 * @param[in] ipAddr The IPv4 address defined for the device
		 * @return A pointer to the live device if this IPv4 address exists. NULL otherwise
		 */
		PcapLiveDevice* getPcapLiveDeviceByIp(const IPv4Address& ipAddr) const;
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIp(const IPv4Address& ipAddr, smart_ptr_api_tag) const;

		/**
		 * Get a pointer to the live device by its IPv6 address
		 * @param[in] ip6Addr The IPv6 address defined for the device
		 * @return A pointer to the live device if this IPv6 address exists. NULL otherwise
		 */
		PcapLiveDevice* getPcapLiveDeviceByIp(const IPv6Address& ip6Addr) const;
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIp(const IPv6Address& ip6Addr, smart_ptr_api_tag) const;

		/**
		 * Get a pointer to the live device by its IP address represented as string. IP address can be both IPv4 or IPv6
		 * @param[in] ipAddrAsString The IP address defined for the device as string
		 * @return A pointer to the live device if this IP address is valid and exists. NULL otherwise
		 */
		PcapLiveDevice* getPcapLiveDeviceByIp(const std::string& ipAddrAsString) const;
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIp(const std::string& ipAddrAsString, smart_ptr_api_tag) const;

		/**
		 * Get a pointer to the live device by its name
		 * @param[in] name The name of the interface (e.g eth0)
		 * @return A pointer to the live device if this name exists. NULL otherwise
		 */
		PcapLiveDevice* getPcapLiveDeviceByName(const std::string& name) const;
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByName(const std::string& name, smart_ptr_api_tag) const;

		/**
		 * Get a pointer to the live device by its IP address or name
		 * @param[in] ipOrName An IP address or name of the interface
		 * @return A pointer to the live device if exists, NULL otherwise
		 */
		PcapLiveDevice* getPcapLiveDeviceByIpOrName(const std::string& ipOrName) const;
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIpOrName(const std::string& ipOrName, smart_ptr_api_tag) const;

		/**
		 * @return A list of all DNS servers defined for this machine. If this list is empty it means no DNS servers were defined or they
		 * couldn't be extracted from some reason
		 */
		const std::vector<IPv4Address>& getDnsServers() const { return m_DnsServers; }

		/**
		 * Copies the current live device list
		 * @return A pointer to the cloned device list
		 */
		PcapLiveDeviceList* clone() const;
		/**
		 * Copies the current live device list
		 * @return A unique ptr managing the cloned device list
		 */
		std::unique_ptr<PcapLiveDeviceList> clone(smart_ptr_api_tag) const;

		/**
		 * Reset the live device list and DNS server list, meaning clear and refetch them
		 */
		void reset();
	};

} // namespace pcpp

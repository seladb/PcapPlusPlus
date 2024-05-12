#pragma once

#include "DeprecationUtils.h"
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

		void init();

		void setDnsServers();

		void updateLiveDeviceListView() const;
	public:
		PcapLiveDeviceList(const PcapLiveDeviceList& other) = delete;
		PcapLiveDeviceList& operator=(const PcapLiveDeviceList& other) = delete;

		/*
		 * @class SmartPtrApiTag
		 * Helper tag to disambiguate smart pointer API.
		 */
		struct SmartPtrApiTag {};
		/**
		 * Helper tag constant for disambuguating smart pointer API.
		 */
		static const SmartPtrApiTag SmartPtrApi;

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
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED const std::vector<PcapLiveDevice*>& getPcapLiveDevicesList() const;
		/**
		 * @return A reference to a vector containing shared pointers to all live devices currently installed on the machine.
		 */
		const std::vector<std::shared_ptr<PcapLiveDevice>>& getPcapLiveDevicesList(SmartPtrApiTag) const { return m_LiveDeviceList; };

		/**
		 * Get a pointer to the live device by its IP address. IP address can be both IPv4 or IPv6
		 * @param[in] ipAddr The IP address defined for the device
		 * @return A pointer to the live device if this IP address exists, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED PcapLiveDevice* getPcapLiveDeviceByIp(const IPAddress& ipAddr) const;
		/**
		 * Get a pointer to the live device by its IP address. IP address can be both IPv4 or IPv6
		 * @param[in] ipAddr The IP address defined for the device
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the live device if this IP address exists, nullptr otherwise
		 */
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIp(const IPAddress& ipAddr, SmartPtrApiTag apiTag) const;

		/**
		 * Get a pointer to the live device by its IPv4 address
		 * @param[in] ipAddr The IPv4 address defined for the device
		 * @return A pointer to the live device if this IPv4 address exists, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED PcapLiveDevice* getPcapLiveDeviceByIp(const IPv4Address& ipAddr) const;
		/**
		 * Get a pointer to the live device by its IPv4 address
		 * @param[in] ipAddr The IPv4 address defined for the device
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the live device if this IPv4 address exists, nullptr otherwise
		 */
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIp(const IPv4Address& ipAddr, SmartPtrApiTag apiTag) const;

		/**
		 * Get a pointer to the live device by its IPv6 address
		 * @param[in] ip6Addr The IPv6 address defined for the device
		 * @return A pointer to the live device if this IPv6 address exists, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED PcapLiveDevice* getPcapLiveDeviceByIp(const IPv6Address& ip6Addr) const;
		/**
		 * Get a pointer to the live device by its IPv6 address
		 * @param[in] ip6Addr The IPv6 address defined for the device
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the live device if this IPv6 address exists, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIp(const IPv6Address& ip6Addr, SmartPtrApiTag apiTag) const;

		/**
		 * Get a pointer to the live device by its IP address represented as string. IP address can be both IPv4 or IPv6
		 * @param[in] ipAddrAsString The IP address defined for the device as string
		 * @return A pointer to the live device if this IP address is valid and exists, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED PcapLiveDevice* getPcapLiveDeviceByIp(const std::string& ipAddrAsString) const;
		/**
		 * Get a pointer to the live device by its IP address represented as string. IP address can be both IPv4 or IPv6
		 * @param[in] ipAddrAsString The IP address defined for the device as string
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the live device if this IP address is valid and exists, nullptr otherwise
		 */
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIp(const std::string& ipAddrAsString, SmartPtrApiTag apiTag) const;

		/**
		 * Get a pointer to the live device by its name
		 * @param[in] name The name of the interface (e.g eth0)
		 * @return A pointer to the live device if this name exists, nullprt otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED PcapLiveDevice* getPcapLiveDeviceByName(const std::string& name) const;
		/**
		 * Get a pointer to the live device by its name
		 * @param[in] name The name of the interface (e.g eth0)
		 * @param[in] Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the live device if this name exists, nullptr otherwise
		 */
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByName(const std::string& name, SmartPtrApiTag) const;

		/**
		 * Get a pointer to the live device by its IP address or name
		 * @param[in] ipOrName An IP address or name of the interface
		 * @return A pointer to the live device if exists, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED PcapLiveDevice* getPcapLiveDeviceByIpOrName(const std::string& ipOrName) const;
		/**
		 * Get a pointer to the live device by its IP address or name
		 * @param[in] ipOrName An IP address or name of the interface
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the live device if exists, nullptr otherwise
		 */
		std::shared_ptr<PcapLiveDevice> getPcapLiveDeviceByIpOrName(const std::string& ipOrName, SmartPtrApiTag apiTag) const;

		/**
		 * @return A list of all DNS servers defined for this machine. If this list is empty it means no DNS servers were defined or they
		 * couldn't be extracted from some reason
		 */
		const std::vector<IPv4Address>& getDnsServers() const { return m_DnsServers; }

		/**
		 * Copies the current live device list
		 * @return A pointer to the cloned device list
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED PcapLiveDeviceList* clone() const;
		/**
		 * Copies the current live device list
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A unique ptr managing the cloned device list
		 */
		std::unique_ptr<PcapLiveDeviceList> clone(SmartPtrApiTag apiTag) const;

		/**
		 * Reset the live device list and DNS server list, meaning clear and refetch them
		 */
		void reset();
	};

} // namespace pcpp

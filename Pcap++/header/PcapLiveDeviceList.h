#pragma once

#include "DeprecationUtils.h"
#include "IpAddress.h"
#include "DeviceListBase.h"
#include "PcapLiveDevice.h"
#include <vector>
#include <memory>

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class PcapLiveDeviceList
	/// A singleton class that creates, stores and provides access to all PcapLiveDevice (on Linux) or WinPcapLiveDevice
	/// (on Windows) instances. All live devices are initialized on startup and wrap the network interfaces installed on
	/// the machine. This class enables access to them through their IP addresses or get a vector of all of them so the
	/// user can search them in some other way
	class PcapLiveDeviceList : public internal::DeviceListBase<PcapLiveDevice>
	{
	private:
		using Base = internal::DeviceListBase<PcapLiveDevice>;

		// Vector of raw device pointers to keep the signature of getPcapLiveDevicesList, as it returns a reference.
		std::vector<PcapLiveDevice*> m_LiveDeviceListView;

		std::vector<IPv4Address> m_DnsServers;

		// private c'tor
		PcapLiveDeviceList();

		static PointerVector<PcapLiveDevice> fetchAllLocalDevices();
		static std::vector<IPv4Address> fetchDnsServers();

	public:
		PcapLiveDeviceList(const PcapLiveDeviceList&) = delete;
		PcapLiveDeviceList(PcapLiveDeviceList&&) noexcept = delete;
		PcapLiveDeviceList& operator=(const PcapLiveDeviceList&) = delete;
		PcapLiveDeviceList& operator=(PcapLiveDeviceList&&) noexcept = delete;

		/// The access method to the singleton
		/// @return The singleton instance of this class
		static PcapLiveDeviceList& getInstance()
		{
			static PcapLiveDeviceList instance;
			return instance;
		}

		/// @return A vector containing pointers to all live devices currently installed on the machine
		const std::vector<PcapLiveDevice*>& getPcapLiveDevicesList() const
		{
			return m_LiveDeviceListView;
		};

		/// Get a pointer to the live device by its IP address. IP address can be both IPv4 or IPv6
		/// @param[in] ipAddr The IP address defined for the device
		/// @return A pointer to the live device if this IP address exists. nullptr otherwise
		PCPP_DEPRECATED("Use `getDeviceByIp`")
		PcapLiveDevice* getPcapLiveDeviceByIp(const IPAddress& ipAddr) const;

		/// Get a pointer to the live device by its IP address. IP address can be both IPv4 or IPv6
		/// @param[in] ipAddr The IP address defined for the device
		/// @return A pointer to the live device if this IP address exists. nullptr otherwise
		PcapLiveDevice* getDeviceByIp(const IPAddress& ipAddr) const;

		/// Get a pointer to the live device by its IPv4 address
		/// @param[in] ipAddr The IPv4 address defined for the device
		/// @return A pointer to the live device if this IPv4 address exists. nullptr otherwise
		PCPP_DEPRECATED("Use `getDeviceByIp`")
		PcapLiveDevice* getPcapLiveDeviceByIp(const IPv4Address& ipAddr) const;

		/// Get a pointer to the live device by its IPv4 address
		/// @param[in] ipAddr The IPv4 address defined for the device
		/// @return A pointer to the live device if this IPv4 address exists. nullptr otherwise
		PcapLiveDevice* getDeviceByIp(const IPv4Address& ipAddr) const;

		/// Get a pointer to the live device by its IPv6 address
		/// @param[in] ip6Addr The IPv6 address defined for the device
		/// @return A pointer to the live device if this IPv6 address exists. nullptr otherwise
		PCPP_DEPRECATED("Use `getDeviceByIp`")
		PcapLiveDevice* getPcapLiveDeviceByIp(const IPv6Address& ip6Addr) const;

		/// Get a pointer to the live device by its IPv6 address
		/// @param[in] ip6Addr The IPv6 address defined for the device
		/// @return A pointer to the live device if this IPv6 address exists. nullptr otherwise
		PcapLiveDevice* getDeviceByIp(const IPv6Address& ip6Addr) const;

		/// Get a pointer to the live device by its IP address represented as string. IP address can be both IPv4 or
		/// IPv6
		/// @param[in] ipAddrAsString The IP address defined for the device as string
		/// @return A pointer to the live device if this IP address is valid and exists. nullptr otherwise
		PCPP_DEPRECATED("Use `getDeviceByIp`")
		PcapLiveDevice* getPcapLiveDeviceByIp(const std::string& ipAddrAsString) const;

		/// Get a pointer to the live device by its IP address represented as string. IP address can be both IPv4 or
		/// IPv6
		/// @param[in] ipAddrAsString The IP address defined for the device as string
		/// @return A pointer to the live device if this IP address is valid and exists. nullptr otherwise
		PcapLiveDevice* getDeviceByIp(const std::string& ipAddrAsString) const;

		/// Get a pointer to the live device by its name
		/// @param[in] name The name of the interface (e.g eth0)
		/// @return A pointer to the live device if this name exists. nullptr otherwise
		PCPP_DEPRECATED("Use `getDeviceByName`")
		PcapLiveDevice* getPcapLiveDeviceByName(const std::string& name) const;

		/// Get a pointer to the live device by its name
		/// @param[in] name The name of the interface (e.g eth0)
		/// @return A pointer to the live device if this name exists. nullptr otherwise
		PcapLiveDevice* getDeviceByName(const std::string& name) const;

		/// Get a pointer to the live device by its IP address or name
		/// @param[in] ipOrName An IP address or name of the interface
		/// @return A pointer to the live device if exists, nullptr otherwise
		PCPP_DEPRECATED("Use `getDeviceByIpOrName`")
		PcapLiveDevice* getPcapLiveDeviceByIpOrName(const std::string& ipOrName) const;

		/// Get a pointer to the live device by its IP address or name
		/// @param[in] ipOrName An IP address or name of the interface
		/// @return A pointer to the live device if exists, nullptr otherwise
		PcapLiveDevice* getDeviceByIpOrName(const std::string& ipOrName) const;

		/// @return A list of all DNS servers defined for this machine. If this list is empty it means no DNS servers
		/// were defined or they couldn't be extracted from some reason
		const std::vector<IPv4Address>& getDnsServers() const
		{
			return m_DnsServers;
		}

		/// Copies the current live device list
		/// @return A pointer to the cloned device list
		PcapLiveDeviceList* clone();

		/// Reset the live device list and DNS server list, meaning clear and refetch them
		void reset();
	};
}  // namespace pcpp

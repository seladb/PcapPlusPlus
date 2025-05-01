#pragma once

#include <memory>
#include "IpAddress.h"
#include "DeviceListBase.h"
#include "PcapRemoteDevice.h"
#include "DeprecationUtils.h"

/// @file

/// @namespace pcpp
/// @brief The main namespace for the PcapPlusPlus lib
namespace pcpp
{
	/// @class PcapRemoteDeviceList
	/// A class that creates, stores and provides access to all instances of PcapRemoteDevice for a certain remote
	/// machine. To get an instance of this class use one of the static methods of getRemoteDeviceList(). These methods
	/// creates a PcapRemoteDeviceList instance for the certain remote machine which holds a list of PcapRemoteDevice
	/// instances, one for each remote network interface. Note there is not a public constructor for this class, so the
	/// only way to get an instance of it is through getRemoteDeviceList(). After getting this object, this class
	/// provides ways to access the PcapRemoteDevice instances: either through IP address of the remote network
	/// interface or by iterating the PcapRemoteDevice instances (through the
	/// PcapRemoteDeviceList#RemoteDeviceListIterator iterator)<BR> Since Remote Capture is supported in WinPcap and
	/// Npcap only, this class is available in Windows only
	class PcapRemoteDeviceList : public internal::DeviceListBase<PcapRemoteDevice>
	{
	private:
		using Base = internal::DeviceListBase<PcapRemoteDevice>;

		IPAddress m_RemoteMachineIpAddress;
		uint16_t m_RemoteMachinePort;
		std::shared_ptr<PcapRemoteAuthentication> m_RemoteAuthentication;

		// private c'tor. User should create the list via static methods PcapRemoteDeviceList::createRemoteDeviceList()
		PcapRemoteDeviceList(const IPAddress& ipAddress, uint16_t port,
		                     std::shared_ptr<PcapRemoteAuthentication> remoteAuth,
		                     PointerVector<PcapRemoteDevice> deviceList);

	public:
		/// Iterator object that can be used for iterating all PcapRemoteDevice in list
		using RemoteDeviceListIterator = iterator;

		/// Const iterator object that can be used for iterating all PcapRemoteDevice in a constant list
		using ConstRemoteDeviceListIterator = const_iterator;

		PcapRemoteDeviceList(const PcapRemoteDeviceList&) = delete;
		PcapRemoteDeviceList(PcapRemoteDeviceList&&) noexcept = delete;
		PcapRemoteDeviceList& operator=(const PcapRemoteDeviceList&) = delete;
		PcapRemoteDeviceList& operator=(PcapRemoteDeviceList&&) noexcept = delete;

		/// A static method for creating a PcapRemoteDeviceList instance for a certain remote machine. This methods
		/// creates the instance, and also creates a list of PcapRemoteDevice instances stored in it, one for each
		/// remote network interface. Notice this method allocates the PcapRemoteDeviceList instance and returns a
		/// pointer to it. It's the user responsibility to free it when done using it<BR> This method overload is for
		/// remote daemons which don't require authentication for accessing them. For daemons which do require
		/// authentication use the other method overload
		/// @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd
		/// daemon
		/// @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		/// @return A pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will be
		/// printed to log in each case):
		/// - IP address provided is nullptr or not valid
		/// - WinPcap/Npcap encountered an error in creating the remote connection string
		/// - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		///   devices on the remote machine
		/// @deprecated This factory function has been deprecated in favor of 'createRemoteDeviceList' factory for
		/// better memory safety.
		PCPP_DEPRECATED("Please use 'createRemoteDeviceList' factory method instead.")
		static PcapRemoteDeviceList* getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port);

		/// A static method for creating a PcapRemoteDeviceList instance for a specific remote machine.
		/// This methods creates the instance and populates it with PcapRemoteDevice instances.
		/// Each PcapRemoteDevice instance corresponds to a network interface on the remote machine.
		///
		/// This method overload is for remote daemons which don't require authentication for accessing them.
		/// For daemons which do require authentication use the other method overload.
		///
		/// @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd
		/// daemon
		/// @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		/// @return A smart pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will
		/// be printed to log in each case):
		/// - WinPcap/Npcap encountered an error in creating the remote connection string
		/// - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		///   devices on the remote machine
		static std::unique_ptr<PcapRemoteDeviceList> createRemoteDeviceList(const IPAddress& ipAddress, uint16_t port);

		/// An overload of the previous getRemoteDeviceList() method but with authentication support. This method is
		/// suitable for connecting to remote daemons which require authentication for accessing them
		/// @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd
		/// daemon
		/// @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		/// @param[in] remoteAuth A pointer to the authentication object which contains the username and password for
		/// connecting to the remote daemon
		/// @return A pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will be
		/// printed to log in each case):
		/// - IP address provided is nullptr or not valid
		/// - WinPcap/Npcap encountered an error in creating the remote connection string
		/// - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		///   devices on the remote machine
		/// @deprecated This factory function has been deprecated in favor of 'createRemoteDeviceList' factory for
		/// better memory safety.
		PCPP_DEPRECATED("Please use 'createRemoteDeviceList' factory method instead.")
		static PcapRemoteDeviceList* getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port,
		                                                 PcapRemoteAuthentication* remoteAuth);

		/// A static method for creating a PcapRemoteDeviceList instance for a specific remote machine.
		/// This methods creates the instance and populates it with PcapRemoteDevice instances.
		/// Each PcapRemoteDevice instance corresponds to a network interface on the remote machine.
		///
		/// This method overload is for remote daemons which require authentication for accessing them.
		/// If no authentication is required, use the other method overload.
		///
		/// @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd
		/// daemon
		/// @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		/// @param[in] remoteAuth A pointer to the authentication object which contains the username and password for
		/// connecting to the remote daemon
		/// @return A smart pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will
		/// be printed to log in each case):
		/// - WinPcap/Npcap encountered an error in creating the remote connection string
		/// - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		///   devices on the remote machine
		static std::unique_ptr<PcapRemoteDeviceList> createRemoteDeviceList(const IPAddress& ipAddress, uint16_t port,
		                                                                    PcapRemoteAuthentication const* remoteAuth);

		/// @return The IP address of the remote machine
		IPAddress getRemoteMachineIpAddress() const
		{
			return m_RemoteMachineIpAddress;
		}

		/// @return The port of the remote machine where packets are transmitted from the remote machine to the client
		/// machine
		uint16_t getRemoteMachinePort() const
		{
			return m_RemoteMachinePort;
		}

		/// Search a PcapRemoteDevice in the list by its IPv4 address
		/// @param[in] ip4Addr The IPv4 address
		/// @return The PcapRemoteDevice if found, nullptr otherwise
		PcapRemoteDevice* getRemoteDeviceByIP(const IPv4Address& ip4Addr) const;

		/// Search a PcapRemoteDevice in the list by its IPv6 address
		/// @param[in] ip6Addr The IPv6 address
		/// @return The PcapRemoteDevice if found, nullptr otherwise
		PcapRemoteDevice* getRemoteDeviceByIP(const IPv6Address& ip6Addr) const;

		/// Search a PcapRemoteDevice in the list by its IP address (IPv4 or IPv6)
		/// @param[in] ipAddr The IP address
		/// @return The PcapRemoteDevice if found, nullptr otherwise
		PcapRemoteDevice* getRemoteDeviceByIP(const IPAddress& ipAddr) const;

		/// Search a PcapRemoteDevice in the list by its IP address
		/// @param[in] ipAddrAsString The IP address in string format
		/// @return The PcapRemoteDevice if found, nullptr otherwise
		PcapRemoteDevice* getRemoteDeviceByIP(const std::string& ipAddrAsString) const;
	};
}  // namespace pcpp

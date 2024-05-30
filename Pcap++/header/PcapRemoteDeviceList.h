#pragma once

#if defined(_WIN32)

#include <memory>
#include "DeprecationUtils.h"
#include "IpAddress.h"
#include "PcapRemoteDevice.h"

/// @file

#define PCPP_DEPRECATED_RAW_PTR_API PCPP_DEPRECATED("This method is deprecated in favor of the SmartPtrAPI overload.")

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{
	/**
	 * @class PcapRemoteDeviceList
	 * A class that creates, stores and provides access to all instances of PcapRemoteDevice for a certain remote machine. To get an instance
	 * of this class use one of the static methods of getRemoteDeviceList(). These methods creates a PcapRemoteDeviceList instance for the
	 * certain remote machine which holds a list of PcapRemoteDevice instances, one for each remote network interface. Note there is
	 * not a public constructor for this class, so the only way to get an instance of it is through getRemoteDeviceList(). After getting
	 * this object, this class provides ways to access the PcapRemoteDevice instances: either through IP address of the remote network interface or
	 * by iterating the PcapRemoteDevice instances (through the PcapRemoteDeviceList#RemoteDeviceListIterator iterator)<BR>
	 * Since Remote Capture is supported in WinPcap and Npcap only, this class is available in Windows only
	 */
	class PcapRemoteDeviceList
	{
	private:
		std::vector<std::shared_ptr<PcapRemoteDevice>> m_RemoteDeviceList;
		// View vector to help keep backward compatibility of iteration.
		std::vector<PcapRemoteDevice*> m_RemoteDeviceListView;
		IPAddress m_RemoteMachineIpAddress;
		uint16_t m_RemoteMachinePort;
		std::shared_ptr<PcapRemoteAuthentication> m_RemoteAuthentication;

		// private c'tor. User should create the list via static methods PcapRemoteDeviceList::getRemoteDeviceList()
		PcapRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, std::shared_ptr<PcapRemoteAuthentication> remoteAuth, std::vector<std::shared_ptr<PcapRemoteDevice>> deviceList);

		void updateDeviceListView();

		// Implementation that uses a shared ptr is private to guarantee that the remote auth object is not shared externally.
		// It is used by the other overloads for casting different kinds of pointers/references into shared_ptr.
		static std::unique_ptr<PcapRemoteDeviceList> getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, std::shared_ptr<PcapRemoteAuthentication> remoteAuth);
	public:
		PcapRemoteDeviceList(const PcapRemoteDeviceList& other) = delete;
		PcapRemoteDeviceList& operator=(const PcapRemoteDeviceList& other) = delete;

		/**
		 * Iterator object that can be used for iterating all PcapRemoteDevice in list
		 */
		using RemoteDeviceListIterator = std::vector<PcapRemoteDevice*>::iterator;
		using iterator = RemoteDeviceListIterator;

		/**
		 * Const iterator object that can be used for iterating all PcapRemoteDevice in a constant list
		 */
		using ConstRemoteDeviceListIterator = std::vector<PcapRemoteDevice*>::const_iterator;
		using const_iterator = ConstRemoteDeviceListIterator;

		/**
		 * A static method for creating a PcapRemoteDeviceList instance for a certain remote machine. This methods creates the instance, and also
		 * creates a list of PcapRemoteDevice instances stored in it, one for each remote network interface. Notice this method allocates
		 * the PcapRemoteDeviceList instance and returns a pointer to it. It's the user responsibility to free it when done using it<BR>
		 * This method overload is for remote daemons which don't require authentication for accessing them. For daemons which do require authentication
		 * use the other method overload
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @return A pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will be printed to log in each case):
		 * - IP address provided is not valid
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving devices on the remote machine
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED_RAW_PTR_API static PcapRemoteDeviceList* getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port);
		/**
		 * A static method for creating a PcapRemoteDeviceList instance for a certain remote machine. This methods creates the instance, and also
		 * creates a list of PcapRemoteDevice instances stored in it, one for each remote network interface. Notice this method allocates
		 * the PcapRemoteDeviceList instance and returns a unique pointer to it.<BR>
		 * This method overload is for remote daemons which don't require authentication for accessing them. For daemons which do require authentication
		 * use the other method overload.
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return An unique pointer to the newly created PcapRemoteDeviceList or a nullptr if (an appropriate error will be printed to log in each case):
		 * - IP address provided is not valid
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving devices on the remote machine
		 */
		static std::unique_ptr<PcapRemoteDeviceList> getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, SmartPtrApiTag apiTag);

		/**
		 * An overload of the previous getRemoteDeviceList() method but with authentication support. This method is suitable for connecting to
		 * remote daemons which require authentication for accessing them
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] remoteAuth A pointer to the authentication object which contains the username and password for connecting to the remote daemon
		 * @return A pointer to the newly created PcapRemoteDeviceList, or NULL if (an appropriate error will be printed to log in each case):
		 * - IP address provided is not valid
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving devices on the remote machine
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED_RAW_PTR_API static PcapRemoteDeviceList* getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, PcapRemoteAuthentication* remoteAuth);
		/**
		 * An overload of the previous getRemoteDeviceList() method but with authentication support. This method is suitable for connecting to
		 * remote daemons which require authentication for accessing them
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] remoteAuth A pointer to the authentication object which contains the username and password for connecting to the remote daemon
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return An unique pointer to the newly created PcapRemoteDeviceList, or NULL if (an appropriate error will be printed to log in each case):
		 * - IP address provided is not valid
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving devices on the remote machine
		 */
		static std::unique_ptr<PcapRemoteDeviceList> getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, PcapRemoteAuthentication* remoteAuth, SmartPtrApiTag apiTag);
		/**
		 * An overload of the previous getRemoteDeviceList() method but with authentication support. This method is
		 * suitable for connecting to remote daemons which require authentication for accessing them
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] remoteAuth An unique pointer to the authentication object which contains the username and password for connecting to the remote daemon
		 * @return An unique pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will be printed to log in each case):
		 * - IP address provided is not valid
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		 * devices on the remote machine
		 */
		static std::unique_ptr<PcapRemoteDeviceList> getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, std::unique_ptr<PcapRemoteAuthentication> remoteAuth);
		/**
		 * An overload of the previous getRemoteDeviceList() method but with authentication support. This method is
		 * suitable for connecting to remote daemons which require authentication for accessing them
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] remoteAuth A reference to the authentication object which contains the username and password for connecting to the remote daemon
		 * @return An unique pointer to the newly created PcapRemoteDeviceList, or nullptr if (an appropriate error will be printed
		 * to log in each case):
		 * - IP address provided is not valid
		 * - WinPcap/Npcap encountered an error in creating the remote connection string
		 * - WinPcap/Npcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving
		 * devices on the remote machine
		 */
		static std::unique_ptr<PcapRemoteDeviceList> getRemoteDeviceList(const IPAddress& ipAddress, uint16_t port, const PcapRemoteAuthentication& remoteAuth);

		/**
		 * @return The IP address of the remote machine
		 */
		IPAddress getRemoteMachineIpAddress() const { return m_RemoteMachineIpAddress; }

		/**
		 * @return The port of the remote machine where packets are transmitted from the remote machine to the client machine
		 */
		uint16_t getRemoteMachinePort() const { return m_RemoteMachinePort; }

		/**
		 * Search a PcapRemoteDevice in the list by its IPv4 address
		 * @param[in] ip4Addr The IPv4 address
		 * @return A pointer to PcapRemoteDevice if found, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED_RAW_PTR_API PcapRemoteDevice* getRemoteDeviceByIP(const IPv4Address& ip4Addr) const;
		/**
		 * Search a PcapRemoteDevice in the list by its IPv4 address
		 * @param[in] ip4Addr The IPv4 address
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the PcapRemoteDevice if found, nullptr otherwise
		 */
		std::shared_ptr<PcapRemoteDevice> getRemoteDeviceByIP(const IPv4Address& ip4Addr, SmartPtrApiTag apiTag) const;

		/**
		 * Search a PcapRemoteDevice in the list by its IPv6 address
		 * @param[in] ip6Addr The IPv6 address
		 * @return A pointer to PcapRemoteDevice if found, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED_RAW_PTR_API PcapRemoteDevice* getRemoteDeviceByIP(const IPv6Address& ip6Addr) const;
		/**
		 * Search a PcapRemoteDevice in the list by its IPv6 address
		 * @param[in] ip6Addr The IPv6 address
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the PcapRemoteDevice if found, nullptr otherwise
		 */
		std::shared_ptr<PcapRemoteDevice> getRemoteDeviceByIP(const IPv6Address& ip6Addr, SmartPtrApiTag apiTag) const;

		/**
		 * Search a PcapRemoteDevice in the list by its IP address (IPv4 or IPv6)
		 * @param[in] ipAddr The IP address
		 * @return A pointer to PcapRemoteDevice if found, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED_RAW_PTR_API PcapRemoteDevice* getRemoteDeviceByIP(const IPAddress& ipAddr) const;
		/**
		 * Search a PcapRemoteDevice in the list by its IP address (IPv4 or IPv6)
		 * @param[in] ipAddr The IP address
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the PcapRemoteDevice if found, nullptr otherwise
		 */
		std::shared_ptr<PcapRemoteDevice> getRemoteDeviceByIP(const IPAddress& ipAddr, SmartPtrApiTag apiTag) const;

		/**
		 * Search a PcapRemoteDevice in the list by its IP address
		 * @param[in] ipAddrAsString The IP address in string format
		 * @return A pointer to PcapRemoteDevice if found, nullptr otherwise
		 * @deprecated This method is deprecated in favor of the SmartPtrAPI overload.
		 */
		PCPP_DEPRECATED_RAW_PTR_API PcapRemoteDevice* getRemoteDeviceByIP(const std::string& ipAddrAsString) const;
		/**
		 * Search a PcapRemoteDevice in the list by its IP address
		 * @param[in] ipAddrAsString The IP address in string format
		 * @param[in] apiTag Disambiguating tag for SmartPtrAPI.
		 * @return A shared pointer to the PcapRemoteDevice if found, nullptr otherwise
		 */
		std::shared_ptr<PcapRemoteDevice> getRemoteDeviceByIP(const std::string& ipAddrAsString, SmartPtrApiTag apiTag) const;

		/**
		 * @return An iterator object pointing to the first PcapRemoteDevice in list
		 */
		RemoteDeviceListIterator begin() { return m_RemoteDeviceListView.begin(); }

		/**
		 * @return A const iterator object pointing to the first PcapRemoteDevice in list
		 */
		ConstRemoteDeviceListIterator begin() const { return m_RemoteDeviceListView.begin(); }

		/**
		 * @return An iterator object pointing to the last PcapRemoteDevice in list
		 */
		RemoteDeviceListIterator end() { return m_RemoteDeviceListView.end(); }

		/**
		 * @return A const iterator object pointing to the last PcapRemoteDevice in list
		 */
		ConstRemoteDeviceListIterator end() const { return m_RemoteDeviceListView.end(); }
	};

} // namespace pcpp

#undef PCPP_DEPRECATED_RAW_PTR_API

#endif // _WIN32

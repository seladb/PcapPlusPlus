#ifndef PCAPP_PCAP_REMOTE_DEVICE_LIST
#define PCAPP_PCAP_REMOTE_DEVICE_LIST

#if defined(WIN32) || defined(WINx64)

#include "IpAddress.h"
#include "PcapRemoteDevice.h"

/// @file

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
	 * Since Remote Capture is supported in WinPcap only, this class is available in Windows only
	 */
	class PcapRemoteDeviceList
	{
	private:
		std::vector<PcapRemoteDevice*> m_RemoteDeviceList;
		IPAddress* m_RemoteMachineIpAddress;
		uint16_t m_RemoteMachinePort;
		PcapRemoteAuthentication* m_RemoteAuthentication;

		// private c'tor. User should create the list via static methods PcapRemoteDeviceList::getRemoteDeviceList()
		PcapRemoteDeviceList() : m_RemoteMachineIpAddress(NULL), m_RemoteMachinePort(0), m_RemoteAuthentication(NULL) {};
		// private copy c'tor
		PcapRemoteDeviceList(const PcapRemoteDeviceList& other);
		PcapRemoteDeviceList& operator=(const PcapRemoteDeviceList& other);

		void setRemoteMachineIpAddress(const IPAddress* ipAddress);
		void setRemoteMachinePort(uint16_t port);
		void setRemoteAuthentication(const PcapRemoteAuthentication* remoteAuth);

	public:
		/**
		 * Iterator object that can be used for iterating all PcapRemoteDevice in list
		 */
		typedef typename std::vector<PcapRemoteDevice*>::iterator RemoteDeviceListIterator;

		/**
		 * Const iterator object that can be used for iterating all PcapRemoteDevice in a constant list
		 */
		typedef typename std::vector<PcapRemoteDevice*>::const_iterator ConstRemoteDeviceListIterator;

		~PcapRemoteDeviceList();

		/**
		 * A static method for creating a PcapRemoteDeviceList instance for a certain remote machine. This methods creates the instance, and also
		 * creates a list of PcapRemoteDevice instances stored in it, one for each remote network interface. Notice this method allocates
		 * the PcapRemoteDeviceList instance and returns a pointer to it. It's the user responsibility to free it when done using it<BR>
		 * This method overload is for remote daemons which don't require authentication for accessing them. For daemons which do require authentication
		 * use the other method overload
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @return A pointer to the newly created PcapRemoteDeviceList, or NULL if (an appropriate error will be printed to log in each case):
		 * - IP address provided is NULL or not valid
		 * - WinPcap encountered an error in creating the remote connection string
		 * - WinPcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving devices on the remote machine
		 */
		static PcapRemoteDeviceList* getRemoteDeviceList(IPAddress* ipAddress, uint16_t port);

		/**
		 * An overload of the previous getRemoteDeviceList() method but with authentication support. This method is suitable for connecting to
		 * remote daemons which require authentication for accessing them
		 * @param[in] ipAddress The IP address of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] port The port of the remote machine through which clients can connect to the rpcapd daemon
		 * @param[in] remoteAuth A pointer to the authentication object which contains the username and password for connecting to the remote
		 * daemon
		 * @return A pointer to the newly created PcapRemoteDeviceList, or NULL if (an appropriate error will be printed to log in each case):
		 * - IP address provided is NULL or not valid
		 * - WinPcap encountered an error in creating the remote connection string
		 * - WinPcap encountered an error connecting to the rpcapd daemon on the remote machine or retrieving devices on the remote machine
		 */
		static PcapRemoteDeviceList* getRemoteDeviceList(IPAddress* ipAddress, uint16_t port, PcapRemoteAuthentication* remoteAuth);

		/**
		 * @return The IP address of the remote machine
		 */
		IPAddress* getRemoteMachineIpAddress() { return m_RemoteMachineIpAddress; }

		/**
		 * @return The port of the remote machine where packets are transmitted from the remote machine to the client machine
		 */
		uint16_t getRemoteMachinePort() { return m_RemoteMachinePort; }

		/**
		 * Search a PcapRemoteDevice in the list by its IPv4 address
		 * @param[in] ip4Addr The IPv4 address
		 * @return The PcapRemoteDevice if found, NULL otherwise
		 */
		PcapRemoteDevice* getRemoteDeviceByIP(IPv4Address ip4Addr);

		/**
		 * Search a PcapRemoteDevice in the list by its IPv6 address
		 * @param[in] ip6Addr The IPv6 address
		 * @return The PcapRemoteDevice if found, NULL otherwise
		 */
		PcapRemoteDevice* getRemoteDeviceByIP(IPv6Address ip6Addr);

		/**
		 * Search a PcapRemoteDevice in the list by its IP address (IPv4 or IPv6)
		 * @param[in] ipAddr The IP address
		 * @return The PcapRemoteDevice if found, NULL otherwise
		 */
		PcapRemoteDevice* getRemoteDeviceByIP(IPAddress* ipAddr);

		/**
		 * Search a PcapRemoteDevice in the list by its IP address
		 * @param[in] ipAddrAsString The IP address in string format
		 * @return The PcapRemoteDevice if found, NULL otherwise
		 */
		PcapRemoteDevice* getRemoteDeviceByIP(const char* ipAddrAsString);

		/**
		 * @return An iterator object pointing to the first PcapRemoteDevice in list
		 */
		inline RemoteDeviceListIterator begin() { return m_RemoteDeviceList.begin(); }

		/**
		 * @return A const iterator object pointing to the first PcapRemoteDevice in list
		 */
		inline ConstRemoteDeviceListIterator begin() const { return m_RemoteDeviceList.begin(); }

		/**
		 * @return An iterator object pointing to the last PcapRemoteDevice in list
		 */
		inline RemoteDeviceListIterator end() { return m_RemoteDeviceList.end(); }

		/**
		 * @return A const iterator object pointing to the last PcapRemoteDevice in list
		 */
		inline ConstRemoteDeviceListIterator end() const { return m_RemoteDeviceList.end(); }

	};

} // namespace pcpp

#endif // WIN32 || WINx64

#endif /* PCAPP_PCAP_REMOTE_DEVICE_LIST */

#ifndef PCAPPP_RAW_SOCKET_DEVICE
#define PCAPPP_RAW_SOCKET_DEVICE

/// @file

#include "IpAddress.h"
#include "Device.h"

/**
* \namespace pcpp
* \brief The main namespace for the PcapPlusPlus lib
*/
namespace pcpp
{
	class RawSocketDevice : public IDevice
	{
	public:

		enum SocketFamily
		{
			Ethernet = 0,
			IPv4 = 1,
			IPv6 = 2
		};

		enum RecvPacketResult
		{
			RecvSuccess = 0,
			RecvTimeout = 1,
			RecvWouldBlock = 2,
			RecvError = 3
		};

		RawSocketDevice(const IPAddress& interfaceIP);

		~RawSocketDevice();

		RecvPacketResult receivePacket(RawPacket& rawPacket, bool blocking = true, int timeout = -1);

		int receivePackets(RawPacketVector& packetVec, int timeout);

		bool sendPacket(const RawPacket* rawPacket);

		int sendPackets(const RawPacketVector& packetVec);

		// overridden methods

		/**
		 * Open the device by creating a socket
		 * @return True if device was opened successfully, false otherwise
		 */
		virtual bool open();

		/**
		 * Close the raw socket
		 */
		virtual void close();

	private:

		SocketFamily m_SockFamily;
		void* m_Socket;
		IPAddress* m_InterfaceIP;

		RecvPacketResult getError(int& errorCode);

	};
}

#endif // PCAPPP_RAW_SOCKET_DEVICE

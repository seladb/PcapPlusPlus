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
	/**
	 * @class RawSocketDevice
	 * A class that wraps the raw socket functionality. A raw socket is a network socket that allows direct sending and receiving
	 * of IP packets without any protocol-specific transport layer formatting
	 * (taken from Wikipedia: https://en.wikipedia.org/wiki/Network_socket#Raw_socket).
	 * This wrapper class enables creation of a raw socket, binding it to a network interface, and then receiving and sending
	 * packets on it. Current implementation supports only Windows and Linux because other platforms provide poor support for raw
	 * sockets making them practically unusable. There are also major differences between Linux and Windows in raw socket
	 * implementation, let's mention some of the:
	 *  - On Windows administrative privileges are required for raw sockets creation, meaning the process running the code
	 *    has to have these privileges. In Linux 'sudo' is required
	 *  - On Windows raw sockets are implemented in L3, meaning the L2 (Ethernet) layer is omitted by the socket and only L3 and
	 *    up are visible to the user. On Linux raw sockets are implemented on L2, meaning all layers (including the Ethernet
	 *    data) are visible to the user.
	 *  - On Windows sending packets is not supported, a raw socket can only receive packets. On Linux both send and receive are
	 *    supported
	 *  - Linux doesn't require binding to a specific network interface for receiving packets, but it does require binding
	 *    for sending packets. Windows requires binding for receiving packets. For the sake of keeping a unified and simple cross-platform interface
	 *    this class requires binding for both Linux and Windows, on both send and receive
	 *
	 * More details about opening the raw socket, receiving and sending packets are explained in the corresponding class methods.
	 * Raw sockets are supported for both IPv4 and IPv6, so you can create and bind raw sockets to each of the two.
	 * Also, there is no limit on the number of sockets opened for a specific IP address or network interface, so you can
	 * create multiple instances of this class and bind all of them to the same interface and IP address.
	 */
	class RawSocketDevice : public IDevice
	{
	public:

		/**
		 * An enum for reporting packet receive results
		 */
		enum RecvPacketResult
		{
			/** Receive success */
			RecvSuccess = 0,
			/** Receive timeout - timeout expired without any packets being captured */
			RecvTimeout = 1,
			/** Receive would block - in non-blocking mode if there are no packets in the rx queue the receive method will return immediately with this return value */
			RecvWouldBlock = 2,
			/** Receive error, usually will be followed by an error log */
			RecvError = 3
		};

		/*
		 * A c'tor for this class. This c'tor doesn't create the raw socket, but rather initializes internal structures. The actual
		 * raw socket creation is done in the open() method. Each raw socket is bound to a network interface which means
		 * packets will be received and sent from only from this network interface only
		 * @param[in] interfaceIP The network interface IP to bind the raw socket to. It can be either an IPv4 or IPv6 address
		 * (both are supported in raw sockets)
		 */
		RawSocketDevice(const IPAddress& interfaceIP);

		/**
		 * A d'tor for this class. It closes the raw socket if not previously closed by calling close()
		 */
		~RawSocketDevice();

		/**
		 * Receive a packet on the raw socket. This method has several modes of operation:
		 *  - Blocking/non-blocking - in blocking mode the method will not return until a packet is received on the socket
		 *    or until the timeout expires. In non-blocking mode it will return immediately and in case no packets are on the
		 *    receive queue RawSocketDevice#RecvWouldBlock will be returned. Unless specified otherwise, the default value is
		 *    blocking mode
		 *  - Receive timeout - in blocking mode, the user can set a timeout to wait until a packet is received. If the timeout
		 *    expires and no packets were received, the method will return RawSocketDevice#RecvTimeout. The default value is a
		 *    negative value which means no timeout
		 *
		 * There is a slight difference on this method's behavior between Windows and Linux around how packets are received.
		 * On Linux the received packet contains all layers starting from the L2 (Ethernet). However on Windows raw socket are
		 * integrated in L3 level so the received packet contains only L3 (IP) layer and up.
		 * @param[out] rawPacket An empty packet instance where the received packet data will be written to
		 * @param[in] blocking Indicates whether to run in blocking or non-blocking mode. Default value is blocking
		 * @param[in] timeout When in blocking mode, specifies the timeout [in seconds] to wait for a packet. If timeout expired
		 * and no packets were captured the method will return RawSocketDevice#RecvTimeout. Zero or negative values mean no
		 * timeout. The default value is no timeout
		 * @return The method returns one on the following values:
		 *  - RawSocketDevice#RecvSuccess is returned if a packet was received successfully
		 *  - RawSocketDevice#RecvTimeout is returned if in blocking mode and timeout expired
		 *  - RawSocketDevice#RecvWouldBlock is returned if in non-blocking mode and no packets were captured
		 *  - RawSocketDevice#RecvError is returned if an error occurred such as device is not opened or the recv operation
		 *    returned some error. A log message will be followed specifying the error and error code
		 */
		RecvPacketResult receivePacket(RawPacket& rawPacket, bool blocking = true, int timeout = -1);

		/**
		 * Receive packets into a packet vector for a certain amount of time. This method starts a timer and invokes the
		 * receivePacket() method in blocking mode repeatedly until the timeout expires. All packets received successfully are
		 * put into a packet vector
		 * @param[out] packetVec The packet vector to add the received packet to
		 * @param[in] timeout Timeout in seconds to receive packets on the raw socket
		 * @param[out] failedRecv Number of receive attempts that failed
		 * @return The number of packets received successfully
		 */
		int receivePackets(RawPacketVector& packetVec, int timeout, int& failedRecv);

		/**
		 * Send an Ethernet packet to the network. L2 protocols other than Ethernet are not supported in raw sockets.
		 * The entire packet is sent as is, including the original Ethernet and IP data.
		 * This method is only supported in Linux as Windows doesn't allow sending packets from raw sockets. Using
		 * it from other platforms will also return "false" with a corresponding error log message
		 * @param[in] rawPacket The packet to send
		 * @return True if packet was sent successfully or false if the socket is not open, if the packet is not Ethernet or
		 * if there was a failure sending the packet
		 */
		bool sendPacket(const RawPacket* rawPacket);

		/**
		 * Send a set of Ethernet packets to the network. L2 protocols other than Ethernet are not supported by raw sockets.
		 * The entire packet is sent as is, including the original Ethernet and IP data.
		 * This method is only supported in Linux as Windows doesn't allow sending packets from raw sockets. Using it from
		 * other platforms will return "false" with an appropriate error log message
		 * @param[in] packetVec The set of packets to send
		 * @return The number of packets sent successfully. For packets that weren't sent successfully there will be a
		 * corresponding error message printed to log
		 */
		int sendPackets(const RawPacketVector& packetVec);

		// overridden methods

		/**
		 * Open the device by creating a raw socket and binding it to the network interface specified in the c'tor
		 * @return True if device was opened successfully, false otherwise with a corresponding error log message
		 */
		virtual bool open();

		/**
		 * Close the raw socket
		 */
		virtual void close();

	private:

		enum SocketFamily
		{
			Ethernet = 0,
			IPv4 = 1,
			IPv6 = 2
		};

		SocketFamily m_SockFamily;
		void* m_Socket;
		IPAddress m_InterfaceIP;

		RecvPacketResult getError(int& errorCode) const;

	};
}

#endif // PCAPPP_RAW_SOCKET_DEVICE

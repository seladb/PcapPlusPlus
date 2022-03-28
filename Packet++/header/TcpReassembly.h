#ifndef PACKETPP_TCP_REASSEMBLY
#define PACKETPP_TCP_REASSEMBLY

#include "Packet.h"
#include "IpAddress.h"
#include "PointerVector.h"
#include <map>
#include <list>
#include <time.h>


/**
 * @file
 * This is an implementation of TCP reassembly logic, which means reassembly of TCP messages spanning multiple TCP segments (or packets).<BR>
 * This logic can be useful in analyzing messages for a large number of protocols implemented on top of TCP including HTTP, SSL/TLS, FTP and many many more.
 *
 * __General Features:__
 * - Manage multiple TCP connections under one pcpp#TcpReassembly instance
 * - Support TCP retransmission
 * - Support out-of-order packets
 * - Support missing TCP data
 * - TCP connections can end "naturally" (by FIN/RST packets) or manually by the user
 * - Support callbacks for new TCP data, connection start and connection end
 *
 * __Logic Description:__
 * - The user creates an instance of the pcpp#TcpReassembly class
 * - Then the user starts feeding it with TCP packets
 * - The pcpp#TcpReassembly instance manages all TCP connections from the packets it's being fed. For each connection it manages its 2 sides (A->B and B->A)
 * - When a packet arrives, it is first classified to a certain TCP connection
 * - Then it is classified to a certain side of the TCP connection
 * - Then the pcpp#TcpReassembly logic tries to understand if the data in this packet is the expected data (sequence-wise) and if it's new (e.g isn't a retransmission)
 * - If the packet data matches these criteria a callback is being invoked. This callback is supplied by the user in the creation of the pcpp#TcpReassembly instance. This callback contains
 *   the new data (of course), but also information about the connection (5-tuple, 4-byte hash key describing the connection, etc.) and also a pointer to a "user cookie", meaning a pointer to
 *   a structure provided by the user during the creation of the pcpp#TcpReassembly instance
 * - If the data in this packet isn't new, it's being ignored
 * - If the data in this packet isn't expected (meaning this packet came out-of-order), then the data is being queued internally and will be sent to the user when its turn arrives
 *   (meaning, after the data before arrives)
 * - If the missing data doesn't arrive until a new message from the other side of the connection arrives or until the connection ends - this will be considered as missing data and the
 *   queued data will be sent to the user, but the string "[X bytes missing]" will be added to the message sent in the callback
 * - pcpp#TcpReassembly supports 2 more callbacks - one is invoked when a new TCP connection is first seen and the other when it's ended (either by a FIN/RST packet or manually by the user).
 *   Both of these callbacks contain data about the connection (5-tuple, 4-byte hash key describing the connection, etc.) and also a pointer to a "user cookie", meaning a pointer to a
 *   structure provided by the user during the creation of the pcpp#TcpReassembly instance. The end connection callback also provides the reason for closing it ("naturally" or manually)
 *
 * __Basic Usage and APIs:__
 * - pcpp#TcpReassembly c'tor - Create an instance, provide the callbacks and the user cookie to the instance
 * - pcpp#TcpReassembly#reassemblePacket() - Feed pcpp#TcpReassembly instance with packets
 * - pcpp#TcpReassembly#closeConnection() - Manually close a connection by a flow key
 * - pcpp#TcpReassembly#closeAllConnections() - Manually close all currently opened connections
 * - pcpp#TcpReassembly#OnTcpMessageReady callback - Invoked when new data arrives on a certain connection. Contains the new data as well as connection data (5-tuple, flow key)
 * - pcpp#TcpReassembly#OnTcpConnectionStart callback - Invoked when a new connection is identified
 * - pcpp#TcpReassembly#OnTcpConnectionEnd callback - Invoked when a connection ends (either by FIN/RST or manually by the user)
 *
 * __Additional information:__
 * When the connection is closed the information is not being deleted from memory immediately. There is a delay between these moments. Existence of this delay is caused by two reasons:
 * - pcpp#TcpReassembly#reassemblePacket() should detect the packets that arrive after the FIN packet has been received
 * - the user can use the information about connections managed by pcpp#TcpReassembly instance. Following methods are used for this purpose: pcpp#TcpReassembly#getConnectionInformation and pcpp#TcpReassembly#isConnectionOpen.
 * Cleaning of memory can be performed automatically (the default behavior) by pcpp#TcpReassembly#reassemblePacket() or manually by calling pcpp#TcpReassembly#purgeClosedConnections in the user code.
 * Automatic cleaning is performed once per second.
 *
 * The struct pcpp#TcpReassemblyConfiguration allows to setup the parameters of cleanup. Following parameters are supported:
 * - pcpp#TcpReassemblyConfiguration#doNotRemoveConnInfo - if this member is set to false the automatic cleanup mode is applied
 * - pcpp#TcpReassemblyConfiguration#closedConnectionDelay - the value of delay expressed in seconds. The minimum value is 1
 * - pcpp#TcpReassemblyConfiguration#maxNumToClean - to avoid performance overhead when the cleanup is being performed, this parameter is used. It defines the maximum number of items to be removed per one call of pcpp#TcpReassembly#purgeClosedConnections
 * - pcpp#TcpReassemblyConfiguration#maxOutOfOrderFragments - the maximum number of unmatched fragments to keep per flow before missed fragments are considered lost. A value of 0 means unlimited
 *
 */

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

/**
 * @struct ConnectionData
 * Represents basic TCP/UDP + IP connection data
 */
struct ConnectionData
{
	/** Source IP address */
	IPAddress srcIP;
	/** Destination IP address */
	IPAddress dstIP;
	/** Source TCP/UDP port */
	uint16_t srcPort;
	/** Destination TCP/UDP port */
	uint16_t dstPort;
	/** A 4-byte hash key representing the connection */
	uint32_t flowKey;
	/** Start TimeStamp of the connection */
	timeval startTime;
	/** End TimeStamp of the connection */
	timeval endTime;

	/**
	 * A c'tor for this struct that basically zeros all members
	 */
	ConnectionData() : srcPort(0), dstPort(0), flowKey(0), startTime(), endTime() {}

	/**
	 * Set startTime of Connection
	 * @param[in] startTime integer value
	 */
	void setStartTime(const timeval &startTime) { this->startTime = startTime; }

	/**
	 * Set endTime of Connection
	 * @param[in] endTime integer value
	 */
	void setEndTime(const timeval &endTime) { this->endTime = endTime; }
};


class TcpReassembly;


/**
 * @class TcpStreamData
 * When following a TCP connection each packet may contain a piece of the data transferred between the client and the server. This class represents these pieces: each instance of it
 * contains a piece of data, usually extracted from a single packet, as well as information about the connection
 */
class TcpStreamData
{
public:
	/**
	 * A c'tor for this class that get data from outside and set the internal members
	 * @param[in] tcpData A pointer to buffer containing the TCP data piece
	 * @param[in] tcpDataLength The length of the buffer
	 * @param[in] missingBytes The number of missing bytes due to packet loss.
	 * @param[in] connData TCP connection information for this TCP data
	 * @param[in] timestamp when this packet was received
	 */
	TcpStreamData(const uint8_t* tcpData, size_t tcpDataLength, size_t missingBytes, const ConnectionData& connData, timeval timestamp)
		: m_Data(tcpData), m_DataLen(tcpDataLength), m_MissingBytes(missingBytes), m_Connection(connData), m_Timestamp(timestamp)
	{
	}

	/**
	 * A getter for the data buffer
	 * @return A pointer to the buffer
	 */
	const uint8_t* getData() const { return m_Data; }

	/**
	 * A getter for buffer length
	 * @return Buffer length
	 */
	size_t getDataLength() const { return m_DataLen; }

	/**
	 * A getter for missing byte count due to packet loss.
	 * @return Missing byte count
	 */
	size_t getMissingByteCount() const { return m_MissingBytes; }

	/**
	 * Determine if bytes are missing. getMissingByteCount can be called to determine the number of missing bytes.
	 * @return true if bytes are missing.
	 */
	bool isBytesMissing() const { return getMissingByteCount() > 0; }

	/**
	 * A getter for the connection data
	 * @return The const reference to connection data
	 */
	const ConnectionData& getConnectionData() const { return m_Connection; }

	/**
	 * A getter for the timestamp of this packet
	 * @return The const timeval object with timestamp of this packet
	 */
	timeval getTimeStamp() const { return m_Timestamp; }

private:
	const uint8_t* m_Data;
	size_t m_DataLen;
	size_t m_MissingBytes;
	const ConnectionData& m_Connection;
	timeval m_Timestamp;
};


/**
 * @struct TcpReassemblyConfiguration
 * A structure for configuring the TcpReassembly class
 */
struct TcpReassemblyConfiguration
{
	/** The flag indicating whether to remove the connection data after a connection is closed */
	bool removeConnInfo;

	/** How long the closed connections will not be cleaned up. The value is expressed in seconds. If the value is set to 0 then TcpReassembly should use the default value.
	 * This parameter is only relevant if removeConnInfo is equal to true.
	 */
	uint32_t closedConnectionDelay;

	/** The maximum number of items to be cleaned up per one call of purgeClosedConnections. If the value is set to 0 then TcpReassembly should use the default value.
	 * This parameter is only relevant if removeConnInfo is equal to true.
	 */
	uint32_t maxNumToClean;

	/** The maximum number of fragments with a non-matching sequence-number to store per connection flow before packets are assumed permanently missed.
	    If the value is 0, TcpReassembly should keep out of order fragments indefinitely, or until a message from the paired side is seen.
	 */
	uint32_t maxOutOfOrderFragments;

	/**  To enable to clear buffer once packet contains data from a different side than the side seen before
	 */
	bool enableBaseBufferClearCondition;

	/**
	 * A c'tor for this struct
	 * @param[in] removeConnInfo The flag indicating whether to remove the connection data after a connection is closed. The default is true
	 * @param[in] closedConnectionDelay How long the closed connections will not be cleaned up. The value is expressed in seconds. If it's set to 0 the default value will be used. The default is 5.
	 * @param[in] maxNumToClean The maximum number of items to be cleaned up per one call of purgeClosedConnections. If it's set to 0 the default value will be used. The default is 30.
	 * @param[in] maxOutOfOrderFragments The maximum number of unmatched fragments to keep per flow before missed fragments are considered lost. The default is unlimited.
	 * @param[in] enableBaseBufferClearCondition To enable to clear buffer once packet contains data from a different side than the side seen before
	 */
	TcpReassemblyConfiguration(bool removeConnInfo = true, uint32_t closedConnectionDelay = 5, uint32_t maxNumToClean = 30, uint32_t maxOutOfOrderFragments = 0,
		bool enableBaseBufferClearCondition = true) : removeConnInfo(removeConnInfo), closedConnectionDelay(closedConnectionDelay), maxNumToClean(maxNumToClean), maxOutOfOrderFragments(maxOutOfOrderFragments), enableBaseBufferClearCondition(enableBaseBufferClearCondition)
	{
	}
};


/**
 * @class TcpReassembly
 * A class containing the TCP reassembly logic. Please refer to the documentation at the top of TcpReassembly.h for understanding how to use this class
 */
class TcpReassembly
{
public:

	/**
	 * An enum for connection end reasons
	 */
	enum ConnectionEndReason
	{
		/** Connection ended because of FIN or RST packet */
		TcpReassemblyConnectionClosedByFIN_RST,
		/** Connection ended manually by the user */
		TcpReassemblyConnectionClosedManually
	};

	/**
	 * An enum for providing reassembly status for each processed packet
	 */
	enum ReassemblyStatus
	{
		/**
		 * The processed packet contains valid TCP payload, and its payload is processed by `OnMessageReadyCallback` callback function.
		 * The packet may be:
		 * 1. An in-order TCP packet, meaning `packet_sequence == sequence_expected`.
		 *    Note if there's any buffered out-of-order packet waiting for this packet, their associated callbacks are called in this `reassemblePacket` call.
		 * 2. An out-of-order TCP packet which satisfy `packet_sequence < sequence_expected && packet_sequence + packet_payload_length > sequence_expected`.
		 *    Note only the new data (the `[sequence_expected, packet_sequence + packet_payload_length]` part ) is processed by `OnMessageReadyCallback` callback function.
		 */
		TcpMessageHandled,
		/**
		 * The processed packet is an out-of-order TCP packet, meaning `packet_sequence > sequence_expected`. It's buffered so no `OnMessageReadyCallback` callback function is called.
		 * The callback function for this packet maybe called LATER, under different circumstances:
		 * 1. When an in-order packet which is right before this packet arrives(case 1 and case 2 described in `TcpMessageHandled` section above).
		 * 2. When a FIN or RST packet arrives, which will clear the buffered out-of-order packets of this side.
		 *    If this packet contains "new data", meaning `(packet_sequence <= sequence_expected) && (packet_sequence + packet_payload_length > sequence_expected)`, the new data is processed by `OnMessageReadyCallback` callback.
		 */
		OutOfOrderTcpMessageBuffered,
		/**
		 * The processed packet is a FIN or RST packet with no payload.
		 * Buffered out-of-order packets will be cleared.
		 * If they contain "new data", the new data is processed by `OnMessageReadyCallback` callback.
		 */
		FIN_RSTWithNoData,
		/**
		 * The processed packet is not a SYN/SYNACK/FIN/RST packet and has no payload.
		 * Normally it's just a bare ACK packet.
		 * It's ignored and no callback function is called.
		 */
		Ignore_PacketWithNoData,
		/**
		 * The processed packet comes from a closed flow(an in-order FIN or RST is seen).
		 * It's ignored and no callback function is called.
		 */
		Ignore_PacketOfClosedFlow,
		/**
		 * The processed packet is a restransmission packet with no new data, meaning the `packet_sequence + packet_payload_length < sequence_expected`.
		 * It's ignored and no callback function is called.
		 */
		Ignore_Retransimission,
		/**
		 * The processed packet is not an IP packet.
		 * It's ignored and no callback function is called.
		 */
		NonIpPacket,
		/**
		 * The processed packet is not a TCP packet.
		 * It's ignored and no callback function is called.
		 */
		NonTcpPacket,
		/**
		 * The processed packet does not belong to any known TCP connection.
		 * It's ignored and no callback function is called.
		 * Normally this will be happen.
		 */
		Error_PacketDoesNotMatchFlow,
	};

	/**
	 * The type for storing the connection information
	 */
	typedef std::map<uint32_t, ConnectionData> ConnectionInfoList;

	/**
	 * @typedef OnTcpMessageReady
	 * A callback invoked when new data arrives on a connection
	 * @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where 0 is the first side seen in the connection and 1 is the second side seen
	 * @param[in] tcpData The TCP data itself + connection information
	 * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly c'tor (or NULL if no cookie provided)
	 */
	typedef void (*OnTcpMessageReady)(int8_t side, const TcpStreamData& tcpData, void* userCookie);

	/**
	 * @typedef OnTcpConnectionStart
	 * A callback invoked when a new TCP connection is identified (whether it begins with a SYN packet or not)
	 * @param[in] connectionData Connection information
	 * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly c'tor (or NULL if no cookie provided)
	 */
	typedef void (*OnTcpConnectionStart)(const ConnectionData& connectionData, void* userCookie);

	/**
	 * @typedef OnTcpConnectionEnd
	 * A callback invoked when a TCP connection is terminated, either by a FIN or RST packet or manually by the user
	 * @param[in] connectionData Connection information
	 * @param[in] reason The reason for connection termination: FIN/RST packet or manually by the user
	 * @param[in] userCookie A pointer to the cookie provided by the user in TcpReassembly c'tor (or NULL if no cookie provided)
	 */
	typedef void (*OnTcpConnectionEnd)(const ConnectionData& connectionData, ConnectionEndReason reason, void* userCookie);

	/**
	 * A c'tor for this class
	 * @param[in] onMessageReadyCallback The callback to be invoked when new data arrives
	 * @param[in] userCookie A pointer to an object provided by the user. This pointer will be returned when invoking the various callbacks. This parameter is optional, default cookie is NULL
	 * @param[in] onConnectionStartCallback The callback to be invoked when a new connection is identified. This parameter is optional
	 * @param[in] onConnectionEndCallback The callback to be invoked when a new connection is terminated (either by a FIN/RST packet or manually by the user). This parameter is optional
	 * @param[in] config Optional parameter for defining special configuration parameters. If not set the default parameters will be set
	 */
	TcpReassembly(OnTcpMessageReady onMessageReadyCallback, void* userCookie = NULL, OnTcpConnectionStart onConnectionStartCallback = NULL, OnTcpConnectionEnd onConnectionEndCallback = NULL, const TcpReassemblyConfiguration &config = TcpReassemblyConfiguration());

	/**
	 * The most important method of this class which gets a packet from the user and processes it. If this packet opens a new connection, ends a connection or contains new data on an
	 * existing connection, the relevant callback will be called (TcpReassembly#OnTcpMessageReady, TcpReassembly#OnTcpConnectionStart, TcpReassembly#OnTcpConnectionEnd)
	 * @param[in] tcpData A reference to the packet to process
	 * @return A enum of `TcpReassembly::ReassemblyStatus`, indicating status of TCP reassembly
	 */
	ReassemblyStatus reassemblePacket(Packet& tcpData);

	/**
	 * The most important method of this class which gets a raw packet from the user and processes it. If this packet opens a new connection, ends a connection or contains new data on an
	 * existing connection, the relevant callback will be invoked (TcpReassembly#OnTcpMessageReady, TcpReassembly#OnTcpConnectionStart, TcpReassembly#OnTcpConnectionEnd)
	 * @param[in] tcpRawData A reference to the raw packet to process
	 * @return A enum of `TcpReassembly::ReassemblyStatus`, indicating status of TCP reassembly
	 */
	ReassemblyStatus reassemblePacket(RawPacket* tcpRawData);

	/**
	 * Close a connection manually. If the connection doesn't exist or already closed an error log is printed. This method will cause the TcpReassembly#OnTcpConnectionEnd to be invoked with
	 * a reason of TcpReassembly#TcpReassemblyConnectionClosedManually
	 * @param[in] flowKey A 4-byte hash key representing the connection. Can be taken from a ConnectionData instance
	 */
	void closeConnection(uint32_t flowKey);

	/**
	 * Close all open connections manually. This method will cause the TcpReassembly#OnTcpConnectionEnd to be invoked for each connection with a reason of
	 * TcpReassembly#TcpReassemblyConnectionClosedManually
	 */
	void closeAllConnections();

	/**
	 * Get a map of all connections managed by this TcpReassembly instance (both connections that are open and those that are already closed)
	 * @return A map of all connections managed. Notice this map is constant and cannot be changed by the user
	 */
	const ConnectionInfoList& getConnectionInformation() const { return m_ConnectionInfo; }

	/**
	 * Check if a certain connection managed by this TcpReassembly instance is currently opened or closed
	 * @param[in] connection The connection to check
	 * @return A positive number (> 0) if connection is opened, zero (0) if connection is closed, and a negative number (< 0) if this connection isn't managed by this TcpReassembly instance
	 */
	int isConnectionOpen(const ConnectionData& connection) const;

	/**
	 * Clean up the closed connections from the memory
	 * @param[in] maxNumToClean The maximum number of items to be cleaned up per one call. This parameter, when its value is not zero, overrides the value that was set by the constructor.
	 * @return The number of cleared items
	 */
	uint32_t purgeClosedConnections(uint32_t maxNumToClean = 0);

private:
	struct TcpFragment
	{
		uint32_t sequence;
		size_t dataLength;
		uint8_t* data;
		timeval timestamp;

		TcpFragment() : sequence(0), dataLength(0), data(NULL) {}
		~TcpFragment() { delete [] data; }
	};

	struct TcpOneSideData
	{
		IPAddress srcIP;
		uint16_t srcPort;
		uint32_t sequence;
		PointerVector<TcpFragment> tcpFragmentList;
		bool gotFinOrRst;

		TcpOneSideData() : srcPort(0), sequence(0), gotFinOrRst(false) {}
	};

	struct TcpReassemblyData
	{
		bool closed;
		int8_t numOfSides;
		int8_t prevSide;
		TcpOneSideData twoSides[2];
		ConnectionData connData;

		TcpReassemblyData() : closed(false), numOfSides(0), prevSide(-1) {}
	};

	typedef std::map<uint32_t, TcpReassemblyData> ConnectionList;
	typedef std::map<time_t, std::list<uint32_t> > CleanupList;

	OnTcpMessageReady m_OnMessageReadyCallback;
	OnTcpConnectionStart m_OnConnStart;
	OnTcpConnectionEnd m_OnConnEnd;
	void* m_UserCookie;
	ConnectionList m_ConnectionList;
	ConnectionInfoList m_ConnectionInfo;
	CleanupList m_CleanupList;
	bool m_RemoveConnInfo;
	uint32_t m_ClosedConnectionDelay;
	uint32_t m_MaxNumToClean;
	size_t m_MaxOutOfOrderFragments;
	time_t m_PurgeTimepoint;
	bool m_EnableBaseBufferClearCondition;

	void checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, bool cleanWholeFragList);

	void handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, uint32_t flowKey);

	void closeConnectionInternal(uint32_t flowKey, ConnectionEndReason reason);

	void insertIntoCleanupList(uint32_t flowKey);
};

}

#endif /* PACKETPP_TCP_REASSEMBLY */

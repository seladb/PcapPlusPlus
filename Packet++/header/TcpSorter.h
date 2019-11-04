#ifndef PACKETPP_TCP_SORTER
#define PACKETPP_TCP_SORTER
#include "Packet.h"
#include "IpAddress.h"
#include "TcpReassembly.h"
#include <map>
#include <list>
#include <time.h>
#include <memory>


/**
 *@file
 * This is an implementation of TCP segment sort logic. It groups and sorts multiple TCP segments by order from TCP connections.<BR>
 *
 * __General Features:__
 * - Manage multiple TCP connections under one pcpp#TcpSorter instance
 * - Support TCP retransmission
 * - Support out-of-order packets
 * - Support detection of missing TCP packet in capture
 * - Support two callbacks: the arrival of TCP packets and the detection of the packets missing in the packet capture.
 * - TCP connections ends by an idle timeout.
 * - TCP segment sort logic follows RFC 753 but disregards packet dropping logic,
 *   such as windows size validation, time stamp validation, and etc.
 *
 * __Logic Description:__
 * - The user creates an instance of the pcpp#TcpSorter class
 * - Then the user starts feeding it with TCP packets.
 * - The pcpp#TcpSorter instance manages all TCP connections from the packets it's being fed. For each connection it manages its 2 sides (A->B and B->A)
 * - When a packet arrives, it is first classified to a certain TCP connection
 * - Then it is classified to a certain side of the TCP connection. We assume such side is the sender.
 * - If the new arrival packet has been already acknowledged by receiver's side, drop it. Otherwise, add it to the unacknowledged packet multi map in sender's side.
 * - If ACK is set in the new arrival packet, flush the unacknowledged packets from receiver's side and set sender's ACK to receiver's SND.UNA.
 * - When flushing the unacknowledged packets, maintain an internal expected sequence number. If the internal expected sequence number is greater than or equal to
 *   the sequence number of the flushed packet, invoke callback function pcpp#TcpSorter#onTcpPacketReady with the raw packet. Otherwise, the missing packet is
 *   detected from captue and invoke callback function pcpp#TcpSorter#OnTcpPacketMIssing.
 *
 * __Basic Usage and APIs:__
 * - pcpp#TcpSorter c'tor - Create an instance, provide the callbacks and the user cookie to the instance
 * - pcpp#TcpSorter#sortPacket() - Feed pcpp#TcpSorter instance with packets
 * - pcpp#TcpSorter#closeAllConnections() - Manually close all currently opened connections
 * - pcpp#TcpSorter#OnTcpPacketReady callback - Invoked when new data arrives on a certain connection. Contains the new data as well as connection data (5-tuple, flow key).
 * - pcpp#TcpSorter#OnTcpPacketMIssing callback - Invoked when detect a missing packet from capture.
 *
 * __Additional information:__
 *
 * - Clean up inactive TCP connection. In case of half-closed TCP connection, it is unwise to stop sorting prematurely
 *   once FIN bit is set in the packet. An inactive timer is setup in each TCP connection. pcpp#TcpSorter scans
 *   a predefined random subset of all TCP connection periodically and check if inactivity of the TCP connection
 *   passes the idle time out.
 */

#define SEQ_LT(a,b)		(static_cast<int32_t>((a)-(b)) < 0)
#define SEQ_LEQ(a,b)		(static_cast<int32_t>((a)-(b)) <= 0)
#define SEQ_GT(a,b)		(static_cast<int32_t>((a)-(b)) > 0)
#define SEQ_GEQ(a,b)		(static_cast<int32_t>((a)-(b)) >= 0)

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
/**
 * @struct TcpSorterConfiguration
 * A structure for configuring the TcpSorter class
 */
struct TcpSorterConfiguration
{
	/** The maximum number of captured packets from both sides in each TCP connection.
	 * The default value 0 means unlimited.
	 */
	uint64_t maxNumCapturedPacket;

	/** The maximum idle timeout in seconds for inactive TCP connections
	 * The default value 0 means it disable clean up inactive TCP connections.
	 */
	uint32_t maxIdleTimeout;

	/** The maximum number of inactive TCP connection scanning in each batch
	 * The default value is 100. The value 0 means scanning all.
	 */
	uint32_t maxNumInactiveConnScan;

	/** The time period in seconds to trigger clean up inactive TCP connection
	 * The default value is 60 seconds.
	 */
	uint32_t cleanUpInactiveConnPeriod;

	/** The maximum segment lifetime
	 * The default value is 60 seconds. In TIME_WAIT state, TCP state machine wait for twice the maximum segment lifetime until transit to the CLOSED state.
	 */
	uint32_t maxSegmentLifeTime;

	/** The flag indicating to include empty segments */
	bool shouldIncludeEmptySegments;

	/**
	 * A c'tor for TcpSorterConfiguration struct
	 * @param[in] maxNumCapturedPacket The maximum number of captured packets from both sides in each TCP connection. The default value 0 means unlimited.
	 * @param[in] maxIdleTimeout The maximum idle timeout in seconds for inactive TCP connections. The default value 0 means disable clean up inactive TCP connections.
	 * @param[in] maxNumInactiveConnScan The maximum number of inactive TCP connection scanning in each batch. The default value is 100. The value 0 means scanning all.
	 * @param[in] cleanUpInactiveConnPeriod The time period in seconds to trigger clean up inactive TCP connection. The default value is 60.
	 * @param[in] maxSegmentLifeTime The maximum segment lifetime. The default value is 60 seconds. In TIME_WAIT state, TCP state machine wait for twice the maximum segment lifetime until transit to the CLOSED state.
	 * @param[in] shouldIncludeEmptySegments The flag indicating to include empty segments. The default value is true.
	 */
	TcpSorterConfiguration(
									uint64_t maxNumCapturedPacket       = 0,
									uint32_t maxIdleTimeout             = 0,
									uint32_t maxNumInactiveConnScan     = 100,
									uint32_t cleanUpInactiveConnPeriod  = 60,
									uint32_t maxSegmentLifeTime         = 60,
									bool shouldIncludeEmptySegments     = true) :
		maxNumCapturedPacket(maxNumCapturedPacket),
		maxIdleTimeout(maxIdleTimeout),
		maxNumInactiveConnScan(maxNumInactiveConnScan),
		cleanUpInactiveConnPeriod(cleanUpInactiveConnPeriod),
		maxSegmentLifeTime(maxSegmentLifeTime),
		shouldIncludeEmptySegments(shouldIncludeEmptySegments)
	{
	}
};

/**
 * @class TcpSorter
 * A class containing the TCP packet sorting logic. Please refer to the documentation at the top of TcpSorter.h for understanding how to use this class
 */
class TcpSorter
{
public:

	/**
	 * @typedef SPRawPacket
	 * The type for shared pointer of raw packet
	 */
	typedef std::shared_ptr<RawPacket> SPRawPacket;

	/**
	 * An enum for TCP state transition
	 */
	enum TcpConnectionState
	{
		CLOSED,
		LISTEN,
		SYN_SENT,
		SYN_RCVD,
		ESTABLISHED,
		CLOSE_WAIT,
		LAST_ACK,
		FIN_WAIT_1,
		FIN_WAIT_2,
		CLOSING,
		TIME_WAIT
	};


	/**
	 * @typedef OnTcpPacketReady
	 * A callback invoked when new TCP packet arrives on a connection
	 * @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where 0 is the first side seen in the connection and 1 is the second side seen
	 * @param[in] connData Connection meta data
	 * @param[in] spRawPacket A shared pointer to a new arrival TCP packet
	 * @param[in] userCookie A pointer to the cookie provided by the user in TcpSorter c'tor (or nullptr if no cookie provided)
	 */
	typedef void (*OnTcpPacketReady)(int side, ConnectionData connData, SPRawPacket spRawPacket, void* userCookie);

	/**
	 * @typedef OnTcpPacketMissing
	 * A callback invoked when found TCP packet missing in capturing
	 * @param[in] side The side this data belongs to (MachineA->MachineB or vice versa). The value is 0 or 1 where 0 is the first side seen in the connection and 1 is the second side seen
	 * @param[in] connData Connection meta data
	 * @param[in] seq The sequence number of the missing packet
	 * @param[in] length The length of the missing packet
	 * @param[in] userCookie A pointer to the cookie provided by the user in TcpSorter c'tor (or nullptr if no cookie provided)
	 */
	typedef void (*OnTcpPacketMissing)(int side, ConnectionData connData, uint32_t seq, uint32_t length, void* userCookie);

	/**
	 * A c'tor for TcpSorter class
	 * @param[in] onPacketReadyCallback The callback to be invoked when new TCP packet arrives
	 * @param[in] onPacketMissingCallback The callback to be invoked when found TCP packet is missing in capture
	 * @param[in] userCookie A pointer to an object provided by the user. This pointer will be returned when invoking the various callbacks. This parameter is optional, default cookie is nullptr
	 * @param[in] config Optional parameter for defining special configuration parameters. If not set the default parameters will be set
	 */
	TcpSorter(OnTcpPacketReady onPacketReadyCallback,
				 OnTcpPacketMissing onPacketMissingCallback = nullptr,
				 void* userCookie = nullptr,
				 const TcpSorterConfiguration &config = TcpSorterConfiguration());

	/**
	 * A d'tor for this class. Close all connections.
	 */
	virtual ~TcpSorter();

	/**
	 * The most important method of this class which gets a raw packet from the user and processes it.
	 * The raw packet will be added to unacknowledged packet list.
	 * If this packet contains ACK bit,	the relevant callback will be invoked (TcpSorter#OnTcpPacketReady, TcpSorter#OnTcpPacketMissing)
	 * @param[in] spRawPacket A shared pointer to the raw packet
	 */
	void sortPacket(SPRawPacket spRawPacket);

	/**
	 * Stop sorting packet and clean up all captured connection.
	 */
	void closeAllConnections();

private:
	/**
	 * @struct SequenceLessThan struct provides sequence number less than comparision method.
	 */
	struct SequenceLessThan {
		bool operator()(const uint32_t leftSeq, const uint32_t rightSeq) const {
			return SEQ_LT(leftSeq, rightSeq);
		}
	};

	/**
	 * @typedef RawPacketMultiMap defines multi map with customized sequence comparison method.
	 */
	typedef std::multimap<uint32_t, SPRawPacket, SequenceLessThan> RawPacketMultiMap;

	/**
	 * @struct TcpOneSideData struct represents the packets from the sender's perspective.
	 */
	struct TcpOneSideData
	{
		RawPacketMultiMap uPacketMap; // unacknowledged raw packet map
		IPAddress* srcIP; // source IP address
		uint64_t acceptedPacketCount;
		uint32_t sndUna; // send unacknowledged
		uint32_t expSeq; // next expected sequence number for packet flushing
		TcpConnectionState tcpState; // tcp state
		uint16_t srcPort; // source port
		bool gotFinOrRst;

		void setSrcIP(IPAddress* sourrcIP);

		TcpOneSideData() { srcIP = nullptr; srcPort = 0; sndUna = 0; gotFinOrRst = false; acceptedPacketCount = 0; tcpState = CLOSED; }

		~TcpOneSideData() { if (srcIP != nullptr) delete srcIP; }
	};

	/**
	 * @struct TcpSorterData struct represents the TCP connection
	 */
	struct TcpSorterData
	{
		TcpOneSideData twoSides[2];
		ConnectionData connData;
		time_t lastActiveTimeStamp;
		int numOfSides;
		bool hasTcp3WayHandShake;

		TcpSorterData() { numOfSides = 0; lastActiveTimeStamp = 0; hasTcp3WayHandShake = false;}
	};

	typedef std::shared_ptr<TcpSorterData> SPTcpSorterData;
	typedef std::map<uint32_t, SPTcpSorterData> ConnectionList;

	// callback function
	OnTcpPacketReady m_OnPacketReadyCallback;
	OnTcpPacketMissing m_OnPacketMissingCallback;
	// user defined handler
	void* m_UserCookie;
	// The key data structure to store TCP connection.
	// a map: flow key -> TcpSorterData
	ConnectionList m_ConnectionList;
	// time stamp for recording last clean up TCP connection
	time_t m_LastCleanupTime;
	// configuration variables
	uint64_t m_MaxNumCapturedPacket;
	bool m_ShouldIncludeEmptySegments;
	// a boolean flag to determine if all connections are closed
	bool m_isClosed;
	uint32_t m_MaxIdleTimeout;
	uint32_t m_CleanUpInactiveConnPeriod;
	uint32_t m_MaxNumInactiveConnScan;
	uint32_t m_MaxSegmentLifeTime;

	/**
	 * @brief cleanUpInactiveTcpConnection Clean up inactive TCP connection by random sample without replacement method.
	 * @param now time stamp now
	 */
	void cleanUpInactiveTcpConnection(time_t now);
	/**
	 * @brief closeConnection Close one TCP connection. Flush the last unacknowledged packet if any.
	 * @param flowKey flow key of the TCP connection
	 */
	void closeConnection(uint32_t flowKey);
	/**
	 * @brief flushPacket Given sender's ACK, flush all acknowledged packets from receiver's side.
	 * @param tcpSorterData TCP connection
	 * @param ack sender's ACK
	 * @param rcvIdx receiver index
	 */
	void flushPacket(SPTcpSorterData tcpSorterData, uint32_t ack, int rcvIdx);
};

}
#endif // PACKETTPP_TCP_SORTER

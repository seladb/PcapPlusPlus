#define LOG_MODULE PacketLogModuleTcpSorter

#include "TcpSorter.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PacketUtils.h"
#include "IpAddress.h"
#include "Logger.h"
#include <sstream>
#include <random>
#include <vector>
#include <algorithm>
#if defined(WIN32) || defined(PCAPPP_MINGW_ENV) //for using ntohl, ntohs, etc.
#include <winsock2.h>
#elif LINUX
#include <in.h> //for using ntohl, ntohs, etc.
#elif MAC_OS_X || FREEBSD
#include <arpa/inet.h> //for using ntohl, ntohs, etc.
#endif

#define PURGE_FREQ_SECS 1

namespace pcpp
{

TcpSorter::TcpSorter(
							OnTcpPacketReady onPacketReadyCallback,
							OnTcpPacketMissing onPacketMissingCallback,
							void* userCookie,
							const TcpSorterConfiguration &config)
{
	m_isClosed = false;
	m_OnPacketReadyCallback = onPacketReadyCallback;
	m_OnPacketMissingCallback = onPacketMissingCallback;
	m_UserCookie = userCookie;
	// configuration value
	m_MaxNumCapturedPacket = config.maxNumCapturedPacket;
	m_MaxIdleTimeout = config.maxIdleTimeout;
	m_MaxNumInactiveConnScan = config.maxNumInactiveConnScan;
	m_MaxSegmentLifeTime = config.maxSegmentLifeTime;
	m_CleanUpInactiveConnPeriod = config.cleanUpInactiveConnPeriod;
	m_ShouldIncludeEmptySegments = config.shouldIncludeEmptySegments;
	// reset clean up timer
	m_LastCleanupTime = time(NULL);
}

TcpSorter::~TcpSorter()
{
	closeAllConnections();
}

void TcpSorter::sortPacket(SPRawPacket spRawPacket)
{
	// stop sorting if it is closed
	if(m_isClosed)
	{
		return;
	}
	// parse the packet
	Packet packet(spRawPacket.get(), false);

	time_t now = time(NULL);

	// clean up any expired inactive TCP connection
	if (0 != m_MaxIdleTimeout && m_LastCleanupTime + m_CleanUpInactiveConnPeriod < now)
	{
		cleanUpInactiveTcpConnection(now);
		m_LastCleanupTime = now;
	}

	// get IP layer
	Layer* ipLayer = nullptr;
	if (packet.isPacketOfType(IPv4))
		ipLayer = dynamic_cast<Layer*>(packet.getLayerOfType<IPv4Layer>());
	else if (packet.isPacketOfType(IPv6))
		ipLayer = dynamic_cast<Layer*>(packet.getLayerOfType<IPv6Layer>());

	if (ipLayer == nullptr)
		return;

	// Ignore non-TCP packets
	TcpLayer* tcpLayer = packet.getLayerOfType<TcpLayer>();
	if (tcpLayer == nullptr)
		return;

	// Ignore the packet if it's an ICMP packet that has a TCP layer
	// Several ICMP messages (like "destination unreachable") have TCP data as part of the ICMP message.
	// This is not real TCP data and packet can be ignored
	if (packet.isPacketOfType(ICMP))
	{
		LOG_DEBUG("Packet is of type ICMP so TCP data is probably  part of the ICMP message. Ignoring this packet");
		return;
	}

	// set the TCP payload size
	uint32_t tcpPayloadSize =static_cast<uint32_t>(tcpLayer->getLayerPayloadSize());

	// get TCP flag
	bool isAck = (tcpLayer->getTcpHeader()->ackFlag == 1);
	bool isSyn = (tcpLayer->getTcpHeader()->synFlag == 1);
	bool isFin = (tcpLayer->getTcpHeader()->finFlag == 1);
	bool isRst = (tcpLayer->getTcpHeader()->rstFlag == 1);

	// TCP connection for captured packet
	SPTcpSorterData tcpSorterData = nullptr;

	// calculate flow key for this packet
	uint32_t flowKey = hash5Tuple(&packet);

	// find the connection in the connection map
	ConnectionList::iterator iter = m_ConnectionList.find(flowKey);

	// get packet's source and dest IP address
	IPAddress* srcIP = nullptr;
	IPAddress* dstIP = nullptr;
	IPv4Address srcIP4Addr = IPv4Address::Zero;
	IPv6Address srcIP6Addr = IPv6Address::Zero;
	IPv4Address dstIP4Addr = IPv4Address::Zero;
	IPv6Address dstIP6Addr = IPv6Address::Zero;
	if (ipLayer->getProtocol() == IPv4)
	{
		srcIP4Addr = (dynamic_cast<IPv4Layer*>(ipLayer))->getSrcIpAddress();
		srcIP = &srcIP4Addr;
		dstIP4Addr = (dynamic_cast<IPv4Layer*>(ipLayer))->getDstIpAddress();
		dstIP = &dstIP4Addr;
	}
	else if (ipLayer->getProtocol() == IPv6)
	{
		srcIP6Addr = (dynamic_cast<IPv6Layer*>(ipLayer))->getSrcIpAddress();
		srcIP = &srcIP6Addr;
		dstIP6Addr = (dynamic_cast<IPv6Layer*>(ipLayer))->getDstIpAddress();
		dstIP = &dstIP6Addr;
	}

	// if TCP connection doesn't exist, create one
	if (iter == m_ConnectionList.end())
	{
		// The SYN flag in the first packet must be set.
		if (! isSyn)
		{
			LOG_DEBUG("Ignore packet of a flow [0x%X] that doesn't start with 3 way handshake.", flowKey);
			return;
		}
		// create a TcpSorterData object and add it to the active connection list
		tcpSorterData = std::make_shared<TcpSorterData>();
		tcpSorterData->connData.setSrcIpAddress(srcIP);
		tcpSorterData->connData.setDstIpAddress(dstIP);
		tcpSorterData->connData.srcPort = ntohs(tcpLayer->getTcpHeader()->portSrc);
		tcpSorterData->connData.dstPort = ntohs(tcpLayer->getTcpHeader()->portDst);
		tcpSorterData->connData.flowKey = flowKey;
		timeval ts = packet.getRawPacket()->getPacketTimeStamp();
		tcpSorterData->connData.setStartTime(ts);
		m_ConnectionList[flowKey] = tcpSorterData;
	}
	else // connection already exists
	{
		tcpSorterData = iter->second;
	} // end of connection exists

	// sender's side index
	int sndIdx = -1;

	// get packet's source port
	uint16_t srcPort = tcpLayer->getTcpHeader()->portSrc;

	// if this is a new connection and it's the first packet we see on that connection
	if (tcpSorterData->numOfSides == 0)
	{
		LOG_DEBUG("Setting side for new connection");

		// open the first side of the connection, side index is 0
		sndIdx = 0;
		tcpSorterData->twoSides[sndIdx].setSrcIP(srcIP);
		tcpSorterData->twoSides[sndIdx].srcPort = srcPort;
		tcpSorterData->numOfSides++;
	}
	// if there is already one side in this connection (which will be at side index 0)
	else if (tcpSorterData->numOfSides == 1)
	{
		// check if packet belongs to that side
		if (tcpSorterData->twoSides[0].srcIP->equals(srcIP) && tcpSorterData->twoSides[0].srcPort == srcPort)
		{
			sndIdx = 0;
		}
		else
		{
			// this means packet belong to the second side which doesn't yet exist. Open a second side with side index 1
			LOG_DEBUG("Setting second side of a connection");
			sndIdx = 1;
			tcpSorterData->twoSides[sndIdx].setSrcIP(srcIP);
			tcpSorterData->twoSides[sndIdx].srcPort = srcPort;
			tcpSorterData->numOfSides++;
		}
	}
	// if there are already 2 sides open for this connection
	else if (tcpSorterData->numOfSides == 2)
	{
		// check if packet matches side 0
		if (tcpSorterData->twoSides[0].srcIP->equals(srcIP) && tcpSorterData->twoSides[0].srcPort == srcPort)
		{
			sndIdx = 0;
		}
		// check if packet matches side 1
		else if (tcpSorterData->twoSides[1].srcIP->equals(srcIP) && tcpSorterData->twoSides[1].srcPort == srcPort)
		{
			sndIdx = 1;
		}
		// packet doesn't match either side. This case doesn't make sense but it's handled anyway. Packet will be ignored
		else
		{
			LOG_ERROR("Error occurred - packet doesn't match either side of the connection!!");
			return;
		}
	}
	// there are more than 2 side - this case doesn't make sense and shouldn't happen, but handled anyway. Packet will be ignored
	else
	{
		LOG_ERROR("Error occurred - connection has more than 2 sides!!");
		return;
	}

	int rcvIdx = 1 - sndIdx;

	// no further processing if accepted packe count reach maximum
	if (0 != m_MaxNumCapturedPacket &&
			((tcpSorterData->twoSides[rcvIdx].acceptedPacketCount +
				tcpSorterData->twoSides[sndIdx].acceptedPacketCount) >= m_MaxNumCapturedPacket))
	{
		return;
	}

	// update TCP connection last active timestamp
	tcpSorterData->lastActiveTimeStamp = now;

	// extract sequence number and acknoledgement number if any
	uint32_t seq = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
	uint32_t ack = ntohl(tcpLayer->getTcpHeader()->ackNumber);

	// Get previous TCP state
	auto sndState = tcpSorterData->twoSides[sndIdx].tcpState;
	auto rcvState = tcpSorterData->twoSides[rcvIdx].tcpState;

	// Update TCP state
	/** Assumption:
	 *
	 * Alice sends a packet to Bob. TcpSorter captures this packet.
	 *
	 * - If (seq + Tcp payload size) >= Alice's SND.UNA, insert the packet into
	 *   Alice's unacknowledged packet multimap with key = (seq + Tcp payload size).
	 *   Otherwise, drop the packet.
	 *
	 * - If Alice sends an ACK, Bob should flush the packets from his unacknowledged
	 *   packet multimap with key up to Alice's ACK and set his SND.UNA to Alice's ACK
	 *   (assuming Bob must receive ACK packet from Alice. If not, Bob would keep sending
	 *    to Alice.).
	 *
	 */

	// For the first packet, we have an early return for special handling.
	/** Start of special handling. **/
	if (sndState == CLOSED)
	{
		if (isSyn)
		{
			// isSyn && isAck
			if (isAck)
			{
				// validate if the sender's ACK matches the receiver's SYN
				if (SEQ_LEQ(tcpSorterData->twoSides[rcvIdx].sndUna, ack))
				{
					// passive OPEN: CLOSED => LISTEN =>  SYN_RCVD, skip LISTEN
					tcpSorterData->twoSides[sndIdx].tcpState = SYN_RCVD;
					// set to ISS
					tcpSorterData->twoSides[sndIdx].expSeq = seq;
					// flush packet in receiver side
					flushPacket(tcpSorterData, ack, rcvIdx);
				}
				else
				{
					LOG_ERROR("Found incorrect ACK number in 3 way TCP handshake.");
					return;
				}
			}
			// isSyn && !isAck
			else
			{
				// active OPEN: CLOSED => SYN_SENT or SEND: LISTEN => SYN_SENT
				tcpSorterData->twoSides[sndIdx].tcpState = SYN_SENT;
				// set to ISS
				tcpSorterData->twoSides[sndIdx].expSeq = seq;
			}

			// Initialize SND.UNA with ISS. Per RFC 7413 TCP Fast Open, add TCP pay load size.
			tcpSorterData->twoSides[sndIdx].sndUna = seq + tcpPayloadSize;
			// Insert the packet into unack packet map.
			tcpSorterData->twoSides[sndIdx].uPacketMap.insert({seq + tcpPayloadSize, spRawPacket});
		} // end of isSyn is true

		if (isRst)
		{
			// isRst && isAck
			if (isAck)
			{
				if (SEQ_LEQ(tcpSorterData->twoSides[rcvIdx].sndUna, ack))
				{
					// force closing connection
					tcpSorterData->twoSides[sndIdx].tcpState = CLOSED;
					tcpSorterData->twoSides[rcvIdx].tcpState = CLOSED;
					tcpSorterData->twoSides[sndIdx].expSeq = seq;
					flushPacket(tcpSorterData, ack, rcvIdx);
					tcpSorterData->twoSides[sndIdx].sndUna = seq + tcpPayloadSize;
					tcpSorterData->twoSides[sndIdx].uPacketMap.insert({seq + tcpPayloadSize, spRawPacket});
					closeConnection(flowKey);
				}
			}
		} // end of isRst is true
		return;
	} // end of sender's CLOSED state

	/** End of speical handling. From below, it needs to take care of sndUna, sndNxt and flush the packet in the receiver side.**/

	if (sndState == SYN_RCVD)
	{
		if (isFin)
		{
			// Close: SYN_RCVD => FIN_WAIT_1
			tcpSorterData->twoSides[sndIdx].tcpState = FIN_WAIT_1;
		}
	} // end of sender's SYN_RCVD state

	if (sndState == SYN_SENT)
	{
		if (isAck)
		{
			if (SEQ_LEQ(tcpSorterData->twoSides[rcvIdx].sndUna, ack))
			{
				tcpSorterData->twoSides[sndIdx].tcpState = ESTABLISHED;
				// change receiver side to ESTABLISHED, we assume the receiver side is going to get this ACK packet
				if (rcvState == SYN_RCVD)
				{
					tcpSorterData->twoSides[rcvIdx].tcpState = ESTABLISHED;
				}
			}
		}
	} // end of sender's SYN_SENT state


	if (sndState == ESTABLISHED)
	{
		if (isFin)
		{
			// Close: ESTABLISHED => FIN_WAIT_1
			tcpSorterData->twoSides[sndIdx].tcpState = FIN_WAIT_1;
		}

		if (rcvState == FIN_WAIT_1 && isAck && SEQ_LEQ(tcpSorterData->twoSides[rcvIdx].sndUna, ack))
		{
			// the receiver side sends FIN and the sender sends ACK,
			// ESTABLISED => CLOSE_WAIT
			tcpSorterData->twoSides[sndIdx].tcpState = CLOSE_WAIT;
		}
	} // end of sendr's ESTABLISHED state

	// Perhaps take care of the rest TCP states... But for now, it is OK.

	// update TCP 3 way handshake boolean flag
	if (!tcpSorterData->hasTcp3WayHandShake &&
		 tcpSorterData->twoSides[sndIdx].tcpState == ESTABLISHED &&
		 tcpSorterData->twoSides[rcvIdx].tcpState == ESTABLISHED)
	{
		tcpSorterData->hasTcp3WayHandShake = true;
	}

	// insert sender's packet to unacknowledged packet multimap only it is unacknowledged.
	if(SEQ_GEQ(seq + tcpPayloadSize, tcpSorterData->twoSides[sndIdx].sndUna))
	{
		tcpSorterData->twoSides[sndIdx].uPacketMap.insert({seq + tcpPayloadSize, spRawPacket});
	}


	// if there is ACK in sender's side, flush acknowledged TCP packets in the receiver's side
	if (isAck)
	{
		flushPacket(tcpSorterData, ack, rcvIdx);
	}

}

void TcpSorter::closeConnection(uint32_t flowKey)
{
	auto iter = m_ConnectionList.find(flowKey);
	if (iter != m_ConnectionList.end())
	{
		auto tcpSorterData = iter->second;
		if (0 != m_MaxNumCapturedPacket &&
				((tcpSorterData->twoSides[0].acceptedPacketCount +
					tcpSorterData->twoSides[1].acceptedPacketCount) >= m_MaxNumCapturedPacket))
		{
			return;
		}
		// flush the remaining packet if there is only one packet left
		auto numUnackPacketAtSide0 = tcpSorterData->twoSides[0].uPacketMap.size();
		auto numUnackPacketAtSide1 = tcpSorterData->twoSides[1].uPacketMap.size();
		if (1 == (numUnackPacketAtSide0 + numUnackPacketAtSide1))
		{
			int idx = (1 == numUnackPacketAtSide0)? 0: 1;
			auto spRawPacket = tcpSorterData->twoSides[idx].uPacketMap.begin()->second;
			m_OnPacketReadyCallback(idx, tcpSorterData->connData, spRawPacket, m_UserCookie);
			tcpSorterData->twoSides[idx].uPacketMap.erase(tcpSorterData->twoSides[idx].uPacketMap.begin());
		}
	}
}

void TcpSorter::closeAllConnections()
{
	if (!m_isClosed)
	{
		m_isClosed = true;

		for(auto it = m_ConnectionList.begin(); it != m_ConnectionList.end(); it++)
		{
			closeConnection(it->first);
		}

		m_ConnectionList.clear();
	}
}

/**
 * Given sender's ACK, flush acknowledged packets from receiver's side.
 */
void TcpSorter::flushPacket(SPTcpSorterData tcpSorterData, uint32_t ack, int rcvIdx)
{
	int sndIdx = 1 - rcvIdx;

	if (tcpSorterData->twoSides[rcvIdx].uPacketMap.empty())
	{
		// update SND.UNA with ACK
		tcpSorterData->twoSides[rcvIdx].sndUna = ack;
		return;
	}

	std::list<SPRawPacket> aPacketList; // acknowledged raw packet list

	auto itLowerAck = tcpSorterData->twoSides[rcvIdx].uPacketMap.lower_bound(ack);
	// move packets up to ack (not include ack)
	for (auto it = tcpSorterData->twoSides[rcvIdx].uPacketMap.begin();
		  it != itLowerAck;
		  ++it)
	{
		aPacketList.push_back(it->second);
	}
	// move packets with key = ack
	auto equRange = tcpSorterData->twoSides[rcvIdx].uPacketMap.equal_range(ack);
	for (auto it = equRange.first; it != equRange.second; ++it)
	{
		aPacketList.push_back(it->second);
	}

	uint32_t expSeq = tcpSorterData->twoSides[rcvIdx].expSeq;

	// remove acknowledged packet from unacknowledged packet
	if (!aPacketList.empty())
	{
		auto itUpperAck = tcpSorterData->twoSides[rcvIdx].uPacketMap.upper_bound(ack);
		auto itBegin = tcpSorterData->twoSides[rcvIdx].uPacketMap.begin();
		tcpSorterData->twoSides[rcvIdx].uPacketMap.erase(itBegin, itUpperAck);
	}

	while (!aPacketList.empty())
	{
		auto spRawPacket = aPacketList.front();
		aPacketList.pop_front();
		// parse the packet
		Packet packet(spRawPacket.get(), false);
		TcpLayer * tcpLayer = packet.getLayerOfType<TcpLayer>();
		if (tcpLayer == nullptr)
			continue;
		uint32_t tcpPayloadSize =static_cast<uint32_t>(tcpLayer->getLayerPayloadSize());
		uint32_t seq = ntohl(tcpLayer->getTcpHeader()->sequenceNumber);
		bool isSyn = (tcpLayer->getTcpHeader()->synFlag == 1);
		bool isFin = (tcpLayer->getTcpHeader()->finFlag == 1);

		// expected sequencepacket sequence number
		if (SEQ_GEQ(expSeq, seq))
		{
			if (tcpPayloadSize > 0 || ( 0 == tcpPayloadSize && m_ShouldIncludeEmptySegments))
			{
				if (0 == m_MaxNumCapturedPacket ||
					 ((tcpSorterData->twoSides[rcvIdx].acceptedPacketCount +
						tcpSorterData->twoSides[sndIdx].acceptedPacketCount) <= m_MaxNumCapturedPacket))
				{
					m_OnPacketReadyCallback(rcvIdx, tcpSorterData->connData, spRawPacket, m_UserCookie);
					tcpSorterData->twoSides[rcvIdx].acceptedPacketCount++;
				}
			}

			// advance expected sequence number only if it grows
			if (SEQ_GT(seq + tcpPayloadSize, expSeq))
			{
				expSeq = seq + tcpPayloadSize;
			}

			// override for Syn or Fin packet
			if ((isSyn || isFin) && SEQ_GT(seq + tcpPayloadSize + 1, expSeq))
			{
				expSeq = seq + tcpPayloadSize + 1;
			}
		}
		// found missing packets
		else
		{
			m_OnPacketMissingCallback(rcvIdx, tcpSorterData->connData, expSeq, seq - expSeq, m_UserCookie);
			// update expected sequence number with packet sequence number
			expSeq = seq;
			// add back packet to the front
			aPacketList.push_front(spRawPacket);
		}
	} // end of while looping acknowledged packet list

	tcpSorterData->twoSides[rcvIdx].expSeq = expSeq;

	// update SND.UNA with ACK
	tcpSorterData->twoSides[rcvIdx].sndUna = ack;
}

void TcpSorter::TcpOneSideData::setSrcIP(IPAddress* sourrcIP)
{
	if (srcIP != nullptr)
		delete srcIP;

	srcIP = sourrcIP->clone();
}

void TcpSorter::cleanUpInactiveTcpConnection(time_t now)
{
	// if disable clean up
	if (0 == m_MaxIdleTimeout)
	{
		return;
	}

	// collect flowKeys from TCP connection list
	auto iterKey = m_ConnectionList.begin(), iterKeyEnd = m_ConnectionList.end();
	std::vector<uint32_t> accessKeys;
	for(; iterKey != iterKeyEnd; iterKey++)
	{
		accessKeys.push_back(iterKey->first);
	}

	// if scan partial of TCP connection list, use random sample without replacement method to get a partial list.
	if (0 != m_MaxNumInactiveConnScan)
	{
		// shuffle the access keys
		std::shuffle(accessKeys.begin(), accessKeys.end(), std::default_random_engine(static_cast<unsigned long>(now)));
		// only keep the first m_MaxNumInactiveConnScan elements
		if (accessKeys.size() > m_MaxNumInactiveConnScan)
		{
			accessKeys.resize(m_MaxNumInactiveConnScan);
		}
	}

	auto iterAccessKey = accessKeys.begin(), iterAccessKeyEnd = accessKeys.end();
	for(; iterAccessKey != iterAccessKeyEnd; iterAccessKey++)
	{
		auto it = m_ConnectionList.find(*iterAccessKey);
		// assert accessKey can be found
		if (m_ConnectionList.end() == it)
		{
			continue;
		}
		auto tcpSorterData = it->second;
		// check if last active timestamp passes idel timeout
		if (tcpSorterData->lastActiveTimeStamp + m_MaxIdleTimeout <= now)
		{
			// close connection
			closeConnection(it->first);
			// clean up expire tcpSorterData
			m_ConnectionList.erase(*iterAccessKey);
		}
	}
}

} // end of namespace pcpp

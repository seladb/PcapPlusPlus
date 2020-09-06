#define LOG_MODULE PacketLogModuleTcpReassembly

#include "TcpReassembly.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <sstream>
#include <vector>
#include "EndianPortable.h"
#include "TimespecTimeval.h"
#ifdef _MSC_VER
#include <time.h>
#endif

#define PURGE_FREQ_SECS 1

#define SEQ_LT(a,b)  ((int32_t)((a)-(b)) < 0)
#define SEQ_LEQ(a,b) ((int32_t)((a)-(b)) <= 0)
#define SEQ_GT(a,b)  ((int32_t)((a)-(b)) > 0)
#define SEQ_GEQ(a,b) ((int32_t)((a)-(b)) >= 0)

namespace pcpp
{

static timeval timespecToTimeval(const timespec& in)
{
	timeval out;
	TIMESPEC_TO_TIMEVAL(&out, &in);
	return out;
}


TcpReassembly::TcpReassembly(OnTcpMessageReady onMessageReadyCallback, void* userCookie, OnTcpConnectionStart onConnectionStartCallback, OnTcpConnectionEnd onConnectionEndCallback, const TcpReassemblyConfiguration &config)
{
	m_OnMessageReadyCallback = onMessageReadyCallback;
	m_UserCookie = userCookie;
	m_OnConnStart = onConnectionStartCallback;
	m_OnConnEnd = onConnectionEndCallback;
	m_ClosedConnectionDelay = (config.closedConnectionDelay > 0) ? config.closedConnectionDelay : 5;
	m_RemoveConnInfo = config.removeConnInfo;
	m_MaxNumToClean = (config.removeConnInfo == true && config.maxNumToClean == 0) ? 30 : config.maxNumToClean;
	m_PurgeTimepoint = time(NULL) + PURGE_FREQ_SECS;
}


TcpReassembly::ReassemblyStatus TcpReassembly::reassemblePacket(Packet& tcpData)
{
	// automatic cleanup
	if (m_RemoveConnInfo == true)
	{
		if (time(NULL) >= m_PurgeTimepoint)
		{
			purgeClosedConnections();
			m_PurgeTimepoint = time(NULL) + PURGE_FREQ_SECS;
		}
	}


	// calculate packet's source and dest IP address
	IPAddress srcIP, dstIP;

	if (tcpData.isPacketOfType(IPv4))
	{
		const IPv4Layer* ipv4Layer = tcpData.getLayerOfType<IPv4Layer>();
		if (ipv4Layer != NULL)
		{
			srcIP = ipv4Layer->getSrcIpAddress();
			dstIP = ipv4Layer->getDstIpAddress();
		}
		else
			return NonIpPacket;
	}
	else if (tcpData.isPacketOfType(IPv6))
	{
		const IPv6Layer* ipv6Layer = tcpData.getLayerOfType<IPv6Layer>();
		if (ipv6Layer != NULL)
		{
			srcIP = ipv6Layer->getSrcIpAddress();
			dstIP = ipv6Layer->getDstIpAddress();
		}
		else
			return NonIpPacket;
	}
	else
		return NonIpPacket;

	// in real traffic the IP addresses cannot be an unspecified
	if (!srcIP.isValid() || !dstIP.isValid())
		return NonIpPacket;


	// Ignore non-TCP packets
	TcpLayer* tcpLayer = tcpData.getLayerOfType<TcpLayer>(true); // lookup in reverse order
	if (tcpLayer == NULL)
	{
		return NonTcpPacket;
	}

	// Ignore the packet if it's an ICMP packet that has a TCP layer
	// Several ICMP messages (like "destination unreachable") have TCP data as part of the ICMP message.
	// This is not real TCP data and packet can be ignored
	if (tcpData.isPacketOfType(ICMP))
	{
		LOG_DEBUG("Packet is of type ICMP so TCP data is probably part of the ICMP message. Ignoring this packet");
		return NonTcpPacket;
	}

	ReassemblyStatus status = TcpMessageHandled;

	// set the TCP payload size
	size_t tcpPayloadSize = tcpLayer->getLayerPayloadSize();

	// calculate if this packet has FIN or RST flags
	bool isFin = (tcpLayer->getTcpHeader()->finFlag == 1);
	bool isRst = (tcpLayer->getTcpHeader()->rstFlag == 1);
	bool isFinOrRst = isFin || isRst;

	// ignore ACK packets or TCP packets with no payload (except for SYN, FIN or RST packets which we'll later need)
	if (tcpPayloadSize == 0 && tcpLayer->getTcpHeader()->synFlag == 0 && !isFinOrRst)
	{
		return Ignore_PacketWithNoData;
	}

	TcpReassemblyData* tcpReassemblyData = NULL;

	// calculate flow key for this packet
	uint32_t flowKey = hash5Tuple(&tcpData);

	// find the connection in the connection map
	ConnectionList::iterator iter = m_ConnectionList.find(flowKey);

	if (iter == m_ConnectionList.end())
	{
		// if it's a packet of a new connection, create a TcpReassemblyData object and add it to the active connection list
		std::pair<ConnectionList::iterator, bool> pair = m_ConnectionList.insert(std::make_pair(flowKey, TcpReassemblyData()));
		tcpReassemblyData = &pair.first->second;
		tcpReassemblyData->connData.srcIP = srcIP;
		tcpReassemblyData->connData.dstIP = dstIP;
		tcpReassemblyData->connData.srcPort = be16toh(tcpLayer->getTcpHeader()->portSrc);
		tcpReassemblyData->connData.dstPort = be16toh(tcpLayer->getTcpHeader()->portDst);
		tcpReassemblyData->connData.flowKey = flowKey;
		timeval ts = timespecToTimeval(tcpData.getRawPacket()->getPacketTimeStamp());
		tcpReassemblyData->connData.setStartTime(ts);

		m_ConnectionInfo[flowKey] = tcpReassemblyData->connData;

		// fire connection start callback
		if (m_OnConnStart != NULL)
			m_OnConnStart(tcpReassemblyData->connData, m_UserCookie);
	}
	else // connection already exists
	{
		// if this packet belongs to a connection that was already closed (for example: data packet that comes after FIN), ignore it.
		if (iter->second.closed)
		{
			LOG_DEBUG("Ignoring packet of already closed flow [0x%X]", flowKey);
			return Ignore_PacketOfClosedFlow;
		}

		tcpReassemblyData = &iter->second;
		timeval currTime = timespecToTimeval(tcpData.getRawPacket()->getPacketTimeStamp());

		if (currTime.tv_sec > tcpReassemblyData->connData.endTime.tv_sec)
		{
			tcpReassemblyData->connData.setEndTime(currTime); 
		}
		else if (currTime.tv_sec == tcpReassemblyData->connData.endTime.tv_sec)
		{
			if (currTime.tv_usec > tcpReassemblyData->connData.endTime.tv_usec)
			{
				tcpReassemblyData->connData.setEndTime(currTime);
			}
		}
	}

	int8_t sideIndex = -1;
	bool first = false;

	// calculate packet's source port
	uint16_t srcPort = tcpLayer->getTcpHeader()->portSrc;

	// if this is a new connection and it's the first packet we see on that connection
	if (tcpReassemblyData->numOfSides == 0)
	{
		LOG_DEBUG("Setting side for new connection");

		// open the first side of the connection, side index is 0
		sideIndex = 0;
		tcpReassemblyData->twoSides[sideIndex].srcIP = srcIP;
		tcpReassemblyData->twoSides[sideIndex].srcPort = srcPort;
		tcpReassemblyData->numOfSides++;
		first = true;
	}
	// if there is already one side in this connection (which will be at side index 0)
	else if (tcpReassemblyData->numOfSides == 1)
	{
		// check if packet belongs to that side
		if (tcpReassemblyData->twoSides[0].srcPort == srcPort && tcpReassemblyData->twoSides[0].srcIP == srcIP)
		{
			sideIndex = 0;
		}
		else
		{
			// this means packet belong to the second side which doesn't yet exist. Open a second side with side index 1
			LOG_DEBUG("Setting second side of a connection");
			sideIndex = 1;
			tcpReassemblyData->twoSides[sideIndex].srcIP = srcIP;
			tcpReassemblyData->twoSides[sideIndex].srcPort = srcPort;
			tcpReassemblyData->numOfSides++;
			first = true;
		}
	}
	// if there are already 2 sides open for this connection
	else if (tcpReassemblyData->numOfSides == 2)
	{
		// check if packet matches side 0
		if (tcpReassemblyData->twoSides[0].srcPort == srcPort && tcpReassemblyData->twoSides[0].srcIP == srcIP)
		{
			sideIndex = 0;
		}
		// check if packet matches side 1
		else if (tcpReassemblyData->twoSides[1].srcPort == srcPort && tcpReassemblyData->twoSides[1].srcIP == srcIP)
		{
			sideIndex = 1;
		}
		// packet doesn't match either side. This case doesn't make sense but it's handled anyway. Packet will be ignored
		else
		{
			LOG_ERROR("Error occurred - packet doesn't match either side of the connection!!");
			return Error_PacketDoesNotMatchFlow;
		}
	}
	// there are more than 2 side - this case doesn't make sense and shouldn't happen, but handled anyway. Packet will be ignored
	else
	{
		LOG_ERROR("Error occurred - connection has more than 2 sides!!");
		return Error_PacketDoesNotMatchFlow;
	}

	// if this side already got FIN or RST packet before, ignore this packet as this side is considered closed
	if (tcpReassemblyData->twoSides[sideIndex].gotFinOrRst)
	{
		LOG_DEBUG("Got a packet after FIN or RST were already seen on this side (%d). Ignoring this packet", sideIndex);
		return Ignore_PacketOfClosedFlow;
	}

	// handle FIN/RST packets that don't contain additional TCP data
	if (isFinOrRst && tcpPayloadSize == 0)
	{
		LOG_DEBUG("Got FIN or RST packet without data on side %d", sideIndex);

		handleFinOrRst(tcpReassemblyData, sideIndex, flowKey);
		return FIN_RSTWithNoData;
	}

	// check if this packet contains data from a different side than the side seen before.
	// If this is the case then treat the out-of-order packet list as missing data and send them to the user (callback) together with an indication that some data was missing.
	// Why? because a new packet from the other side means the previous message was probably already received and a new message is starting.
	// In this case out-of-order packets are probably actually missing data
	// For example: let's assume these are HTTP messages. If we're seeing the first packet of a response this means the server has already received the full request and is now starting
	// to send the response. So if we still have out-of-order packets from the request it probably means that some packets were lost during the capture. So we don't expect the client to
	// continue sending packets of the previous request, so we'll treat the out-of-order packets as missing data
	//
	// I'm aware that there are edge cases where the situation I described above is not true, but at some point we must clean the out-of-order packet list to avoid memory leak.
	// I decided to do what Wireshark does and clean this list when starting to see a message from the other side
	if (!first && tcpPayloadSize > 0 && tcpReassemblyData->prevSide != -1 && tcpReassemblyData->prevSide != sideIndex &&
			tcpReassemblyData->twoSides[tcpReassemblyData->prevSide].tcpFragmentList.size() > 0)
	{
		LOG_DEBUG("Seeing a first data packet from a different side. Previous side was %d, current side is %d", tcpReassemblyData->prevSide, sideIndex);
		checkOutOfOrderFragments(tcpReassemblyData, tcpReassemblyData->prevSide, true);
	}
	tcpReassemblyData->prevSide = sideIndex;

	// extract sequence value from packet
	uint32_t sequence = be32toh(tcpLayer->getTcpHeader()->sequenceNumber);

	// if it's the first packet we see on this side of the connection
	if (first)
	{
		LOG_DEBUG("First data from this side of the connection");

		// set initial sequence
		tcpReassemblyData->twoSides[sideIndex].sequence = sequence + tcpPayloadSize;
		if (tcpLayer->getTcpHeader()->synFlag != 0)
			tcpReassemblyData->twoSides[sideIndex].sequence++;

		// send data to the callback
		if (tcpPayloadSize != 0 && m_OnMessageReadyCallback != NULL)
		{
			TcpStreamData streamData(tcpLayer->getLayerPayload(), tcpPayloadSize, 0, tcpReassemblyData->connData);
			m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
		}
		status = TcpMessageHandled;

		// handle case where this packet is FIN or RST (although it's unlikely)
		if (isFinOrRst)
			handleFinOrRst(tcpReassemblyData, sideIndex, flowKey);
		
		// return - nothing else to do here
		return status;
	}

	// if packet sequence is smaller than expected - this means that part or all of the TCP data is being re-transmitted
	if (SEQ_LT(sequence, tcpReassemblyData->twoSides[sideIndex].sequence))
	{
		LOG_DEBUG("Found new data with the sequence lower than expected");

		// calculate the sequence after this packet to see if this TCP payload contains also new data
		uint32_t newSequence = sequence + tcpPayloadSize;

		// this means that some of payload is new
		if (SEQ_GT(newSequence, tcpReassemblyData->twoSides[sideIndex].sequence))
		{
			// calculate the size of the new data
			uint32_t newLength = tcpReassemblyData->twoSides[sideIndex].sequence - sequence;

			LOG_DEBUG("Although sequence is lower than expected payload is long enough to contain new data. Calling the callback with the new data");

			// update the sequence for this side to include the new data that was seen
			tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize - newLength;

			// send only the new data to the callback
			if (m_OnMessageReadyCallback != NULL)
			{
				TcpStreamData streamData(tcpLayer->getLayerPayload() + newLength, tcpPayloadSize - newLength, 0, tcpReassemblyData->connData);
				m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
			}
			status = TcpMessageHandled;
		}
		else {
			status = Ignore_Retransimission;
		}

		// handle case where this packet is FIN or RST
		if (isFinOrRst)
			handleFinOrRst(tcpReassemblyData, sideIndex, flowKey);
			
		// return - nothing else to do here
		return status;
	}

	// if packet sequence is exactly as expected - this is the "good" case and the most common one
	else if (sequence == tcpReassemblyData->twoSides[sideIndex].sequence)
	{
		// if TCP data size is 0 - nothing to do
		if (tcpPayloadSize == 0)
		{
			LOG_DEBUG("Payload length is 0, doing nothing");

			// handle case where this packet is FIN or RST
			if (isFinOrRst)
			{
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey);
				status = FIN_RSTWithNoData;
			}
			else
			{
				status = Ignore_PacketWithNoData;
			}

			return status;
		}

		LOG_DEBUG("Found new data with expected sequence. Calling the callback");

		// update the sequence for this side to include TCP data from this packet
		tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize;

		// if this is a SYN packet - add +1 to the sequence
		if (tcpLayer->getTcpHeader()->synFlag != 0)
			tcpReassemblyData->twoSides[sideIndex].sequence++;

		// send the data to the callback
		if (m_OnMessageReadyCallback != NULL)
		{
			TcpStreamData streamData(tcpLayer->getLayerPayload(), tcpPayloadSize, 0, tcpReassemblyData->connData);
			m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
		}
		status = TcpMessageHandled;

		//while (checkOutOfOrderFragments(tcpReassemblyData, sideIndex)) {}

		// now that we've seen new data, go over the list of out-of-order packets and see if one or more of them fits now
		checkOutOfOrderFragments(tcpReassemblyData, sideIndex, false);

		// handle case where this packet is FIN or RST
		if (isFinOrRst)
			handleFinOrRst(tcpReassemblyData, sideIndex, flowKey);

		// return - nothing else to do here
		return status;
	}

	// this case means sequence size of the packet is higher than expected which means the packet is out-of-order or some packets were lost (missing data).
	// we don't know which of the 2 cases it is at this point so we just add this data to the out-of-order packet list
	else
	{
		// if TCP data size is 0 - nothing to do
		if (tcpPayloadSize == 0)
		{
			LOG_DEBUG("Payload length is 0, doing nothing");

			// handle case where this packet is FIN or RST
			if (isFinOrRst)
			{
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey);
				status = FIN_RSTWithNoData;
			}
			else
			{
				status = Ignore_PacketWithNoData;
			}

			return status;
		}

		// create a new TcpFragment, copy the TCP data to it and add this packet to the the out-of-order packet list
		TcpFragment* newTcpFrag = new TcpFragment();
		newTcpFrag->data = new uint8_t[tcpPayloadSize];
		newTcpFrag->dataLength = tcpPayloadSize;
		newTcpFrag->sequence = sequence;
		memcpy(newTcpFrag->data, tcpLayer->getLayerPayload(), tcpPayloadSize);
		tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.pushBack(newTcpFrag);

		LOG_DEBUG("Found out-of-order packet and added a new TCP fragment with size %d to the out-of-order list of side %d", (int)tcpPayloadSize, sideIndex);
		status = OutOfOrderTcpMessageBuffered;

		// handle case where this packet is FIN or RST
		if (isFinOrRst)
		{
			handleFinOrRst(tcpReassemblyData, sideIndex, flowKey);
		}

		return status;
	}
}

TcpReassembly::ReassemblyStatus TcpReassembly::reassemblePacket(RawPacket* tcpRawData)
{
	Packet parsedPacket(tcpRawData, false);
	return reassemblePacket(parsedPacket);
}

static std::string prepareMissingDataMessage(uint32_t missingDataLen)
{
	std::stringstream missingDataTextStream;
	missingDataTextStream << '[' << missingDataLen << " bytes missing]";
	return missingDataTextStream.str();
}

void TcpReassembly::handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, uint32_t flowKey)
{
	// if this side already saw a FIN or RST packet, do nothing and return
	if (tcpReassemblyData->twoSides[sideIndex].gotFinOrRst)
		return;

	LOG_DEBUG("Handling FIN or RST packet on side %d", sideIndex);

	// set FIN/RST flag for this side
	tcpReassemblyData->twoSides[sideIndex].gotFinOrRst = true;

	// check if the other side also sees FIN or RST packet. If so - close the flow. Otherwise - only clear the out-of-order packets for this side
	int otherSideIndex = 1 - sideIndex;
	if (tcpReassemblyData->twoSides[otherSideIndex].gotFinOrRst)
		closeConnectionInternal(flowKey, TcpReassembly::TcpReassemblyConnectionClosedByFIN_RST);
	else
		checkOutOfOrderFragments(tcpReassemblyData, sideIndex, true);
}

void TcpReassembly::checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, bool cleanWholeFragList)
{
	bool foundSomething = false;

	do
	{
		LOG_DEBUG("Starting first iteration of checkOutOfOrderFragments - looking for fragments that match the current sequence or have smaller sequence");

		int index = 0;
		foundSomething = false;

		do
		{
			index = 0;
			foundSomething = false;

			// first fragment list iteration - go over the whole fragment list and see if can find fragments that match the current sequence
			// or have smaller sequence but have big enough payload to get new data
			while (index < (int)tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.size())
			{
				TcpFragment* curTcpFrag = tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.at(index);

				// if fragment sequence matches the current sequence
				if (curTcpFrag->sequence == tcpReassemblyData->twoSides[sideIndex].sequence)
				{
					// update sequence
					tcpReassemblyData->twoSides[sideIndex].sequence += curTcpFrag->dataLength;
					if (curTcpFrag->data != NULL)
					{
						LOG_DEBUG("Found an out-of-order packet matching to the current sequence with size %d on side %d. Pulling it out of the list and sending the data to the callback", (int)curTcpFrag->dataLength, sideIndex);

						// send new data to callback

						if (m_OnMessageReadyCallback != NULL)
						{
							TcpStreamData streamData(curTcpFrag->data, curTcpFrag->dataLength, 0, tcpReassemblyData->connData);
							m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
						}
					}


					// remove fragment from list
					tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.erase(tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.begin() + index);

					foundSomething = true;

					continue;
				}

				// if fragment sequence has lower sequence than the current sequence
				if (SEQ_LT(curTcpFrag->sequence, tcpReassemblyData->twoSides[sideIndex].sequence))
				{
					// check if it still has new data
					uint32_t newSequence = curTcpFrag->sequence + curTcpFrag->dataLength;

					// it has new data
					if (SEQ_GT(newSequence, tcpReassemblyData->twoSides[sideIndex].sequence))
					{
						// calculate the delta new data size
						uint32_t newLength = tcpReassemblyData->twoSides[sideIndex].sequence - curTcpFrag->sequence;

						LOG_DEBUG("Found a fragment in the out-of-order list which its sequence is lower than expected but its payload is long enough to contain new data. "
							"Calling the callback with the new data. Fragment size is %d on side %d, new data size is %d", (int)curTcpFrag->dataLength, sideIndex, (int)(curTcpFrag->dataLength - newLength));

						// update current sequence with the delta new data size
						tcpReassemblyData->twoSides[sideIndex].sequence += curTcpFrag->dataLength - newLength;

						// send only the new data to the callback
						if (m_OnMessageReadyCallback != NULL)
						{
							TcpStreamData streamData(curTcpFrag->data + newLength, curTcpFrag->dataLength - newLength, 0, tcpReassemblyData->connData);
							m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
						}

						foundSomething = true;
					}
					else
					{
						LOG_DEBUG("Found a fragment in the out-of-order list which doesn't contain any new data, ignoring it. Fragment size is %d on side %d", (int)curTcpFrag->dataLength, sideIndex);
					}

					// delete fragment from list
					tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.erase(tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.begin() + index);

					continue;
				}

				//if got to here it means the fragment has higher sequence than current sequence, increment index and continue
				index++;
			}

			// if managed to find new segment, do the search all over again
		} while (foundSomething);


		// if got here it means we're left only with fragments that have higher sequence than current sequence. This means out-of-order packets or
		// missing data. If we don't want to clear the frag list yet, assume it's out-of-order and return
		if (!cleanWholeFragList)
			return;

		LOG_DEBUG("Starting second  iteration of checkOutOfOrderFragments - handle missing data");

		// second fragment list iteration - now we're left only with fragments that have higher sequence than current sequence. This means missing data.
		// Search for the fragment with the closest sequence to the current one

		uint32_t closestSequence = 0xffffffff;
		bool closestSequenceDefined = false;
		int closestSequenceFragIndex = -1;
		index = 0;

		while (index < (int)tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.size())
		{
			// extract segment at current index
			TcpFragment* curTcpFrag = tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.at(index);

			// check if its sequence is closer than current closest sequence
			if (!closestSequenceDefined || SEQ_LT(curTcpFrag->sequence, closestSequence))
			{
				closestSequence = curTcpFrag->sequence;
				closestSequenceFragIndex = index;
				closestSequenceDefined = true;
			}

			index++;
		}

		// this means fragment list is not empty at this stage
		if (closestSequenceFragIndex > -1)
		{
			// get the fragment with the closest sequence
			TcpFragment* curTcpFrag = tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.at(closestSequenceFragIndex);

			// calculate number of missing bytes
			uint32_t missingDataLen = curTcpFrag->sequence - tcpReassemblyData->twoSides[sideIndex].sequence;

			// update sequence
			tcpReassemblyData->twoSides[sideIndex].sequence = curTcpFrag->sequence + curTcpFrag->dataLength;
			if (curTcpFrag->data != NULL)
			{
				// send new data to callback
				if (m_OnMessageReadyCallback != NULL)
				{
					// prepare missing data text
					std::string missingDataTextStr = prepareMissingDataMessage(missingDataLen);

					// add missing data text to the data that will be sent to the callback. This means that the data will look something like:
					// "[xx bytes missing]<original_data>"
					std::vector<uint8_t> dataWithMissingDataText;
					dataWithMissingDataText.reserve(missingDataTextStr.length() + curTcpFrag->dataLength);
					dataWithMissingDataText.insert(dataWithMissingDataText.end(), missingDataTextStr.begin(), missingDataTextStr.end());
					dataWithMissingDataText.insert(dataWithMissingDataText.end(), curTcpFrag->data, curTcpFrag->data + curTcpFrag->dataLength);

					//TcpStreamData streamData(curTcpFrag->data, curTcpFrag->dataLength, tcpReassemblyData->connData);
					TcpStreamData streamData(&dataWithMissingDataText[0], dataWithMissingDataText.size(), missingDataLen, tcpReassemblyData->connData);
					m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);

					LOG_DEBUG("Found missing data on side %d: %d byte are missing. Sending the closest fragment which is in size %d + missing text message which size is %d",
						sideIndex, missingDataLen, (int)curTcpFrag->dataLength, (int)missingDataTextStr.length());
				}
			}

			// remove fragment from list
			tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.erase(tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.begin() + closestSequenceFragIndex);

			LOG_DEBUG("Calling checkOutOfOrderFragments again from the start");

			// call the method again from the start to do the whole search again (both iterations). 
			// the stop condition is when the list is empty (so closestSequenceFragIndex == -1)
			foundSomething = true;
		}

	} while (foundSomething);
}

void TcpReassembly::closeConnection(uint32_t flowKey)
{
	closeConnectionInternal(flowKey, TcpReassembly::TcpReassemblyConnectionClosedManually);
}

void TcpReassembly::closeConnectionInternal(uint32_t flowKey, ConnectionEndReason reason)
{
	ConnectionList::iterator iter = m_ConnectionList.find(flowKey);
	if (iter == m_ConnectionList.end())
	{
		LOG_ERROR("Cannot close flow with key 0x%X: cannot find flow", flowKey);
		return;
	}

	TcpReassemblyData& tcpReassemblyData = iter->second;

	if (tcpReassemblyData.closed) // the connection is already closed
		return;

	LOG_DEBUG("Closing connection with flow key 0x%X", flowKey);

	LOG_DEBUG("Calling checkOutOfOrderFragments on side 0");
	checkOutOfOrderFragments(&tcpReassemblyData, 0, true);

	LOG_DEBUG("Calling checkOutOfOrderFragments on side 1");
	checkOutOfOrderFragments(&tcpReassemblyData, 1, true);

	if (m_OnConnEnd != NULL)
		m_OnConnEnd(tcpReassemblyData.connData, reason, m_UserCookie);

	tcpReassemblyData.closed = true; // mark the connection as closed
	insertIntoCleanupList(flowKey);

	LOG_DEBUG("Connection with flow key 0x%X is closed", flowKey);
}

void TcpReassembly::closeAllConnections()
{
	LOG_DEBUG("Closing all flows");

	ConnectionList::iterator iter = m_ConnectionList.begin(), iterEnd = m_ConnectionList.end();
	for (; iter != iterEnd; ++iter)
	{
		TcpReassemblyData& tcpReassemblyData = iter->second;

		if (tcpReassemblyData.closed) // the connection is already closed, skip it
			continue;

		uint32_t flowKey = tcpReassemblyData.connData.flowKey;
		LOG_DEBUG("Closing connection with flow key 0x%X", flowKey);

		LOG_DEBUG("Calling checkOutOfOrderFragments on side 0");
		checkOutOfOrderFragments(&tcpReassemblyData, 0, true);

		LOG_DEBUG("Calling checkOutOfOrderFragments on side 1");
		checkOutOfOrderFragments(&tcpReassemblyData, 1, true);

		if (m_OnConnEnd != NULL)
			m_OnConnEnd(tcpReassemblyData.connData, TcpReassemblyConnectionClosedManually, m_UserCookie);

		tcpReassemblyData.closed = true; // mark the connection as closed
		insertIntoCleanupList(flowKey);

		LOG_DEBUG("Connection with flow key 0x%X is closed", flowKey);
	}
}

int TcpReassembly::isConnectionOpen(const ConnectionData& connection) const
{
	ConnectionList::const_iterator iter = m_ConnectionList.find(connection.flowKey);
	if (iter != m_ConnectionList.end())
		return iter->second.closed == false;

	return -1;
}

void TcpReassembly::insertIntoCleanupList(uint32_t flowKey)
{
	// m_CleanupList is a map with key of type time_t (expiration time). The mapped type is a list that stores the flow keys to be cleared in certain point of time.
	// m_CleanupList.insert inserts an empty list if the container does not already contain an element with an equivalent key,
	// otherwise this method returns an iterator to the element that prevents insertion.
	std::pair<CleanupList::iterator, bool> pair = m_CleanupList.insert(std::make_pair(time(NULL) + m_ClosedConnectionDelay, CleanupList::mapped_type()));

	// getting the reference to list
	CleanupList::mapped_type& keysList = pair.first->second;
	keysList.push_front(flowKey);
}

uint32_t TcpReassembly::purgeClosedConnections(uint32_t maxNumToClean)
{
	uint32_t count = 0;

	if (maxNumToClean == 0)
		maxNumToClean = m_MaxNumToClean;

	CleanupList::iterator iterTime = m_CleanupList.begin(), iterTimeEnd = m_CleanupList.upper_bound(time(NULL));
	while (iterTime != iterTimeEnd && count < maxNumToClean)
	{
		CleanupList::mapped_type& keysList = iterTime->second;

		for (; !keysList.empty() && count < maxNumToClean; ++count)
		{
			CleanupList::mapped_type::const_reference key = keysList.front();
			m_ConnectionInfo.erase(key);
			m_ConnectionList.erase(key);
			keysList.pop_front();
		}

		if (keysList.empty())
			m_CleanupList.erase(iterTime++);
		else
			++iterTime;
	}

	return count;
}

}

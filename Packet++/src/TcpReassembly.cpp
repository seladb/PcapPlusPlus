#define LOG_MODULE PacketLogModuleTcpReassembly

#include "TcpReassembly.h"
#include "TcpLayer.h"
#include "IPLayer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include <sstream>
#include <vector>
#include "EndianPortable.h"
#include "TimespecTimeval.h"
#ifdef _MSC_VER
#	include <time.h>
#endif

#define PURGE_FREQ_SECS 1

#define SEQ_LT(a, b) ((int32_t)((a) - (b)) < 0)
#define SEQ_LEQ(a, b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a, b) ((int32_t)((a) - (b)) > 0)
#define SEQ_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)

namespace pcpp
{

	static timeval timePointToTimeval(const std::chrono::time_point<std::chrono::high_resolution_clock>& in)
	{
		auto duration = in.time_since_epoch();

		auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
		auto microseconds =
		    std::chrono::duration_cast<std::chrono::microseconds>(duration).count() -
		    std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::seconds(seconds)).count();

		struct timeval out;
		out.tv_sec = seconds;
		out.tv_usec = microseconds;
		return out;
	}

	static std::chrono::time_point<std::chrono::high_resolution_clock> timespecToTimePoint(const timespec& in)
	{
		auto duration = std::chrono::duration_cast<std::chrono::high_resolution_clock::duration>(
		    std::chrono::seconds(in.tv_sec) + std::chrono::nanoseconds(in.tv_nsec));

		return std::chrono::time_point<std::chrono::high_resolution_clock>(duration);
	}

	void ConnectionData::setStartTime(const std::chrono::time_point<std::chrono::high_resolution_clock>& startTimeValue)
	{
		startTime = timePointToTimeval(startTimeValue);
		startTimePrecise = startTimeValue;
	}

	void ConnectionData::setEndTime(const std::chrono::time_point<std::chrono::high_resolution_clock>& endTimeValue)
	{
		endTime = timePointToTimeval(endTimeValue);
		endTimePrecise = endTimeValue;
	}

	timeval TcpStreamData::getTimeStamp() const
	{
		return timePointToTimeval(m_Timestamp);
	}

	TcpReassembly::TcpReassembly(OnTcpMessageReady onMessageReadyCallback, void* userCookie,
	                             OnTcpConnectionStart onConnectionStartCallback,
	                             OnTcpConnectionEnd onConnectionEndCallback, const TcpReassemblyConfiguration& config)
	{
		m_OnMessageReadyCallback = onMessageReadyCallback;
		m_UserCookie = userCookie;
		m_OnConnStart = onConnectionStartCallback;
		m_OnConnEnd = onConnectionEndCallback;
		m_ClosedConnectionDelay = (config.closedConnectionDelay > 0) ? config.closedConnectionDelay : 5;
		m_RemoveConnInfo = config.removeConnInfo;
		m_MaxNumToClean = (config.removeConnInfo == true && config.maxNumToClean == 0) ? 30 : config.maxNumToClean;
		m_MaxOutOfOrderFragments = config.maxOutOfOrderFragments;
		m_PurgeTimepoint = time(nullptr) + PURGE_FREQ_SECS;
		m_EnableBaseBufferClearCondition = config.enableBaseBufferClearCondition;
	}

	TcpReassembly::ReassemblyStatus TcpReassembly::reassemblePacket(Packet& tcpData)
	{
		// automatic cleanup
		if (m_RemoveConnInfo == true)
		{
			if (time(nullptr) >= m_PurgeTimepoint)
			{
				purgeClosedConnections();
				m_PurgeTimepoint = time(nullptr) + PURGE_FREQ_SECS;
			}
		}

		// calculate packet's source and dest IP address
		IPAddress srcIP, dstIP;

		if (tcpData.isPacketOfType(IP))
		{
			const IPLayer* ipLayer = tcpData.getLayerOfType<IPLayer>();
			srcIP = ipLayer->getSrcIPAddress();
			dstIP = ipLayer->getDstIPAddress();
		}
		else
			return NonIpPacket;

		// Ignore non-TCP packets
		TcpLayer* tcpLayer = tcpData.getLayerOfType<TcpLayer>(true);  // lookup in reverse order
		if (tcpLayer == nullptr)
		{
			return NonTcpPacket;
		}

		// Ignore the packet if it's an ICMP packet that has a TCP layer
		// Several ICMP messages (like "destination unreachable") have TCP data as part of the ICMP message.
		// This is not real TCP data and packet can be ignored
		if (tcpData.isPacketOfType(ICMP))
		{
			PCPP_LOG_DEBUG(
			    "Packet is of type ICMP so TCP data is probably part of the ICMP message. Ignoring this packet");
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

		TcpReassemblyData* tcpReassemblyData = nullptr;

		// calculate flow key for this packet
		uint32_t flowKey = hash5Tuple(&tcpData);

		// time stamp for this packet
		auto currTime = timespecToTimePoint(tcpData.getRawPacket()->getPacketTimeStamp());

		// find the connection in the connection map
		ConnectionList::iterator iter = m_ConnectionList.find(flowKey);

		if (iter == m_ConnectionList.end())
		{
			// if it's a packet of a new connection, create a TcpReassemblyData object and add it to the active
			// connection list
			std::pair<ConnectionList::iterator, bool> pair =
			    m_ConnectionList.insert(std::make_pair(flowKey, TcpReassemblyData()));
			tcpReassemblyData = &pair.first->second;
			tcpReassemblyData->connData.srcIP = srcIP;
			tcpReassemblyData->connData.dstIP = dstIP;
			tcpReassemblyData->connData.srcPort = tcpLayer->getSrcPort();
			tcpReassemblyData->connData.dstPort = tcpLayer->getDstPort();
			tcpReassemblyData->connData.flowKey = flowKey;
			tcpReassemblyData->connData.setStartTime(currTime);

			m_ConnectionInfo[flowKey] = tcpReassemblyData->connData;

			// fire connection start callback
			if (m_OnConnStart != nullptr)
				m_OnConnStart(tcpReassemblyData->connData, m_UserCookie);
		}
		else  // connection already exists
		{
			// if this packet belongs to a connection that was already closed (for example: data packet that comes after
			// FIN), ignore it.
			if (iter->second.closed)
			{
				PCPP_LOG_DEBUG("Ignoring packet of already closed flow [0x" << std::hex << flowKey << "]");
				return Ignore_PacketOfClosedFlow;
			}

			tcpReassemblyData = &iter->second;

			if (currTime > tcpReassemblyData->connData.endTimePrecise)
			{
				tcpReassemblyData->connData.setEndTime(currTime);
				m_ConnectionInfo[flowKey].setEndTime(currTime);
			}
		}

		int8_t sideIndex = -1;
		bool first = false;

		// calculate packet's source port
		uint16_t srcPort = tcpLayer->getTcpHeader()->portSrc;

		// if this is a new connection and it's the first packet we see on that connection
		if (tcpReassemblyData->numOfSides == 0)
		{
			PCPP_LOG_DEBUG("Setting side for new connection");

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
				// this means packet belong to the second side which doesn't yet exist. Open a second side with side
				// index 1
				PCPP_LOG_DEBUG("Setting second side of a connection");
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
			// packet doesn't match either side. This case doesn't make sense but it's handled anyway. Packet will be
			// ignored
			else
			{
				PCPP_LOG_ERROR("Error occurred - packet doesn't match either side of the connection!!");
				return Error_PacketDoesNotMatchFlow;
			}
		}
		// there are more than 2 side - this case doesn't make sense and shouldn't happen, but handled anyway. Packet
		// will be ignored
		else
		{
			PCPP_LOG_ERROR("Error occurred - connection has more than 2 sides!!");
			return Error_PacketDoesNotMatchFlow;
		}

		// if this side already got FIN or RST packet before, ignore this packet as this side is considered closed
		if (tcpReassemblyData->twoSides[sideIndex].gotFinOrRst)
		{
			if (!tcpReassemblyData->twoSides[1 - sideIndex].gotFinOrRst && isRst)
			{
				handleFinOrRst(tcpReassemblyData, 1 - sideIndex, flowKey, isRst);
				return FIN_RSTWithNoData;
			}

			PCPP_LOG_DEBUG("Got a packet after FIN or RST were already seen on this side ("
			               << static_cast<int>(sideIndex) << "). Ignoring this packet");

			return Ignore_PacketOfClosedFlow;
		}

		// handle FIN/RST packets that don't contain additional TCP data
		if (isFinOrRst && tcpPayloadSize == 0)
		{
			PCPP_LOG_DEBUG("Got FIN or RST packet without data on side " << sideIndex);

			handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
			return FIN_RSTWithNoData;
		}

		// check if this packet contains data from a different side than the side seen before.
		// If this is the case then treat the out-of-order packet list as missing data and send them to the user
		// (callback) together with an indication that some data was missing. Why? because a new packet from the other
		// side means the previous message was probably already received and a new message is starting. In this case
		// out-of-order packets are probably actually missing data For example: let's assume these are HTTP messages. If
		// we're seeing the first packet of a response this means the server has already received the full request and
		// is now starting to send the response. So if we still have out-of-order packets from the request it probably
		// means that some packets were lost during the capture. So we don't expect the client to continue sending
		// packets of the previous request, so we'll treat the out-of-order packets as missing data
		//
		// I'm aware that there are edge cases where the situation I described above is not true, but at some point we
		// must clean the out-of-order packet list to avoid memory leak. I decided to do what Wireshark does and clean
		// this list when starting to see a message from the other side

		// Since there are instances where this buffer clear condition can lead to declaration of excessive missing
		// packets. Hence user should have a config file parameter to disable this and purely rely on max buffer size
		// condition. As none of them are perfect solutions this will give user a little more control over it.

		if (m_EnableBaseBufferClearCondition && !first && tcpPayloadSize > 0 && tcpReassemblyData->prevSide != -1 &&
		    tcpReassemblyData->prevSide != sideIndex &&
		    tcpReassemblyData->twoSides[tcpReassemblyData->prevSide].tcpFragmentList.size() > 0)
		{
			PCPP_LOG_DEBUG("Seeing a first data packet from a different side. Previous side was "
			               << static_cast<int>(tcpReassemblyData->prevSide) << ", current side is "
			               << static_cast<int>(sideIndex));
			checkOutOfOrderFragments(tcpReassemblyData, tcpReassemblyData->prevSide, true);
		}
		tcpReassemblyData->prevSide = sideIndex;

		// extract sequence value from packet
		uint32_t sequence = be32toh(tcpLayer->getTcpHeader()->sequenceNumber);

		// if it's the first packet we see on this side of the connection
		if (first)
		{
			PCPP_LOG_DEBUG("First data from this side of the connection");

			// set initial sequence
			tcpReassemblyData->twoSides[sideIndex].sequence = sequence + tcpPayloadSize;
			if (tcpLayer->getTcpHeader()->synFlag != 0)
				tcpReassemblyData->twoSides[sideIndex].sequence++;

			// send data to the callback
			if (tcpPayloadSize != 0 && m_OnMessageReadyCallback != nullptr)
			{
				TcpStreamData streamData(tcpLayer->getLayerPayload(), tcpPayloadSize, 0, tcpReassemblyData->connData,
				                         currTime);
				m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
			}
			status = TcpMessageHandled;

			// handle case where this packet is FIN or RST (although it's unlikely)
			if (isFinOrRst)
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);

			// return - nothing else to do here
			return status;
		}

		// if packet sequence is smaller than expected - this means that part or all of the TCP data is being
		// re-transmitted
		if (SEQ_LT(sequence, tcpReassemblyData->twoSides[sideIndex].sequence))
		{
			PCPP_LOG_DEBUG("Found new data with the sequence lower than expected");

			// calculate the sequence after this packet to see if this TCP payload contains also new data
			uint32_t newSequence = sequence + tcpPayloadSize;

			// this means that some of payload is new
			if (SEQ_GT(newSequence, tcpReassemblyData->twoSides[sideIndex].sequence))
			{
				// calculate the size of the new data
				uint32_t newLength = tcpReassemblyData->twoSides[sideIndex].sequence - sequence;

				PCPP_LOG_DEBUG(
				    "Although sequence is lower than expected payload is long enough to contain new data. Calling the callback with the new data");

				// update the sequence for this side to include the new data that was seen
				tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize - newLength;

				// send only the new data to the callback
				if (m_OnMessageReadyCallback != nullptr)
				{
					TcpStreamData streamData(tcpLayer->getLayerPayload() + newLength, tcpPayloadSize - newLength, 0,
					                         tcpReassemblyData->connData, currTime);
					m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
				}
				status = TcpMessageHandled;
			}
			else
			{
				status = Ignore_Retransimission;
			}

			// handle case where this packet is FIN or RST
			if (isFinOrRst)
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);

			// return - nothing else to do here
			return status;
		}

		// if packet sequence is exactly as expected - this is the "good" case and the most common one
		else if (sequence == tcpReassemblyData->twoSides[sideIndex].sequence)
		{
			// if TCP data size is 0 - nothing to do
			if (tcpPayloadSize == 0)
			{
				PCPP_LOG_DEBUG("Payload length is 0, doing nothing");

				// handle case where this packet is FIN or RST
				if (isFinOrRst)
				{
					handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
					status = FIN_RSTWithNoData;
				}
				else
				{
					status = Ignore_PacketWithNoData;
				}

				return status;
			}

			PCPP_LOG_DEBUG("Found new data with expected sequence. Calling the callback");

			// update the sequence for this side to include TCP data from this packet
			tcpReassemblyData->twoSides[sideIndex].sequence += tcpPayloadSize;

			// if this is a SYN packet - add +1 to the sequence
			if (tcpLayer->getTcpHeader()->synFlag != 0)
				tcpReassemblyData->twoSides[sideIndex].sequence++;

			// send the data to the callback
			if (m_OnMessageReadyCallback != nullptr)
			{
				TcpStreamData streamData(tcpLayer->getLayerPayload(), tcpPayloadSize, 0, tcpReassemblyData->connData,
				                         currTime);
				m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
			}
			status = TcpMessageHandled;

			// now that we've seen new data, go over the list of out-of-order packets and see if one or more of them
			// fits now
			checkOutOfOrderFragments(tcpReassemblyData, sideIndex, false);

			// handle case where this packet is FIN or RST
			if (isFinOrRst)
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);

			// return - nothing else to do here
			return status;
		}

		// this case means sequence size of the packet is higher than expected which means the packet is out-of-order or
		// some packets were lost (missing data). we don't know which of the 2 cases it is at this point so we just add
		// this data to the out-of-order packet list
		else
		{
			// if TCP data size is 0 - nothing to do
			if (tcpPayloadSize == 0)
			{
				PCPP_LOG_DEBUG("Payload length is 0, doing nothing");

				// handle case where this packet is FIN or RST
				if (isFinOrRst)
				{
					handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
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
			newTcpFrag->timestamp = currTime;
			memcpy(newTcpFrag->data, tcpLayer->getLayerPayload(), tcpPayloadSize);
			tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.pushBack(newTcpFrag);

			PCPP_LOG_DEBUG("Found out-of-order packet and added a new TCP fragment with size "
			               << tcpPayloadSize << " to the out-of-order list of side " << static_cast<int>(sideIndex));
			status = OutOfOrderTcpMessageBuffered;

			// check if we've stored too many out-of-order fragments; if so, consider missing packets lost and
			// continue processing until the number of stored fragments is lower than the acceptable limit again
			if (m_MaxOutOfOrderFragments > 0 &&
			    tcpReassemblyData->twoSides[sideIndex].tcpFragmentList.size() > m_MaxOutOfOrderFragments)
			{
				checkOutOfOrderFragments(tcpReassemblyData, sideIndex, false);
			}

			// handle case where this packet is FIN or RST
			if (isFinOrRst)
			{
				handleFinOrRst(tcpReassemblyData, sideIndex, flowKey, isRst);
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

	void TcpReassembly::handleFinOrRst(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex, uint32_t flowKey,
	                                   bool isRst)
	{
		// if this side already saw a FIN or RST packet, do nothing and return
		if (tcpReassemblyData->twoSides[sideIndex].gotFinOrRst)
			return;

		PCPP_LOG_DEBUG("Handling FIN or RST packet on side " << static_cast<int>(sideIndex));

		// set FIN/RST flag for this side
		tcpReassemblyData->twoSides[sideIndex].gotFinOrRst = true;

		// check if the other side also sees FIN or RST packet. If so - just close the flow. Otherwise - clear the
		// out-of-order packets for this side
		int otherSideIndex = 1 - sideIndex;
		if (tcpReassemblyData->twoSides[otherSideIndex].gotFinOrRst)
		{
			closeConnectionInternal(flowKey, TcpReassembly::TcpReassemblyConnectionClosedByFIN_RST);
			return;
		}
		else
			checkOutOfOrderFragments(tcpReassemblyData, sideIndex, true);

		// and if it's a rst, close the flow unilaterally
		if (isRst)
			closeConnectionInternal(flowKey, TcpReassembly::TcpReassemblyConnectionClosedByFIN_RST);
	}

	void TcpReassembly::checkOutOfOrderFragments(TcpReassemblyData* tcpReassemblyData, int8_t sideIndex,
	                                             bool cleanWholeFragList)
	{
		if (m_ProcessingOutOfOrder)
		{
			return;
		}

		OutOfOrderProcessingGuard guard(m_ProcessingOutOfOrder);

		bool foundSomething = false;

		auto& curSideData = tcpReassemblyData->twoSides[sideIndex];

		do
		{
			PCPP_LOG_DEBUG(
			    "Starting first iteration of checkOutOfOrderFragments - looking for fragments that match the current sequence or have smaller sequence");

			do
			{
				auto tcpFragIter = curSideData.tcpFragmentList.begin();
				foundSomething = false;

				// first fragment list iteration - go over the whole fragment list and see if can find fragments that
				// match the current sequence or have smaller sequence but have big enough payload to get new data
				while (tcpFragIter != curSideData.tcpFragmentList.end())
				{
					// if fragment sequence matches the current sequence
					if ((*tcpFragIter)->sequence == curSideData.sequence)
					{
						// pop the fragment from fragment list
						auto curTcpFrag = curSideData.tcpFragmentList.getAndDetach(tcpFragIter);
						// update sequence
						curSideData.sequence += curTcpFrag->dataLength;
						if (curTcpFrag->data != nullptr)
						{
							PCPP_LOG_DEBUG("Found an out-of-order packet matching to the current sequence with size "
							               << curTcpFrag->dataLength << " on side " << static_cast<int>(sideIndex)
							               << ". Pulling it out of the list and sending the data to the callback");

							// send new data to callback

							if (m_OnMessageReadyCallback != nullptr)
							{
								TcpStreamData streamData(curTcpFrag->data, curTcpFrag->dataLength, 0,
								                         tcpReassemblyData->connData, curTcpFrag->timestamp);
								m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
							}
						}

						foundSomething = true;

						continue;
					}

					// if fragment sequence has lower sequence than the current sequence
					if (SEQ_LT((*tcpFragIter)->sequence, curSideData.sequence))
					{
						// pop the fragment from fragment list
						auto curTcpFrag = curSideData.tcpFragmentList.getAndDetach(tcpFragIter);
						// check if it still has new data
						uint32_t newSequence = curTcpFrag->sequence + curTcpFrag->dataLength;

						// it has new data
						if (SEQ_GT(newSequence, curSideData.sequence))
						{
							// calculate the delta new data size
							uint32_t newLength = curSideData.sequence - curTcpFrag->sequence;

							PCPP_LOG_DEBUG(
							    "Found a fragment in the out-of-order list which its sequence is lower than expected but its payload is long enough to contain new data. "
							    "Calling the callback with the new data. Fragment size is "
							    << curTcpFrag->dataLength << " on side " << static_cast<int>(sideIndex)
							    << ", new data size is " << static_cast<int>(curTcpFrag->dataLength - newLength));

							// update current sequence with the delta new data size
							curSideData.sequence += curTcpFrag->dataLength - newLength;

							// send only the new data to the callback
							if (m_OnMessageReadyCallback != nullptr)
							{
								TcpStreamData streamData(curTcpFrag->data + newLength,
								                         curTcpFrag->dataLength - newLength, 0,
								                         tcpReassemblyData->connData, curTcpFrag->timestamp);
								m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);
							}

							foundSomething = true;
						}
						else
						{
							PCPP_LOG_DEBUG(
							    "Found a fragment in the out-of-order list which doesn't contain any new data, ignoring it. Fragment size is "
							    << curTcpFrag->dataLength << " on side " << static_cast<int>(sideIndex));
						}

						continue;
					}

					// if got to here it means the fragment has higher sequence than current sequence, increment it and
					// continue
					tcpFragIter++;
				}

				// if managed to find new segment, do the search all over again
			} while (foundSomething);

			// if got here it means we're left only with fragments that have higher sequence than current sequence. This
			// means out-of-order packets or missing data. If we don't want to clear the frag list yet and the number of
			// out of order fragments isn't above the configured limit, assume it's out-of-order and return
			if (!cleanWholeFragList &&
			    (m_MaxOutOfOrderFragments == 0 || curSideData.tcpFragmentList.size() <= m_MaxOutOfOrderFragments))
			{
				return;
			}

			PCPP_LOG_DEBUG("Starting second  iteration of checkOutOfOrderFragments - handle missing data");

			// second fragment list iteration - now we're left only with fragments that have higher sequence than
			// current sequence. This means missing data. Search for the fragment with the closest sequence to the
			// current one

			uint32_t closestSequence = 0xffffffff;
			bool closestSequenceDefined = false;
			auto closestSequenceFragIt = curSideData.tcpFragmentList.end();

			for (auto tcpFragIter = curSideData.tcpFragmentList.begin();
			     tcpFragIter != curSideData.tcpFragmentList.end(); tcpFragIter++)
			{
				// check if its sequence is closer than current closest sequence
				if (!closestSequenceDefined || SEQ_LT((*tcpFragIter)->sequence, closestSequence))
				{
					closestSequence = (*tcpFragIter)->sequence;
					closestSequenceFragIt = tcpFragIter;
					closestSequenceDefined = true;
				}
			}

			// this means fragment list is not empty at this stage
			if (closestSequenceFragIt != curSideData.tcpFragmentList.end())
			{
				// get the fragment with the closest sequence
				auto curTcpFrag = curSideData.tcpFragmentList.getAndDetach(closestSequenceFragIt);

				// calculate number of missing bytes
				uint32_t missingDataLen = curTcpFrag->sequence - curSideData.sequence;

				// update sequence
				curSideData.sequence = curTcpFrag->sequence + curTcpFrag->dataLength;
				if (curTcpFrag->data != nullptr)
				{
					// send new data to callback
					if (m_OnMessageReadyCallback != nullptr)
					{
						// prepare missing data text
						std::string missingDataTextStr = prepareMissingDataMessage(missingDataLen);

						// add missing data text to the data that will be sent to the callback. This means that the data
						// will look something like:
						// "[xx bytes missing]<original_data>"
						std::vector<uint8_t> dataWithMissingDataText;
						dataWithMissingDataText.reserve(missingDataTextStr.length() + curTcpFrag->dataLength);
						dataWithMissingDataText.insert(dataWithMissingDataText.end(), missingDataTextStr.begin(),
						                               missingDataTextStr.end());
						dataWithMissingDataText.insert(dataWithMissingDataText.end(), curTcpFrag->data,
						                               curTcpFrag->data + curTcpFrag->dataLength);

						// TcpStreamData streamData(curTcpFrag->data, curTcpFrag->dataLength,
						// tcpReassemblyData->connData);
						TcpStreamData streamData(&dataWithMissingDataText[0], dataWithMissingDataText.size(),
						                         missingDataLen, tcpReassemblyData->connData, curTcpFrag->timestamp);
						m_OnMessageReadyCallback(sideIndex, streamData, m_UserCookie);

						PCPP_LOG_DEBUG("Found missing data on side "
						               << static_cast<int>(sideIndex) << ": " << missingDataLen
						               << " byte are missing. Sending the closest fragment which is in size "
						               << curTcpFrag->dataLength << " + missing text message which size is "
						               << missingDataTextStr.length());
					}
				}

				PCPP_LOG_DEBUG("Calling checkOutOfOrderFragments again from the start");

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
			PCPP_LOG_ERROR("Cannot close flow with key 0x" << std::uppercase << std::hex << flowKey
			                                               << ": cannot find flow");
			return;
		}

		TcpReassemblyData& tcpReassemblyData = iter->second;

		if (tcpReassemblyData.closed)  // the connection is already closed
			return;

		PCPP_LOG_DEBUG("Closing connection with flow key 0x" << std::hex << flowKey);

		PCPP_LOG_DEBUG("Calling checkOutOfOrderFragments on side 0");
		checkOutOfOrderFragments(&tcpReassemblyData, 0, true);

		PCPP_LOG_DEBUG("Calling checkOutOfOrderFragments on side 1");
		checkOutOfOrderFragments(&tcpReassemblyData, 1, true);

		if (m_OnConnEnd != nullptr)
			m_OnConnEnd(tcpReassemblyData.connData, reason, m_UserCookie);

		tcpReassemblyData.closed = true;  // mark the connection as closed
		insertIntoCleanupList(flowKey);

		PCPP_LOG_DEBUG("Connection with flow key 0x" << std::hex << flowKey << " is closed");
	}

	void TcpReassembly::closeAllConnections()
	{
		PCPP_LOG_DEBUG("Closing all flows");

		ConnectionList::iterator iter = m_ConnectionList.begin(), iterEnd = m_ConnectionList.end();
		for (; iter != iterEnd; ++iter)
		{
			TcpReassemblyData& tcpReassemblyData = iter->second;

			if (tcpReassemblyData.closed)  // the connection is already closed, skip it
				continue;

			uint32_t flowKey = tcpReassemblyData.connData.flowKey;
			PCPP_LOG_DEBUG("Closing connection with flow key 0x" << std::hex << flowKey);

			PCPP_LOG_DEBUG("Calling checkOutOfOrderFragments on side 0");
			checkOutOfOrderFragments(&tcpReassemblyData, 0, true);

			PCPP_LOG_DEBUG("Calling checkOutOfOrderFragments on side 1");
			checkOutOfOrderFragments(&tcpReassemblyData, 1, true);

			if (m_OnConnEnd != nullptr)
				m_OnConnEnd(tcpReassemblyData.connData, TcpReassemblyConnectionClosedManually, m_UserCookie);

			tcpReassemblyData.closed = true;  // mark the connection as closed
			insertIntoCleanupList(flowKey);

			PCPP_LOG_DEBUG("Connection with flow key 0x" << std::hex << flowKey << " is closed");
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
		// m_CleanupList is a map with key of type time_t (expiration time). The mapped type is a list that stores the
		// flow keys to be cleared in certain point of time. m_CleanupList.insert inserts an empty list if the container
		// does not already contain an element with an equivalent key, otherwise this method returns an iterator to the
		// element that prevents insertion.
		std::pair<CleanupList::iterator, bool> pair =
		    m_CleanupList.insert(std::make_pair(time(nullptr) + m_ClosedConnectionDelay, CleanupList::mapped_type()));

		// getting the reference to list
		CleanupList::mapped_type& keysList = pair.first->second;
		keysList.push_front(flowKey);
	}

	uint32_t TcpReassembly::purgeClosedConnections(uint32_t maxNumToClean)
	{
		uint32_t count = 0;

		if (maxNumToClean == 0)
			maxNumToClean = m_MaxNumToClean;

		CleanupList::iterator iterTime = m_CleanupList.begin(), iterTimeEnd = m_CleanupList.upper_bound(time(nullptr));
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

}  // namespace pcpp

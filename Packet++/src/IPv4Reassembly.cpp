#define LOG_MODULE PacketLogModuleIPv4Reassembly

#include "IPv4Reassembly.h"
#include "IPv4Layer.h"
#include "IpUtils.h"
#include "Logger.h"
#include <string.h>
#if defined(WIN32) || defined(WINx64)
#include <winsock2.h>
#elif LINUX
#include <in.h>
#endif

namespace pcpp
{

uint32_t ipv4ReassemblyHashPacket(IPv4Layer* ipv4Layer)
{
	ScalarBuffer<uint8_t> vec[3];

	vec[0].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipSrc;
	vec[0].len = 4;
	vec[1].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipDst;
	vec[1].len = 4;
	vec[2].buffer = (uint8_t*)&ipv4Layer->getIPv4Header()->ipId;
	vec[2].len = 2;

	return pcpp::fnv_hash(vec, 3);
}

uint32_t ipv4ReassemblyHashBy3Tuple(const IPv4Address& ipSrc, const IPv4Address& ipDst, uint16_t ipID)
{
	ScalarBuffer<uint8_t> vec[3];

	uint16_t ipIdNetworkOrder = htons(ipID);
	uint32_t ipSrcAsInt = ipSrc.toInt();
	uint32_t ipDstAsInt = ipDst.toInt();


	vec[0].buffer = (uint8_t*)&ipSrcAsInt;
	vec[0].len = 4;
	vec[1].buffer = (uint8_t*)&ipDstAsInt;
	vec[1].len = 4;
	vec[2].buffer = (uint8_t*)&ipIdNetworkOrder;
	vec[2].len = 2;

	return pcpp::fnv_hash(vec, 3);
}

IPv4Reassembly::IPv4Reassembly(OnFragmentsClean onFragmentsCleanCallback, int maxPacketsToStore, int cleanTimeout)
{
	m_PacketLRU = new LRUList<uint32_t>(maxPacketsToStore);
	m_CleanTimeout = cleanTimeout;
	m_OnFragmentsCleanCallback = onFragmentsCleanCallback;
}

IPv4Reassembly::~IPv4Reassembly()
{
	delete m_PacketLRU;

	while (!m_FragmentMap.empty())
	{
		delete m_FragmentMap.begin()->second;
		m_FragmentMap.erase(m_FragmentMap.begin());
	}
}

Packet* IPv4Reassembly::processPacket(Packet* packet, ReassemblyStatus& status)
{
	status = NON_IP_PACKET;

	if (!packet->isPacketOfType(IPv4))
	{
		LOG_DEBUG("Got a non-IPv4 packet");
		status = NON_IP_PACKET;
		return packet;
	}

	IPv4Layer* ipLayer = packet->getLayerOfType<IPv4Layer>();

	if (!(ipLayer->isFragment()))
	{
		LOG_DEBUG("Got a non fragment packet");
		status = NON_FRAGMENT;
		return packet;
	}

	uint32_t hash = ipv4ReassemblyHashPacket(ipLayer);

	IPFragmentData* fragData = NULL;
	std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);
	if (iter == m_FragmentMap.end())
	{
		LOG_DEBUG("Got new packet with IP ID=0x%X, allocating place in map", ntohs(ipLayer->getIPv4Header()->ipId));
		fragData = new IPFragmentData(ipLayer->getIPv4Header()->ipId);
		addNewFragment(hash, fragData);
	}
	else
	{
		fragData = iter->second;
	}


	bool gotLastFragment = false;

	if (ipLayer->isFirstFragment())
	{
		if (fragData->data == NULL) // first fragment
		{
			LOG_DEBUG("Got first fragment, allocating RawPacket");
			fragData->data = new RawPacket(*(packet->getRawPacket()));
			fragData->currentOffset = ipLayer->getLayerPayloadSize();
			status = FIRST_FRAGMENT;
			gotLastFragment = matchOutOfOrderFragments(fragData);
		}
		else // duplicated first fragment
		{
			LOG_DEBUG("Got duplicated first fragment");
			status = FIRST_FRAGMENT;
			return NULL;
		}
	}

	else // not first fragment
	{
		LOG_DEBUG("Got fragment");

		uint16_t fragOffset = ipLayer->getFragmentOffset();
		if (fragData->currentOffset == fragOffset)
		{
			// malformed fragment which is not the first fragment but its offset is 0
			if (fragData->data == NULL)
			{
				LOG_DEBUG("Fragment is malformed");
				status = MALFORMED_FRAGMENT;
				return NULL;
			}

			LOG_DEBUG("Found next matching fragment with offset %d, adding fragment data to reassembled packet", (int)fragOffset);
			fragData->data->reallocateData(fragData->data->getRawDataLen() + ipLayer->getLayerPayloadSize());
			fragData->data->appendData(ipLayer->getLayerPayload(), ipLayer->getLayerPayloadSize());
			fragData->currentOffset += ipLayer->getLayerPayloadSize();
			if (ipLayer->isLastFragment())
				gotLastFragment = true;
			else
				gotLastFragment = matchOutOfOrderFragments(fragData);
		}
		else if (fragOffset > fragData->currentOffset)
		{
			LOG_DEBUG("Got out-of-ordered fragment with offset %d (expected: %d). Adding it to out-of-order list", (int)fragOffset, (int)fragData->currentOffset);
			IPFragment* newFrag = new IPFragment();
			newFrag->fragmentOffset = ipLayer->getFragmentOffset();
			newFrag->fragmentData = new uint8_t[ipLayer->getLayerPayloadSize()];
			newFrag->fragmentDataLen = ipLayer->getLayerPayloadSize();
			memcpy(newFrag->fragmentData, ipLayer->getLayerPayload(), newFrag->fragmentDataLen);
			newFrag->lastFragment = ipLayer->isLastFragment();
			fragData->outOfOrderFragments.pushBack(newFrag);
			status = OUT_OF_ORDER_FRAGMENT;
			return NULL;
		}
		else
		{
			LOG_DEBUG("Got a fragment with an offset that was already seen: %d (current offset is: %d), probably duplicated fragment", (int)fragOffset, (int)fragData->currentOffset);
		}

	}

	if (gotLastFragment)
	{
		LOG_DEBUG("Reassembly process completed, allocating a packet and returning it");
		fragData->deleteData = false;
		Packet* reassembledPacket = new Packet(fragData->data, true);
		ipLayer = reassembledPacket->getLayerOfType<IPv4Layer>();
		ipLayer->getIPv4Header()->fragmentOffset = 0;
		ipLayer->computeCalculateFields();

		LOG_DEBUG("Deleting fragment data from map");
		delete fragData;
		m_FragmentMap.erase(iter);
		status = REASSEMBLED;
		return reassembledPacket;
	}

	if (status != FIRST_FRAGMENT)
		status = FRAGMENT;

	return NULL;
}

Packet* IPv4Reassembly::getCurrentPacket(const IPv4Address& srcIP, const IPv4Address& dstIP, uint16_t ipID)
{
	uint32_t hash = ipv4ReassemblyHashBy3Tuple(srcIP, dstIP, ipID);
	std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);
	if (iter != m_FragmentMap.end())
	{
		IPFragmentData* fragData = iter->second;
		if (fragData != NULL && fragData->data != NULL)
		{
			RawPacket* partialRawPacket = new RawPacket(*(fragData->data));
			Packet* partialDataPacket = new Packet(partialRawPacket, true);
			IPv4Layer* ipLayer = partialDataPacket->getLayerOfType<IPv4Layer>();
			ipLayer->getIPv4Header()->fragmentOffset = 0;
			ipLayer->computeCalculateFields();
			return partialDataPacket;
		}
	}

	return NULL;
}

void IPv4Reassembly::addNewFragment(uint32_t hash, IPFragmentData* fragData)
{
	uint32_t* packetRemoved = m_PacketLRU->put(hash);

	if (packetRemoved != NULL)
	{
		std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(*packetRemoved);
		IPFragmentData* dataRemoved = iter->second;
		uint16_t ipIdRemoved = dataRemoved->ipID;
		LOG_DEBUG("Reached maximum packet capacity, removing data for IP ID = %d", ipIdRemoved);
		delete dataRemoved;
		m_FragmentMap.erase(iter);

		if (m_OnFragmentsCleanCallback != NULL)
			m_OnFragmentsCleanCallback(ipIdRemoved);

		delete packetRemoved;
	}

	std::pair<uint32_t, IPFragmentData*> pair(hash, fragData);
	m_FragmentMap.insert(pair);
}

bool IPv4Reassembly::matchOutOfOrderFragments(IPFragmentData* fragData)
{
	LOG_DEBUG("Searching out-of-order fragment list for the next fragment");
	bool foundLastSgement = false;

	while (!foundLastSgement)
	{
		bool foundOutOfOrderFrag = false;

		int index = 0;
		while (index < (int)fragData->outOfOrderFragments.size())
		{
			IPFragment* frag = fragData->outOfOrderFragments.at(index);
			if (fragData->currentOffset == frag->fragmentOffset)
			{
				LOG_DEBUG("Found the next matching fragment in out-of-order list with offset %d, adding its data to reassembled packet", (int)frag->fragmentOffset);
				fragData->data->reallocateData(fragData->data->getRawDataLen() + frag->fragmentDataLen);
				fragData->data->appendData(frag->fragmentData, frag->fragmentDataLen);
				fragData->currentOffset += frag->fragmentDataLen;
				if (frag->lastFragment)
				{
					LOG_DEBUG("Found last fragment inside out-of-order list");
					foundLastSgement = true;
				}
				fragData->outOfOrderFragments.erase(fragData->outOfOrderFragments.begin() + index);
				foundOutOfOrderFrag = true;
			}
			else
				index++;
		}

		if (!foundOutOfOrderFrag)
		{
			LOG_DEBUG("Didn't find the next fragment in out-of-order list");
			break;
		}
	}

	return foundLastSgement;
}

}

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

IPv4Reassembly::IPv4Reassembly(OnFragmentsClean onFragmentsCleanCallback, void* callbackUserCookie, size_t maxPacketsToStore)
{
	m_PacketLRU = new LRUList<uint32_t>(maxPacketsToStore);
	m_OnFragmentsCleanCallback = onFragmentsCleanCallback;
	m_CallbackUserCookie = callbackUserCookie;
}

IPv4Reassembly::~IPv4Reassembly()
{
	delete m_PacketLRU;

	// empty the map - go over all keys, delete all IPFragmentData objects and remove them from the map
	while (!m_FragmentMap.empty())
	{
		delete m_FragmentMap.begin()->second;
		m_FragmentMap.erase(m_FragmentMap.begin());
	}
}

Packet* IPv4Reassembly::processPacket(Packet* packet, ReassemblyStatus& status)
{
	status = NON_IP_PACKET;

	// packet is not of type IPv4
	if (!packet->isPacketOfType(IPv4))
	{
		LOG_DEBUG("Got a non-IPv4 packet, returning packet to user");
		status = NON_IP_PACKET;
		return packet;
	}

	// get IPv4 layer
	IPv4Layer* ipLayer = packet->getLayerOfType<IPv4Layer>();

	// packet is not a fragment
	if (!(ipLayer->isFragment()))
	{
		LOG_DEBUG("Got a non fragment packet with IP ID=0x%X, returning packet to user", ntohs(ipLayer->getIPv4Header()->ipId));
		status = NON_FRAGMENT;
		return packet;
	}

	// create a hash from source IP, destination IP and IP ID
	uint32_t hash = ipv4ReassemblyHashPacket(ipLayer);

	IPFragmentData* fragData = NULL;

	// check whether this packet already exists in the map
	std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);

	// this is the first fragment seen for this packet
	if (iter == m_FragmentMap.end())
	{
		LOG_DEBUG("Got new packet with IP ID=0x%X, allocating place in map", ntohs(ipLayer->getIPv4Header()->ipId));

		// create the IPFragmentData object
		fragData = new IPFragmentData(ipLayer->getIPv4Header()->ipId, ipLayer->getIPv4Header()->ipSrc, ipLayer->getIPv4Header()->ipDst);

		// add the new fragment to the map
		addNewFragment(hash, fragData);
	}
	else // packet was seen before
	{
		// get the IPFragmentData object
		fragData = iter->second;

		// mark this packet as used
		m_PacketLRU->put(hash);
	}

	bool gotLastFragment = false;

	// if current fragment is the first fragment of this packet
	if (ipLayer->isFirstFragment())
	{
		if (fragData->data == NULL) // first fragment
		{
			LOG_DEBUG("[IPID=0x%X] Got first fragment, allocating RawPacket", ntohs(ipLayer->getIPv4Header()->ipId));

			// create the reassembled packet and copy the fragment data to it
			fragData->data = new RawPacket(*(packet->getRawPacket()));
			fragData->currentOffset = ipLayer->getLayerPayloadSize();
			status = FIRST_FRAGMENT;

			// check if the next fragments already arrived out-of-order and waiting in the out-of-order list
			gotLastFragment = matchOutOfOrderFragments(fragData);
		}
		else // duplicated first fragment
		{
			LOG_DEBUG("[IPID=0x%X] Got duplicated first fragment", ntohs(ipLayer->getIPv4Header()->ipId));
			status = FRAGMENT;
			return NULL;
		}
	}

	else // not first fragment
	{
		LOG_DEBUG("[IPID=0x%X] Got fragment", ntohs(ipLayer->getIPv4Header()->ipId));

		uint16_t fragOffset = ipLayer->getFragmentOffset();

		// check if the current fragment offset matches the expected fragment offset
		if (fragData->currentOffset == fragOffset)
		{
			// malformed fragment which is not the first fragment but its offset is 0
			if (fragData->data == NULL)
			{
				LOG_DEBUG("[IPID=0x%X] Fragment is malformed", ntohs(ipLayer->getIPv4Header()->ipId));
				status = MALFORMED_FRAGMENT;
				return NULL;
			}

			LOG_DEBUG("[IPID=0x%X] Found next matching fragment with offset %d, adding fragment data to reassembled packet", ntohs(ipLayer->getIPv4Header()->ipId), (int)fragOffset);

			// copy fragment data to reassembled packet
			fragData->data->reallocateData(fragData->data->getRawDataLen() + ipLayer->getLayerPayloadSize());
			fragData->data->appendData(ipLayer->getLayerPayload(), ipLayer->getLayerPayloadSize());

			// update expected offset
			fragData->currentOffset += ipLayer->getLayerPayloadSize();

			// if this is the last fragment - mark it
			if (ipLayer->isLastFragment())
				gotLastFragment = true;
			else
				// if not the last fragment - check if the next fragments are waiting in the out-of-order list
				gotLastFragment = matchOutOfOrderFragments(fragData);
		}
		// if current fragment offset is larger than expected - this means this fragment is out-of-order
		else if (fragOffset > fragData->currentOffset)
		{
			LOG_DEBUG("[IPID=0x%X] Got out-of-ordered fragment with offset %d (expected: %d). Adding it to out-of-order list", ntohs(ipLayer->getIPv4Header()->ipId), (int)fragOffset, (int)fragData->currentOffset);

			// create a new IPFragment and copy the fragment data and params to it
			IPFragment* newFrag = new IPFragment();
			newFrag->fragmentOffset = ipLayer->getFragmentOffset();
			newFrag->fragmentData = new uint8_t[ipLayer->getLayerPayloadSize()];
			newFrag->fragmentDataLen = ipLayer->getLayerPayloadSize();
			memcpy(newFrag->fragmentData, ipLayer->getLayerPayload(), newFrag->fragmentDataLen);
			newFrag->lastFragment = ipLayer->isLastFragment();

			// store the IPFragment in the out-of-order fragment list
			fragData->outOfOrderFragments.pushBack(newFrag);

			status = OUT_OF_ORDER_FRAGMENT;
			return NULL;
		}
		else
		{
			LOG_DEBUG("[IPID=0x%X] Got a fragment with an offset that was already seen: %d (current offset is: %d), probably duplicated fragment", ntohs(ipLayer->getIPv4Header()->ipId), (int)fragOffset, (int)fragData->currentOffset);
		}

	}

	// if seen the last fragment
	if (gotLastFragment)
	{
		LOG_DEBUG("[IPID=0x%X] Reassembly process completed, allocating a packet and returning it", ntohs(ipLayer->getIPv4Header()->ipId));
		fragData->deleteData = false;

		// create a new Packet object with the reassembled data as its RawPacket
		Packet* reassembledPacket = new Packet(fragData->data, true);

		// set the fragment offset to 0
		ipLayer = reassembledPacket->getLayerOfType<IPv4Layer>();
		ipLayer->getIPv4Header()->fragmentOffset = 0;

		// re-calculate all IPv4 fields
		ipLayer->computeCalculateFields();

		LOG_DEBUG("[IPID=0x%X] Deleting fragment data from map", ntohs(ipLayer->getIPv4Header()->ipId));

		// delete the IPFragmentData object and remove it from the map
		delete fragData;
		m_FragmentMap.erase(iter);
		m_PacketLRU->eraseElement(hash);
		status = REASSEMBLED;
		return reassembledPacket;
	}

	// if got to here it means this fragment is either the first fragment or a fragment in the middle. Set the appropriate status and return
	if (status != FIRST_FRAGMENT)
		status = FRAGMENT;

	return NULL;
}

Packet* IPv4Reassembly::processPacket(RawPacket* packet, ReassemblyStatus& status)
{
	Packet* parsedPacket = new Packet(packet);
	Packet* result = processPacket(parsedPacket, status);
	if (result != parsedPacket)
		delete parsedPacket;

	return result;
}

Packet* IPv4Reassembly::getCurrentPacket(const PacketKey& key)
{
	uint32_t hash = ipv4ReassemblyHashBy3Tuple(key.srcIP, key.dstIP, key.ipID);
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

void IPv4Reassembly::removePacket(const PacketKey& key)
{
	uint32_t hash = ipv4ReassemblyHashBy3Tuple(key.srcIP, key.dstIP, key.ipID);
	std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);
	if (iter != m_FragmentMap.end())
	{
		delete iter->second;
		m_FragmentMap.erase(iter);
		m_PacketLRU->eraseElement(hash);
	}
}

void IPv4Reassembly::addNewFragment(uint32_t hash, IPFragmentData* fragData)
{
	uint32_t* packetRemoved = m_PacketLRU->put(hash);

	if (packetRemoved != NULL)
	{
		std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(*packetRemoved);
		IPFragmentData* dataRemoved = iter->second;
		uint16_t ipIdRemoved = dataRemoved->ipID;
		IPv4Address srcIP(dataRemoved->srcIP);
		IPv4Address dstIP(dataRemoved->dstIP);
		LOG_DEBUG("Reached maximum packet capacity, removing data for IP ID = 0x%X", ipIdRemoved);
		delete dataRemoved;
		m_FragmentMap.erase(iter);

		if (m_OnFragmentsCleanCallback != NULL)
		{
			PacketKey key(ntohs(ipIdRemoved), srcIP, dstIP);
			m_OnFragmentsCleanCallback(key, m_CallbackUserCookie);
		}


		delete packetRemoved;
	}

	std::pair<uint32_t, IPFragmentData*> pair(hash, fragData);
	m_FragmentMap.insert(pair);
}

bool IPv4Reassembly::matchOutOfOrderFragments(IPFragmentData* fragData)
{
	LOG_DEBUG("[IPID=0x%X] Searching out-of-order fragment list for the next fragment", ntohs(fragData->ipID));
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
				LOG_DEBUG("[IPID=0x%X] Found the next matching fragment in out-of-order list with offset %d, adding its data to reassembled packet", ntohs(fragData->ipID), (int)frag->fragmentOffset);
				fragData->data->reallocateData(fragData->data->getRawDataLen() + frag->fragmentDataLen);
				fragData->data->appendData(frag->fragmentData, frag->fragmentDataLen);
				fragData->currentOffset += frag->fragmentDataLen;
				if (frag->lastFragment)
				{
					LOG_DEBUG("[IPID=0x%X] Found last fragment inside out-of-order list", ntohs(fragData->ipID));
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
			LOG_DEBUG("[IPID=0x%X] Didn't find the next fragment in out-of-order list", ntohs(fragData->ipID));
			break;
		}
	}

	return foundLastSgement;
}

}

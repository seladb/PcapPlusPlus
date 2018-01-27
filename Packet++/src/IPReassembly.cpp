#define LOG_MODULE PacketLogModuleIPReassembly

#include "IPReassembly.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
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

uint32_t IPReassemblyHashPacket(IPv4Layer* ipv4Layer)
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

uint32_t IPReassemblyHashBy3Tuple(const IPv4Address& ipSrc, const IPv4Address& ipDst, uint16_t ipID)
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

class IPFragmentWrapper
{
public:
	virtual bool isFragment() = 0;
	virtual bool isFirstFragment() = 0;
	virtual bool isLastFragment() = 0;
	virtual uint16_t getFragmentOffset() = 0;
	virtual uint32_t getFragmentId() = 0;
	virtual uint32_t hashPacket() = 0;
	virtual IPReassembly::PacketKey* createPacketKey() = 0;

	virtual uint8_t* getIPLayerPayload() = 0;
	virtual size_t getIPLayerPayloadSize() = 0;

	virtual ~IPFragmentWrapper() { }

protected:

	IPFragmentWrapper() {}
};

class IPv4FragmentWrapper : public IPFragmentWrapper
{
public:
	IPv4FragmentWrapper(Packet* fragment)
	{
		m_IPLayer =  fragment->getLayerOfType<IPv4Layer>();
	}

	// implement abstract methods

	bool isFragment()
	{
		return m_IPLayer->isFragment();
	}

	bool isFirstFragment()
	{
		return m_IPLayer->isFirstFragment();
	}

	bool isLastFragment()
	{
		return m_IPLayer->isLastFragment();
	}

	uint16_t getFragmentOffset()
	{
		return m_IPLayer->getFragmentOffset();
	}

	uint32_t getFragmentId()
	{
		return (uint32_t)ntohs(m_IPLayer->getIPv4Header()->ipId);
	}

	uint32_t hashPacket()
	{
		ScalarBuffer<uint8_t> vec[3];

		vec[0].buffer = (uint8_t*)&m_IPLayer->getIPv4Header()->ipSrc;
		vec[0].len = 4;
		vec[1].buffer = (uint8_t*)&m_IPLayer->getIPv4Header()->ipDst;
		vec[1].len = 4;
		vec[2].buffer = (uint8_t*)&m_IPLayer->getIPv4Header()->ipId;
		vec[2].len = 2;

		return pcpp::fnv_hash(vec, 3);
	}

	IPReassembly::PacketKey* createPacketKey()
	{
		return new IPReassembly::IPv4PacketKey(ntohs(m_IPLayer->getIPv4Header()->ipId), m_IPLayer->getSrcIpAddress(), m_IPLayer->getDstIpAddress());
	}

	uint8_t* getIPLayerPayload()
	{
		return m_IPLayer->getLayerPayload();
	}

	size_t getIPLayerPayloadSize()
	{
		return m_IPLayer->getLayerPayloadSize();
	}

private:
	IPv4Layer* m_IPLayer;

};

class IPv6FragmentWrapper : public IPFragmentWrapper
{
public:
	IPv6FragmentWrapper(Packet* fragment)
	{
		m_IPLayer =  fragment->getLayerOfType<IPv6Layer>();
		if (m_IPLayer != NULL)
			m_FragHeader = m_IPLayer->getExtensionOfType<IPv6FragmentationHeader>();
		else
			m_FragHeader = NULL;
	}

	// implement abstract methods

	bool isFragment()
	{
		return (m_FragHeader != NULL);
	}

	bool isFirstFragment()
	{
		if (isFragment())
			return m_FragHeader->isFirstFragment();

		return false;
	}

	bool isLastFragment()
	{
		if (isFragment())
			return m_FragHeader->isLastFragment();

		return false;
	}


	uint16_t getFragmentOffset()
	{
		if (isFragment())
			return m_FragHeader->getFragmentOffset();

		return 0;
	}

	uint32_t getFragmentId()
	{
		return ntohl(m_FragHeader->getFragHeader()->id);
	}

	uint32_t hashPacket()
	{
		if (m_FragHeader == NULL)
			return 0;

		ScalarBuffer<uint8_t> vec[3];

		vec[0].buffer = m_IPLayer->getIPv6Header()->ipSrc;
		vec[0].len = 16;
		vec[1].buffer = m_IPLayer->getIPv6Header()->ipDst;
		vec[1].len = 16;
		vec[2].buffer = (uint8_t*)&m_FragHeader->getFragHeader()->id;
		vec[2].len = 4;

		return pcpp::fnv_hash(vec, 3);
	}

	IPReassembly::PacketKey* createPacketKey()
	{
		return new IPReassembly::IPv6PacketKey(ntohl(m_FragHeader->getFragHeader()->id), m_IPLayer->getSrcIpAddress(), m_IPLayer->getDstIpAddress());
	}

	uint8_t* getIPLayerPayload()
	{
		return m_IPLayer->getLayerPayload();
	}

	size_t getIPLayerPayloadSize()
	{
		return m_IPLayer->getLayerPayloadSize();
	}

private:
	IPv6Layer* m_IPLayer;
	IPv6FragmentationHeader* m_FragHeader;

};


uint32_t IPReassembly::IPv4PacketKey::getHashValue() const
{
	ScalarBuffer<uint8_t> vec[3];

	uint16_t ipIdNetworkOrder = htons(m_IpID);
	uint32_t ipSrcAsInt = m_SrcIP.toInt();
	uint32_t ipDstAsInt = m_DstIP.toInt();

	vec[0].buffer = (uint8_t*)&ipSrcAsInt;
	vec[0].len = 4;
	vec[1].buffer = (uint8_t*)&ipDstAsInt;
	vec[1].len = 4;
	vec[2].buffer = (uint8_t*)&ipIdNetworkOrder;
	vec[2].len = 2;

	return pcpp::fnv_hash(vec, 3);
}

uint32_t IPReassembly::IPv6PacketKey::getHashValue() const
{
	ScalarBuffer<uint8_t> vec[3];

	uint32_t fragIdNetworkOrder = htonl(m_FragmentID);
	uint8_t ipSrcAsByteArr[16];
	uint8_t ipDstAsByteArr[16];
	m_SrcIP.copyTo(ipSrcAsByteArr);
	m_DstIP.copyTo(ipDstAsByteArr);

	vec[0].buffer = ipSrcAsByteArr;
	vec[0].len = 16;
	vec[1].buffer = ipDstAsByteArr;
	vec[1].len = 16;
	vec[2].buffer = (uint8_t*)&fragIdNetworkOrder;
	vec[2].len = 4;

	return pcpp::fnv_hash(vec, 3);
}



IPReassembly::IPReassembly(OnFragmentsClean onFragmentsCleanCallback, void* callbackUserCookie, size_t maxPacketsToStore)
{
	m_PacketLRU = new LRUList<uint32_t>(maxPacketsToStore);
	m_OnFragmentsCleanCallback = onFragmentsCleanCallback;
	m_CallbackUserCookie = callbackUserCookie;
}

IPReassembly::~IPReassembly()
{
	delete m_PacketLRU;

	// empty the map - go over all keys, delete all IPFragmentData objects and remove them from the map
	while (!m_FragmentMap.empty())
	{
		delete m_FragmentMap.begin()->second;
		m_FragmentMap.erase(m_FragmentMap.begin());
	}
}

Packet* IPReassembly::processPacket(Packet* fragment, ReassemblyStatus& status)
{
	status = NON_IP_PACKET;

	// packet is not an IP packet
	if (!fragment->isPacketOfType(IPv4) && !fragment->isPacketOfType(IPv6))
	{
		LOG_DEBUG("Got a non-IP packet, returning packet to user");
		status = NON_IP_PACKET;
		return fragment;
	}

	// get IPv4 layer
	//IPv4Layer* ipLayer = fragment->getLayerOfType<IPv4Layer>();

	// create fragment wrapper
	IPv4FragmentWrapper ipv4Wrapper(fragment);
	IPv6FragmentWrapper ipv6Wrapper(fragment);
	IPFragmentWrapper* fragWrapper = NULL;
	if (fragment->isPacketOfType(IPv4))
		fragWrapper = &ipv4Wrapper;
	else // fragment->isPacketOfType(IPv6)
		fragWrapper = &ipv6Wrapper;

	// packet is not a fragment
	if (!(fragWrapper->isFragment()))
	{
		LOG_DEBUG("Got a non fragment packet with FragID=0x%X, returning packet to user", fragWrapper->getFragmentId());
		status = NON_FRAGMENT;
		return fragment;
	}

	// create a hash from source IP, destination IP and IP/fragment ID
	uint32_t hash = fragWrapper->hashPacket();

	IPFragmentData* fragData = NULL;

	// check whether this packet already exists in the map
	std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);

	// this is the first fragment seen for this packet
	if (iter == m_FragmentMap.end())
	{
		LOG_DEBUG("Got new packet with FragID=0x%X, allocating place in map", fragWrapper->getFragmentId());

		// create the IPFragmentData object
		fragData = new IPFragmentData(fragWrapper->createPacketKey(), fragWrapper->getFragmentId());

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
	if (fragWrapper->isFirstFragment())
	{
		if (fragData->data == NULL) // first fragment
		{
			LOG_DEBUG("[FragID=0x%X] Got first fragment, allocating RawPacket", fragWrapper->getFragmentId());

			// create the reassembled packet and copy the fragment data to it
			fragData->data = new RawPacket(*(fragment->getRawPacket()));
			fragData->currentOffset = fragWrapper->getIPLayerPayloadSize();
			status = FIRST_FRAGMENT;

			// check if the next fragments already arrived out-of-order and waiting in the out-of-order list
			gotLastFragment = matchOutOfOrderFragments(fragData);
		}
		else // duplicated first fragment
		{
			LOG_DEBUG("[FragID=0x%X] Got duplicated first fragment", fragWrapper->getFragmentId());
			status = FRAGMENT;
			return NULL;
		}
	}

	else // not first fragment
	{
		LOG_DEBUG("[FragID=0x%X] Got fragment", fragWrapper->getFragmentId());

		uint16_t fragOffset = fragWrapper->getFragmentOffset();

		// check if the current fragment offset matches the expected fragment offset
		if (fragData->currentOffset == fragOffset)
		{
			// malformed fragment which is not the first fragment but its offset is 0
			if (fragData->data == NULL)
			{
				LOG_DEBUG("[FragID=0x%X] Fragment is malformed", fragWrapper->getFragmentId());
				status = MALFORMED_FRAGMENT;
				return NULL;
			}

			LOG_DEBUG("[FragID=0x%X] Found next matching fragment with offset %d, adding fragment data to reassembled packet", fragWrapper->getFragmentId(), (int)fragOffset);

			// copy fragment data to reassembled packet
			fragData->data->reallocateData(fragData->data->getRawDataLen() + fragWrapper->getIPLayerPayloadSize());
			fragData->data->appendData(fragWrapper->getIPLayerPayload(), fragWrapper->getIPLayerPayloadSize());

			// update expected offset
			fragData->currentOffset += fragWrapper->getIPLayerPayloadSize();

			// if this is the last fragment - mark it
			if (fragWrapper->isLastFragment())
				gotLastFragment = true;
			else
				// if not the last fragment - check if the next fragments are waiting in the out-of-order list
				gotLastFragment = matchOutOfOrderFragments(fragData);
		}
		// if current fragment offset is larger than expected - this means this fragment is out-of-order
		else if (fragOffset > fragData->currentOffset)
		{
			LOG_DEBUG("[FragID=0x%X] Got out-of-ordered fragment with offset %d (expected: %d). Adding it to out-of-order list", fragWrapper->getFragmentId(), (int)fragOffset, (int)fragData->currentOffset);

			// create a new IPFragment and copy the fragment data and params to it
			IPFragment* newFrag = new IPFragment();
			newFrag->fragmentOffset = fragWrapper->getFragmentOffset();
			newFrag->fragmentData = new uint8_t[fragWrapper->getIPLayerPayloadSize()];
			newFrag->fragmentDataLen = fragWrapper->getIPLayerPayloadSize();
			memcpy(newFrag->fragmentData, fragWrapper->getIPLayerPayload(), newFrag->fragmentDataLen);
			newFrag->lastFragment = fragWrapper->isLastFragment();

			// store the IPFragment in the out-of-order fragment list
			fragData->outOfOrderFragments.pushBack(newFrag);

			status = OUT_OF_ORDER_FRAGMENT;
			return NULL;
		}
		else
		{
			LOG_DEBUG("[FragID=0x%X] Got a fragment with an offset that was already seen: %d (current offset is: %d), probably duplicated fragment", fragWrapper->getFragmentId(), (int)fragOffset, (int)fragData->currentOffset);
		}

	}

	// if seen the last fragment
	if (gotLastFragment)
	{
		LOG_DEBUG("[FragID=0x%X] Reassembly process completed, allocating a packet and returning it", fragWrapper->getFragmentId());
		fragData->deleteData = false;

		// create a new Packet object with the reassembled data as its RawPacket
		Packet* reassembledPacket = new Packet(fragData->data, true);

		if (fragData->packetKey->getProtocolType() == IPv4)
		{
			// set the fragment offset to 0
			IPv4Layer* ipLayer = reassembledPacket->getLayerOfType<IPv4Layer>();
			ipLayer->getIPv4Header()->fragmentOffset = 0;

			// re-calculate all IPv4 fields
			ipLayer->computeCalculateFields();
		}
		else
		{
			// remove fragment extension
			IPv6Layer* ipLayer = reassembledPacket->getLayerOfType<IPv6Layer>();
			ipLayer->removeAllExtensions();

			// re-calculate all IPv4 fields
			ipLayer->computeCalculateFields();
		}

		LOG_DEBUG("[FragID=0x%X] Deleting fragment data from map", fragWrapper->getFragmentId());

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

Packet* IPReassembly::processPacket(RawPacket* fragment, ReassemblyStatus& status)
{
	Packet* parsedFragment = new Packet(fragment);
	Packet* result = processPacket(parsedFragment, status);
	if (result != parsedFragment)
		delete parsedFragment;

	return result;
}

Packet* IPReassembly::getCurrentPacket(const PacketKey& key)
{
	// create a hash out of the packet key
	uint32_t hash = key.getHashValue();

	// look for this hash value in the map
	std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);

	// hash was found
	if (iter != m_FragmentMap.end())
	{
		IPFragmentData* fragData = iter->second;

		// some data already exists
		if (fragData != NULL && fragData->data != NULL)
		{
			// create a copy of the RawPacket object
			RawPacket* partialRawPacket = new RawPacket(*(fragData->data));

			// create a packet object wrapping the RawPacket we've just created
			Packet* partialDataPacket = new Packet(partialRawPacket, true);

			// prepare the packet and return it
			if (key.getProtocolType() == IPv4)
			{
				IPv4Layer* ipLayer = partialDataPacket->getLayerOfType<IPv4Layer>();
				ipLayer->getIPv4Header()->fragmentOffset = 0;
				ipLayer->computeCalculateFields();
			}
			else // key.getProtocolType() == IPv6
			{
				IPv6Layer* ipLayer = partialDataPacket->getLayerOfType<IPv6Layer>();
				ipLayer->removeAllExtensions();
				ipLayer->computeCalculateFields();
			}

			return partialDataPacket;
		}
	}

	return NULL;
}

void IPReassembly::removePacket(const PacketKey& key)
{
	// create a hash out of the packet key
	uint32_t hash = key.getHashValue();

	// look for this hash value in the map
	std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);

	// hash was found
	if (iter != m_FragmentMap.end())
	{
		// free all data saved in the map
		delete iter->second;
		m_FragmentMap.erase(iter);

		// remove from LRU list
		m_PacketLRU->eraseElement(hash);
	}
}

void IPReassembly::addNewFragment(uint32_t hash, IPFragmentData* fragData)
{
	// put the new frag in the LRU list
	uint32_t* packetRemoved = m_PacketLRU->put(hash);

	if (packetRemoved != NULL) // this means LRU list was full and the least recently used item was removed
	{
		// remove this item from the fragment map
		std::map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(*packetRemoved);
		IPFragmentData* dataRemoved = iter->second;
		PacketKey* key = dataRemoved->packetKey->clone();
		LOG_DEBUG("Reached maximum packet capacity, removing data for FragID=0x%X", dataRemoved->fragmentID);
		delete dataRemoved;
		m_FragmentMap.erase(iter);

		// fire callback if not null
		if (m_OnFragmentsCleanCallback != NULL)
		{
			m_OnFragmentsCleanCallback(key, m_CallbackUserCookie);
		}

		delete key;
		delete packetRemoved;
	}

	// add the new fragment to the map
	std::pair<uint32_t, IPFragmentData*> pair(hash, fragData);
	m_FragmentMap.insert(pair);
}

bool IPReassembly::matchOutOfOrderFragments(IPFragmentData* fragData)
{
	LOG_DEBUG("[FragID=0x%X] Searching out-of-order fragment list for the next fragment", fragData->fragmentID);

	// a flag indicating whether the last fragment of the packet was found
	bool foundLastSgement = false;

	// run until the last fragment was found or until we finished going over the out-of-order list and didn't find any matching fragment
	while (!foundLastSgement)
	{
		bool foundOutOfOrderFrag = false;

		int index = 0;

		// go over all fragment in the out-of-order list
		while (index < (int)fragData->outOfOrderFragments.size())
		{
			// get the current fragment from the out-of-order list
			IPFragment* frag = fragData->outOfOrderFragments.at(index);

			// this fragment is exactly the one we're looking for
			if (fragData->currentOffset == frag->fragmentOffset)
			{
				// add it to the reassembled packet
				LOG_DEBUG("[FragID=0x%X] Found the next matching fragment in out-of-order list with offset %d, adding its data to reassembled packet", fragData->fragmentID, (int)frag->fragmentOffset);
				fragData->data->reallocateData(fragData->data->getRawDataLen() + frag->fragmentDataLen);
				fragData->data->appendData(frag->fragmentData, frag->fragmentDataLen);
				fragData->currentOffset += frag->fragmentDataLen;
				if (frag->lastFragment) // if this is the last fragment of the packet
				{
					LOG_DEBUG("[FragID=0x%X] Found last fragment inside out-of-order list", fragData->fragmentID);
					foundLastSgement = true;
				}

				// remove this fragment from the out-of-order list
				fragData->outOfOrderFragments.erase(fragData->outOfOrderFragments.begin() + index);

				// mark that we found at least one matching fragment in the out-of-order list
				foundOutOfOrderFrag = true;
			}
			else
				index++;
		}

		// during the search we did on the out-of-order list we didn't find any matching fragment
		if (!foundOutOfOrderFrag)
		{
			// break the loop - need to wait for the missing fragment in next incoming packets
			LOG_DEBUG("[FragID=0x%X] Didn't find the next fragment in out-of-order list", fragData->fragmentID);
			break;
		}
	}

	return foundLastSgement;
}

}

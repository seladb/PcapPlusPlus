#define LOG_MODULE PacketLogModuleIPReassembly

#include "IPReassembly.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PacketUtils.h"
#include "Logger.h"
#include "EndianPortable.h"

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

		return pcpp::fnvHash(vec, 3);
	}

	uint32_t IPReassemblyHashBy3Tuple(const IPv4Address& ipSrc, const IPv4Address& ipDst, uint16_t ipID)
	{
		ScalarBuffer<uint8_t> vec[3];

		uint16_t ipIdNetworkOrder = htobe16(ipID);
		uint32_t ipSrcAsInt = ipSrc.toInt();
		uint32_t ipDstAsInt = ipDst.toInt();

		vec[0].buffer = (uint8_t*)&ipSrcAsInt;
		vec[0].len = 4;
		vec[1].buffer = (uint8_t*)&ipDstAsInt;
		vec[1].len = 4;
		vec[2].buffer = (uint8_t*)&ipIdNetworkOrder;
		vec[2].len = 2;

		return pcpp::fnvHash(vec, 3);
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

		virtual ~IPFragmentWrapper()
		{}

	protected:
		IPFragmentWrapper()
		{}
	};

	class IPv4FragmentWrapper : public IPFragmentWrapper
	{
	public:
		explicit IPv4FragmentWrapper(Packet* fragment)
		{
			m_IPLayer = fragment->isPacketOfType(IPv4) ? fragment->getLayerOfType<IPv4Layer>() : nullptr;
		}

		// implement abstract methods

		bool isFragment() override
		{
			return m_IPLayer->isFragment();
		}

		bool isFirstFragment() override
		{
			return m_IPLayer->isFirstFragment();
		}

		bool isLastFragment() override
		{
			return m_IPLayer->isLastFragment();
		}

		uint16_t getFragmentOffset() override
		{
			return m_IPLayer->getFragmentOffset();
		}

		uint32_t getFragmentId() override
		{
			return (uint32_t)be16toh(m_IPLayer->getIPv4Header()->ipId);
		}

		uint32_t hashPacket() override
		{
			ScalarBuffer<uint8_t> vec[3];

			vec[0].buffer = (uint8_t*)&m_IPLayer->getIPv4Header()->ipSrc;
			vec[0].len = 4;
			vec[1].buffer = (uint8_t*)&m_IPLayer->getIPv4Header()->ipDst;
			vec[1].len = 4;
			vec[2].buffer = (uint8_t*)&m_IPLayer->getIPv4Header()->ipId;
			vec[2].len = 2;

			return pcpp::fnvHash(vec, 3);
		}

		IPReassembly::PacketKey* createPacketKey() override
		{
			return new IPReassembly::IPv4PacketKey(be16toh(m_IPLayer->getIPv4Header()->ipId),
			                                       m_IPLayer->getSrcIPv4Address(), m_IPLayer->getDstIPv4Address());
		}

		uint8_t* getIPLayerPayload() override
		{
			return m_IPLayer->getLayerPayload();
		}

		size_t getIPLayerPayloadSize() override
		{
			return m_IPLayer->getLayerPayloadSize();
		}

	private:
		IPv4Layer* m_IPLayer;
	};

	class IPv6FragmentWrapper : public IPFragmentWrapper
	{
	public:
		explicit IPv6FragmentWrapper(Packet* fragment)
		{
			m_IPLayer = fragment->isPacketOfType(IPv6) ? fragment->getLayerOfType<IPv6Layer>() : nullptr;
			if (m_IPLayer != nullptr)
				m_FragHeader = m_IPLayer->getExtensionOfType<IPv6FragmentationHeader>();
			else
				m_FragHeader = nullptr;
		}

		// implement abstract methods

		bool isFragment() override
		{
			return (m_FragHeader != nullptr);
		}

		bool isFirstFragment() override
		{
			if (isFragment())
				return m_FragHeader->isFirstFragment();

			return false;
		}

		bool isLastFragment() override
		{
			if (isFragment())
				return m_FragHeader->isLastFragment();

			return false;
		}

		uint16_t getFragmentOffset() override
		{
			if (isFragment())
				return m_FragHeader->getFragmentOffset();

			return 0;
		}

		uint32_t getFragmentId() override
		{
			return be32toh(m_FragHeader->getFragHeader()->id);
		}

		uint32_t hashPacket() override
		{
			if (m_FragHeader == nullptr)
				return 0;

			ScalarBuffer<uint8_t> vec[3];

			vec[0].buffer = m_IPLayer->getIPv6Header()->ipSrc;
			vec[0].len = 16;
			vec[1].buffer = m_IPLayer->getIPv6Header()->ipDst;
			vec[1].len = 16;
			vec[2].buffer = (uint8_t*)&m_FragHeader->getFragHeader()->id;
			vec[2].len = 4;

			return pcpp::fnvHash(vec, 3);
		}

		IPReassembly::PacketKey* createPacketKey() override
		{
			return new IPReassembly::IPv6PacketKey(be32toh(m_FragHeader->getFragHeader()->id),
			                                       m_IPLayer->getSrcIPv6Address(), m_IPLayer->getDstIPv6Address());
		}

		uint8_t* getIPLayerPayload() override
		{
			return m_IPLayer->getLayerPayload();
		}

		size_t getIPLayerPayloadSize() override
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

		uint16_t ipIdNetworkOrder = htobe16(m_IpID);
		uint32_t ipSrcAsInt = m_SrcIP.toInt();
		uint32_t ipDstAsInt = m_DstIP.toInt();

		vec[0].buffer = (uint8_t*)&ipSrcAsInt;
		vec[0].len = 4;
		vec[1].buffer = (uint8_t*)&ipDstAsInt;
		vec[1].len = 4;
		vec[2].buffer = (uint8_t*)&ipIdNetworkOrder;
		vec[2].len = 2;

		return pcpp::fnvHash(vec, 3);
	}

	uint32_t IPReassembly::IPv6PacketKey::getHashValue() const
	{
		ScalarBuffer<uint8_t> vec[3];

		uint32_t fragIdNetworkOrder = htobe32(m_FragmentID);
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

		return pcpp::fnvHash(vec, 3);
	}

	IPReassembly::~IPReassembly()
	{
		// empty the map - go over all keys, delete all IPFragmentData objects and remove them from the map
		while (!m_FragmentMap.empty())
		{
			delete m_FragmentMap.begin()->second;
			m_FragmentMap.erase(m_FragmentMap.begin());
		}
	}

	Packet* IPReassembly::processPacket(Packet* fragment, ReassemblyStatus& status, ProtocolType parseUntil,
	                                    OsiModelLayer parseUntilLayer)
	{
		status = NON_IP_PACKET;

		// packet is not an IP packet
		if (!fragment->isPacketOfType(IPv4) && !fragment->isPacketOfType(IPv6))
		{
			PCPP_LOG_DEBUG("Got a non-IP packet, returning packet to user");
			status = NON_IP_PACKET;
			return fragment;
		}

		// get IPv4 layer
		// IPv4Layer* ipLayer = fragment->getLayerOfType<IPv4Layer>();

		// create fragment wrapper
		IPv4FragmentWrapper ipv4Wrapper(fragment);
		IPv6FragmentWrapper ipv6Wrapper(fragment);
		IPFragmentWrapper* fragWrapper = nullptr;
		if (fragment->isPacketOfType(IPv4))
			fragWrapper = &ipv4Wrapper;
		else  // fragment->isPacketOfType(IPv6)
			fragWrapper = &ipv6Wrapper;

		// packet is not a fragment
		if (!(fragWrapper->isFragment()))
		{
			PCPP_LOG_DEBUG("Got a non fragment packet with FragID=0x" << std::hex << fragWrapper->getFragmentId()
			                                                          << ", returning packet to user");
			status = NON_FRAGMENT;
			return fragment;
		}

		// create a hash from source IP, destination IP and IP/fragment ID
		uint32_t hash = fragWrapper->hashPacket();

		IPFragmentData* fragData = nullptr;

		// check whether this packet already exists in the map
		std::unordered_map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);

		// this is the first fragment seen for this packet
		if (iter == m_FragmentMap.end())
		{
			PCPP_LOG_DEBUG("Got new packet with FragID=0x" << std::hex << fragWrapper->getFragmentId()
			                                               << ", allocating place in map");

			// create the IPFragmentData object
			fragData = new IPFragmentData(fragWrapper->createPacketKey(), fragWrapper->getFragmentId());

			// add the new fragment to the map
			addNewFragment(hash, fragData);
		}
		else  // packet was seen before
		{
			// get the IPFragmentData object
			fragData = iter->second;

			// mark this packet as used
			m_PacketLRU.put(hash, nullptr);
		}

		bool gotLastFragment = false;

		// if current fragment is the first fragment of this packet
		if (fragWrapper->isFirstFragment())
		{
			if (fragData->data == nullptr)  // first fragment
			{
				PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragWrapper->getFragmentId()
				                            << "] Got first fragment, allocating RawPacket");

				// create the reassembled packet and copy the fragment data to it

				// copy only data from the beginning of the fragment to the end of IP layer payload.
				// Don't copy data beyond it such as packet trailer
				auto fragmentRawPacket = fragment->getRawPacket();
				auto rawDataLen = fragWrapper->getIPLayerPayload() - fragmentRawPacket->getRawData() +
				                  fragWrapper->getIPLayerPayloadSize();
				auto rawData = new uint8_t[rawDataLen];
				memcpy(rawData, fragmentRawPacket->getRawData(), rawDataLen);

				fragData->data = new RawPacket(rawData, rawDataLen, fragmentRawPacket->getPacketTimeStamp(), true,
				                               fragmentRawPacket->getLinkLayerType());
				fragData->currentOffset = fragWrapper->getIPLayerPayloadSize();
				status = FIRST_FRAGMENT;

				// check if the next fragments already arrived out-of-order and waiting in the out-of-order list
				gotLastFragment = matchOutOfOrderFragments(fragData);
			}
			else  // duplicated first fragment
			{
				PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragWrapper->getFragmentId()
				                            << "] Got duplicated first fragment");
				status = FRAGMENT;
				return nullptr;
			}
		}

		else  // not first fragment
		{
			PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragWrapper->getFragmentId() << "] Got fragment");

			uint16_t fragOffset = fragWrapper->getFragmentOffset();

			// check if the current fragment offset matches the expected fragment offset
			if (fragData->currentOffset == fragOffset)
			{
				// malformed fragment which is not the first fragment but its offset is 0
				if (fragData->data == nullptr)
				{
					PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragWrapper->getFragmentId()
					                            << "] Fragment is malformed");
					status = MALFORMED_FRAGMENT;
					return nullptr;
				}

				PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragWrapper->getFragmentId()
				                            << "] Found next matching fragment with offset " << fragOffset
				                            << ", adding fragment data to reassembled packet");

				size_t payloadSize = fragWrapper->getIPLayerPayloadSize();
				// copy fragment data to reassembled packet
				fragData->data->reallocateData(fragData->data->getRawDataLen() + payloadSize);
				fragData->data->appendData(fragWrapper->getIPLayerPayload(), payloadSize);

				// update expected offset
				fragData->currentOffset += payloadSize;

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
				PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragWrapper->getFragmentId()
				                            << "] Got out-of-ordered fragment with offset " << fragOffset
				                            << " (expected: " << fragData->currentOffset
				                            << "). Adding it to out-of-order list");

				// create a new IPFragment and copy the fragment data and params to it
				size_t payloadSize = fragWrapper->getIPLayerPayloadSize();
				IPFragment* newFrag = new IPFragment();
				newFrag->fragmentOffset = fragWrapper->getFragmentOffset();
				newFrag->fragmentData = new uint8_t[payloadSize];
				newFrag->fragmentDataLen = payloadSize;
				memcpy(newFrag->fragmentData, fragWrapper->getIPLayerPayload(), newFrag->fragmentDataLen);
				newFrag->lastFragment = fragWrapper->isLastFragment();

				// store the IPFragment in the out-of-order fragment list
				fragData->outOfOrderFragments.pushBack(newFrag);

				status = OUT_OF_ORDER_FRAGMENT;
				return nullptr;
			}
			else
			{
				PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragWrapper->getFragmentId()
				                            << "] Got a fragment with an offset that was already seen: " << fragOffset
				                            << " (current offset is: " << fragData->currentOffset
				                            << "), probably duplicated fragment");
			}
		}

		// if seen the last fragment
		if (gotLastFragment)
		{
			PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragWrapper->getFragmentId()
			                            << "] Reassembly process completed, allocating a packet and returning it");
			fragData->deleteData = false;

			// fix IP length field
			if (fragData->packetKey->getProtocolType() == IPv4)
			{
				Packet tempPacket(fragData->data, IPv4);
				IPv4Layer* ipLayer = tempPacket.getLayerOfType<IPv4Layer>();
				iphdr* iphdr = ipLayer->getIPv4Header();
				iphdr->totalLength = htobe16(fragData->currentOffset + ipLayer->getHeaderLen());
				iphdr->fragmentOffset = 0;
			}
			else
			{
				Packet tempPacket(fragData->data, IPv6);
				IPv6Layer* ipLayer = tempPacket.getLayerOfType<IPv6Layer>();
				tempPacket.getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength =
				    fragData->currentOffset + ipLayer->getHeaderLen();
			}

			// create a new Packet object with the reassembled data as its RawPacket
			Packet* reassembledPacket = new Packet(fragData->data, true, parseUntil, parseUntilLayer);

			if (fragData->packetKey->getProtocolType() == IPv4)
			{
				// re-calculate all IPv4 fields
				reassembledPacket->getLayerOfType<IPv4Layer>()->computeCalculateFields();
			}
			else
			{
				// remove fragment extension
				IPv6Layer* ipLayer = reassembledPacket->getLayerOfType<IPv6Layer>();
				ipLayer->removeAllExtensions();

				// re-calculate all IPv4 fields
				ipLayer->computeCalculateFields();
			}

			PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragWrapper->getFragmentId()
			                            << "] Deleting fragment data from map");

			// delete the IPFragmentData object and remove it from the map
			delete fragData;
			m_FragmentMap.erase(iter);
			m_PacketLRU.eraseElement(hash);
			status = REASSEMBLED;
			return reassembledPacket;
		}

		// if got to here it means this fragment is either the first fragment or a fragment in the middle. Set the
		// appropriate status and return
		if (status != FIRST_FRAGMENT)
			status = FRAGMENT;

		return nullptr;
	}

	Packet* IPReassembly::processPacket(RawPacket* fragment, ReassemblyStatus& status, ProtocolType parseUntil,
	                                    OsiModelLayer parseUntilLayer)
	{
		Packet* parsedFragment = new Packet(fragment, false, parseUntil, parseUntilLayer);
		Packet* result = processPacket(parsedFragment, status, parseUntil, parseUntilLayer);
		if (result != parsedFragment)
			delete parsedFragment;

		return result;
	}

	Packet* IPReassembly::getCurrentPacket(const PacketKey& key)
	{
		// create a hash out of the packet key
		uint32_t hash = key.getHashValue();

		// look for this hash value in the map
		std::unordered_map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);

		// hash was found
		if (iter != m_FragmentMap.end())
		{
			IPFragmentData* fragData = iter->second;

			// some data already exists
			if (fragData != nullptr && fragData->data != nullptr)
			{
				// create a copy of the RawPacket object
				RawPacket* partialRawPacket = new RawPacket(*(fragData->data));

				// fix IP length field
				if (fragData->packetKey->getProtocolType() == IPv4)
				{
					Packet tempPacket(partialRawPacket, IPv4);
					IPv4Layer* ipLayer = tempPacket.getLayerOfType<IPv4Layer>();
					ipLayer->getIPv4Header()->totalLength = htobe16(fragData->currentOffset + ipLayer->getHeaderLen());
				}
				else
				{
					Packet tempPacket(partialRawPacket, IPv6);
					IPv6Layer* ipLayer = tempPacket.getLayerOfType<IPv6Layer>();
					tempPacket.getLayerOfType<IPv6Layer>()->getIPv6Header()->payloadLength =
					    fragData->currentOffset + +ipLayer->getHeaderLen();
				}

				// create a packet object wrapping the RawPacket we've just created
				Packet* partialDataPacket = new Packet(partialRawPacket, true);

				// prepare the packet and return it
				if (key.getProtocolType() == IPv4)
				{
					IPv4Layer* ipLayer = partialDataPacket->getLayerOfType<IPv4Layer>();
					ipLayer->getIPv4Header()->fragmentOffset = 0;
					ipLayer->computeCalculateFields();
				}
				else  // key.getProtocolType() == IPv6
				{
					IPv6Layer* ipLayer = partialDataPacket->getLayerOfType<IPv6Layer>();
					ipLayer->removeAllExtensions();
					ipLayer->computeCalculateFields();
				}

				return partialDataPacket;
			}
		}

		return nullptr;
	}

	void IPReassembly::removePacket(const PacketKey& key)
	{
		// create a hash out of the packet key
		uint32_t hash = key.getHashValue();

		// look for this hash value in the map
		std::unordered_map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(hash);

		// hash was found
		if (iter != m_FragmentMap.end())
		{
			// free all data saved in the map
			delete iter->second;
			m_FragmentMap.erase(iter);

			// remove from LRU list
			m_PacketLRU.eraseElement(hash);
		}
	}

	void IPReassembly::addNewFragment(uint32_t hash, IPFragmentData* fragData)
	{
		// put the new frag in the LRU list
		uint32_t packetRemoved;

		// this means LRU list was full and the least recently used item was removed
		if (m_PacketLRU.put(hash, &packetRemoved) == 1)
		{
			// remove this item from the fragment map
			std::unordered_map<uint32_t, IPFragmentData*>::iterator iter = m_FragmentMap.find(packetRemoved);
			IPFragmentData* dataRemoved = iter->second;

			PacketKey* key = nullptr;
			if (m_OnFragmentsCleanCallback != nullptr)
				key = dataRemoved->packetKey->clone();

			PCPP_LOG_DEBUG("Reached maximum packet capacity, removing data for FragID=0x" << std::hex
			                                                                              << dataRemoved->fragmentID);
			delete dataRemoved;
			m_FragmentMap.erase(iter);

			// fire callback if not null
			if (m_OnFragmentsCleanCallback != nullptr)
			{
				m_OnFragmentsCleanCallback(key, m_CallbackUserCookie);
				delete key;
			}
		}

		// add the new fragment to the map
		std::pair<uint32_t, IPFragmentData*> pair(hash, fragData);
		m_FragmentMap.insert(pair);
	}

	bool IPReassembly::matchOutOfOrderFragments(IPFragmentData* fragData)
	{
		PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragData->fragmentID
		                            << "] Searching out-of-order fragment list for the next fragment");

		// a flag indicating whether the last fragment of the packet was found
		bool foundLastSegment = false;

		// run until the last fragment was found or until we finished going over the out-of-order list and didn't find
		// any matching fragment
		while (!foundLastSegment)
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
					PCPP_LOG_DEBUG("[FragID=0x"
					               << std::hex << fragData->fragmentID
					               << "] Found the next matching fragment in out-of-order list with offset "
					               << frag->fragmentOffset << ", adding its data to reassembled packet");
					fragData->data->reallocateData(fragData->data->getRawDataLen() + frag->fragmentDataLen);
					fragData->data->appendData(frag->fragmentData, frag->fragmentDataLen);
					fragData->currentOffset += frag->fragmentDataLen;
					if (frag->lastFragment)  // if this is the last fragment of the packet
					{
						PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragData->fragmentID
						                            << "] Found last fragment inside out-of-order list");
						foundLastSegment = true;
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
				PCPP_LOG_DEBUG("[FragID=0x" << std::hex << fragData->fragmentID
				                            << "] Didn't find the next fragment in out-of-order list");
				break;
			}
		}

		return foundLastSegment;
	}

}  // namespace pcpp

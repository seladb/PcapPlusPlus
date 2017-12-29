#ifndef PACKETPP_IPV4_REASSEMBLY
#define PACKETPP_IPV4_REASSEMBLY

#include "Packet.h"
#include "LRUList.h"
#include "IpAddress.h"
#include "PointerVector.h"
#include <map>

namespace pcpp
{

	#define PCPP_IPV4_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE 500000

	class IPv4Reassembly
	{
	public:

		struct PacketKey
		{
			PacketKey() : ipID(0), srcIP(IPv4Address::Zero), dstIP(IPv4Address::Zero) { }
			PacketKey(uint16_t ipid, IPv4Address srcip, IPv4Address dstip) : ipID(ipid), srcIP(srcip), dstIP(dstip) { }
			uint16_t ipID;
			IPv4Address srcIP;
			IPv4Address dstIP;
		};

		typedef void (*OnFragmentsClean)(const PacketKey& key, void* userCookie);

		enum ReassemblyStatus
		{
			NON_IP_PACKET =         0x00,
			NON_FRAGMENT =          0x01,
			FIRST_FRAGMENT =        0x02,
			FRAGMENT =              0x04,
			OUT_OF_ORDER_FRAGMENT = 0x08,
			MALFORMED_FRAGMENT =    0x10,
			REASSEMBLED =           0x20
		};

		IPv4Reassembly(OnFragmentsClean onFragmentsCleanCallback = NULL, void* callbackUserCookie = NULL, int maxPacketsToStore = PCPP_IPV4_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE);

		~IPv4Reassembly();

		Packet* processPacket(Packet* packet, ReassemblyStatus& status);

		Packet* processPacket(RawPacket* packet, ReassemblyStatus& status);

		Packet* getCurrentPacket(const PacketKey& key);

	private:

		struct IPFragment
		{
			uint16_t fragmentOffset;
			bool lastFragment;
			uint8_t* fragmentData;
			size_t fragmentDataLen;
			IPFragment() { fragmentOffset = 0; lastFragment = false; fragmentData = NULL; fragmentDataLen = 0; }
			~IPFragment() { delete [] fragmentData; }
		};

		struct IPFragmentData
		{
			uint16_t currentOffset;
			RawPacket* data;
			bool deleteData;
			uint16_t ipID;
			uint32_t srcIP;
			uint32_t dstIP;
			PointerVector<IPFragment> outOfOrderFragments;
			IPFragmentData(uint16_t ipId, uint32_t srcIp, uint32_t dstIp) { currentOffset = 0; data = NULL; deleteData = true; ipID = ipId; srcIP = srcIp; dstIP = dstIp; }
			~IPFragmentData() { if (deleteData && data != NULL) { delete data; } }
		};

		LRUList<uint32_t>* m_PacketLRU;
		std::map<uint32_t, IPFragmentData*> m_FragmentMap;
		OnFragmentsClean m_OnFragmentsCleanCallback;
		void* m_CallbackUserCookie;

		void addNewFragment(uint32_t hash, IPFragmentData* fragData);
		bool matchOutOfOrderFragments(IPFragmentData* fragData);
	};

} // namespace pcpp

#endif // PACKETPP_IPV4_REASSEMBLY

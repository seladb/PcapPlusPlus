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
	#define PCPP_IPV4_REASSEMBLY_DEFAULT_CLEAN_TIMEOUT 3600

	class IPv4Reassembly
	{
	public:
		typedef void (*OnFragmentsClean)(uint16_t ipID);

		enum ReassemblyStatus
		{
			NON_IP_PACKET =         0x00,
			NON_FRAGMENT =          0x01,
			FIRST_FRAGMENT =        0x02,
			FRAGMENT =              0x04,
			OUT_OF_ORDER_FRAGMENT = 0x08,
			MALFORMED_FRAGMENT    = 0x10,
			REASSEMBLED =           0x20
		};

		IPv4Reassembly(OnFragmentsClean onFragmentsCleanCallback = NULL, int maxPacketsToStore = PCPP_IPV4_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE, int cleanTimeout = PCPP_IPV4_REASSEMBLY_DEFAULT_CLEAN_TIMEOUT);

		~IPv4Reassembly();

		Packet* processPacket(Packet* packet, ReassemblyStatus& status);

		RawPacket* getCurrentPacket(const IPv4Address& srcIP, const IPv4Address& dstIP, uint16_t ipID);

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
			PointerVector<IPFragment> outOfOrderFragments;
			IPFragmentData(uint16_t ipId) { currentOffset = 0; data = NULL; deleteData = true; ipID = ipId; }
			~IPFragmentData() { if (deleteData && data != NULL) { delete data; } }
		};

		LRUList<uint32_t>* m_PacketLRU;
		std::map<uint32_t, IPFragmentData*> m_FragmentMap;
		int m_CleanTimeout;
		OnFragmentsClean m_OnFragmentsCleanCallback;

		void addNewFragment(uint32_t hash, IPFragmentData* fragData);
		bool matchOutOfOrderFragments(IPFragmentData* fragData);
	};

} // namespace pcpp

#endif // PACKETPP_IPV4_REASSEMBLY

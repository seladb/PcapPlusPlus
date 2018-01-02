#ifndef PACKETPP_IPV4_REASSEMBLY
#define PACKETPP_IPV4_REASSEMBLY

#include "Packet.h"
#include "LRUList.h"
#include "IpAddress.h"
#include "PointerVector.h"
#include <map>

/**
 * @file
 * This file includes an implementation of IPv4 reassembly mechanism (a.k.a IPv4 de-fragmentation), which is the mechanism of assembling IPv4
 * fragments back into one whole packet. You can read more about IP fragmentation here: https://en.wikipedia.org/wiki/IP_fragmentation.<BR>
 * The API is rather simple and contains one main method: pcpp#IPv4Reassembly#processPacket() which gets a fragment packet as a parameter, does the
 * reassembly and returns a fully reassembled packet when done.<BR>
 *
 * The logic works as follows:
 * - There is an internal map that stores the reassembly data for each packet. The key to this map, meaning the way to uniquely associate a
 *   fragment to a (reassembled) packet is the triplet of source IP, destination IP and IP ID
 * - When the first fragment arrives a new record is created in the map and the fragment data is copied
 * - With each fragment arriving the fragment data is copied right after the previous fragment and the reassembled packet is gradually being built
 * - When the last fragment arrives the packet is fully reassembled and returned to the user. Since all fragment data is copied, the packet pointer
 *   returned to the user has to be freed by the user when done using it
 * - The logic supports out-of-order fragments, meaning that a fragment which arrives out-of-order, its data will be copied to a list of out-of-order
 *   fragments where it waits for its turn. This list is observed each time a new fragment arrives to see if the next fragment(s) wait(s) in this
 *   list
 * - If a non-IPv4 packet arrives it's returned as is to the user
 * - If a non-fragment packet arrives it's returned as is to the user
 *
 * In order to limit the amount of memory used by this mechanism there is a limit to the number of concurrent packets being reassembled.
 * The default limit is #PCPP_IPV4_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE but the user can set any value (determined in pcpp#IPv4Reassembly
 * c'tor). Once capacity (the number of concurrent reassembled packets) exceeds this number, the packet that was least recently used will be
 * dropped from the map along with all the data that was reassembled so far. This means that if the next fragment from this packet suddenly
 * appears it will be treated as a new reassembled packet (which will create another record in the map). The user can be notified when
 * reassembled packets are removed from the map by registering to the pcpp#IPv4Reassembly#OnFragmentsClean callback in pcpp#IPv4Reassembly c'tor
 */

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/** IPv4 reassembly mechanism default capacity. If concurrent packet volume exceeds this numbers, packets will start to be dropped in
	 * a LRU manner
	 */
	#define PCPP_IPV4_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE 500000

	/**
	 * @class IPv4Reassembly
	 * Contains the IPv4 reassembly (a.k.a IPv4 de-fragmentation) mechanism. Please refer to the documentation at the top of IPv4Reassembly.h
	 * to understand how this mechanism works. The main APIs are:
	 * - IPv4Reassembly#processPacket() - process a fragment. This is the main method which should be called whenever a new fragment arrives.
	 *   This method processes the fragment, runs the reassembly logic and returns the result packet when it's fully reassembled
	 * - IPv4Reassembly#getCurrentPacket() - get the reassembled data that is currently available, even if reassembly process is not yet completed
	 * - IPv4Reassembly#removePacket() - remove all data that is currently stored for a packet, including the reassembled data that was gathered
	 *   so far
	 */
	class IPv4Reassembly
	{
	public:

		/**
		 * @struct PacketKey
		 * Each fragment in the IPv4 reassebmly logic is uniquely identified by its source IP address, dest IP address and the packet ID.
		 * This struct gathers all 3 to one structure
		 */
		struct PacketKey
		{
			/**
			 * A default c'tor which zeros all members
			 */
			PacketKey() : ipID(0), srcIP(IPv4Address::Zero), dstIP(IPv4Address::Zero) { }

			/**
			 * A c'tor that sets values in each one of the members
			 * @param[in] ipid The value to set in PacketKey#ipID
			 * @param[in] srcip The value to set in PacketKey#srcIP
			 * @param[in] dstip The value to set in PacketKey#dstIP
			 */
			PacketKey(uint16_t ipid, IPv4Address srcip, IPv4Address dstip) : ipID(ipid), srcIP(srcip), dstIP(dstip) { }

			/** IPv4 packet ID */
			uint16_t ipID;
			/** IPv4 source IP address */
			IPv4Address srcIP;
			/** IPv4 destination IP address */
			IPv4Address dstIP;
		};


		/**
		 * @typedef OnFragmentsClean
		 * The IPv4 reassembly mechanism has a certain capacity of concurrent packets it can handle. This capacity is determined in its c'tor
		 * (default value is #PCPP_IPV4_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE). When traffic volume exceeds this capacity the mechanism starts
		 * dropping packets in a LRU manner (least recently used are dropped first). Whenever a packet is dropped this callback is fired
		 * @param[in] key The identifiers of the packet that is being dropped
		 * @param[in] userCookie A pointer to the cookie provided by the user in IPv4Reassemby c'tor (or NULL if no cookie provided)
		 */
		typedef void (*OnFragmentsClean)(const PacketKey& key, void* userCookie);

		/**
		 * An enum representing the status returned from processing a fragment
		 */
		enum ReassemblyStatus
		{
			/** The processed packet isn't of type IPv4 */
			NON_IP_PACKET =         0x00,
			/** The processed packet isn't a fragment */
			NON_FRAGMENT =          0x01,
			/** The processed fragment is the first fragment */
			FIRST_FRAGMENT =        0x02,
			/** The processed fragment is a fragment (but not the first one) */
			FRAGMENT =              0x04,
			/** The processed fragment is not the fragment that was expected at this time */
			OUT_OF_ORDER_FRAGMENT = 0x08,
			/** The processed fragment is malformed, meaning a fragment which has offset of zero but isn't the first fragment */
			MALFORMED_FRAGMENT =    0x10,
			/** Packet is now fully reassembled */
			REASSEMBLED =           0x20
		};

		/**
		 * A c'tor for this class.
		 * @param[in] onFragmentsCleanCallback The callback to be called when packets are dropped due to capacity limit.
		 * Please read more about capacity limit in IPv4Reassembly.h file description. This parameter is optional, default value is NULL (no callback)
		 * @param[in] callbackUserCookie A pointer to an object provided by the user. This pointer will be returned when invoking the
		 * onFragmentsCleanCallback. This parameter is optional, default cookie is NULL
		 * @param[in] maxPacketsToStore Set the capacity limit of the IPv4 reassembly mechanism. Default capacity is #PCPP_IPV4_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE
		 */
		IPv4Reassembly(OnFragmentsClean onFragmentsCleanCallback = NULL, void* callbackUserCookie = NULL, size_t maxPacketsToStore = PCPP_IPV4_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE);

		/**
		 * A d'tor for this class
		 */
		~IPv4Reassembly();

		/**
		 * The main API that drives IPv4Reassembly. This method should be called whenever a fragment arrives. This method finds the relevant
		 * packet this fragment belongs to and runs the IPv4 reassembly logic that is described in IPv4Reassembly.h.
		 * @param[in] fragment The fragment to process. Please notice that the reassembly logic doesn't change or manipulate this object in any way.
		 * All of its data is copied to internal structures and manipulated there
		 * @param[out] status An indication of the packet reassembly status following the processing of this fragment. Possible values are:
		 * - The input fragment is not a IPv4 packet
		 * - The input fragment is not a IPv4 fragment packet
		 * - The input fragment is the first fragment of the packet
		 * - The input fragment is not the first or last fragment
		 * - The input fragment came out-of-order, meaning that wasn't the fragment that was currently expected (it's data is copied to
		 *   the out-of-order fragment list)
		 * - The input fragment is malformed and will be ignored
		 * - The input fragment is the last one and the packet is now fully reassembled. In this case the return value will contain
		 *   a pointer to the reassebmled packet
		 * @return
		 * - If the input fragment isn't an IPv4 packet or if it isn't an IPv4 fragment, the return value is a pointer to the input fragment
		 * - If the input fragment is the last one and the reassembled packet is ready - a pointer to the reassembled packet is
		 *   returned. Notice it's the user's responsibility to free this pointer when done using it
		 * - If the reassembled packet isn't ready then NULL is returned
		 */
		Packet* processPacket(Packet* fragment, ReassemblyStatus& status);

		/**
		 * The main API that drives IPv4Reassembly. This method should be called whenever a fragment arrives. This method finds the relevant
		 * packet this fragment belongs to and runs the IPv4 reassembly logic that is described in IPv4Reassembly.h.
		 * @param[in] fragment The fragment to process. Please notice that the reassembly logic doesn't change or manipulate this object in any way.
		 * All of its data is copied to internal structures and manipulated there
		 * @param[out] status An indication of the packet reassembly status following the processing of this fragment. Possible values are:
		 * - The input fragment is not a IPv4 packet
		 * - The input fragment is not a IPv4 fragment packet
		 * - The input fragment is the first fragment of the packet
		 * - The input fragment is not the first or last fragment
		 * - The input fragment came out-of-order, meaning that wasn't the fragment that was currently expected (it's data is copied to
		 *   the out-of-order fragment list)
		 * - The input fragment is malformed and will be ignored
		 * - The input fragment is the last one and the packet is now fully reassembled. In this case the return value will contain
		 *   a pointer to the reassebmled packet
		 * @return
		 * - If the input fragment isn't an IPv4 packet or if it isn't an IPv4 fragment, the return value is a pointer to a Packet object
		 *   wrapping the input fragment RawPacket object. It's the user responsibility to free this instance
		 * - If the input fragment is the last one and the reassembled packet is ready - a pointer to the reassembled packet is
		 *   returned. Notice it's the user's responsibility to free this pointer when done using it
		 * - If the reassembled packet isn't ready then NULL is returned
		 */
		Packet* processPacket(RawPacket* fragment, ReassemblyStatus& status);

		/**
		 * Get a partially reassembled packet. This method returns all the reassembled data that was gathered so far which is obviously not
		 * a fully reassembled packet (otherwise it would have returned by processPacket()). Notice all data is being copied so the user is
		 * responsible to free the returned Packet object when done using it. Notice#2 - calling this method doesn't interfere with the
		 * reassembly of this packet - all internal structures and data remain
		 * @param[in] key The identifiers of the packet to return
		 * @return A pointer to a Packet object containing the partially reassembled packet. Notice the user is responsible to free this
		 * object when done using it
		 */
		Packet* getCurrentPacket(const PacketKey& key);

		/**
		 * Remove a partially reassembled packet from all internal structures. That means that if another fragment of this packet appears
		 * it will be treated as a new packet
		 * @param[in] key The identifiers of the packet to remove
		 */
		void removePacket(const PacketKey& key);

		/**
		 * Get the maximum capacity as determined in the c'tor
		 */
		inline size_t getMaxCapacity() { return (int)m_PacketLRU->getMaxSize(); }

		/**
		 * Get the current number of packets being processed
		 */
		inline size_t getCurrentCapacity() { return m_FragmentMap.size(); }

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

#ifndef PACKETPP_IP_REASSEMBLY
#define PACKETPP_IP_REASSEMBLY

#include "Packet.h"
#include "LRUList.h"
#include "IpAddress.h"
#include "PointerVector.h"
#include <map>

/**
 * @file
 * This file includes an implementation of IP reassembly mechanism (a.k.a IP de-fragmentation), which is the mechanism of assembling IPv4 or IPv6
 * fragments back into one whole packet. As the previous sentence imply, this module supports both IPv4 and IPv6 reassembly which means
 * the same pcpp#IPReassembly instance can reassemble both IPv4 and IPv6 fragments. You can read more about IP fragmentation here:
 * https://en.wikipedia.org/wiki/IP_fragmentation.<BR>
 * The API is rather simple and contains one main method: pcpp#IPReassembly#processPacket() which gets a fragment packet as a parameter, does the
 * reassembly and returns a fully reassembled packet when done.<BR>
 *
 * The logic works as follows:
 * - There is an internal map that stores the reassembly data for each packet. The key to this map, meaning the way to uniquely associate a
 *   fragment to a (reassembled) packet is the triplet of source IP, destination IP and IP ID (for IPv4) or Fragment ID (for IPv6)
 * - When the first fragment arrives a new record is created in the map and the fragment data is copied
 * - With each fragment arriving the fragment data is copied right after the previous fragment and the reassembled packet is gradually being built
 * - When the last fragment arrives the packet is fully reassembled and returned to the user. Since all fragment data is copied, the packet pointer
 *   returned to the user has to be freed by the user when done using it
 * - The logic supports out-of-order fragments, meaning that a fragment which arrives out-of-order, its data will be copied to a list of out-of-order
 *   fragments where it waits for its turn. This list is observed each time a new fragment arrives to see if the next fragment(s) wait(s) in this
 *   list
 * - If a non-IP packet arrives it's returned as is to the user
 * - If a non-fragment packet arrives it's returned as is to the user
 *
 * In order to limit the amount of memory used by this mechanism there is a limit to the number of concurrent packets being reassembled.
 * The default limit is #PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE but the user can set any value (determined in pcpp#IPReassembly
 * c'tor). Once capacity (the number of concurrent reassembled packets) exceeds this number, the packet that was least recently used will be
 * dropped from the map along with all the data that was reassembled so far. This means that if the next fragment from this packet suddenly
 * appears it will be treated as a new reassembled packet (which will create another record in the map). The user can be notified when
 * reassembled packets are removed from the map by registering to the pcpp#IPReassembly#OnFragmentsClean callback in pcpp#IPReassembly c'tor
 */

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{

	/** IP reassembly mechanism default capacity. If concurrent packet volume exceeds this numbers, packets will start to be dropped in
	 * a LRU manner
	 */
	#define PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE 500000

	/**
	 * @class IPReassembly
	 * Contains the IP reassembly (a.k.a IP de-fragmentation) mechanism. Encapsulates both IPv4 and IPv6 reassembly.
	 * Please refer to the documentation at the top of IPReassembly.h
	 * to understand how this mechanism works. The main APIs are:
	 * - IPReassembly#processPacket() - process a fragment. This is the main method which should be called whenever a new fragment arrives.
	 *   This method processes the fragment, runs the reassembly logic and returns the result packet when it's fully reassembled
	 * - IPReassembly#getCurrentPacket() - get the reassembled data that is currently available, even if reassembly process is not yet completed
	 * - IPReassembly#removePacket() - remove all data that is currently stored for a packet, including the reassembled data that was gathered
	 *   so far
	 */
	class IPReassembly
	{
	public:

		/**
		 * @class PacketKey
		 * An abstract class that represents a key that can uniquely identify an IP packet. This class cannot be instantiated or copied,
		 * only its derived classes can
		 */
		class PacketKey
		{
		public:

			/**
			 * A default virtual d'tor
			 */
			virtual ~PacketKey() {}

			/**
			 * @return A 4-byte hash value of the packet key
			 */
			virtual uint32_t getHashValue() const = 0;

			/**
			 * @return The IP protocol this key represents (pcpp#IPv4 or pcpp#IPv6)
			 */
			virtual ProtocolType getProtocolType() const = 0;

			/**
			 * @return A pointer to a new instance which is a clone of the current instance
			 */
			virtual PacketKey* clone() const = 0;

		protected:
			// private c'tor
			PacketKey() {}

			// private copy c'tor
			PacketKey(const PacketKey& other);
		};


		/**
		 * @class IPv4PacketKey
		 * Represents a key that can uniquely identify IPv4 packets. The key comprises of source IPv4 address, dest IPv4 address and IP ID
		 */
		class IPv4PacketKey : public PacketKey
		{
		public:

			/**
			 * A default c'tor which zeros all members
			 */
			IPv4PacketKey() : m_IpID(0), m_SrcIP(IPv4Address::Zero), m_DstIP(IPv4Address::Zero) { }

			/**
			 * A c'tor that sets values in each one of the members
			 * @param[in] ipid IP ID value
			 * @param[in] srcip Source IPv4 address
			 * @param[in] dstip Dest IPv4 address
			 */
			IPv4PacketKey(uint16_t ipid, IPv4Address srcip, IPv4Address dstip) : m_IpID(ipid), m_SrcIP(srcip), m_DstIP(dstip) { }

			/**
			 * A copy c'tor for this class
			 */
			IPv4PacketKey(const IPv4PacketKey& other) : m_IpID(other.m_IpID), m_SrcIP(other.m_SrcIP), m_DstIP(other.m_DstIP) { }

			/**
			 * @return IP ID value
			 */
			inline uint16_t getIpID() { return m_IpID; }

			/**
			 * @return Source IP address
			 */
			inline IPv4Address getSrcIP() { return m_SrcIP; }

			/**
			 * @return Dest IP address
			 */
			inline IPv4Address getDstIP() { return m_DstIP; }

			/**
			 * Set IP ID
			 * @param[in] ipID IP ID value to set
			 */
			inline void setIpID(uint16_t ipID) { m_IpID = ipID; }

			/**
			 * Set source IPv4 address
			 * @param[in] srcIP Source IP to set
			 */
			inline void setSrcIP(const IPv4Address& srcIP) { m_SrcIP = srcIP; }

			/**
			 * Set dest IPv4 address
			 * @param[in] dstIP Dest IP to set
			 */
			inline void setDstIP(const IPv4Address& dstIP) { m_DstIP = dstIP; }


			// implement abstract methods

			uint32_t getHashValue() const;

			/**
			 * @return pcpp#IPv4 protocol
			 */
			ProtocolType getProtocolType() const { return IPv4; }

			PacketKey* clone() const { return new IPv4PacketKey(*this); }

		private:
			uint16_t m_IpID;
			IPv4Address m_SrcIP;
			IPv4Address m_DstIP;
		};


		/**
		 * @class IPv6PacketKey
		 * Represents a key that can uniquely identify IPv6 fragment packets. The key comprises of source IPv6 address, dest IPv6 address
		 * and fragment ID (which resides in the IPv6 fragmentation extension)
		 */
		class IPv6PacketKey : public PacketKey
		{
		public:

			/**
			 * A default c'tor which zeros all members
			 */
			IPv6PacketKey() : m_FragmentID(0), m_SrcIP(IPv6Address::Zero), m_DstIP(IPv6Address::Zero) { }

			/**
			 * A c'tor that sets values in each one of the members
			 * @param[in] fragmentID Fragment ID value
			 * @param[in] srcip Source IPv6 address
			 * @param[in] dstip Dest IPv6 address
			 */
			IPv6PacketKey(uint32_t fragmentID, IPv6Address srcip, IPv6Address dstip) : m_FragmentID(fragmentID), m_SrcIP(srcip), m_DstIP(dstip) { }

			/**
			 * A copy c'tor for this class
			 */
			IPv6PacketKey(const IPv6PacketKey& other) : m_FragmentID(other.m_FragmentID), m_SrcIP(other.m_SrcIP), m_DstIP(other.m_DstIP) { }

			/**
			 * @return Fragment ID value
			 */
			inline uint32_t getFragmentID() { return m_FragmentID; }

			/**
			 * @return Source IP address
			 */
			inline IPv6Address getSrcIP() { return m_SrcIP; }

			/**
			 * @return Dest IP address
			 */
			inline IPv6Address getDstIP() { return m_DstIP; }

			/**
			 * Set fragment ID
			 * @param[in] fragID Fragment ID value to set
			 */
			inline void setFragmentID(uint32_t fragID) { m_FragmentID = fragID; }

			/**
			 * Set source IPv6 address
			 * @param[in] srcIP Source IP to set
			 */
			inline void setSrcIP(const IPv6Address& srcIP) { m_SrcIP = srcIP; }

			/**
			 * Set dest IPv6 address
			 * @param[in] dstIP Dest IP to set
			 */
			inline void setDstIP(const IPv6Address& dstIP) { m_DstIP = dstIP; }


			// implement abstract methods

			uint32_t getHashValue() const;

			/**
			 * @return pcpp#IPv6 protocol
			 */
			ProtocolType getProtocolType() const { return IPv6; }

			PacketKey* clone() const { return new IPv6PacketKey(*this); }

		private:
			uint32_t m_FragmentID;
			IPv6Address m_SrcIP;
			IPv6Address m_DstIP;
		};


		/**
		 * @typedef OnFragmentsClean
		 * The IP reassembly mechanism has a certain capacity of concurrent packets it can handle. This capacity is determined in its c'tor
		 * (default value is #PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE). When traffic volume exceeds this capacity the mechanism starts
		 * dropping packets in a LRU manner (least recently used are dropped first). Whenever a packet is dropped this callback is fired
		 * @param[in] key A pointer to the identifier of the packet that is being dropped
		 * @param[in] userCookie A pointer to the cookie provided by the user in IPReassemby c'tor (or NULL if no cookie provided)
		 */
		typedef void (*OnFragmentsClean)(const PacketKey* key, void* userCookie);

		/**
		 * An enum representing the status returned from processing a fragment
		 */
		enum ReassemblyStatus
		{
			/** The processed packet isn't of type IPv4 or IPv6 */
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
		 * Please read more about capacity limit in IPReassembly.h file description. This parameter is optional, default value is NULL (no callback)
		 * @param[in] callbackUserCookie A pointer to an object provided by the user. This pointer will be returned when invoking the
		 * onFragmentsCleanCallback. This parameter is optional, default cookie is NULL
		 * @param[in] maxPacketsToStore Set the capacity limit of the IP reassembly mechanism. Default capacity is #PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE
		 */
		IPReassembly(OnFragmentsClean onFragmentsCleanCallback = NULL, void* callbackUserCookie = NULL, size_t maxPacketsToStore = PCPP_IP_REASSEMBLY_DEFAULT_MAX_PACKETS_TO_STORE);

		/**
		 * A d'tor for this class
		 */
		~IPReassembly();

		/**
		 * The main API that drives IPReassembly. This method should be called whenever a fragment arrives. This method finds the relevant
		 * packet this fragment belongs to and runs the IP reassembly logic that is described in IPReassembly.h.
		 * @param[in] fragment The fragment to process (IPv4 or IPv6). Please notice that the reassembly logic doesn't change or manipulate
		 * this object in any way. All of its data is copied to internal structures and manipulated there
		 * @param[out] status An indication of the packet reassembly status following the processing of this fragment. Possible values are:
		 * - The input fragment is not a IPv4 or IPv6 packet
		 * - The input fragment is not a IPv4 or IPv6 fragment packet
		 * - The input fragment is the first fragment of the packet
		 * - The input fragment is not the first or last fragment
		 * - The input fragment came out-of-order, meaning that wasn't the fragment that was currently expected (it's data is copied to
		 *   the out-of-order fragment list)
		 * - The input fragment is malformed and will be ignored
		 * - The input fragment is the last one and the packet is now fully reassembled. In this case the return value will contain
		 *   a pointer to the reassebmled packet
		 * @return
		 * - If the input fragment isn't an IPv4/IPv6 packet or if it isn't an IPv4/IPv6 fragment, the return value is a pointer to the input fragment
		 * - If the input fragment is the last one and the reassembled packet is ready - a pointer to the reassembled packet is
		 *   returned. Notice it's the user's responsibility to free this pointer when done using it
		 * - If the reassembled packet isn't ready then NULL is returned
		 */
		Packet* processPacket(Packet* fragment, ReassemblyStatus& status);

		/**
		 * The main API that drives IPReassembly. This method should be called whenever a fragment arrives. This method finds the relevant
		 * packet this fragment belongs to and runs the IPv4 reassembly logic that is described in IPReassembly.h.
		 * @param[in] fragment The fragment to process (IPv4 or IPv6). Please notice that the reassembly logic doesn't change or manipulate
		 * this object in any way. All of its data is copied to internal structures and manipulated there
		 * @param[out] status An indication of the packet reassembly status following the processing of this fragment. Possible values are:
		 * - The input fragment is not a IPv4 or IPv6 packet
		 * - The input fragment is not a IPv4 or IPv6 fragment packet
		 * - The input fragment is the first fragment of the packet
		 * - The input fragment is not the first or last fragment
		 * - The input fragment came out-of-order, meaning that wasn't the fragment that was currently expected (it's data is copied to
		 *   the out-of-order fragment list)
		 * - The input fragment is malformed and will be ignored
		 * - The input fragment is the last one and the packet is now fully reassembled. In this case the return value will contain
		 *   a pointer to the reassebmled packet
		 * @return
		 * - If the input fragment isn't an IPv4/IPv6 packet or if it isn't an IPv4/IPv6 fragment, the return value is a pointer to a Packet object
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
			uint32_t fragmentID;
			PacketKey* packetKey;
			PointerVector<IPFragment> outOfOrderFragments;
			IPFragmentData(PacketKey* pktKey, uint32_t fragId) { currentOffset = 0; data = NULL; deleteData = true; fragmentID = fragId; packetKey = pktKey; }
			~IPFragmentData() { delete packetKey; if (deleteData && data != NULL) { delete data; } }
		};

		LRUList<uint32_t>* m_PacketLRU;
		std::map<uint32_t, IPFragmentData*> m_FragmentMap;
		OnFragmentsClean m_OnFragmentsCleanCallback;
		void* m_CallbackUserCookie;

		void addNewFragment(uint32_t hash, IPFragmentData* fragData);
		bool matchOutOfOrderFragments(IPFragmentData* fragData);
	};

} // namespace pcpp

#endif // PACKETPP_IP_REASSEMBLY

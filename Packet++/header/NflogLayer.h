#ifndef PACKETPP_NFLOG_LAYER
#define PACKETPP_NFLOG_LAYER

#include "Layer.h"

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/*
 	* TLV types.
 	*/
	#define NFULA_PACKET_HDR			1	/* nflog_packet_hdr_t */
	#define NFULA_MARK					2	/* packet mark from skbuff */
	#define NFULA_TIMESTAMP				3	/* nflog_timestamp_t for skbuff's time stamp */
	#define NFULA_IFINDEX_INDEV			4	/* ifindex of device on which packet received (possibly bridge group) */
	#define NFULA_IFINDEX_OUTDEV		5	/* ifindex of device on which packet transmitted (possibly bridge group) */
	#define NFULA_IFINDEX_PHYSINDEV		6	/* ifindex of physical device on which packet received (not bridge group) */
	#define NFULA_IFINDEX_PHYSOUTDEV	7	/* ifindex of physical device on which packet transmitted (not bridge group) */
	#define NFULA_HWADDR				8	/* nflog_hwaddr_t for hardware address */
	#define NFULA_PAYLOAD				9	/* packet payload */
	#define NFULA_PREFIX				10	/* text string - null-terminated, count includes NUL */
	#define NFULA_UID					11	/* UID owning socket on which packet was sent/received */
	#define NFULA_SEQ					12	/* sequence number of packets on this NFLOG socket */
	#define NFULA_SEQ_GLOBAL			13	/* sequence number of pakets on all NFLOG sockets */
	#define NFULA_GID					14	/* GID owning socket on which packet was sent/received */
	#define NFULA_HWTYPE				15	/* ARPHRD_ type of skbuff's device */
	#define NFULA_HWHEADER				16	/* skbuff's MAC-layer header */
	#define NFULA_HWLEN					17	/* length of skbuff's MAC-layer header */



	/**
	 * @struct nflog_header
	 * Represents Nflog header
	 */
#pragma pack(push, 1)
	struct nflog_header
	{
		uint8_t address_family;
		uint8_t version;
		uint16_t resource_id;
	};
#pragma pack(pop)

	/**
	 * @struct nflog_tlv
	 * Represents Nflog tlv structure
	 */
#pragma pack(push, 1)
	struct nflog_tlv
	{
		/** tlv length */
		uint16_t tlv_length;

		/** tlv type */
		uint16_t tlv_type;
	};
#pragma pack(pop)

	/**
	 * @struct nflog_packet_header
	 * represents data of the first tlv by tlv type 1
	*/
#pragma pack(push, 1)
	struct nflog_packet_header
	{
		/** e.g. ipv4, unknown, etc */
		uint16_t hardware_protocol;

		/** local-in, local-out, post-routing, etc */
		uint8_t netfilter_hook;

		/** one byte padding */
		uint8_t padding;
	};
#pragma pack(pop)

	/**
	 * @class NflogLayer
	 * Represents an NFLOG protocol layer
	 */
	class NflogLayer : public Layer
	{
	public:
		/**
		 * A constructor that creates the layer from an existing packet raw data
		 * @param[in] data A pointer to the raw data (will be casted to ether_header)
		 * @param[in] dataLen Size of the data in bytes
		 * @param[in] packet A pointer to the Packet instance where layer will be stored in
		 */
		NflogLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { m_Protocol = NFLOG; }

		~NflogLayer() {}

		/**
		 * Get a pointer to the Nflog header.
		 * @return A pointer to the nflog_header
		 */
		nflog_header* getNflogHeader() const { return (nflog_header*)m_Data; }

		/**
		 * Get address family of the packet. e.g. 2 for ipv4 and 10 for ipv6
		 * @return an unsigned char of address famliy
		*/
		uint8_t getFamily();

		/**
		 * get packet header of the packet as the tlv value of 1
		 * @return pointer to nflog_packet_header
		*/
		nflog_packet_header* getPacketHeader();

		/**
		 * returns a pair of pointer to payload of packet and the offset from the beginning of m_Data
		 * @return pair of <uint8_t*, int>
		*/
		std::pair<uint8_t*, int> getPayload();

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer using address family
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of nflog_header
		 */
		size_t getHeaderLen() const { return sizeof(nflog_header); }

		/**
		 * nothing to do for now
		*/
		void computeCalculateFields() {};

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelDataLinkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_NFLOG_LAYER */

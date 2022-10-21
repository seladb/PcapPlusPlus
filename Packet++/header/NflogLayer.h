#ifndef PACKETPP_NFLOG_LAYER
#define PACKETPP_NFLOG_LAYER

#include "MacAddress.h"
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
		/** Specifies whether packet was: specifically sent to us by somebody else (value=0);
		 *  broadcast by somebody else (value=1); multicast, but not broadcast, by somebody else (value=2);
		 *  sent to somebody else by somebody else (value=3); sent by us (value=4)
		 **/
		uint8_t address_family;
		/** Contains a Linux ARPHRD_ value for the link-layer device type */
		uint8_t version;
		/** Contains the length of the link-layer address of the sender of the packet. That length could be zero */
		uint16_t resource_id;
		/** contains the link-layer address of the sender of the packet; the number of bytes of that field that are
		 *  meaningful is specified by the link-layer address length field
		 **/
		// uint8_t link_layer_addr[8];
		/** Contains an Ethernet protocol type of the next layer */
		// uint16_t protocol_type;
	};
#pragma pack(pop)

	/**
	 * @struct nflog_tlv
	 * Represents Nflog tlv structure
	 */
#pragma pack(push, 1)
	struct nflog_tlv
	{
		/* tlv length */
		uint16_t tlv_length;

		/* tlv type */
		uint16_t tlv_type;
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

		/**
		 * A constructor that creates a new SLL header and allocates the data
		 * @param[in] packetType The packet type
		 * @param[in] ARPHRDType The ARPHRD type
		 */
		NflogLayer(uint16_t packetType, uint16_t ARPHRDType);

		~NflogLayer() {}

		/**
		 * Get a pointer to the Sll header. Notice this points directly to the data, so every change will change the actual packet data
		 * @return A pointer to the sll_header
		 */
		nflog_header* getNflogHeader() const { return (nflog_header*)m_Data; }

		/**
		 * A setter for the link layer address field
		 * @param[in] addr The address to set. Memory will be copied to packet
		 * @param[in] addrLength Address length, must be lower or equal to 8 (which is max length for SLL address)
		 * @return True if address was set successfully, or false of addrLength is out of bounds (0 or larger than 8)
		 */
		bool setLinkLayerAddr(uint8_t* addr, size_t addrLength);

		/**
		 * Set a MAC address in the link layer address field
		 * @param[in] macAddr MAC address to set
		 * @return True if address was set successfully, false if MAC address isn't valid or if set failed
		 */
		bool setMacAddressAsLinkLayer(MacAddress macAddr);

		/**
		 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, VlanLayer, PPPoESessionLayer, PPPoEDiscoveryLayer,
		 * MplsLayer.
		 * Otherwise sets PayloadLayer
		 */
		void parseNextLayer();

		/**
		 * @return Size of sll_header
		 */
		size_t getHeaderLen() const { return sizeof(nflog_header); }

		/**
		 * Calculate the next protocol type for known protocols: IPv4, IPv6, ARP, VLAN
		 */
		void computeCalculateFields();

		std::string toString() const;

		OsiModelLayer getOsiModelLayer() const { return OsiModelDataLinkLayer; }
	};

} // namespace pcpp

#endif /* PACKETPP_NFLOG_LAYER */

#ifndef PACKETPP_ETH_LAYER
#define PACKETPP_ETH_LAYER

#include "Layer.h"
#include "MacAddress.h"

/// @file

/**
 * @struct ether_header
 * Represents an Ethernet header
 */
#pragma pack(push, 1)
struct ether_header {
	/** Destination MAC */
	uint8_t dstMac[6];
	/** Source MAC */
	uint8_t srcMac[6];
	/** EtherType */
	uint16_t etherType;
};
#pragma pack(pop)

/* Ethernet protocol ID's */

/** Xerox PUP */
#define	ETHERTYPE_PUP		0x0200
/** Sprite */
#define ETHERTYPE_SPRITE	0x0500
/** IP */
#define	ETHERTYPE_IP		0x0800
/** Address resolution */
#define	ETHERTYPE_ARP		0x0806
/** Reverse ARP */
#define	ETHERTYPE_REVARP	0x8035
/** AppleTalk protocol */
#define ETHERTYPE_AT		0x809B
/** AppleTalk ARP */
#define ETHERTYPE_AARP		0x80F3
/** IEEE 802.1Q VLAN tagging */
#define	ETHERTYPE_VLAN		0x8100
/** IPX */
#define ETHERTYPE_IPX		0x8137
/** IP protocol version 6 */
#define	ETHERTYPE_IPV6		0x86dd
/** used to test interfaces */
#define ETHERTYPE_LOOPBACK	0x9000


/**
 * @class EthLayer
 * Represents an Ethernet protocol layer
 */
class EthLayer : public Layer
{
public:
	/**
	 * A constructor that creates the layer from an existing packet raw data
	 * @param[in] data A pointer to the raw data (will be casted to ether_header)
	 * @param[in] dataLen Size of the data in bytes
	 * @param[in] packet A pointer to the Packet instance where layer will be stored in
	 */
	EthLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { m_Protocol = Ethernet; }

	/**
	 * A constructor that creates a new Ethernet header and allocates the data
	 * @param[in] sourceMac The source MAC address
	 * @param[in] destMac The destination MAC address
	 * @param[in] etherType The EtherType to be used
	 */
	EthLayer(MacAddress& sourceMac, MacAddress& destMac, uint16_t etherType);

	~EthLayer() {}

	/**
	 * Get a pointer to the Ethernet header. Notice this points directly to the data, so every change will change the actual packet data
	 * @return A pointer to the ether_header
	 */
	inline ether_header* getEthHeader() { return (ether_header*)m_Data; };

	/**
	 * Get the source MAC address
	 * @return The source MAC address
	 */
	inline MacAddress getSourceMac() { return MacAddress(getEthHeader()->srcMac); };

	/**
	 * Get the destination MAC address
	 * @return The destination MAC address
	 */
	inline MacAddress getDestMac() { return MacAddress(getEthHeader()->dstMac); };

	// implement abstract methods

	/**
	 * Currently identifies the following next layers: IPv4Layer, IPv6Layer, ArpLayer, VlanLayer. Otherwise sets PayloadLayer
	 */
	void parseNextLayer();

	/**
	 * @return Size of ether_header
	 */
	inline size_t getHeaderLen() { return sizeof(ether_header); }

	/**
	 * Calculate ether_header#etherType for known protocols: IPv4, IPv6, ARP, VLAN
	 */
	void computeCalculateFields();

	string toString();
};

#endif /* PACKETPP_ETH_LAYER */

#ifndef PACKETPP_ETH_LAYER
#define PACKETPP_ETH_LAYER

#include "Layer.h"
#include "MacAddress.h"

#pragma pack(push, 1)
struct ether_header {
	uint8_t dstMac[6];
	uint8_t srcMac[6];
	uint16_t etherType;
};
#pragma pack(pop)

/* Ethernet protocol ID's */
#define	ETHERTYPE_PUP		0x0200      /* Xerox PUP */
#define ETHERTYPE_SPRITE	0x0500		/* Sprite */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
#define ETHERTYPE_AT		0x809B		/* AppleTalk protocol */
#define ETHERTYPE_AARP		0x80F3		/* AppleTalk ARP */
#define	ETHERTYPE_VLAN		0x8100		/* IEEE 802.1Q VLAN tagging */
#define ETHERTYPE_IPX		0x8137		/* IPX */
#define	ETHERTYPE_IPV6		0x86dd		/* IP protocol version 6 */
#define ETHERTYPE_LOOPBACK	0x9000		/* used to test interfaces */

class EthLayer : public Layer
{
public:
	EthLayer(uint8_t* data, size_t dataLen, Packet* packet) : Layer(data, dataLen, NULL, packet) { m_Protocol = Ethernet; }
	EthLayer(MacAddress& sourceMac, MacAddress& destMac, uint16_t etherType);
	~EthLayer() {}

	inline ether_header* getEthHeader() { return (ether_header*)m_Data; };
	inline MacAddress getSourceMac() { return MacAddress(getEthHeader()->srcMac); };
	inline MacAddress getDestMac() { return MacAddress(getEthHeader()->dstMac); };

	// implement abstract methods
	void parseNextLayer();
	inline size_t getHeaderLen() { return sizeof(ether_header); }
	void computeCalculateFields();
	string toString();
};

#endif /* PACKETPP_ETH_LAYER */

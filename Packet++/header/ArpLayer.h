#ifndef PACKETPP_ARP_LAYER
#define PACKETPP_ARP_LAYER

#include <Layer.h>
#include <IpAddress.h>
#include <MacAddress.h>

#pragma pack(push, 1)
struct arphdr {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t	hardwareSize;
    uint8_t	protocolSize;
    uint16_t opcode;
    uint8_t senderMacAddr[6];
    uint32_t senderIpAddr;
    uint8_t targetMacAddr[6];
    uint32_t targetIpAddr;
};
#pragma pack(pop)

enum ArpOpcode
{
	ARP_REQUEST = 0x0001,
	ARP_REPLY   = 0x0002
};

class ArpLayer : public Layer
{
public:
	ArpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = ARP; }
	ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const MacAddress& targetMacAddr, const IPv4Address senderIpAddr, const IPv4Address& targetIpAddr);
	~ArpLayer() {}

	inline arphdr* getArpHeader() { return (arphdr*)m_Data; };
	inline MacAddress getSenderMacAddress() { return MacAddress(getArpHeader()->senderMacAddr); }
	inline MacAddress getTargetMacAddress() { return MacAddress(getArpHeader()->targetMacAddr); }
	inline IPv4Address getSenderIpAddr() { return IPv4Address(getArpHeader()->senderIpAddr); }
	inline IPv4Address getTargetIpAddr() { return IPv4Address(getArpHeader()->targetIpAddr); }

	// implement abstract methods
	void parseNextLayer() {}
	inline size_t getHeaderLen() { return sizeof(arphdr); }
	void computeCalculateFields();
};

#endif /* PACKETPP_ARP_LAYER */

#ifndef PACKETPP_VLAN_LAYER
#define PACKETPP_VLAN_LAYER

#include <Layer.h>
#include <EthLayer.h>
#ifdef WIN32
#include <winsock2.h>
#endif

#pragma pack(push, 1)
struct vlan_header {
#if (BYTE_ORDER == LITTLE_ENDIAN)
	uint16_t priority:3,
			 cfi:1,
			 vlanID:12;
#else
	uint16_t vlanID:12,
			 cfi:1,
			 priority:3;
#endif
	uint16_t etherType;
};
#pragma pack(pop)

class VlanLayer : public Layer
{
public:
	VlanLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet) : Layer(data, dataLen, prevLayer, packet) { m_Protocol = VLAN; }
	VlanLayer(const uint16_t vlanID, bool cfi, uint8_t priority, uint16_t etherType);
	~VlanLayer() {}

	inline vlan_header* getVlanHeader() { return (vlan_header*)m_Data; }

	//TODO: solve this to big endian as well
	inline uint16_t getVlanID() { return (getVlanHeader()->vlanID >> 4) | ((getVlanHeader()->vlanID & 0x00f) << 8); }
	//TODO: solve this to big endian as well
	inline void setVlanID(uint16_t id) { getVlanHeader()->vlanID = ((id << 4) & 0xff0) | (id >> 8); }

	// implement abstract methods
	void parseNextLayer();
	inline size_t getHeaderLen() { return sizeof(vlan_header); }
	void computeCalculateFields() {}
};


#endif /* PACKETPP_VLAN_LAYER */

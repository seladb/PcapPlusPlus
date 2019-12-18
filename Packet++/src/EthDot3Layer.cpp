#include "EthDot3Layer.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"

namespace pcpp
{


EthDot3Layer::EthDot3Layer(const MacAddress& sourceMac, const MacAddress& destMac, uint16_t length) : Layer()
{
	const size_t headerLen = sizeof(ether_dot3_header);
	m_DataLen = headerLen;
	m_Data = new uint8_t[headerLen];
	memset(m_Data, 0, headerLen);

	ether_dot3_header* ethHdr = (ether_dot3_header*)m_Data;
	destMac.copyTo(ethHdr->dstMac);
	sourceMac.copyTo(ethHdr->srcMac);
	ethHdr->length = be16toh(length);
	m_Protocol = Ethernet;
}

void EthDot3Layer::parseNextLayer()
{
	if (m_DataLen <= sizeof(ether_dot3_header))
		return;

	uint8_t* payload = m_Data + sizeof(ether_dot3_header);
	size_t payloadLen = m_DataLen - sizeof(ether_dot3_header);

	m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
}

std::string EthDot3Layer::toString() const
{
	return "IEEE 802.3 Ethernet, Src: " + getSourceMac().toString() + ", Dst: " + getDestMac().toString();
}

}
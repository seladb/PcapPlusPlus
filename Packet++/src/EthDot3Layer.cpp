#include "EthDot3Layer.h"
#include "EndianPortable.h"
#include "PayloadLayer.h"
#include "LLCLayer.h"

#include <cstring>

namespace pcpp
{
	EthDot3Layer::EthDot3Layer(const MacAddress& sourceMac, const MacAddress& destMac, uint16_t length) : Layer()
	{
		const size_t headerLen = sizeof(ether_dot3_header);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);

		ether_dot3_header* ethHdr = getEthHeader();
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

		if (LLCLayer::isDataValid(payload, payloadLen))
			m_NextLayer = new LLCLayer(payload, payloadLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}

	std::string EthDot3Layer::toString() const
	{
		return "IEEE 802.3 Ethernet, Src: " + getSourceMac().toString() + ", Dst: " + getDestMac().toString();
	}

	bool EthDot3Layer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		if (dataLen >= sizeof(ether_dot3_header))
		{
			// LSAPs: ... Such a length must, when considered as an
			// unsigned integer, be less than 0x5DC or it could be mistaken as
			// an Ethertype...
			//
			// From: https://tools.ietf.org/html/rfc5342#section-2.3.2.1
			// More: IEEE Std 802.3 Clause 3.2.6
			return be16toh(*reinterpret_cast<const uint16_t*>(data + 12)) <= static_cast<uint16_t>(0x05DC);
		}
		else
		{
			return false;
		}
	}
}  // namespace pcpp

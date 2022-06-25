#define LOG_MODULE PacketLogModuleLLCLayer

#include "LLCLayer.h"
#include "PayloadLayer.h"
#include "StpLayer.h"
#include <iostream>
namespace pcpp
{

void LLCLayer::parseNextLayer()
{
	if (m_DataLen <= sizeof(llc_header))
		return;

	llc_header *hdr = getLLCheader();
	uint8_t *payload = m_Data + sizeof(llc_header);
	size_t payloadLen = m_DataLen - sizeof(llc_header);

	if (hdr->dsap == 0x42 && hdr->ssap == 0x42)
	{
		if (StpLayer::isDataValid(payload, payloadLen))
		{
			switch (StpLayer::getStpType(payload, payloadLen))
			{
			case StpLayer::NotSTP:
				m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
				return;
			case StpLayer::ConfigurationBPDU:
				m_NextLayer = new StpConfigurationBPDULayer((uint8_t *)payload, payloadLen, this, m_Packet);
				return;
			case StpLayer::TopologyChangeBPDU:
				m_NextLayer = new StpTopologyChangeBPDULayer((uint8_t *)payload, payloadLen, this, m_Packet);
				return;
			case StpLayer::Rapid:
				m_NextLayer = new RapidStpLayer((uint8_t *)payload, payloadLen, this, m_Packet);
				return;
			case StpLayer::Multiple:
				m_NextLayer = new MultipleStpLayer((uint8_t *)payload, payloadLen, this, m_Packet);
				return;
			default:
				m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
				return;
			}
		}
	}
	m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
}

std::string LLCLayer::toString() const
{
	return "Logical Link Control";
}

} // namespace pcpp

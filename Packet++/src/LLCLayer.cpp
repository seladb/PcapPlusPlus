#define LOG_MODULE PacketLogModuleLLCLayer

#include "LLCLayer.h"
#include "PayloadLayer.h"
#include "StpLayer.h"

#include <cstring>

namespace pcpp
{

	LLCLayer::LLCLayer(uint8_t dsap, uint8_t ssap, uint8_t control)
	{
		m_DataLen = sizeof(llc_header);
		m_Data = new uint8_t[sizeof(llc_header)];
		memset(m_Data, 0, sizeof(llc_header));

		m_Protocol = LLC;

		// Set values
		llc_header* header = getLlcHeader();
		header->dsap = dsap;
		header->ssap = ssap;
		header->control = control;
	}

	void LLCLayer::parseNextLayer()
	{
		if (m_DataLen <= sizeof(llc_header))
			return;

		llc_header* hdr = getLlcHeader();
		uint8_t* payload = m_Data + sizeof(llc_header);
		size_t payloadLen = m_DataLen - sizeof(llc_header);

		if (hdr->dsap == 0x42 && hdr->ssap == 0x42 && StpLayer::isDataValid(payload, payloadLen))
		{
			m_NextLayer = StpLayer::parseStpLayer(payload, payloadLen, this, m_Packet);
			if (!m_NextLayer)
				m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
			return;
		}
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}

	std::string LLCLayer::toString() const
	{
		return "Logical Link Control";
	}

	bool LLCLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		return dataLen >= sizeof(llc_header) && !(data[0] == 0xFF && data[1] == 0xFF);
	}

}  // namespace pcpp

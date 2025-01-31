#include "../header/CotpLayer.h"
#include "S7CommLayer.h"
#include <PayloadLayer.h>

#include <cstring>

namespace pcpp
{

	pcpp::CotpLayer::CotpLayer(uint8_t tpduNumber)
	{
		const size_t headerLen = sizeof(cotphdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		cotphdr* cotpHdr = getCotpHeader();
		cotpHdr->length = 0x02;
		cotpHdr->pduType = 0x0f;
		cotpHdr->tpduNumber = tpduNumber;
		m_Protocol = COTP;
	}

	std::string CotpLayer::toString() const
	{
		return "Cotp Layer";
	}

	uint8_t CotpLayer::getLength() const
	{
		return getCotpHeader()->length;
	}

	uint8_t CotpLayer::getPduType() const
	{
		return getCotpHeader()->pduType;
	}

	uint8_t CotpLayer::getTpduNumber() const
	{
		return getCotpHeader()->tpduNumber;
	}

	void CotpLayer::setLength(uint8_t length) const
	{
		getCotpHeader()->length = length;
	}

	void CotpLayer::setPduType(uint8_t pduType) const
	{
		getCotpHeader()->pduType = pduType;
	}

	void CotpLayer::setTpduNumber(uint8_t tpduNumber) const
	{
		getCotpHeader()->tpduNumber = tpduNumber;
	}

	bool CotpLayer::isDataValid(const uint8_t* data, size_t dataSize)
	{
		if (!data || dataSize < sizeof(cotphdr))
			return false;

		return data[1] == 0xf0 && data[0] == 2;
	}

	void CotpLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t* payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		if (S7CommLayer::isDataValid(payload, payloadLen))
			m_NextLayer = new S7CommLayer(payload, payloadLen, this, m_Packet);
		else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}
}  // namespace pcpp

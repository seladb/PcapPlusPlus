#include "../header/CotpLayer.h"
#include "EndianPortable.h"
#include <PayloadLayer.h>
#include <cstring>
#include <iostream>
#include <sstream>

namespace pcpp
{

	pcpp::CotpLayer::CotpLayer(uint8_t length, uint8_t pduType, uint8_t tpduNumber)
	{
		const size_t headerLen = sizeof(cotphdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		cotphdr *cotpHdr = (cotphdr *)m_Data;
		cotpHdr->length = length;
		cotpHdr->pduType = pduType;
		cotpHdr->tpduNumber = tpduNumber;
		m_Protocol = COTP;
	}

	void CotpLayer::computeCalculateFields() {}

	std::string CotpLayer::toString() const
	{
		std::ostringstream lengthStream;
		lengthStream << std::to_string(getLength());
		std::ostringstream pduTypeStream;
		pduTypeStream << std::to_string(getPduType());
		std::ostringstream tpduNumberStream;
		tpduNumberStream << std::to_string(getTpduNumber());

		return "Cotp Layer";
	}

	CotpLayer *CotpLayer::parseCotpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
	{
		if (dataLen < sizeof(cotphdr))
			return NULL;

		cotphdr *cotpHdr = (cotphdr *)data;

		// illegal header data - length is too small
		if (be16toh(cotpHdr->length) < static_cast<uint16_t>(sizeof(cotphdr)))
			return NULL;
		return new CotpLayer(data, dataLen, prevLayer, packet);
	}

	uint8_t CotpLayer::getLength() const { return getCotpHeader()->length; }

	uint8_t CotpLayer::getPduType() const { return getCotpHeader()->pduType; }

	uint8_t CotpLayer::getTpduNumber() const { return getCotpHeader()->tpduNumber; }
	void CotpLayer::setLength(uint8_t length) const { getCotpHeader()->length = length; }
	void CotpLayer::setPduType(uint8_t pduType) const { getCotpHeader()->pduType = pduType; }
	void CotpLayer::setTpduNumber(uint8_t tpduNumber) const { getCotpHeader()->tpduNumber = tpduNumber; }

	void CotpLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t *payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}
} // namespace pcpp

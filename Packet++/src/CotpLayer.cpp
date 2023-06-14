#include "../header/CotpLayer.h"
#include "EndianPortable.h"
#include <PayloadLayer.h>
#include <cstring>
#include <iostream>
#include <sstream>

namespace pcpp
{

	pcpp::CotpLayer::CotpLayer(uint8_t length, uint8_t pdu_type, uint8_t tpdu_number)
	{
		const size_t headerLen = sizeof(cotphdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		cotphdr *cotpHdr = (cotphdr *)m_Data;
		cotpHdr->length = length;
		cotpHdr->pdu_type = pdu_type;
		cotpHdr->tpdu_number = tpdu_number;
		m_Protocol = COTP;
	}

	void CotpLayer::computeCalculateFields() {}

	std::string CotpLayer::toString() const
	{
		std::ostringstream lengthStream;
		lengthStream << std::to_string(getLength());
		std::ostringstream pduTypeStream;
		pduTypeStream << std::to_string(getPdu_type());
		std::ostringstream tpduNumberStream;
		tpduNumberStream << std::to_string(getTpdu_number());

		return "Cotp Layer length: " + lengthStream.str() + ", pdu_type: " + pduTypeStream.str() +
			   ", tpdu_number: " + tpduNumberStream.str();
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

	uint8_t CotpLayer::getPdu_type() const { return getCotpHeader()->pdu_type; }

	uint8_t CotpLayer::getTpdu_number() const { return getCotpHeader()->tpdu_number; }
	void CotpLayer::setLength(uint8_t length) const { getCotpHeader()->length = length; }
	void CotpLayer::setPdu_type(uint8_t pdu_type) const { getCotpHeader()->pdu_type = pdu_type; }
	void CotpLayer::setTpdu_number(uint8_t tpdu_number) const { getCotpHeader()->tpdu_number = tpdu_number; }

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

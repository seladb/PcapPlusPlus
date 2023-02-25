#include "CotpLayer.h"
#include "EndianPortable.h"
#include "S7commLayer.h"
#include <PayloadLayer.h>
#include <cstring>
#include <iostream>
#include <sstream>

namespace pcpp
{

	std::string CotpLayer::toString() const
	{
		std::ostringstream lengthStream;
		lengthStream << getLength();
		std::ostringstream pduTypeStream;
		pduTypeStream << getPdu_type();
		std::ostringstream tpduNumberStream;
		tpduNumberStream << getTpdu_number();

		return "COTP Layer, length: " + lengthStream.str() + ", pdu_type: " + pduTypeStream.str() +
			   ", tpdu_number: " + tpduNumberStream.str();
	}

	void CotpLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t *payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		if (S7commLayer::isS7commPort(payload[0]) && S7commLayer::isDataValid(payload, payloadLen))
		{

			m_NextLayer = S7commLayer::parseS7commLayer(payload, payloadLen, this, m_Packet);
		}
		else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}

	CotpLayer *CotpLayer::parseCotpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
	{
		return new CotpLayer(data, dataLen, prevLayer, packet);
	}

	uint8_t CotpLayer::getLength() const { return getCotpHeader()->length; }

	uint8_t CotpLayer::getPdu_type() const { return getCotpHeader()->pdu_type; }

	uint8_t CotpLayer::getTpdu_number() const { return getCotpHeader()->tpdu_number; }

} // namespace pcpp

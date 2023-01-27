#include "../header/CotpLayer.h"
#include "EndianPortable.h"
#include <iostream>
#include "S7commLayer.h"

#include <cstring>
#include <sstream>
#include <PayloadLayer.h>

namespace pcpp {

	pcpp::CotpLayer::CotpLayer(uint8_t length, uint8_t pdu_type, uint8_t tpdu_number) {
		const size_t headerLen = sizeof(cotphdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		cotphdr *cotpHdr = (cotphdr *) m_Data;
		cotpHdr->length = length;
		cotpHdr->pdu_type = pdu_type;
		cotpHdr->tpdu_number = tpdu_number;
		m_Protocol = COTP;
	}

	void CotpLayer::computeCalculateFields() {
	}

	std::string CotpLayer::toString() const {
		std::ostringstream lengthStream;
		lengthStream << getLength();
		std::ostringstream pduTypeStream;
		pduTypeStream << getPdu_type();
		std::ostringstream tpduNumberStream;
		tpduNumberStream << getTpdu_number();

		return "Cotp Layer, length: " + lengthStream.str() +
			   ", pdu_type: " + pduTypeStream.str() +
			   ", tpdu_number: " + tpduNumberStream.str();
	}

	void CotpLayer::parseNextLayer() {
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t *payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		if (S7commLayer::isS7commPort(payload[0])) {

			m_NextLayer = S7commLayer::parseS7commLayer(payload, payloadLen, this, m_Packet);

		} else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);

	}

	CotpLayer *CotpLayer::parseCotpLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) {
		if (dataLen < sizeof(cotphdr))
			return NULL;

		cotphdr *cotpHdr = (cotphdr *) data;

		// illegal header data - length is too small
		if (be16toh(cotpHdr->length) < static_cast<uint16_t>(sizeof(cotphdr)))
			return NULL;
		return new CotpLayer(data, dataLen, prevLayer, packet);
	}

	CotpLayer::CotpLayer() {
		const size_t headerLen = sizeof(cotphdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		m_Protocol = COTP;
	}

	uint8_t CotpLayer::getLength() const {
		return getCotpHeader()->length;
	}

	uint8_t CotpLayer::getPdu_type() const {
		return getCotpHeader()->pdu_type;
	}

	uint8_t CotpLayer::getTpdu_number() const {
		return getCotpHeader()->tpdu_number;
	}

} // namespace pcpp

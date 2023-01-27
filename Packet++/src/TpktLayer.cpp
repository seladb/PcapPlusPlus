#include "EndianPortable.h"
#include "TpktLayer.h"
#include "../header/TpktLayer.h"
#include <iostream>
#include "CotpLayer.h"
#include "TcpLayer.h"


#include <string.h>
#include <sstream>
#include <PayloadLayer.h>

namespace pcpp {


	pcpp::TpktLayer::TpktLayer(uint8_t vrsn, uint8_t reserved, uint16_t length) {
		const size_t headerLen = sizeof(tpkthdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		auto *tpktHdr = (tpkthdr *) m_Data;
		tpktHdr->vrsn = vrsn;
		tpktHdr->reserved = reserved;
		tpktHdr->length = htobe16(length);
		m_Protocol = TPKT;
	}

	uint8_t TpktLayer::getReserved() const {
		return getTpktHeader()->reserved;
	}

	uint8_t TpktLayer::getVrsn() const {
		return getTpktHeader()->vrsn;
	}

	uint16_t TpktLayer::getLength() const {
		return htobe16(getTpktHeader()->length);
	}

	void TpktLayer::computeCalculateFields() {
	}

	std::string TpktLayer::toString() const {
		std::ostringstream vrsnStream;
		vrsnStream << getVrsn();
		std::ostringstream reservedStream;
		reservedStream << getReserved();
		std::ostringstream lengthStream;
		lengthStream << getLength();

		return "Tpkt Layer, vrsn: " + vrsnStream.str() +
			   ", reserved: " + reservedStream.str() +
			   ", length: " + lengthStream.str();
	}

	void TpktLayer::parseNextLayer() {
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t *payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;
		uint8_t cotpType = payload[1];
		if (CotpLayer::isCotpPort(cotpType)) {
			m_NextLayer = CotpLayer::parseCotpLayer(payload, payloadLen, this, m_Packet);
		} else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);

	}

	TpktLayer *TpktLayer::parseTpktLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) {
		if (dataLen < sizeof(tpkthdr))
			return NULL;

		auto *tpktheader = (tpkthdr *) data;

		// illegal header data - length is too small
		if (be16toh(tpktheader->length) < static_cast<uint16_t>(sizeof(tpkthdr)))
			return NULL;
		return new TpktLayer(data, dataLen, prevLayer, packet);
	}

	TpktLayer::TpktLayer() {
		const size_t headerLen = sizeof(tpkthdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		auto *tpktHdr = (tpkthdr *) m_Data;
		tpktHdr->vrsn = 0;
		tpktHdr->reserved = 0;
		tpktHdr->length = 0;
		m_Protocol = TPKT;
	}
} // namespace pcpp

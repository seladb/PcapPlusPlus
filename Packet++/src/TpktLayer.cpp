#include "TpktLayer.h"
#include "CotpLayer.h"
#include "EndianPortable.h"
<<<<<<< HEAD
=======
#include "TcpLayer.h"
#include "CotpLayer.h"
>>>>>>> 77464cb5 (create COTP)
#include "PayloadLayer.h"
#include "TcpLayer.h"
#include <iostream>
#include <sstream>
#include <string.h>

namespace pcpp
{
	TpktLayer::TpktLayer(uint8_t version, uint16_t length)
	{
		m_DataLen = sizeof(tpkthdr);
		m_Data = new uint8_t[m_DataLen];
		memset(m_Data, 0, m_DataLen);
		tpkthdr *tpktHdr = getTpktHeader();
		tpktHdr->version = version;
		tpktHdr->reserved = 0;
		tpktHdr->length = htobe16(length);
		m_Protocol = TPKT;
	}

	uint8_t TpktLayer::getReserved() const { return getTpktHeader()->reserved; }

	uint8_t TpktLayer::getVersion() const { return getTpktHeader()->version; }

	uint16_t TpktLayer::getLength() const { return htobe16(getTpktHeader()->length); }

	void TpktLayer::setLength(uint16_t length) const { getTpktHeader()->length = htobe16(length); }

	void TpktLayer::setVersion(uint8_t version) const { getTpktHeader()->version = version; }

	std::string TpktLayer::toString() const
	{
		std::ostringstream versionStream;
		versionStream << std::to_string(getVersion());
		std::ostringstream lengthStream;
		lengthStream << std::to_string(getLength());

		return "TPKT Layer, version: " + versionStream.str() + ", length: " + lengthStream.str();
	}

	void TpktLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t *payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;
		uint8_t length = payload[0];
		uint8_t cotpType = payload[1];

		if (CotpLayer::isDataValid(payload, payloadLen, cotpType, length))
		{
			m_NextLayer = CotpLayer::parseCotpLayer(payload, payloadLen, this, m_Packet);
		}
		else
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}

} // namespace pcpp

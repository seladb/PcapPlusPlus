#include "TpktLayer.h"
#include "EndianPortable.h"
#include "TcpLayer.h"
#include <PayloadLayer.h>
#include <iostream>
#include <sstream>
#include <string.h>

namespace pcpp
{
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
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}

} // namespace pcpp

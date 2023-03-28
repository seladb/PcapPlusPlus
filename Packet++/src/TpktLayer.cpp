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

	std::string TpktLayer::toString() const
	{
		std::ostringstream versionStream;
		versionStream << getVersion();
		std::ostringstream reservedStream;
		reservedStream << getReserved();
		std::ostringstream lengthStream;
		lengthStream << getLength();

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

	TpktLayer *TpktLayer::parseTpktLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
	{
		return new TpktLayer(data, dataLen, prevLayer, packet);
	}

} // namespace pcpp

#include "S7commLayer.h"
#include "EndianPortable.h"
#include "TcpLayer.h"
#include "TpktLayer.h"
#include <cstring>
#include <iostream>
#include <sstream>

namespace pcpp
{

	std::string S7commLayer::toString() const
	{
		std::ostringstream protocolIdStream;
		protocolIdStream << getProtocolId();
		std::ostringstream msgTypeStream;
		msgTypeStream << getMsgType();
		std::ostringstream reservedStream;
		reservedStream << getReserved();
		std::ostringstream pduRefStream;
		pduRefStream << getPduRef();
		std::ostringstream paramLengthStream;
		paramLengthStream << getParamLength();
		std::ostringstream dataLengthStream;
		dataLengthStream << getDataLength();

		return "S7COMM Layer, protocol_id: " + protocolIdStream.str() + ", msg_type: " + msgTypeStream.str() +
			   ", reserved: " + reservedStream.str() + ", pdu_ref: " + pduRefStream.str() +
			   ", param_length: " + paramLengthStream.str() + ", data_length: " + dataLengthStream.str();
	}

	void S7commLayer::parseNextLayer() {}

	S7commLayer *S7commLayer::parseS7commLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet)
	{
		if (dataLen < sizeof(s7commhdr))
			return NULL;

		return new S7commLayer(data, dataLen, prevLayer, packet);
	}

	uint8_t S7commLayer::getProtocolId() const { return getS7commHeader()->protocol_id; }

	uint8_t S7commLayer::getMsgType() const { return getS7commHeader()->msg_type; }

	uint16_t S7commLayer::getReserved() const { return htobe16(getS7commHeader()->reserved); }

	uint16_t S7commLayer::getParamLength() const { return htobe16(getS7commHeader()->param_length); }

	uint16_t S7commLayer::getPduRef() const
	{
		return htobe16(getS7commHeader()->pdu_ref);
		;
	}

	uint16_t S7commLayer::getDataLength() const { return htobe16(getS7commHeader()->data_length); }
} // namespace pcpp

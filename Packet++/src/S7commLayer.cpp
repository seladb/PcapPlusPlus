#include "EndianPortable.h"
#include "TpktLayer.h"

#include <iostream>
#include "TcpLayer.h"
#include "S7commLayer.h"

#include <cstring>
#include <sstream>

namespace pcpp {


	S7commLayer::S7commLayer(uint8_t protocol_id, uint8_t msg_type, uint16_t reserved, uint16_t pdu_ref,
							 uint16_t param_length,
							 uint16_t data_length
							 //  , uint8_t error_class, uint8_t error_code
	) {
		const size_t headerLen = sizeof(s7commhdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		s7commhdr *s7commHdr = (s7commhdr *) m_Data;
		s7commHdr->protocol_id = protocol_id;
		s7commHdr->msg_type = msg_type;
		s7commHdr->reserved = htobe16(reserved);
		s7commHdr->pdu_ref = htobe16(pdu_ref);
		s7commHdr->param_length = htobe16(param_length);
		s7commHdr->data_length = htobe16(data_length);
		//        s7commHdr->error_class = error_class;
		//        s7commHdr->error_code = error_code;
		m_Protocol = S7COMM;
	}

	void S7commLayer::computeCalculateFields() {
	}

	std::string S7commLayer::toString() const {
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

		return "S7comm Layer, protocol_id: " + protocolIdStream.str() +
			   ", msg_type: " + msgTypeStream.str() +
			   ", reserved: " + reservedStream.str() +
			   ", pdu_ref: " + pduRefStream.str() +
			   ", param_length: " + paramLengthStream.str() +
			   ", data_length: " + dataLengthStream.str();

	}

	void S7commLayer::parseNextLayer() {

	}

	S7commLayer *S7commLayer::parseS7commLayer(uint8_t *data, size_t dataLen, Layer *prevLayer, Packet *packet) {
		if (dataLen < sizeof(s7commhdr))
			return NULL;

		return new S7commLayer(data, dataLen, prevLayer, packet);
	}

	S7commLayer::S7commLayer() {
		const size_t headerLen = sizeof(s7commhdr)-2;
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);

		m_Protocol = S7COMM;
	}

	uint8_t S7commLayer::getProtocolId() const {
		return getS7commHeader()->protocol_id;
	}

	uint8_t S7commLayer::getMsgType() const {
		return getS7commHeader()->msg_type;
	}

	uint16_t S7commLayer::getReserved() const {
		return htobe16(getS7commHeader()->reserved);
	}

	uint16_t S7commLayer::getParamLength() const {
		return htobe16(getS7commHeader()->param_length);
	}

	uint16_t S7commLayer::getPduRef() const {
		return htobe16(getS7commHeader()->pdu_ref);;
	}

	uint16_t S7commLayer::getDataLength() const {
		return htobe16(getS7commHeader()->data_length);
	}
} // namespace pcpp

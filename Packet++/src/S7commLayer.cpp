#include "EndianPortable.h"
#include "TpktLayer.h"

#include <iostream>
#include "TcpLayer.h"
#include "S7commLayer.h"

#include <cstring>
#include <sstream>

namespace pcpp {

	S7commLayer::S7commLayer(uint8_t msg_type, uint16_t pdu_ref,
							 uint16_t param_length, uint16_t data_length) {
		const size_t headerLen = sizeof(s7commhdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);
		s7commhdr *s7commHdr = (s7commhdr *) m_Data;
		s7commHdr->protocol_id = 0x32;
		s7commHdr->msg_type = msg_type;
		s7commHdr->reserved = 0x0000;
		s7commHdr->pdu_ref = htobe16(pdu_ref);
		s7commHdr->param_length = htobe16(param_length);
		s7commHdr->data_length = htobe16(data_length);
		m_Protocol = S7COMM;
	}

    std::string S7commLayer::toString() const {
        std::ostringstream msgTypeStream;
        msgTypeStream << getMsgType();
        std::ostringstream pduRefStream;
        pduRefStream << getPduRef();
        std::ostringstream paramLengthStream;
        paramLengthStream << getParamLength();
        std::ostringstream dataLengthStream;
        dataLengthStream << getDataLength();

        return "S7comm Layer, msg_type: " + msgTypeStream.str() +
               ", pdu_ref: " + pduRefStream.str() +
               ", param_length: " + paramLengthStream.str() +
               ", data_length: " + dataLengthStream.str();

    }

	bool S7commLayer::isDataValid(const uint8_t *data, size_t dataSize)
	{
		if (!data || dataSize < sizeof(s7commhdr))
			return false;

		return data[0] == 0x32;
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

	void S7commLayer::setMsgType(uint8_t msg_type) const {
		getS7commHeader()->msg_type = msg_type;
	}

	void S7commLayer::setParamLength(uint16_t param_length) const {
		getS7commHeader()->param_length = htobe16(param_length);
	}

	void S7commLayer::setPduRef(uint16_t pdu_ref) const {
		getS7commHeader()->pdu_ref = htobe16(pdu_ref);
	}

	void S7commLayer::setDataLength(uint16_t data_length) const {
		getS7commHeader()->data_length = htobe16(data_length);
	}
} // namespace pcpp

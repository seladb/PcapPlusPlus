#include "EndianPortable.h"
#include "TpktLayer.h"

#include "S7commLayer.h"
#include "TcpLayer.h"
#include <iostream>

#include <cstring>
#include <sstream>

namespace pcpp
{

	S7commLayer::S7commLayer(uint8_t msg_type, uint16_t pdu_ref, uint16_t param_length, uint16_t data_length,
							 uint8_t error_class, uint8_t error_code)
	{
		size_t headerLen;
		if (msg_type == 0x03)
		{
			headerLen = sizeof(s7comm_ack_data_hdr);
			m_DataLen = headerLen;
			m_Data = new uint8_t[headerLen];
			memset(m_Data, 0, headerLen);
			s7comm_ack_data_hdr *ack_d = (s7comm_ack_data_hdr *)m_Data;
			ack_d->protocol_id = 0x32;
			ack_d->msg_type = msg_type;
			ack_d->reserved = 0x0000;
			ack_d->pdu_ref = htobe16(pdu_ref);
			ack_d->param_length = htobe16(param_length);
			ack_d->data_length = htobe16(data_length);
			ack_d->error_class = error_class;
			ack_d->error_code = error_code;
		}
		else
		{
			headerLen = sizeof(s7commhdr);
			m_DataLen = headerLen;
			m_Data = new uint8_t[headerLen];
			memset(m_Data, 0, headerLen);
			s7commhdr *s7commHdr = (s7commhdr *)m_Data;
			s7commHdr->protocol_id = 0x32;
			s7commHdr->msg_type = msg_type;
			s7commHdr->reserved = 0x0000;
			s7commHdr->pdu_ref = htobe16(pdu_ref);
			s7commHdr->param_length = htobe16(param_length);
			s7commHdr->data_length = htobe16(data_length);
		}

		m_Protocol = S7COMM;
	}

	std::string S7commLayer::toString() const
	{
		std::ostringstream str;
		std::string error;
		if (getMsgType() == 0x03)
		{
			error =
				", error class: " + std::to_string(getErrorClass()) + ", error code: " + std::to_string(getErrorCode());
		}
		str << "S7comm Layer, "
			<< "msg_type: " << std::to_string(getMsgType()) << ", pdu_ref: " << std::to_string(getPduRef())
			<< ", param_length: " << std::to_string(getParamLength())
			<< ", data_length: " << std::to_string(getDataLength()) << error;

		return str.str();
	}

	bool S7commLayer::isDataValid(const uint8_t *data, size_t dataSize)
	{
		if (!data || dataSize < sizeof(s7commhdr))
			return false;

		return data[0] == 0x32;
	}

	uint8_t S7commLayer::getProtocolId() const { return getS7commHeader()->protocol_id; }

	uint8_t S7commLayer::getMsgType() const { return getS7commHeader()->msg_type; }

	uint16_t S7commLayer::getReserved() const { return htobe16(getS7commHeader()->reserved); }

	uint16_t S7commLayer::getParamLength() const { return htobe16(getS7commHeader()->param_length); }

	uint16_t S7commLayer::getPduRef() const { return htobe16(getS7commHeader()->pdu_ref); }

	uint16_t S7commLayer::getDataLength() const { return htobe16(getS7commHeader()->data_length); }

	void S7commLayer::setMsgType(uint8_t msg_type) const { getS7commHeader()->msg_type = msg_type; }

	uint8_t S7commLayer::getErrorCode() const { return getS7commAckDataHeader()->error_code; }

	uint8_t S7commLayer::getErrorClass() const { return getS7commAckDataHeader()->error_class; }

	void S7commLayer::setParamLength(uint16_t param_length) const
	{
		getS7commHeader()->param_length = htobe16(param_length);
	}

	void S7commLayer::setPduRef(uint16_t pdu_ref) const { getS7commHeader()->pdu_ref = htobe16(pdu_ref); }

	void S7commLayer::setDataLength(uint16_t data_length) const
	{
		getS7commHeader()->data_length = htobe16(data_length);
	}

	void S7commLayer::setErrorCode(uint8_t error_code) const { getS7commAckDataHeader()->error_code = error_code; }

	void S7commLayer::setErrorClass(uint8_t error_class) const { getS7commAckDataHeader()->error_class = error_class; }

	S7CommParameter *S7commLayer::getParameter() const
	{
		S7CommParameter *m_Parameter = nullptr;

		uint8_t *payload = m_Data + getHeaderLen() - getParamLength() -getDataLen();//- getHeaderLen() + parameterLen; //;+ parameterLen;
		size_t payloadLen = m_DataLen - getHeaderLen() + getParamLength() + getDataLength();

		m_Parameter = new S7CommParameter(payload, payloadLen);
		return m_Parameter;
	}

} // namespace pcpp

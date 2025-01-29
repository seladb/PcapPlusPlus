#include "EndianPortable.h"

#include "S7CommLayer.h"
#include <iostream>
#include <cstring>
#include <sstream>

namespace pcpp
{

	S7CommLayer::S7CommLayer(uint8_t msgType, uint16_t pduRef, uint16_t paramLength, uint16_t dataLength,
	                         uint8_t errorClass, uint8_t errorCode)
	{
		size_t basicHeaderLen = msgType == 0x03 ? sizeof(s7comm_ack_data_hdr) : sizeof(s7commhdr);
		size_t headerLen = basicHeaderLen + paramLength + dataLength;
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, headerLen);

		if (msgType == 0x03)
		{
			auto* ack_d = (s7comm_ack_data_hdr*)m_Data;
			ack_d->protocolId = 0x32;
			ack_d->msgType = msgType;
			ack_d->reserved = 0x0000;
			ack_d->pduRef = htobe16(pduRef);
			ack_d->paramLength = htobe16(paramLength);
			ack_d->dataLength = htobe16(dataLength);
			ack_d->errorClass = errorClass;
			ack_d->errorCode = errorCode;
		}
		else
		{
			auto* s7commHdr = (s7commhdr*)m_Data;
			s7commHdr->protocolId = 0x32;
			s7commHdr->msgType = msgType;
			s7commHdr->reserved = 0x0000;
			s7commHdr->pduRef = htobe16(pduRef);
			s7commHdr->paramLength = htobe16(paramLength);
			s7commHdr->dataLength = htobe16(dataLength);
		}

		m_Parameter = nullptr;
		m_Protocol = S7COMM;
	}

	std::string S7CommLayer::toString() const
	{
		std::ostringstream str;
		str << "S7Comm Layer, ";

		switch (getS7commHeader()->msgType)
		{
		case 0x01:
			str << "Job Request";
			break;
		case 0x02:
			str << "Ack";
			break;
		case 0x03:
			str << "Ack-Data";
			break;
		case 0x07:
			str << "Userdata";
			break;
		default:
			str << "Unknown message";
		}

		return str.str();
	}

	bool S7CommLayer::isDataValid(const uint8_t* data, size_t dataSize)
	{
		if (!data || dataSize < sizeof(s7commhdr))
			return false;

		return data[0] == 0x32;
	}

	uint8_t S7CommLayer::getProtocolId() const
	{
		return getS7commHeader()->protocolId;
	}

	uint8_t S7CommLayer::getMsgType() const
	{
		return getS7commHeader()->msgType;
	}

	uint16_t S7CommLayer::getParamLength() const
	{
		return be16toh(getS7commHeader()->paramLength);
	}

	uint16_t S7CommLayer::getPduRef() const
	{
		return be16toh(getS7commHeader()->pduRef);
	}

	uint16_t S7CommLayer::getDataLength() const
	{
		return be16toh(getS7commHeader()->dataLength);
	}

	void S7CommLayer::setMsgType(uint8_t msgType) const
	{
		getS7commHeader()->msgType = msgType;
	}

	uint8_t S7CommLayer::getErrorCode() const
	{
		return getS7commAckDataHeader()->errorCode;
	}

	uint8_t S7CommLayer::getErrorClass() const
	{
		return getS7commAckDataHeader()->errorClass;
	}

	void S7CommLayer::setPduRef(uint16_t pduRef) const
	{
		getS7commHeader()->pduRef = htobe16(pduRef);
	}

	void S7CommLayer::setErrorCode(uint8_t errorCode) const
	{
		getS7commAckDataHeader()->errorCode = errorCode;
	}

	void S7CommLayer::setErrorClass(uint8_t errorClass) const
	{
		getS7commAckDataHeader()->errorClass = errorClass;
	}

	const S7CommParameter* S7CommLayer::getParameter()
	{
		if (!m_Parameter)
		{
			uint8_t* payload = m_Data + getS7commHeaderLength();
			m_Parameter = new S7CommParameter(payload, getParamLength());
		}

		return m_Parameter;
	}

	size_t S7CommLayer::getS7commHeaderLength() const
	{
		if (getS7commHeader()->msgType == 0x03)
		{
			return sizeof(s7comm_ack_data_hdr);
		}
		return sizeof(s7commhdr);
	}

}  // namespace pcpp

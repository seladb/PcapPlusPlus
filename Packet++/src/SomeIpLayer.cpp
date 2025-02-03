#define LOG_MODULE PacketLogModuleSomeIpLayer

#include "SomeIpLayer.h"
#include "SomeIpSdLayer.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "EndianPortable.h"
#include <algorithm>
#include <sstream>

namespace pcpp
{

	// SomeIpLayer

	void splitUint32Id(uint32_t uint32Id, uint16_t& uint16IdUpper, uint16_t& uint16IdLower)
	{
		uint16IdLower = (uint32Id & 0x0000ffff);
		uint16IdUpper = (uint32Id & 0xffff0000) >> 16;
	}

	std::unordered_set<uint16_t> SomeIpLayer::m_SomeIpPorts{};

	SomeIpLayer::SomeIpLayer(uint16_t serviceID, uint16_t methodID, uint16_t clientID, uint16_t sessionID,
	                         uint8_t interfaceVersion, MsgType type, uint8_t returnCode, const uint8_t* const data,
	                         size_t dataLen)
	{
		const size_t headerLen = sizeof(someiphdr);
		m_DataLen = headerLen + dataLen;
		m_Data = new uint8_t[m_DataLen];
		m_Protocol = SomeIP;
		memset(m_Data, 0, headerLen);
		memcpy(m_Data + headerLen, data, dataLen);

		setServiceID(serviceID);
		setMethodID(methodID);
		setPayloadLength((uint32_t)dataLen);
		setClientID(clientID);
		setSessionID(sessionID);
		setProtocolVersion(0x01);
		setInterfaceVersion(interfaceVersion);
		setMessageType(type);
		setReturnCode(returnCode);
	}

	Layer* SomeIpLayer::parseSomeIpLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		// Ideas taken from wireshark some ip dissector
		const size_t headerLen = sizeof(someiphdr);
		if (dataLen < headerLen)
			return new PayloadLayer(data, dataLen, prevLayer, packet);

		uint32_t lengthBE = 0;
		memcpy(&lengthBE, data + sizeof(uint32_t), sizeof(uint32_t));  // length field in SOME/IP header
		uint32_t length = be32toh(lengthBE);
		if ((length < 8) || (length > dataLen - 8))
			return new PayloadLayer(data, dataLen, prevLayer, packet);

		if (data[12] != SOMEIP_PROTOCOL_VERSION)
			return new PayloadLayer(data, dataLen, prevLayer, packet);

		someiphdr* hdr = (someiphdr*)data;

		switch (static_cast<MsgType>(hdr->msgType & ~(uint8_t)MsgType::TP_REQUEST))
		{
		case MsgType::REQUEST:
		case MsgType::REQUEST_ACK:
		case MsgType::REQUEST_NO_RETURN:
		case MsgType::REQUEST_NO_RETURN_ACK:
		case MsgType::NOTIFICATION:
		case MsgType::NOTIFICATION_ACK:
		case MsgType::RESPONSE:
		case MsgType::RESPONSE_ACK:
		case MsgType::ERRORS:
		case MsgType::ERROR_ACK:
			break;
		default:
			return new PayloadLayer(data, dataLen, prevLayer, packet);
		}

		if (be16toh(hdr->serviceID) == 0xFFFF && be16toh(hdr->methodID) == 0x8100 &&
		    SomeIpSdLayer::isDataValid(data, dataLen))
		{
			return new SomeIpSdLayer(data, dataLen, prevLayer, packet);
		}
		else if ((hdr->msgType & (uint8_t)SomeIpLayer::MsgType::TP_REQUEST) != 0)
		{
			return new SomeIpTpLayer(data, dataLen, prevLayer, packet);
		}
		else
		{
			return new SomeIpLayer(data, dataLen, prevLayer, packet);
		}
	}

	bool SomeIpLayer::isSomeIpPort(uint16_t port)
	{
		return SomeIpSdLayer::isSomeIpSdPort(port) ||
		       std::any_of(m_SomeIpPorts.begin(), m_SomeIpPorts.end(),
		                   [&](const uint16_t& someIpPort) { return someIpPort == port; });
	}

	void SomeIpLayer::addSomeIpPort(uint16_t port)
	{
		m_SomeIpPorts.insert(port);
	}

	void SomeIpLayer::removeSomeIpPort(uint16_t port)
	{
		m_SomeIpPorts.erase(port);
	}

	void SomeIpLayer::removeAllSomeIpPorts()
	{
		m_SomeIpPorts.clear();
	}

	uint32_t SomeIpLayer::getMessageID() const
	{
		someiphdr* hdr = getSomeIpHeader();

		return ((uint32_t)be16toh(hdr->serviceID) << 16) + be16toh(hdr->methodID);
	}

	void SomeIpLayer::setMessageID(uint32_t messageID)
	{
		uint16_t methodID;
		uint16_t serviceID;

		splitUint32Id(messageID, serviceID, methodID);

		someiphdr* hdr = getSomeIpHeader();
		hdr->serviceID = htobe16(serviceID);
		hdr->methodID = htobe16(methodID);
	}

	uint16_t SomeIpLayer::getServiceID() const
	{
		return be16toh(getSomeIpHeader()->serviceID);
	}

	void SomeIpLayer::setServiceID(uint16_t serviceID)
	{
		getSomeIpHeader()->serviceID = htobe16(serviceID);
	}

	uint16_t SomeIpLayer::getMethodID() const
	{
		return be16toh(getSomeIpHeader()->methodID);
	}

	void SomeIpLayer::setMethodID(uint16_t methodID)
	{
		getSomeIpHeader()->methodID = htobe16(methodID);
	}

	uint32_t SomeIpLayer::getLengthField() const
	{
		return be32toh(getSomeIpHeader()->length);
	}

	uint32_t SomeIpLayer::getRequestID() const
	{
		someiphdr* hdr = getSomeIpHeader();

		return ((uint32_t)be16toh(hdr->clientID) << 16) + be16toh(hdr->sessionID);
	}

	void SomeIpLayer::setRequestID(uint32_t requestID)
	{
		uint16_t clientID;
		uint16_t sessionID;

		splitUint32Id(requestID, clientID, sessionID);

		someiphdr* hdr = getSomeIpHeader();
		hdr->clientID = htobe16(clientID);
		hdr->sessionID = htobe16(sessionID);
	}

	uint16_t SomeIpLayer::getClientID() const
	{
		return be16toh(getSomeIpHeader()->clientID);
	}

	void SomeIpLayer::setClientID(uint16_t clientID)
	{
		getSomeIpHeader()->clientID = htobe16(clientID);
	}

	uint16_t SomeIpLayer::getSessionID() const
	{
		return be16toh(getSomeIpHeader()->sessionID);
	}

	void SomeIpLayer::setSessionID(uint16_t sessionID)
	{
		getSomeIpHeader()->sessionID = htobe16(sessionID);
	}

	uint8_t SomeIpLayer::getProtocolVersion() const
	{
		return getSomeIpHeader()->protocolVersion;
	}

	void SomeIpLayer::setProtocolVersion(uint8_t version)
	{
		getSomeIpHeader()->protocolVersion = version;
	}

	uint8_t SomeIpLayer::getInterfaceVersion() const
	{
		return getSomeIpHeader()->interfaceVersion;
	}

	void SomeIpLayer::setInterfaceVersion(uint8_t version)
	{
		getSomeIpHeader()->interfaceVersion = version;
	}

	SomeIpLayer::MsgType SomeIpLayer::getMessageType() const
	{
		return static_cast<SomeIpLayer::MsgType>(getSomeIpHeader()->msgType);
	}

	uint8_t SomeIpLayer::getMessageTypeAsInt() const
	{
		return getSomeIpHeader()->msgType;
	}

	void SomeIpLayer::setMessageType(MsgType type)
	{
		setMessageType(static_cast<uint8_t>(type));
	}

	void SomeIpLayer::setMessageType(uint8_t type)
	{
		getSomeIpHeader()->msgType = type;
	}

	uint8_t SomeIpLayer::getReturnCode() const
	{
		return getSomeIpHeader()->returnCode;
	}

	void SomeIpLayer::setReturnCode(uint8_t returnCode)
	{
		getSomeIpHeader()->returnCode = returnCode;
	}

	void SomeIpLayer::setPayloadLength(uint32_t payloadLength)
	{
		someiphdr* hdr = getSomeIpHeader();
		hdr->length = htobe32(sizeof(someiphdr) - sizeof(hdr->serviceID) - sizeof(hdr->methodID) - sizeof(hdr->length) +
		                      payloadLength);
	}

	void SomeIpLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t* payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		m_NextLayer = parseSomeIpLayer(payload, payloadLen, this, m_Packet);
	}

	std::string SomeIpLayer::toString() const
	{
		std::stringstream dataStream;

		dataStream << "SOME/IP Layer" << std::hex << ", Service ID: 0x" << getServiceID() << ", Method ID: 0x"
		           << getMethodID() << std::dec << ", Length: " << getLengthField();

		return dataStream.str();
	}

	// SomeIpTpLayer

	SomeIpTpLayer::SomeIpTpLayer(uint16_t serviceID, uint16_t methodID, uint16_t clientID, uint16_t sessionID,
	                             uint8_t interfaceVersion, MsgType type, uint8_t returnCode, uint32_t offset,
	                             bool moreSegmentsFlag, const uint8_t* const data, size_t dataLen)
	{
		const size_t headerLen = sizeof(someiptphdr);

		m_DataLen = headerLen + dataLen;
		m_Data = new uint8_t[m_DataLen];
		m_Protocol = SomeIP;
		memset(m_Data, 0, headerLen);
		memcpy(m_Data + headerLen, data, dataLen);

		setServiceID(serviceID);
		setMethodID(methodID);
		setPayloadLength((uint32_t)(dataLen + sizeof(uint32_t)));
		setClientID(clientID);
		setSessionID(sessionID);
		setProtocolVersion(0x01);
		setInterfaceVersion(interfaceVersion);
		setMessageType(setTpFlag((uint8_t)type));
		setReturnCode(returnCode);
		setOffset(offset);
		setMoreSegmentsFlag(moreSegmentsFlag);
	}

	uint32_t SomeIpTpLayer::getOffset() const
	{
		return (be32toh(getSomeIpTpHeader()->offsetAndFlag) & SOMEIP_TP_OFFSET_MASK) >> 4;
	}

	void SomeIpTpLayer::setOffset(uint32_t offset)
	{
		uint32_t val = (offset << 4) | (be32toh(getSomeIpTpHeader()->offsetAndFlag) & ~SOMEIP_TP_OFFSET_MASK);
		getSomeIpTpHeader()->offsetAndFlag = htobe32(val);
	}

	bool SomeIpTpLayer::getMoreSegmentsFlag() const
	{
		return be32toh(getSomeIpTpHeader()->offsetAndFlag) & SOMEIP_TP_MORE_FLAG_MASK;
	}

	void SomeIpTpLayer::setMoreSegmentsFlag(bool flag)
	{
		uint32_t val = be32toh(getSomeIpTpHeader()->offsetAndFlag);

		if (flag)
		{
			val = val | SOMEIP_TP_MORE_FLAG_MASK;
		}
		else
		{
			val = val & ~SOMEIP_TP_MORE_FLAG_MASK;
		}

		getSomeIpTpHeader()->offsetAndFlag = htobe32(val);
	}

	void SomeIpTpLayer::computeCalculateFields()
	{
		setMessageType(setTpFlag(getMessageTypeAsInt()));
	}

	std::string SomeIpTpLayer::toString() const
	{
		std::stringstream dataStream;

		dataStream << "SOME/IP-TP Layer" << std::hex << ", Service ID: 0x" << getServiceID() << ", Method ID: 0x"
		           << getMethodID() << std::dec << ", Length: " << getLengthField();

		return dataStream.str();
	}

	uint8_t SomeIpTpLayer::setTpFlag(uint8_t messageType)
	{
		return messageType | (uint8_t)SomeIpLayer::MsgType::TP_REQUEST;
	}
}  // namespace pcpp

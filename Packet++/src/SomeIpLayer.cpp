#define LOG_MODULE PacketLogModuleSomeIpLayer

#include "SomeIpLayer.h"
#include "EndianPortable.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include <algorithm>
#include <sstream>
#include <string.h>

namespace pcpp
{

void splitUint32Id(uint32_t uint32Id, uint16_t &uint16IdUpper, uint16_t &uint16IdLower)
{
	uint16IdLower = (uint32Id & 0x0000ffff);
	uint16IdUpper = (uint32Id & 0xffff0000) >> 16;
}

std::unordered_set<uint16_t> SomeIpLayer::m_SomeIpPorts{};

SomeIpLayer::SomeIpLayer(uint16_t serviceID, uint16_t methodID, uint16_t clientID, uint16_t sessionID,
						 uint8_t interfaceVersion, MsgType type, uint8_t returnCode, const uint8_t *const data,
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
	setPayloadLength(dataLen);
	setClientID(clientID);
	setSessionID(sessionID);
	setProtocolVersion(0x01);
	setInterfaceVersion(interfaceVersion);
	setMessageType(type);
	setReturnCode(returnCode);
}

bool SomeIpLayer::isSomeIpPort(uint16_t port)
{
	return std::any_of(m_SomeIpPorts.begin(), m_SomeIpPorts.end(),
					   [&](const uint16_t &someIpPort) { return someIpPort == port; });
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

bool SomeIpLayer::isDataValid(uint8_t *data, uint32_t dataLen)
{
	/* Ideas taken from wireshark some ip dissector */
	const size_t headerLen = sizeof(someiphdr);
	if (dataLen < headerLen)
		return false;

	uint32_t lengthBE = 0;
	memcpy(&lengthBE, data + sizeof(uint32_t), sizeof(uint32_t)); // length field in SOME/IP header
	uint32_t length = be32toh(lengthBE);
	if ((length < 8) || (length > dataLen - 8))
		return false;

	if (data[12] != SOMEIP_PROTOCOL_VERSION)
		return false;

	someiphdr *hdr = (someiphdr *)data;

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
		return false;
	}

	return true;
}

uint32_t SomeIpLayer::getMessageID() const
{
	someiphdr *hdr = getSomeIpHeader();

	return ((uint32_t)be16toh(hdr->serviceID) << 16) + be16toh(hdr->methodID);
}

void SomeIpLayer::setMessageID(uint32_t messageID)
{
	uint16_t methodID;
	uint16_t serviceID;

	splitUint32Id(messageID, serviceID, methodID);

	someiphdr *hdr = getSomeIpHeader();
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
	someiphdr *hdr = getSomeIpHeader();

	return ((uint32_t)be16toh(hdr->clientID) << 16) + be16toh(hdr->sessionID);
}

void SomeIpLayer::setRequestID(uint32_t requestID)
{
	uint16_t clientID;
	uint16_t sessionID;

	splitUint32Id(requestID, clientID, sessionID);

	someiphdr *hdr = getSomeIpHeader();
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
	setMessageType((uint8_t)type);
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
	someiphdr *hdr = getSomeIpHeader();
	hdr->length = htobe32(sizeof(someiphdr) - sizeof(hdr->serviceID) - sizeof(hdr->methodID) - sizeof(hdr->length) +
						  payloadLength);
}

uint32_t SomeIpLayer::getHeaderLengthWithPayload() const
{
	/* Add outer header of SOME/IP to length (messageId and length field itself) */
	return sizeof(uint32_t) * 2 + getLengthField();
}

size_t SomeIpLayer::getHeaderLen() const
{
	if (subProtocolFollows())
	{
		/* If there is a protocol coming after the normal SOME/IP header, return just the header length so PcapPlusPlus
		handles the oncoming protocols correctly */
		return sizeof(someiphdr);
	}
	else
	{
		/* Else, return the length of the header + payload, since it is a normal SOME/IP PDU */
		return getHeaderLengthWithPayload();
	}
}

bool SomeIpLayer::subProtocolFollows() const
{
	/* Check if the header is a valid SOME/IP-SD header */
	if (isSomeIpSdPacket(getServiceID(), getMethodID()))
	{
		return true;
	}
	/* Check if the payload is a valid SOME/IP-TP layer */
	if (isSomeIpTpPacket(getMessageTypeAsInt()))
	{
		return true;
	}

	return false;
}

void SomeIpLayer::parseNextLayer()
{
	size_t headerLen = getHeaderLen();
	if (m_DataLen <= headerLen)
		return;

	uint8_t *payload = m_Data + headerLen;
	size_t payloadLen = m_DataLen - headerLen;

	/* Check if the header is a valid SomeIpSd header */
	if (isSomeIpSdPacket(getServiceID(), getMethodID()))
	{
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}
	/* Check if the payload is a valid SomeIp TP layer */
	else if (isSomeIpTpPacket(getMessageTypeAsInt()))
	{
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}
	else if (isDataValid(payload, payloadLen))
	/* else parse as SomeIpLayer (i.e. respect chaining of SomeIpLayers in one Ethernet frame) */
	{
		m_NextLayer = new SomeIpLayer(payload, payloadLen, this, m_Packet);
	}
	else
	{
		m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
	}
}

std::string SomeIpLayer::toString() const
{
	std::stringstream dataStream;
	dataStream << std::hex;

	dataStream << "SOME/IP Layer"
			   << ", Service ID: 0x" << getServiceID()
			   << ", Method ID: 0x" << getMethodID()
			   << std::dec
			   << ", Length: " << getLengthField();

	return dataStream.str();
}

bool SomeIpLayer::isSomeIpSdPacket(uint16_t serviceId, uint16_t methodId)
{
	return serviceId == 0xFFFF && methodId == 0x8100;
}

bool SomeIpLayer::isSomeIpTpPacket(uint8_t msgType)
{
	/* Check if TP flag is set in msgType */
	return (msgType & (uint8_t)SomeIpLayer::MsgType::TP_REQUEST) != 0;
}

} // namespace pcpp

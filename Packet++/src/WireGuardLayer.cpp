#define LOG_MODULE PacketLogModuleWireGuardLayer

#include "UdpLayer.h"
#include "WireGuardLayer.h"
#include "EndianPortable.h"
#include <iomanip>
#include <cstring>

namespace pcpp
{
	WireGuardLayer* WireGuardLayer::parseWireGuardLayer(uint8_t* data, size_t dataLen, Layer* prevLayer, Packet* packet)
	{
		if (dataLen < sizeof(WireGuardLayer::wg_common_header))
			return nullptr;
		wg_common_header* wgHeader = reinterpret_cast<wg_common_header*>(data);

		switch (wgHeader->messageType)
		{
		case static_cast<uint8_t>(WireGuardMessageType::HandshakeInitiation):
			return new WireGuardHandshakeInitiationLayer(data, dataLen, prevLayer, packet);
		case static_cast<uint8_t>(WireGuardMessageType::HandshakeResponse):
			return new WireGuardHandshakeResponseLayer(data, dataLen, prevLayer, packet);
		case static_cast<uint8_t>(WireGuardMessageType::CookieReply):
			return new WireGuardCookieReplyLayer(data, dataLen, prevLayer, packet);
		case static_cast<uint8_t>(WireGuardMessageType::TransportData):
			return new WireGuardTransportDataLayer(data, dataLen, prevLayer, packet);
		default:
			return nullptr;
		}
	}

	std::string WireGuardLayer::getMessageTypeAsString() const
	{
		uint32_t messageType = getMessageType();
		switch (messageType)
		{
		case static_cast<uint8_t>(WireGuardMessageType::HandshakeInitiation):
			return "Handshake Initiation";
		case static_cast<uint8_t>(WireGuardMessageType::HandshakeResponse):
			return "Handshake Response";
		case static_cast<uint8_t>(WireGuardMessageType::CookieReply):
			return "Cookie Reply";
		case static_cast<uint8_t>(WireGuardMessageType::TransportData):
			return "Transport Data";
		default:
			return "Unknown";
		}
	}

	std::string WireGuardLayer::toString() const
	{
		return "WireGuard Layer, " + getMessageTypeAsString() + " message";
	}

	size_t WireGuardLayer::getHeaderLen() const
	{
		return m_DataLen;
	}

	uint8_t WireGuardLayer::getMessageType() const
	{
		return getBasicHeader()->messageType;
	}

	uint32_t WireGuardLayer::getReserved() const
	{
		uint32_t reservedValue = 0;
		memcpy(&reservedValue, getBasicHeader()->reserved, 3);
		return be32toh(reservedValue);
	}

	bool WireGuardLayer::isDataValid(const uint8_t* data, size_t dataLen)
	{
		if (dataLen < sizeof(WireGuardLayer::wg_common_header))
			return false;

		uint8_t messageType = data[0];
		return messageType >= static_cast<uint8_t>(WireGuardLayer::WireGuardMessageType::HandshakeInitiation) &&
		       messageType <= static_cast<uint8_t>(WireGuardLayer::WireGuardMessageType::TransportData);
	}

	// ~~~~~~~~~~~~~~~~~~~~
	// WireGuardHandshakeInitiationLayer
	// ~~~~~~~~~~~~~~~~~~~~

	WireGuardHandshakeInitiationLayer::WireGuardHandshakeInitiationLayer(uint32_t senderIndex,
	                                                                     const uint8_t initiatorEphemeral[32],
	                                                                     const uint8_t encryptedInitiatorStatic[48],
	                                                                     const uint8_t encryptedTimestamp[28],
	                                                                     const uint8_t mac1[16], const uint8_t mac2[16])
	{
		const size_t messageLen = sizeof(wg_handshake_initiation);
		m_DataLen = messageLen;
		m_Data = new uint8_t[messageLen];
		memset(m_Data, 0, messageLen);

		wg_handshake_initiation* msgHdr = reinterpret_cast<wg_handshake_initiation*>(m_Data);

		msgHdr->messageType = static_cast<uint8_t>(WireGuardMessageType::HandshakeInitiation);
		msgHdr->senderIndex = htobe32(senderIndex);

		memcpy(msgHdr->initiatorEphemeral, initiatorEphemeral, 32);
		memcpy(msgHdr->encryptedInitiatorStatic, encryptedInitiatorStatic, 48);
		memcpy(msgHdr->encryptedTimestamp, encryptedTimestamp, 28);
		memcpy(msgHdr->mac1, mac1, 16);
		memcpy(msgHdr->mac2, mac2, 16);

		m_Protocol = WireGuard;
	}

	uint32_t WireGuardHandshakeInitiationLayer::getSenderIndex() const
	{
		return be32toh(getHandshakeInitiationHeader()->senderIndex);
	}

	std::array<uint8_t, 32> WireGuardHandshakeInitiationLayer::getInitiatorEphemeral() const
	{
		std::array<uint8_t, 32> ephemeralArray;
		memcpy(ephemeralArray.data(), getHandshakeInitiationHeader()->initiatorEphemeral, 32);
		return ephemeralArray;
	}

	std::array<uint8_t, 48> WireGuardHandshakeInitiationLayer::getEncryptedInitiatorStatic() const
	{
		std::array<uint8_t, 48> initArray;
		memcpy(initArray.data(), getHandshakeInitiationHeader()->encryptedInitiatorStatic, 48);
		return initArray;
	}

	std::array<uint8_t, 28> WireGuardHandshakeInitiationLayer::getEncryptedTimestamp() const
	{
		std::array<uint8_t, 28> tsArray;
		memcpy(tsArray.data(), getHandshakeInitiationHeader()->encryptedTimestamp, 28);
		return tsArray;
	}

	std::array<uint8_t, 16> WireGuardHandshakeInitiationLayer::getMac1() const
	{
		std::array<uint8_t, 16> mac1Array;
		memcpy(mac1Array.data(), getHandshakeInitiationHeader()->mac1, 16);
		return mac1Array;
	}

	std::array<uint8_t, 16> WireGuardHandshakeInitiationLayer::getMac2() const
	{
		std::array<uint8_t, 16> mac2Array;
		memcpy(mac2Array.data(), getHandshakeInitiationHeader()->mac2, 16);
		return mac2Array;
	}

	// ~~~~~~~~~~~~~~~~~~~~
	// WireGuardHandshakeResponseLayer
	// ~~~~~~~~~~~~~~~~~~~~

	WireGuardHandshakeResponseLayer::WireGuardHandshakeResponseLayer(uint32_t senderIndex, uint32_t receiverIndex,
	                                                                 const uint8_t responderEphemeral[32],
	                                                                 const uint8_t encryptedEmpty[16],
	                                                                 const uint8_t mac1[16], const uint8_t mac2[16])
	{
		const size_t messageLen = sizeof(wg_handshake_response);
		m_DataLen = messageLen;
		m_Data = new uint8_t[messageLen];
		wg_handshake_response* msg = reinterpret_cast<wg_handshake_response*>(m_Data);

		msg->messageType = static_cast<uint8_t>(WireGuardMessageType::HandshakeResponse);
		msg->senderIndex = htobe32(senderIndex);
		msg->receiverIndex = htobe32(receiverIndex);
		memcpy(msg->responderEphemeral, responderEphemeral, 32);
		memcpy(msg->encryptedEmpty, encryptedEmpty, 16);
		memcpy(msg->mac1, mac1, 16);
		memcpy(msg->mac2, mac2, 16);

		m_Protocol = WireGuard;
	}

	uint32_t WireGuardHandshakeResponseLayer::getSenderIndex() const
	{
		return be32toh(getHandshakeResponseHeader()->senderIndex);
	}

	uint32_t WireGuardHandshakeResponseLayer::getReceiverIndex() const
	{
		return be32toh(getHandshakeResponseHeader()->receiverIndex);
	}

	std::array<uint8_t, 32> WireGuardHandshakeResponseLayer::getResponderEphemeral() const
	{
		std::array<uint8_t, 32> responderEphemeralArray;
		memcpy(responderEphemeralArray.data(), getHandshakeResponseHeader()->responderEphemeral, 32);
		return responderEphemeralArray;
	}

	std::array<uint8_t, 16> WireGuardHandshakeResponseLayer::getEncryptedEmpty() const
	{
		std::array<uint8_t, 16> encryptedEmptyArray;
		memcpy(encryptedEmptyArray.data(), getHandshakeResponseHeader()->encryptedEmpty, 16);
		return encryptedEmptyArray;
	}

	std::array<uint8_t, 16> WireGuardHandshakeResponseLayer::getMac1() const
	{
		std::array<uint8_t, 16> mac1Array;
		memcpy(mac1Array.data(), getHandshakeResponseHeader()->mac1, 16);
		return mac1Array;
	}

	std::array<uint8_t, 16> WireGuardHandshakeResponseLayer::getMac2() const
	{
		std::array<uint8_t, 16> mac2Array;
		memcpy(mac2Array.data(), getHandshakeResponseHeader()->mac2, 16);
		return mac2Array;
	}

	// ~~~~~~~~~~~~~~~~~~~~
	// WireGuardCookieReplyLayer
	// ~~~~~~~~~~~~~~~~~~~~

	WireGuardCookieReplyLayer::WireGuardCookieReplyLayer(uint32_t receiverIndex, const uint8_t nonce[24],
	                                                     const uint8_t encryptedCookie[32])
	{
		const size_t messageLen = sizeof(wg_cookie_reply);
		m_DataLen = messageLen;
		m_Data = new uint8_t[messageLen];
		memset(m_Data, 0, messageLen);

		wg_cookie_reply* msg = reinterpret_cast<wg_cookie_reply*>(m_Data);

		msg->messageType = static_cast<uint8_t>(WireGuardMessageType::CookieReply);
		msg->receiverIndex = htobe32(receiverIndex);
		memcpy(msg->nonce, nonce, 24);
		memcpy(msg->encryptedCookie, encryptedCookie, 32);

		m_Protocol = WireGuard;
	}

	uint32_t WireGuardCookieReplyLayer::getReceiverIndex() const
	{
		return be32toh(getCookieReplyHeader()->receiverIndex);
	}

	std::array<uint8_t, 24> WireGuardCookieReplyLayer::getNonce() const
	{
		std::array<uint8_t, 24> nonceArray;
		memcpy(nonceArray.data(), getCookieReplyHeader()->nonce, 24);
		return nonceArray;
	}

	std::array<uint8_t, 32> WireGuardCookieReplyLayer::getEncryptedCookie() const
	{
		std::array<uint8_t, 32> encryptedCookieArray;
		memcpy(encryptedCookieArray.data(), getCookieReplyHeader()->encryptedCookie, 32);
		return encryptedCookieArray;
	}

	// ~~~~~~~~~~~~~~~~~~~~
	// WireGuardTransportDataLayer
	// ~~~~~~~~~~~~~~~~~~~~

	WireGuardTransportDataLayer::WireGuardTransportDataLayer(uint32_t receiverIndex, uint64_t counter,
	                                                         const uint8_t* encryptedData, size_t encryptedDataLen)
	{
		const size_t messageLen = sizeof(wg_transport_data) + encryptedDataLen;
		m_DataLen = messageLen;
		m_Data = new uint8_t[messageLen];
		memset(m_Data, 0, messageLen);

		wg_transport_data* msg = reinterpret_cast<wg_transport_data*>(m_Data);

		msg->messageType = static_cast<uint8_t>(WireGuardMessageType::TransportData);
		msg->receiverIndex = htobe32(receiverIndex);
		msg->counter = htobe64(counter);
		memcpy(m_Data + sizeof(wg_transport_data), encryptedData, encryptedDataLen);

		m_Protocol = WireGuard;
	}

	uint32_t WireGuardTransportDataLayer::getReceiverIndex() const
	{
		return be32toh(getTransportHeader()->receiverIndex);
	}

	uint64_t WireGuardTransportDataLayer::getCounter() const
	{
		return be64toh(getTransportHeader()->counter);
	}

	const uint8_t* WireGuardTransportDataLayer::getEncryptedData() const
	{
		return getTransportHeader()->encryptedData;
	}

}  // namespace pcpp

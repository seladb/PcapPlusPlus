#define LOG_MODULE PacketLogModuleWireGuardLayer

#include "UdpLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "WireGuardLayer.h"
#include "Logger.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace pcpp
{
	void WireGuardLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen || headerLen == 0)
			return;
		m_NextLayer = WireGuardLayer::parseWireGuardLayer(m_Data, m_DataLen, this, m_Packet);
	}

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
		// Assuming you have a method to retrieve the message type from the header
		wg_common_header* wgHeader = reinterpret_cast<wg_common_header*>(this->getData());
		switch (wgHeader->messageType)
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
		return "WireGuardLayer, " + getMessageTypeAsString() + " message";
	}

	size_t WireGuardLayer::getHeaderLen() const
	{
		return m_DataLen;
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

		std::memset(msgHdr->reserved, 0, sizeof(msgHdr->reserved));

		msgHdr->senderIndex = senderIndex;
		std::memcpy(msgHdr->initiatorEphemeral, initiatorEphemeral, 32);
		std::memcpy(msgHdr->encryptedInitiatorStatic, encryptedInitiatorStatic, 48);
		std::memcpy(msgHdr->encryptedTimestamp, encryptedTimestamp, 28);
		std::memcpy(msgHdr->mac1, mac1, 16);
		std::memcpy(msgHdr->mac2, mac2, 16);

		m_Protocol = Wireguard;
	}

	uint32_t WireGuardHandshakeInitiationLayer::getMessageType() const
	{
		return getHandshakeInitiationHeader()->messageType;
	}

	const uint8_t* WireGuardHandshakeInitiationLayer::getReserved() const
	{
		return getHandshakeInitiationHeader()->reserved;
	}

	uint32_t WireGuardHandshakeInitiationLayer::getSenderIndex() const
	{
		return getHandshakeInitiationHeader()->senderIndex;
	}

	const uint8_t* WireGuardHandshakeInitiationLayer::getInitiatorEphemeral() const
	{
		return getHandshakeInitiationHeader()->initiatorEphemeral;
	}

	const uint8_t* WireGuardHandshakeInitiationLayer::getEncryptedInitiatorStatic() const
	{
		return getHandshakeInitiationHeader()->encryptedInitiatorStatic;
	}

	const uint8_t* WireGuardHandshakeInitiationLayer::getEncryptedTimestamp() const
	{
		return getHandshakeInitiationHeader()->encryptedTimestamp;
	}

	const uint8_t* WireGuardHandshakeInitiationLayer::getMac1() const
	{
		return getHandshakeInitiationHeader()->mac1;
	}

	const uint8_t* WireGuardHandshakeInitiationLayer::getMac2() const
	{
		return getHandshakeInitiationHeader()->mac2;
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
		std::memset(m_Data, 0, messageLen);

		wg_handshake_response* msg = reinterpret_cast<wg_handshake_response*>(m_Data);

		msg->messageType = static_cast<uint8_t>(WireGuardMessageType::HandshakeResponse);

		std::memset(msg->reserved, 0, sizeof(msg->reserved));

		msg->senderIndex = senderIndex;
		msg->receiverIndex = receiverIndex;
		std::memcpy(msg->responderEphemeral, responderEphemeral, 32);
		std::memcpy(msg->encryptedEmpty, encryptedEmpty, 16);
		std::memcpy(msg->mac1, mac1, 16);
		std::memcpy(msg->mac2, mac2, 16);

		m_Protocol = Wireguard;
	}

	uint32_t WireGuardHandshakeResponseLayer::getMessageType() const
	{
		return getHandshakeResponseHeader()->messageType;
	}

	const uint8_t* WireGuardHandshakeResponseLayer::getReserved() const
	{
		return getHandshakeResponseHeader()->reserved;
	}

	uint32_t WireGuardHandshakeResponseLayer::getSenderIndex() const
	{
		return getHandshakeResponseHeader()->senderIndex;
	}

	uint32_t WireGuardHandshakeResponseLayer::getReceiverIndex() const
	{
		return getHandshakeResponseHeader()->receiverIndex;
	}

	const uint8_t* WireGuardHandshakeResponseLayer::getResponderEphemeral() const
	{
		return getHandshakeResponseHeader()->responderEphemeral;
	}

	const uint8_t* WireGuardHandshakeResponseLayer::getEncryptedEmpty() const
	{
		return getHandshakeResponseHeader()->encryptedEmpty;
	}

	const uint8_t* WireGuardHandshakeResponseLayer::getMac1() const
	{
		return getHandshakeResponseHeader()->mac1;
	}

	const uint8_t* WireGuardHandshakeResponseLayer::getMac2() const
	{
		return getHandshakeResponseHeader()->mac2;
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
		std::memset(m_Data, 0, messageLen);

		wg_cookie_reply* msg = reinterpret_cast<wg_cookie_reply*>(m_Data);

		msg->messageType = static_cast<uint8_t>(WireGuardMessageType::CookieReply);

		std::memset(msg->reserved, 0, sizeof(msg->reserved));

		msg->receiverIndex = receiverIndex;
		std::memcpy(msg->nonce, nonce, 24);
		std::memcpy(msg->encryptedCookie, encryptedCookie, 32);

		m_Protocol = Wireguard;
	}

	uint32_t WireGuardCookieReplyLayer::getMessageType() const
	{
		return getCookieReplyHeader()->messageType;
	}

	const uint8_t* WireGuardCookieReplyLayer::getReserved() const
	{
		return getCookieReplyHeader()->reserved;
	}

	uint32_t WireGuardCookieReplyLayer::getReceiverIndex() const
	{
		return getCookieReplyHeader()->receiverIndex;
	}

	const uint8_t* WireGuardCookieReplyLayer::getNonce() const
	{
		return getCookieReplyHeader()->nonce;
	}

	const uint8_t* WireGuardCookieReplyLayer::getEncryptedCookie() const
	{
		return getCookieReplyHeader()->encryptedCookie;
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
		std::memset(m_Data, 0, messageLen);

		wg_transport_data* msg = reinterpret_cast<wg_transport_data*>(m_Data);

		msg->messageType = static_cast<uint8_t>(WireGuardMessageType::TransportData);

		std::memset(msg->reserved, 0, sizeof(msg->reserved));

		msg->receiverIndex = receiverIndex;
		msg->counter = counter;

		std::memcpy(m_Data + sizeof(wg_transport_data), encryptedData, encryptedDataLen);

		m_Protocol = Wireguard;
	}

	uint32_t WireGuardTransportDataLayer::getMessageType() const
	{
		return getTransportHeader()->messageType;
	}

	const uint8_t* WireGuardTransportDataLayer::getReserved() const
	{
		return getTransportHeader()->reserved;
	}

	uint32_t WireGuardTransportDataLayer::getReceiverIndex() const
	{
		return getTransportHeader()->receiverIndex;
	}

	uint64_t WireGuardTransportDataLayer::getCounter() const
	{
		return getTransportHeader()->counter;
	}

	const uint8_t* WireGuardTransportDataLayer::getEncryptedData() const
	{
		return getTransportHeader()->encryptedData;
	}

}  // namespace pcpp

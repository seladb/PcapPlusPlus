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
	std::string WireGuardLayer::toString() const
	{
		if (m_DataLen < sizeof(wg_common_header))
		{
			return "WireGuard header (incomplete)";
		}

		std::stringstream ss;
		const wg_common_header* header = reinterpret_cast<const wg_common_header*>(m_Data);
		ss << "WireGuard Layer\n";
		ss << "  Type: " << static_cast<int>(header->messageType) << "\n";
		ss << "  Reserved: ";
		for (int i = 0; i < 3; ++i)
		{
			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(header->reserved[i]);
		}
		ss << std::dec << "\n";  // Reset to decimal

		switch (header->messageType)
		{
		case static_cast<uint8_t>(WireGuardMessageType::HandshakeInitiation):
		{
			const wg_handshake_initiation* msg = getHandshakeInitiation();
			ss << "  Handshake Initiation\n";
			ss << "    Sender Index: " << msg->senderIndex << "\n";
			ss << "    Initiator Ephemeral: ";
			for (const auto& byte : msg->initiatorEphemeral)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			ss << "    Encrypted Initiator Static: ";
			for (const auto& byte : msg->encryptedInitiatorStatic)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			ss << "    Encrypted Timestamp: ";
			for (const auto& byte : msg->encryptedTimestamp)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			ss << "    MAC1: ";
			for (const auto& byte : msg->mac1)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			ss << "    MAC2: ";
			for (const auto& byte : msg->mac2)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			break;
		}
		case static_cast<uint8_t>(WireGuardMessageType::HandshakeResponse):
		{
			const wg_handshake_response* msg = getHandshakeResponse();
			ss << "  Handshake Response\n";
			ss << "    Sender Index: " << msg->senderIndex << "\n";
			ss << "    Receiver Index: " << msg->receiverIndex << "\n";
			ss << "    Responder Ephemeral: ";
			for (const auto& byte : msg->responderEphemeral)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			ss << "    Encrypted Empty: ";
			for (const auto& byte : msg->encryptedEmpty)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			ss << "    MAC1: ";
			for (const auto& byte : msg->mac1)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			ss << "    MAC2: ";
			for (const auto& byte : msg->mac2)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			break;
		}
		case static_cast<uint8_t>(WireGuardMessageType::CookieReply):
		{
			const wg_cookie_reply* msg = getCookieReply();
			ss << "  Cookie Reply\n";
			ss << "    Receiver Index: " << msg->receiverIndex << "\n";
			ss << "    Nonce: ";
			for (const auto& byte : msg->nonce)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			ss << "    Encrypted Cookie: ";
			for (const auto& byte : msg->encryptedCookie)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
			}
			ss << std::dec << "\n";
			break;
		}
		case static_cast<uint8_t>(WireGuardMessageType::TransportData):
		{
			const wg_transport_data* msg = getTransportData();
			ss << "  Transport Data\n";
			ss << "    Receiver Index: " << msg->receiverIndex << "\n";
			ss << "    Counter: " << msg->counter << "\n";
			ss << "    Encrypted Data: ";
			for (size_t i = 0; i < m_DataLen - sizeof(wg_transport_data); ++i)
			{
				ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(msg->encryptedData[i]);
			}
			ss << std::dec << "\n";
			break;
		}
		default:
			ss << "  Unknown message type\n";
			break;
		}

		return ss.str();
	}

	size_t WireGuardLayer::getHeaderLen() const
	{
		return m_DataLen;
	}

}  // namespace pcpp

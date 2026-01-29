#define LOG_MODULE PacketLogModuleIPSecLayer

#include "EndianPortable.h"
#include "GeneralUtils.h"
#include "IPSecLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "UdpLayer.h"
#include "TcpLayer.h"
#include "PayloadLayer.h"
#include <sstream>

namespace pcpp
{

	// ---------------------------------
	// AuthenticationHeaderLayer methods
	// ---------------------------------

	uint32_t AuthenticationHeaderLayer::getSPI() const
	{
		return be32toh(getAHHeader()->spi);
	}

	uint32_t AuthenticationHeaderLayer::getSequenceNumber() const
	{
		return be32toh(getAHHeader()->sequenceNumber);
	}

	size_t AuthenticationHeaderLayer::getICVLength() const
	{
		// payloadLen = 3 (fixed ipsec_authentication_header size 32-bit words) + ICV - 2
		// ICV = (payloadLen + 2 - 3) in 32-bit words
		return (getAHHeader()->payloadLen - 1) * 4;
	}

	uint8_t* AuthenticationHeaderLayer::getICVBytes() const
	{
		size_t icvLength = getICVLength();
		if (icvLength > 0)
			return m_Data + sizeof(ipsec_authentication_header);
		return nullptr;
	}

	std::string AuthenticationHeaderLayer::getICVHexStream() const
	{
		uint8_t* bytes = getICVBytes();
		if (bytes == nullptr)
			return "";

		return byteArrayToHexString(bytes, getICVLength());
	}

	void AuthenticationHeaderLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		uint8_t* payload = m_Data + headerLen;
		size_t payloadLen = m_DataLen - headerLen;

		switch (getAHHeader()->nextHeader)
		{
		case PACKETPP_IPPROTO_UDP:
		{
			tryConstructNextLayerWithFallback<UdpLayer, PayloadLayer>(payload, payloadLen);
			break;
		}
		case PACKETPP_IPPROTO_TCP:
		{
			tryConstructNextLayerWithFallback<TcpLayer, PayloadLayer>(payload, payloadLen);
			break;
		}
		case PACKETPP_IPPROTO_IPIP:
		{
			uint8_t ipVersion = *payload >> 4;
			switch (ipVersion)
			{
			case 4:
			{
				tryConstructNextLayerWithFallback<IPv4Layer, PayloadLayer>(payload, payloadLen);
				break;
			}
			case 6:
			{
				tryConstructNextLayerWithFallback<IPv6Layer, PayloadLayer>(payload, payloadLen);
				break;
			}
			default:
			{
				constructNextLayer<PayloadLayer>(payload, payloadLen);
				break;
			}
			}
			break;
		}
		case PACKETPP_IPPROTO_ESP:
		{
			tryConstructNextLayerWithFallback<ESPLayer, PayloadLayer>(payload, payloadLen);
			break;
		}
		default:
			constructNextLayer<PayloadLayer>(payload, payloadLen);
		}
	}

	std::string AuthenticationHeaderLayer::toString() const
	{
		return "Authentication Header Layer";
	}

	// ----------------
	// ESPLayer methods
	// ----------------

	uint32_t ESPLayer::getSPI() const
	{
		return be32toh(getESPHeader()->spi);
	}

	uint32_t ESPLayer::getSequenceNumber() const
	{
		return be32toh(getESPHeader()->sequenceNumber);
	}

	void ESPLayer::parseNextLayer()
	{
		size_t headerLen = getHeaderLen();
		if (m_DataLen <= headerLen)
			return;

		constructNextLayer<PayloadLayer>(m_Data + headerLen, m_DataLen - headerLen);
	}

	std::string ESPLayer::toString() const
	{
		std::ostringstream stream;
		stream << "ESP Layer, SPI: 0x" << std::hex << getSPI();
		return stream.str();
	}

}  // namespace pcpp

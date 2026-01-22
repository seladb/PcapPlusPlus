#include "NullLoopbackLayer.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"

namespace pcpp
{

#define BSWAP16(x) (((x) >> 8) | ((x) << 8))
#define BSWAP32(x) (((x) >> 24) | (((x) & 0x00FF'0000) >> 8) | (((x) & 0x0000'FF00) << 8) | ((x) << 24))

#define IEEE_802_3_MAX_LEN 0x5dc

	NullLoopbackLayer::NullLoopbackLayer(uint32_t family)
	{
		const size_t dataLen = sizeof(uint32_t);
		m_DataLen = dataLen;
		m_Data = new uint8_t[dataLen];
		memset(m_Data, 0, dataLen);
		m_Protocol = NULL_LOOPBACK;

		setFamily(family);
	}

	uint32_t NullLoopbackLayer::getFamily() const
	{
		uint32_t family = *(reinterpret_cast<uint32_t*>(m_Data));
		if ((family & 0xFFFF'0000) != 0)
		{
			if ((family & 0xFF00'0000) == 0 && (family & 0x00FF'0000) < 0x0006'0000)
			{
				family >>= 16;
			}
			else
			{
				family = BSWAP32(family);
			}
		}
		else if ((family & 0x0000'00FF) == 0 && (family & 0x0000'FF00) < 0x0000'0600)
		{
			family = BSWAP16(family & 0xFFFF);
		}

		return family;
	}

	void NullLoopbackLayer::setFamily(uint32_t family)
	{
		*m_Data = family;
	}

	void NullLoopbackLayer::parseNextLayer()
	{
		uint8_t* payload = m_Data + sizeof(uint32_t);
		size_t payloadLen = m_DataLen - sizeof(uint32_t);

		uint32_t family = getFamily();
		if (family > IEEE_802_3_MAX_LEN)
		{
			uint16_t ethType = static_cast<uint16_t>(family);
			switch (ethType)
			{
			case PCPP_ETHERTYPE_IP:
			{
				tryConstructNextLayerWithFallback<IPv4Layer, PayloadLayer>(payload, payloadLen);
				return;
			}
			case PCPP_ETHERTYPE_IPV6:
			{
				tryConstructNextLayerWithFallback<IPv6Layer, PayloadLayer>(payload, payloadLen);
				return;
			}
			default:
			{
				constructNextLayer<PayloadLayer>(payload, payloadLen);
				return;
			}
			}
		}

		switch (family)
		{
		case PCPP_BSD_AF_INET:
		{
			tryConstructNextLayerWithFallback<IPv4Layer, PayloadLayer>(payload, payloadLen);
			break;
		}
		case PCPP_BSD_AF_INET6_BSD:
		case PCPP_BSD_AF_INET6_FREEBSD:
		case PCPP_BSD_AF_INET6_DARWIN:
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
	}

	std::string NullLoopbackLayer::toString() const
	{
		return "Null/Loopback";
	}

}  // namespace pcpp

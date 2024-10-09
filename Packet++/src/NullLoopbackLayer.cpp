#include "NullLoopbackLayer.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"

namespace pcpp
{

#define BSWAP16(x) (((x) >> 8) | ((x) << 8))
#define BSWAP32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))

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
		if ((family & 0xFFFF0000) != 0)
		{
			if ((family & 0xFF000000) == 0 && (family & 0x00FF0000) < 0x00060000)
			{
				family >>= 16;
			}
			else
			{
				family = BSWAP32(family);
			}
		}
		else if ((family & 0x000000FF) == 0 && (family & 0x0000FF00) < 0x00000600)
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
				m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
				                  ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
				                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
				return;
			case PCPP_ETHERTYPE_IPV6:
				m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
				                  ? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
				                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
				return;
			default:
				m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
				return;
			}
		}

		switch (family)
		{
		case PCPP_BSD_AF_INET:
			m_NextLayer = IPv4Layer::isDataValid(payload, payloadLen)
			                  ? static_cast<Layer*>(new IPv4Layer(payload, payloadLen, this, m_Packet))
			                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
			break;
		case PCPP_BSD_AF_INET6_BSD:
		case PCPP_BSD_AF_INET6_FREEBSD:
		case PCPP_BSD_AF_INET6_DARWIN:
			m_NextLayer = IPv6Layer::isDataValid(payload, payloadLen)
			                  ? static_cast<Layer*>(new IPv6Layer(payload, payloadLen, this, m_Packet))
			                  : static_cast<Layer*>(new PayloadLayer(payload, payloadLen, this, m_Packet));
			break;
		default:
			m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
		}
	}

	std::string NullLoopbackLayer::toString() const
	{
		return "Null/Loopback";
	}

}  // namespace pcpp

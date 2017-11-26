#include "NullLoopbackLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "PayloadLayer.h"
#include <string.h>

namespace pcpp
{

#define BSWAP16(x) (((x) >> 8) | ((x) << 8))
#define BSWAP32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) \
                  | (((x) & 0x0000FF00) << 8) | ((x) << 24))


NullLoopbackLayer::NullLoopbackLayer(uint32_t family)
{
	m_DataLen = sizeof(uint32_t);
	m_Data = new uint8_t[m_DataLen];
	memset(m_Data, 0, m_DataLen);
	m_Protocol = NULL_LOOPBACK;

	setFamily(family);
}

uint32_t NullLoopbackLayer::getFamily()
{
	uint32_t family = *(uint32_t*)m_Data;
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
    else
    {
		if ((family & 0x000000FF) == 0 && (family & 0x0000FF00) < 0x00000600)
		{
			family = BSWAP16(family & 0xFFFF);
		}
    }

    return family;
}

void NullLoopbackLayer::setFamily(uint32_t family)
{
	*m_Data = family;
}

void NullLoopbackLayer::parseNextLayer()
{
	uint32_t family = getFamily();
	switch (family)
	{
	case PCPP_BSD_AF_INET:
		m_NextLayer = new IPv4Layer(m_Data + sizeof(uint32_t), m_DataLen - sizeof(uint32_t), this, m_Packet);
		break;
    case PCPP_BSD_AF_INET6_BSD:
    case PCPP_BSD_AF_INET6_FREEBSD:
    case PCPP_BSD_AF_INET6_DARWIN:
		m_NextLayer = new IPv6Layer(m_Data + sizeof(uint32_t), m_DataLen - sizeof(uint32_t), this, m_Packet);
		break;
    default:
    	m_NextLayer = new PayloadLayer(m_Data + sizeof(uint32_t), m_DataLen - sizeof(uint32_t), this, m_Packet);
	}
}


std::string NullLoopbackLayer::toString()
{
	return "Null/Loopback";
}

}
